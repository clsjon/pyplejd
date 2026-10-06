import asyncio
import binascii
import logging
import os
from collections import deque
from datetime import datetime, timedelta
from functools import partial
from typing import Callable
import time

from bleak import BleakClient, BleakError
from bleak.backends.device import BLEDevice
from bleak_retry_connector import establish_connection, BleakClientWithServiceCache

from .crypto import auth_response, encrypt_decrypt
from . import ble_characteristics as gatt
from . import payload_encode
from .lastdata import LastData, MiniPkg
from .lightlevel import parse_lightlevels, LightLevel
from .ble_characteristics import PLEJD_SERVICE
from .debug import rec_log

_LOGGER = logging.getLogger(__name__)
_CONNECTION_LOG = logging.getLogger("pyplejd.ble.connection")

# Connection parameters requested once the mesh connection is up.
#
# A Plejd unit is not only a GATT peripheral: the same radio also carries the
# Plejd mesh, relaying and re-announcing traffic for every other unit. Home
# Assistant's Bluetooth stack asks BlueZ for an aggressive 8.75-11.25 ms
# connection interval, which leaves the unit too little radio time for that
# second duty. Measured on a two-unit mesh with a local adapter, the effects
# began abruptly below 15 ms and were severe at 11.25 ms:
#
#   interval    behaviour
#   11.25 ms    unit emits a 1.6 s on/off state pulse train, relays almost
#               nothing from its peers, and switches its own output unbidden
#   12.50 ms    same, less frequent
#   15.00 ms    clean
#   20.00 ms    clean
#   45.00 ms    clean
#
# 30-50 ms is chosen rather than the measured 15 ms boundary because that
# boundary was found on the smallest possible mesh. A larger installation has
# more traffic to relay and therefore needs more radio time, not less, so the
# margin protects meshes bigger than the one it was measured on. For lighting,
# the added latency of a few tens of milliseconds is imperceptible.
CONN_MIN_INTERVAL = 24  # 24 * 1.25 ms = 30 ms
CONN_MAX_INTERVAL = 40  # 40 * 1.25 ms = 50 ms
CONN_LATENCY = 0
CONN_TIMEOUT = 800  # 800 * 10 ms = 8 s

# Button event re-arming.
#
# Buttons only report a press (0x0016) once per EVENT_PREPARE (0x0015)
# broadcast, so every received event has to be answered with a new broadcast
# to hear the next one. A gateway unit that misreports its own input under
# load turns that into a self-sustaining loop: phantom event -> re-arm ->
# phantom event, at the mesh round-trip rate. A DIM-01 toggles its own output
# on a button press, so the loop shows up as the gateway light blinking.
#
# The re-arm is therefore rate limited, and a burst of events from a single
# input is treated as a storm: re-arming is paused for a while and the
# offending input is named in the log. The periodic keep-alive still re-arms,
# so real presses are picked up again after the pause.
BUTTON_REARM_COOLDOWN = 1.0  # s, minimum spacing between EVENT_PREPARE writes
BUTTON_STORM_WINDOW = 20.0  # s
BUTTON_STORM_COUNT = 15  # events from one input within the window
BUTTON_STORM_BACKOFF = 60.0  # s, re-arming pause after a storm


class MeshDevice:
    BLEaddress: str
    connectable: bool
    last_seen: datetime = None
    rssi: int = None
    bleDevice: BLEDevice = None
    is_gateway: bool = False

    def see(self, rssi, bleDevice: BLEDevice) -> bool:
        # Returns true if first seen
        if first_seen := (self.rssi is None):
            self.bleDevice = bleDevice
            self.rssi = rssi

        self.last_seen = datetime.now()
        self.rssi = max(self.rssi, rssi)

        return first_seen

    def update(self):
        pass


def normalize_address(addr: str) -> str:
    return addr.replace(":", "").upper()


class PlejdMesh:
    def __init__(self, manager):
        self.manager = manager
        self._mesh_devices: dict[str, MeshDevice] = {}
        self._gateway_node: MeshDevice | None = None
        self._crypto_key: bytearray = None
        self._client: BleakClient = None

        # Incremented for every connection attempt. Disconnect callbacks carry
        # the id of the connection they belong to, so a late callback from a
        # connection that has already been replaced or torn down is ignored.
        self._connection_id = 0

        self._ble_lock = asyncio.Lock()

        self._last_button_rearm = 0.0
        self._button_rearm_task: asyncio.Task | None = None
        self._button_events: dict[tuple[int, int], deque[float]] = {}
        self._button_storm_until = 0.0

    @property
    def connected(self):
        return self._client is not None and self._client.is_connected

    def expect_device(self, node: MeshDevice = None):
        self._mesh_devices[node.BLEaddress] = node

    def see_device(self, node: BLEDevice, rssi: int) -> bool:
        _CONNECTION_LOG.debug(f"Saw device {node} (rssi: {rssi})")
        addr = normalize_address(node.address)
        if hw := self._mesh_devices.get(addr):
            return hw.see(rssi, node)
        return False

    def set_key(self, key: str):
        self._crypto_key = key

    # --- Connection handling -------------------------------------------------

    def _on_disconnect(self, connection_id: int, _client) -> None:
        """Called by bleak when the gateway connection is lost."""
        if connection_id != self._connection_id or self._client is None:
            # A connection we have already dropped or replaced
            return
        _CONNECTION_LOG.warning("Lost connection to the Plejd mesh")
        self._client = None
        self._mark_disconnected()

    def _mark_disconnected(self) -> None:
        if self._gateway_node:
            self._gateway_node.is_gateway = False
            self._gateway_node.update()
            self._gateway_node = None
        self.manager.connect_callback(False)

    @staticmethod
    async def _close_client(client: BleakClient) -> None:
        try:
            await client.disconnect()
        except (BleakError, asyncio.TimeoutError, EOFError) as e:
            _CONNECTION_LOG.debug("Error while closing connection: %s", e)

    async def disconnect(self):
        client = self._client
        if client is None:
            return False

        # Invalidate first so the bleak callback for this disconnect is ignored
        self._client = None
        self._connection_id += 1
        await self._close_client(client)
        self._mark_disconnected()
        return True

    async def connect(self):
        if self.connected:
            return True
        if self._client is not None:
            # The link dropped without the disconnect callback having run yet
            await self.disconnect()

        _CONNECTION_LOG.debug("Trying to connect to BLE mesh")

        # Try to connect to nodes in order of decreasing RSSI
        filtered_nodes = filter(
            lambda n: n.connectable and n.rssi is not None,
            self._mesh_devices.values(),
        )
        sorted_nodes = sorted(filtered_nodes, key=lambda n: n.rssi, reverse=True)

        if not sorted_nodes:
            _CONNECTION_LOG.debug("No connectable Plejd device has been seen yet")
            return False

        for node in sorted_nodes:
            self._connection_id += 1
            connection_id = self._connection_id
            try:
                _CONNECTION_LOG.debug("Attempting to connect to %s", node)
                client = await establish_connection(
                    BleakClientWithServiceCache,
                    node.bleDevice,
                    node.bleDevice.name,
                    partial(self._on_disconnect, connection_id),
                    max_attempts=2,
                )
            except (BleakError, asyncio.TimeoutError) as e:
                _CONNECTION_LOG.warning("Failed to connect to %s: %s", node, str(e))
                continue

            try:
                if not await self._authenticate(client):
                    await self._close_client(client)
                    continue

                # Requested after authentication, which is the order the
                # interval change was verified in. Both BlueZ and ESPHome
                # apply their own parameters around service discovery.
                await self._relax_connection_params(client)

                await client.start_notify(
                    gatt.PLEJD_LASTDATA, partial(self._lastdata_listener, node)
                )
                await client.start_notify(
                    gatt.PLEJD_LIGHTLEVEL, self._lightlevel_listener
                )
            except (BleakError, asyncio.TimeoutError) as e:
                _CONNECTION_LOG.warning(
                    "Failed to set up mesh connection via %s: %s", node, str(e)
                )
                await self._close_client(client)
                continue

            self._gateway_node = node
            node.is_gateway = True
            node.update()
            self._client = client
            break

        else:
            _CONNECTION_LOG.warning(
                "Failed to connect to plejd mesh - %s", sorted_nodes
            )
            return False

        _CONNECTION_LOG.info("Connected to the Plejd mesh via %s", node.BLEaddress)
        self.manager.connect_callback(True)

        await self.poll()
        return True

    # --- Notifications -------------------------------------------------------

    async def _lastdata_listener(self, node: MeshDevice, _char, lastdata: bytearray):
        if not self.connected or self._gateway_node is not node:
            return

        data = encrypt_decrypt(self._crypto_key, node.BLEaddress, lastdata)

        ld = LastData(data)
        rec_log(f"lastdata {ld}")
        await self.manager.lastdata_callback(ld)

        if ld.command == LastData.CMD_EVENT_FIRED:
            self._schedule_button_rearm(ld)

    async def _lightlevel_listener(self, _char, lightlevel: bytearray):
        if not self.connected:
            return

        rec_log(f"lightlevel {lightlevel}")
        await self.manager.lightlevel_callback(parse_lightlevels(lightlevel))

    def _schedule_button_rearm(self, event: LastData) -> None:
        """Re-arm button reporting, rate limited and with storm protection."""
        loop = asyncio.get_running_loop()
        now = loop.time()

        if now < self._button_storm_until:
            return

        key = (
            int(event.payload[0]) if len(event.payload) > 0 else -1,
            int(event.payload[1]) if len(event.payload) > 1 else -1,
        )
        times = self._button_events.setdefault(key, deque())
        times.append(now)
        while times and times[0] < now - BUTTON_STORM_WINDOW:
            times.popleft()

        if len(times) >= BUTTON_STORM_COUNT:
            self._button_storm_until = now + BUTTON_STORM_BACKOFF
            times.clear()
            if self._button_rearm_task is not None and not self._button_rearm_task.done():
                self._button_rearm_task.cancel()
                self._button_rearm_task = None
            gateway = self._gateway_node.BLEaddress if self._gateway_node else "?"
            _LOGGER.warning(
                "Button event storm: %d events from mesh address %d button %d in %.0f s. "
                "Pausing button re-arming for %.0f s. If this keeps happening the "
                "current gateway (%s) is probably misbehaving - try turning off "
                "'May be gateway' for that device.",
                BUTTON_STORM_COUNT,
                key[0],
                key[1],
                BUTTON_STORM_WINDOW,
                BUTTON_STORM_BACKOFF,
                gateway,
            )
            return

        if self._button_rearm_task is not None and not self._button_rearm_task.done():
            # A re-arm is already pending; it covers this event too
            return
        self._button_rearm_task = loop.create_task(self._rearm_buttons())

    async def _rearm_buttons(self) -> None:
        loop = asyncio.get_running_loop()
        wait = self._last_button_rearm + BUTTON_REARM_COOLDOWN - loop.time()
        if wait > 0:
            await asyncio.sleep(wait)
        if loop.time() < self._button_storm_until:
            return
        self._last_button_rearm = loop.time()
        await self.poll_buttons()

    # --- Mesh operations -----------------------------------------------------

    async def poll(self):
        if not self.connected:
            return False

        _LOGGER.debug("Polling mesh for current state")
        try:
            await self._client.write_gatt_char(
                gatt.PLEJD_LIGHTLEVEL, b"\x01", response=True
            )
        except (BleakError, asyncio.TimeoutError) as e:
            _LOGGER.warning("Polling plejd mesh failed: %s", str(e))
            return False
        return True

    async def poll_buttons(self):
        await self.write(LastData(command=LastData.CMD_EVENT_PREPARE).hex)

    async def ping(self):
        async with self._ble_lock:
            if not await self.connect():
                return False
            if not await self._ping(self._client):
                _CONNECTION_LOG.warning(
                    "Plejd mesh keep-alive failed - dropping the connection so it "
                    "can be re-established"
                )
                await self.disconnect()
                return False

        await self.poll()
        await self.poll_buttons()
        return True

    async def poll_time(self, address: int):
        if not self.connected or self._gateway_node is None:
            return False

        payloads = payload_encode.request_time(self, address)
        await self.write(payloads)

        try:
            retval = await self._client.read_gatt_char(gatt.PLEJD_LASTDATA)
        except (BleakError, asyncio.TimeoutError) as e:
            _LOGGER.debug("Reading time from plejd mesh failed: %s", str(e))
            return False
        data = encrypt_decrypt(self._crypto_key, self._gateway_node.BLEaddress, retval)
        ts = int.from_bytes(data[5:9], "little")
        dt = datetime.fromtimestamp(ts)

        now = datetime.now() + timedelta(seconds=3600 * time.daylight)
        if abs(dt - now) > timedelta(seconds=60):
            _LOGGER.debug(f"Device {address} repported the wrong time {dt} ({now=})")
            return True
        return False

    async def broadcast_time(self):
        payloads = payload_encode.set_time(self)
        await self.write(payloads)

    async def write(self, *payloads: list[str]):
        if not self.connected or self._gateway_node is None:
            return False

        pl = [
            encrypt_decrypt(
                self._crypto_key,
                self._gateway_node.BLEaddress,
                binascii.a2b_hex(payload.replace(" ", "")),
            )
            for payload in payloads
        ]
        _LOGGER.debug(f"Write: {payloads}")
        return await self._write(pl)

    async def _write(self, payloads):
        if not self.connected:
            return False

        try:
            async with self._ble_lock:
                if not self.connected:
                    return False
                for payload in payloads:
                    _LOGGER.debug("Writing to plejd mesh: %s", payload.hex())
                    await self._client.write_gatt_char(
                        gatt.PLEJD_DATA, payload, response=True
                    )
        except (BleakError, asyncio.TimeoutError) as e:
            _LOGGER.warning("Writing to plejd mesh failed: %s", str(e))
            return False
        return True

    async def _ping(self, client):
        if client is None:
            return False
        try:
            ping = bytearray(os.urandom(1))
            _LOGGER.debug("Ping(%s)", int.from_bytes(ping, "little"))
            await client.write_gatt_char(gatt.PLEJD_PING, ping, response=True)
            pong = await client.read_gatt_char(gatt.PLEJD_PING)
            _LOGGER.debug("Pong(%s)", int.from_bytes(pong, "little"))
            if (ping[0] + 1) & 0xFF == pong[0]:
                return True
        except (BleakError, asyncio.TimeoutError) as e:
            _LOGGER.warning("Plejd mesh keepalive signal failed: %s", str(e))
        return False

    async def _relax_connection_params(self, client: BleakClient) -> None:
        """Ask the host stack for a gentler connection interval.

        See CONN_MIN_INTERVAL above for why this is wanted.

        Best effort by design. The call is habluetooth's
        HaBleakClientWrapper.set_connection_params(), which is present when
        running under Home Assistant and handles both the local BlueZ mgmt
        path and ESPHome proxies. Plain bleak offers no portable equivalent,
        so a missing method - or a call that fails - is not an error, but it
        is logged so that an unstable mesh can be traced back to it.

        Note that an ESPHome proxy must run firmware that supports connection
        parameter updates. Older firmware is reported by Home Assistant's
        ESPHome Bluetooth client as a warning, and the request is dropped.
        """
        set_params = getattr(client, "set_connection_params", None)
        if set_params is None:
            _CONNECTION_LOG.info(
                "Bluetooth backend %s cannot change connection parameters - "
                "keeping the stack default interval",
                type(client).__name__,
            )
            return
        try:
            await set_params(
                CONN_MIN_INTERVAL, CONN_MAX_INTERVAL, CONN_LATENCY, CONN_TIMEOUT
            )
        except Exception as e:  # a failed optimisation must not fail the connection
            _CONNECTION_LOG.warning(
                "Could not set BLE connection parameters (%s). The mesh may be "
                "unstable with the default connection interval.",
                e,
            )
        else:
            _CONNECTION_LOG.info(
                "Requested BLE connection interval %.2f-%.2f ms (latency %d, timeout %d ms)",
                CONN_MIN_INTERVAL * 1.25,
                CONN_MAX_INTERVAL * 1.25,
                CONN_LATENCY,
                CONN_TIMEOUT * 10,
            )

    async def _authenticate(self, client: BleakClient):
        if client is None:
            return False
        try:
            _CONNECTION_LOG.debug("Authenticating with plejd mesh")
            await client.write_gatt_char(gatt.PLEJD_AUTH, b"\x00", response=True)
            _CONNECTION_LOG.debug("Requested auth")
            challenge = await client.read_gatt_char(gatt.PLEJD_AUTH)
            _CONNECTION_LOG.debug("Got challenge")
            response = auth_response(self._crypto_key, challenge)
            await client.write_gatt_char(gatt.PLEJD_AUTH, response, response=True)
            _CONNECTION_LOG.debug("Wrote response")
            if not await self._ping(client):
                _CONNECTION_LOG.debug("Authentication failed!")
                return False
            _CONNECTION_LOG.debug("Authentication successful")
            return True
        except (BleakError, asyncio.TimeoutError) as e:
            _CONNECTION_LOG.warning("Plejd mesh authentication failed: %s", str(e))
        return False
