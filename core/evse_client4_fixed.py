import asyncio
import urllib.request
import websockets
import pandapower as pp
import numpy as np
import random
import argparse
from datetime import datetime, timezone
import pandapower.plotting as pplt

from ocpp.routing import on
from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call, call_result
from ocpp.v16.enums import FirmwareStatus

# -----------------------------
# CLI — target URL
# BUG FIX: EVSE was hardcoded to ws://127.0.0.1:9000, connecting
# directly to the CSMS and bypassing the MITM proxy entirely.
# Now accepts --url so you can point it at the proxy (port 9001)
# for the MITM attack without editing source.
#
#   Normal operation : python evse_client4_fixed.py
#   MITM attack      : python evse_client4_fixed.py --url ws://127.0.0.1:9001
# -----------------------------
parser = argparse.ArgumentParser(description="OCPP 1.6 EVSE simulator")
parser.add_argument(
    "--url",
    default="ws://127.0.0.1:9000",
    help="CSMS WebSocket URL (use ws://127.0.0.1:9001 when running MITM proxy)"
)
args = parser.parse_args()
TARGET_URL = args.url


# -----------------------------
# PANDAPOWER NETWORK
# -----------------------------
def create_net():
    net = pp.create_empty_network()

    bus_hv = pp.create_bus(net, vn_kv=6.6)
    bus_lv = pp.create_bus(net, vn_kv=0.4)

    pp.create_ext_grid(net, bus_hv)

    pp.create_transformer_from_parameters(
        net, bus_hv, bus_lv,
        sn_mva=1.0,
        vn_hv_kv=6.6,
        vn_lv_kv=0.4,
        vk_percent=6,
        vkr_percent=1,
        pfe_kw=1,
        i0_percent=0.1
    )

    loads = []

    for i in range(5):
        b = pp.create_bus(net, vn_kv=0.4)

        pp.create_line_from_parameters(
            net, bus_lv, b,
            length_km=0.02,
            r_ohm_per_km=0.2,
            x_ohm_per_km=0.08,
            c_nf_per_km=200,
            max_i_ka=0.2
        )

        ld = pp.create_load(net, b, p_mw=0.06, scaling=0.0)
        loads.append(ld)

    return net, loads


# -----------------------------
# OCPP CLIENT
# -----------------------------
class EVSE(cp):

    async def send_boot(self):
        request = call.BootNotification(
            charge_point_vendor="Vendor",
            charge_point_model="Model1"
        )
        response = await self.call(request)
        print("[CLIENT] Boot Response:", response.status)

    async def send_meter(self, connector_id, p_kw):
        request = call.MeterValues(
            connector_id=connector_id,
            meter_value=[{
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sampledValue": [{
                    "value": str(round(p_kw, 2)),
                    "measurand": "Power.Active.Import"
                }]
            }]
        )
        await self.call(request)

    # ------------------------------------------------------------------
    # UpdateFirmware handler — PoC #3 (INL/CON-23-72329)
    # OCPP 1.6 provides no signature or hash on firmware updates.
    # The EVSE downloads and executes whatever URL the CSMS supplies.
    # ------------------------------------------------------------------
    @on('UpdateFirmware')
    async def on_update_firmware(self, location, retrieve_date, **kwargs):
        print()
        print(f"[EVSE] {'!'*46}")
        print(f"[EVSE]  UpdateFirmware received from CSMS")
        print(f"[EVSE]  location     : {location}")
        print(f"[EVSE]  retrieve_date: {retrieve_date}")
        print(f"[EVSE]  No signature check — OCPP 1.6 has none")
        print(f"[EVSE] {'!'*46}")
        print()
        asyncio.create_task(self._execute_firmware_update(location))
        return call_result.UpdateFirmware()

    async def _execute_firmware_update(self, location: str):
        await asyncio.sleep(1)

        await self._send_firmware_status(FirmwareStatus.downloading)
        print(f"[EVSE] Downloading firmware from {location} ...")
        await asyncio.sleep(2)

        # Fetch the payload over HTTP and print its contents
        try:
            loop = asyncio.get_running_loop()
            data = await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(location, timeout=10).read()
            )
            payload_text = data.decode("utf-8", errors="replace")
            print()
            print(f"[EVSE] {'='*52}")
            print(f"[EVSE] Downloaded firmware ({len(data)} bytes):")
            print(f"[EVSE] {'='*52}")
            for line in payload_text.splitlines()[:25]:
                print(f"[EVSE]   {line}")
            print(f"[EVSE] {'='*52}")
            print()
        except Exception as exc:
            print(f"[EVSE] HTTP fetch failed ({exc}) — simulating download")

        await self._send_firmware_status(FirmwareStatus.downloaded)
        print(f"[EVSE] Download complete — no integrity check performed")
        await asyncio.sleep(1)

        await self._send_firmware_status(FirmwareStatus.installing)
        print(f"[EVSE] Installing firmware (executing payload as root) ...")
        await asyncio.sleep(3)

        await self._send_firmware_status(FirmwareStatus.installed)
        print(f"[EVSE] Firmware install complete — EVSE now compromised")

    async def _send_firmware_status(self, status: FirmwareStatus):
        try:
            await self.call(call.FirmwareStatusNotification(status=status))
            print(f"[EVSE] FirmwareStatusNotification: {status}")
        except Exception as exc:
            print(f"[EVSE] FirmwareStatusNotification failed: {exc}")


# ------------------
# OCPP SENDER TASK
# ------------------
async def ocpp_sender(queue, evse):
    while True:
        charger_id, p_kw = await queue.get()

        # BUG FIX: filter out zero-load readings to reduce noise.
        # Without this, the CSMS receives a flood of 0.0 kW values
        # every cycle (when loads are off), making tampered 0.0 values
        # indistinguishable from real ones.
        if p_kw < 0.5:
            continue

        print(f"[CLIENT] OCPP sending: {p_kw} kW to connector {charger_id}")

        try:
            await evse.send_meter(charger_id, p_kw)
        except Exception as exc:
            # Connection may be briefly disrupted during MITM attack.
            print(f"[CLIENT] send_meter error: {exc}")


# -----------------------------
# SIMULATION + OCPP BRIDGE
# -----------------------------
async def run_sim(queue):

    net, loads = create_net()
    t = 0

    while t < 300:

        for l in loads:
            net.load.at[l, "scaling"] = 1 if random.random() < 0.5 else 0

        if t % 5 == 0:
            pp.runpp(net, numba=False)

            for i, l in enumerate(loads):
                p_kw = net.res_load.p_mw[l] * 1000
                await queue.put((i + 1, p_kw))

        await asyncio.sleep(1)
        t += 1


# -----------------------------
# MAIN
# -----------------------------
async def main():

    print("ENTERING MAIN")
    print(f"CONNECTING to {TARGET_URL} ...")

    queue = asyncio.Queue()

    async with websockets.connect(TARGET_URL) as ws:

        print("CONNECTED TO SERVER")

        await ws.send("CP_1")

        evse = EVSE("CP_1", ws)
        start_task = asyncio.create_task(evse.start())

        await evse.send_boot()

        print("[CLIENT] connected to CSMS")

        await asyncio.gather(
            run_sim(queue),
            ocpp_sender(queue, evse)
        )

        start_task.cancel()
        try:
            await start_task
        except (asyncio.CancelledError, websockets.exceptions.ConnectionClosedOK):
            pass


# Show the pandapower network diagram BEFORE asyncio starts.
# plt.ion() makes the window non-blocking so the simulation can continue.
import os
import matplotlib.pyplot as plt
net_preview, _ = create_net()
if os.environ.get('MPLBACKEND', '').lower() != 'agg':
    plt.ion()
    pplt.simple_plot(net_preview, plot_line_switches=True)
    plt.pause(0.5)   # give the window time to render

asyncio.run(main())
