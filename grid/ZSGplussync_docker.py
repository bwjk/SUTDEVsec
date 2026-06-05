###################################
# 7ss without socket communication
#      Jit Biswas
# modified to handle mqtt
# Docker/headless patch — Bryan Wang Jun Keat
#   Changes from original ZSGplussync.py:
#   1. matplotlib.use('Agg')  — no display in containers; ENV MPLBACKEND=Agg
#      already set in Dockerfile but the explicit call overrides it if present
#   2. Both pplt.simple_plot() calls commented out — GUI blocks headless loop
#   3. mqtt_publish_voltages() replaced with no-op — mosquitto_pub not installed
#   4. read_ev_load_kw() added — reads /shared/ev_load_kw.txt written by attack
#   5. Two lines added in while True: to inject EV load before each runpp()
#   Everything else is IDENTICAL to Dr. Biswas's original.
###################################

import pandapower as pp
import pandapower.plotting as pplt
import matplotlib
matplotlib.use('Agg')          # CHANGE 1: headless, no Qt display needed
import matplotlib.pyplot as plt
from pandapower import runpp
from pandapower.pf.runpp_3ph import runpp_3ph
import csv
import os
import sys
import random
import pandas as pd
from datetime import datetime

MQTTBrokerIP = '127.0.0.1'

DistGridnames = {}
DistGridnames[1] = 'Kampong Java'
DistGridnames[2] = 'Tampines'
DistGridnames[3] = 'Paya Lebar'
DistGridnames[4] = 'Ayer Rajah'
DistGridnames[5] = 'Jurong Pier'
DistGridnames[6] = 'Choa Chu Kang'

# Load at which SubStation
LoadSS = {}
LoadSS[1] = "DS2"
LoadSS[2] = "DS3"
LoadSS[3] = "DS3"
LoadSS[4] = "DS4"
LoadSS[5] = "DS4"
LoadSS[6] = "DS4"
LoadSS[7] = "DS4"

load_buslist  = [21, 42, 43, 44, 45, 46, 47]
load_linelist = [24, 34, 35, 36, 37, 38, 39]

# ── EV load integration ───────────────────────────────────────────────────────
# CHANGE 4: read aggregated EV load written by the attack container.
# The attack scripts write a plain float (kW) to this shared file every time
# MeterValues arrive from a charger.  ZSGplussync reads it before each runpp().
EV_LOAD_FILE    = '/shared/ev_load_kw.txt'   # Docker volume shared with attack
EV_LOAD_IDX     = 3                           # net.load index for Load4 (Bus 44)
EV_LOAD_BASELINE_MW = 0.1                     # original Load4 p_mw from create_pgtv2

def read_ev_load_kw() -> float:
    """Return aggregated EV load in kW from shared file, 0.0 if not yet written."""
    try:
        with open(EV_LOAD_FILE, 'r') as f:
            return max(0.0, float(f.read().strip()))
    except Exception:
        return 0.0
# ─────────────────────────────────────────────────────────────────────────────


# pandapower start

class PGT():

    def __init__(self):
        self.net = pp.create_empty_network()
        self.busvarnames = ['vm_pu', 'va_degree', 'p_mw', 'q_mvar']
        self.linevarnames = ['pl_mw', 'ql_mvar', 'i_from_ka', 'i_to_ka', 'i_ka', 'loading_percent']
        self.linevarnamespower = ['p_from_mw', 'q_from_mvar']

    def create_line_with_switch(self, first_bus, last_bus, length_km, std_type, status):
        lidx = pp.create_line_from_parameters(net=self.net, from_bus=first_bus, to_bus=last_bus, length_km=length_km,
                              r_ohm_per_km=0.343, x_ohm_per_km=0.077, c_nf_per_km=410, max_i_ka=0.588,
                              r0_ohm_per_km=0.7766, x0_ohm_per_km=0.29907, c0_nf_per_km=490)
        sw = pp.create_switch(net=self.net, bus=first_bus, element=lidx, et="l", closed=status)

    def create_network(self):

        self.brkrnames = ['QG1', 'QG2',
                          'QT1-1', 'QT1-2', 'QT1-3', 'QT1-4', 'QT1-5', 'QT1-6',
                          'QT1-7', 'QT1-8', 'QT1-9', 'QT1-10', 'QT1-11',
                          'QT2-1', 'QT2-2', 'QT2-3', 'QT2-4', 'QT2-5', 'QT2-6',
                          'QT2-7', 'QT2-8', 'QT2-9', 'QT2-10', 'QT2-11', 'QT2-12',
                          'QD1-1', 'QD1-2', 'QD1-3',
                          'QD2-1', 'QD2-2', 'QD2-3', 'QD2-4']

    def create_pgtv2(self):
        self.net = pp.create_empty_network()
        self.create_network()

        bus_data = [
            {"name": "Bus 0",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 1",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 2",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 3",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 4",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 5",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 6",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 7",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 8",  "vn_kv": 66,  "type": "b"},
            {"name": "Bus 9",  "vn_kv": 22,  "type": "b"},
            {"name": "Bus 10", "vn_kv": 22,  "type": "b"},
            {"name": "Bus 11", "vn_kv": 22,  "type": "b"},
            {"name": "Bus 12", "vn_kv": 22,  "type": "b"},
            {"name": "Bus 13", "vn_kv": 22,  "type": "b"},
            {"name": "Bus 14", "vn_kv": 22,  "type": "b"},
            {"name": "Bus 15", "vn_kv": 22,  "type": "b"},
            {"name": "Bus 16", "vn_kv": 22,  "type": "b"},
            {"name": "Bus 17", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 18", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 19", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 20", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 21", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 22", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 23", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 24", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 25", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 26", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 27", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 28", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 29", "vn_kv": 6.6, "type": "b"},
            {"name": "Bus 30", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 31", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 32", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 33", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 34", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 35", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 36", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 37", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 38", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 39", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 40", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 41", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 42", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 43", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 44", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 45", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 46", "vn_kv": 0.4, "type": "b"},
            {"name": "Bus 47", "vn_kv": 0.4, "type": "b"},
        ]

        for bus in bus_data:
            pp.create_bus(net=self.net, name=bus["name"], vn_kv=bus["vn_kv"], type=bus["type"])

        pp.create_gen(net=self.net, bus=0, p_mw=1.3607, vm_pu=1, slack=True)

        line_data = [
            (2,  5,  15),
            (4,  6,  15),
            (11, 13, 10),
            (12, 14, 10),
            (22, 24,  2),
            (25, 26,  5),
            (23, 27,  5),
            (34, 38, 0.5),
            (36, 39, 0.5),
            (37, 40, 0.5),
            (35, 41, 0.5),
        ]

        for from_bus, to_bus, length_km in line_data:
            pp.create_line(net=self.net, from_bus=from_bus, to_bus=to_bus, length_km=length_km,
                           std_type="N2XS(FL)2Y 1x300 RM/35 64/110 kV",
                           r0_ohm_per_km=0.0848, x0_ohm_per_km=0.4649556, c0_nf_per_km=230.6)

        brkr_data = [
            {"from_bus":  0, "to_bus":  1, "length_km": 0.001, "status": True},   # QG1
            {"from_bus":  1, "to_bus":  3, "length_km": 0.001, "status": True},   # QG2
            {"from_bus":  1, "to_bus":  2, "length_km": 0.001, "status": True},   # QT1-1
            {"from_bus":  1, "to_bus":  4, "length_km": 0.001, "status": True},   # QT2-1
            {"from_bus":  5, "to_bus":  7, "length_km": 0.001, "status": True},   # QT1-2
            {"from_bus":  6, "to_bus":  8, "length_km": 0.001, "status": True},   # QT2-2
            {"from_bus":  9, "to_bus": 11, "length_km": 0.001, "status": True},   # QT1-3
            {"from_bus": 10, "to_bus": 12, "length_km": 0.001, "status": True},   # QT2-3
            {"from_bus": 13, "to_bus": 15, "length_km": 0.001, "status": True},   # QT1-4
            {"from_bus": 14, "to_bus": 16, "length_km": 0.001, "status": True},   # QT2-4
            {"from_bus": 17, "to_bus": 19, "length_km": 0.001, "status": True},   # QT1-5
            {"from_bus": 18, "to_bus": 20, "length_km": 0.001, "status": True},   # QT2-5
            {"from_bus": 19, "to_bus": 21, "length_km": 0.001, "status": True},   # QD1-1
            {"from_bus": 19, "to_bus": 23, "length_km": 0.001, "status": True},   # QT1-6
            {"from_bus": 20, "to_bus": 25, "length_km": 0.001, "status": True},   # QT2-6
            {"from_bus": 26, "to_bus": 28, "length_km": 0.001, "status": True},   # QT2-7
            {"from_bus": 27, "to_bus": 29, "length_km": 0.001, "status": True},   # QT1-7
            {"from_bus": 30, "to_bus": 32, "length_km": 0.001, "status": True},   # QT2-8
            {"from_bus": 31, "to_bus": 33, "length_km": 0.001, "status": True},   # QT1-8
            {"from_bus": 33, "to_bus": 35, "length_km": 0.001, "status": True},   # QT1-9
            {"from_bus": 32, "to_bus": 36, "length_km": 0.001, "status": True},   # QT2-9
            {"from_bus": 32, "to_bus": 37, "length_km": 0.001, "status": True},   # QT2-10
            {"from_bus": 39, "to_bus": 42, "length_km": 0.001, "status": True},   # QD2-1
            {"from_bus": 39, "to_bus": 43, "length_km": 0.001, "status": True},   # QD2-2
            {"from_bus": 40, "to_bus": 44, "length_km": 0.001, "status": True},   # QD2-3
            {"from_bus": 40, "to_bus": 45, "length_km": 0.001, "status": True},   # QD2-4
            {"from_bus": 41, "to_bus": 46, "length_km": 0.001, "status": True},   # QD1-2
            {"from_bus": 41, "to_bus": 47, "length_km": 0.001, "status": True},   # QD1-3
            {"from_bus": 20, "to_bus": 22, "length_km": 0.001, "status": False},  # QT2-11 (N/O)
            {"from_bus": 19, "to_bus": 24, "length_km": 0.001, "status": False},  # QT1-10 (N/O)
            {"from_bus": 32, "to_bus": 34, "length_km": 0.001, "status": False},  # QT2-12 (N/O)
            {"from_bus": 33, "to_bus": 38, "length_km": 0.001, "status": False},  # QT1-11 (N/O)
        ]

        for brkr in brkr_data:
            self.create_line_with_switch(first_bus=brkr["from_bus"], last_bus=brkr["to_bus"],
                    length_km=brkr["length_km"], std_type="679-AL1/86-ST1A 220.0", status=brkr["status"])

        pp.create_transformer_from_parameters(net=self.net, hv_bus=7,  lv_bus=9,  name="trafo1", sn_mva=100, vn_hv_kv=66,  vn_lv_kv=22,  pfe_kw=10, i0_percent=1.2, shift_degree=0, vector_group='YNyn', vkr_percent=1, vk_percent=10, vk0_percent=10, vkr0_percent=1, mag0_percent=100, mag0_rx=0.1, si0_hv_partial=0.9)
        pp.create_transformer_from_parameters(net=self.net, hv_bus=8,  lv_bus=10, name="trafo2", sn_mva=100, vn_hv_kv=66,  vn_lv_kv=22,  pfe_kw=10, i0_percent=1.2, shift_degree=0, vector_group='YNyn', vkr_percent=1, vk_percent=10, vk0_percent=10, vkr0_percent=1, mag0_percent=100, mag0_rx=0.1, si0_hv_partial=0.9)
        pp.create_transformer_from_parameters(net=self.net, hv_bus=15, lv_bus=17, name="trafo3", sn_mva=50,  vn_hv_kv=22,  vn_lv_kv=6.6, pfe_kw=10, i0_percent=0,   shift_degree=0, vector_group='YNyn', vkr_percent=1, vk_percent=10, vk0_percent=10, vkr0_percent=1, mag0_percent=100, mag0_rx=0.1, si0_hv_partial=0.9)
        pp.create_transformer_from_parameters(net=self.net, hv_bus=16, lv_bus=18, name="trafo4", sn_mva=50,  vn_hv_kv=22,  vn_lv_kv=6.6, pfe_kw=10, i0_percent=0,   shift_degree=0, vector_group='YNyn', vkr_percent=1, vk_percent=10, vk0_percent=10, vkr0_percent=1, mag0_percent=100, mag0_rx=0.1, si0_hv_partial=0.9)
        pp.create_transformer_from_parameters(net=self.net, hv_bus=28, lv_bus=30, name="trafo5", sn_mva=25,  vn_hv_kv=6.6, vn_lv_kv=0.4, pfe_kw=10, i0_percent=0,   shift_degree=0, vector_group='YNyn', vkr_percent=1, vk_percent=10, vk0_percent=10, vkr0_percent=1, mag0_percent=100, mag0_rx=0.1, si0_hv_partial=0.9)
        pp.create_transformer_from_parameters(net=self.net, hv_bus=29, lv_bus=31, name="trafo6", sn_mva=25,  vn_hv_kv=6.6, vn_lv_kv=0.4, pfe_kw=10, i0_percent=0,   shift_degree=0, vector_group='YNyn', vkr_percent=1, vk_percent=10, vk0_percent=10, vkr0_percent=1, mag0_percent=100, mag0_rx=0.1, si0_hv_partial=0.9)

        # Loads — identical to Dr. Biswas's original
        pp.create_load(net=self.net, name="Load1", index=0, bus=21, p_mw=1.0,  q_mvar=0.001)  # Industrial (DS2)
        pp.create_load(net=self.net, name="Load2", index=1, bus=42, p_mw=0.05, q_mvar=0.002)  # Residential (DS3)
        pp.create_load(net=self.net, name="Load3", index=2, bus=43, p_mw=0.03, q_mvar=0.002)  # Residential (DS3)
        pp.create_load(net=self.net, name="Load4", index=3, bus=44, p_mw=0.1,  q_mvar=0.001)  # Small industry (DS4) ← EV target
        pp.create_load(net=self.net, name="Load5", index=4, bus=45, p_mw=0.03, q_mvar=0.001)  # Residential (DS4)
        pp.create_load(net=self.net, name="Load6", index=5, bus=46, p_mw=0.05, q_mvar=0.002)  # Residential (DS4)
        pp.create_load(net=self.net, name="Load7", index=6, bus=47, p_mw=0.03, q_mvar=0.002)  # Residential (DS4)

        return self.net

    def makeheader(self, obtype, listlen):
        out = []
        s = str(datetime.now())
        out.append(s)
        if obtype == "busall":
            for busvar in self.busvarnames:
                for i in range(listlen):
                    obname = busvar + str(i + 1)
                    out.append(obname)
        elif obtype == "linecurrent":
            for linevar in self.linevarnames:
                for i in range(listlen):
                    obname = linevar + str(i + 1)
                    out.append(obname)
        elif obtype == "linepower":
            for powervar in self.linevarnamespower:
                for i in range(listlen):
                    obname = powervar + str(i + 1)
                    out.append(obname)
        elif obtype == "breaker":
            for b in self.brkrnames:
                out.append(b)
        else:
            print(obtype, " is not handled yet. Returning empty list.")
        return out

    def prep_csv_files(self, net):
        outdir = os.environ.get('CSV_DIR', '/shared')
        os.makedirs(outdir, exist_ok=True)

        self.outFilebus = open(os.path.join(outdir, 'SimOutputBus.csv'), 'w')
        self.buswriter = csv.writer(self.outFilebus)
        self.buswriter.writerow(self.makeheader("busall", len(net.bus)))

        self.outFileline = open(os.path.join(outdir, 'SimOutputLine.csv'), 'w')
        self.linewriter = csv.writer(self.outFileline)
        self.linewriter.writerow(self.makeheader("linecurrent", len(net.line)))

        self.outFilelinePower = open(os.path.join(outdir, 'SimOutputPower.csv'), 'w')
        self.linewriterpower = csv.writer(self.outFilelinePower)
        self.linewriterpower.writerow(self.makeheader("linepower", len(net.line)))

        self.breakerFile = open(os.path.join(outdir, 'SimOutputBreaker.csv'), 'w')
        self.breakerwriter = csv.writer(self.breakerFile)
        self.breakerwriter.writerow(self.makeheader("breaker", len(net.switch)))

    def close_csv_files(self, net):
        self.outFilebus.close()
        self.outFileline.close()
        self.outFilelinePower.close()
        self.breakerFile.close()

    def get_pair(self, comptype, compnumber):
        if comptype == "line":
            lineno = compnumber
            line_list = net.res_line
            pl_mw = line_list.pl_mw.tolist()
            ql_mvar = line_list.ql_mvar.tolist()
            real = pl_mw[lineno]
            reactive = ql_mvar[lineno]
            return real, reactive
        else:
            return None, None

    def write_to_csv_files(self, net):
        bus_list = net.res_bus
        line_list = net.res_line
        brkr_list = net.switch.closed
        brkrlist = brkr_list.tolist()

        vm_pu     = bus_list.vm_pu.tolist()
        va_degree = bus_list.va_degree.tolist()
        p_mw      = bus_list.p_mw.tolist()
        q_mvar    = bus_list.q_mvar.tolist()

        outrow = []
        sdatetimenow = str(datetime.now())
        outrow.append(sdatetimenow)
        for i in range(len(vm_pu)):     outrow.append(vm_pu[i])
        for i in range(len(vm_pu)):     outrow.append(va_degree[i])
        for i in range(len(vm_pu)):     outrow.append(p_mw[i])
        for i in range(len(vm_pu)):     outrow.append(q_mvar[i])
        self.buswriter.writerow(outrow)

        pl_mw        = line_list.pl_mw.tolist()
        ql_mvar      = line_list.ql_mvar.tolist()
        i_from_ka    = line_list.i_from_ka.tolist()
        i_to_ka      = line_list.i_to_ka.tolist()
        i_ka         = line_list.i_ka.tolist()
        loading_percent = line_list.loading_percent.tolist()

        outrow = []
        outrow.append(sdatetimenow)
        lenline = len(pl_mw)
        for i in range(lenline): outrow.append(pl_mw[i])
        for i in range(lenline): outrow.append(ql_mvar[i])
        for i in range(lenline): outrow.append(i_from_ka[i])
        for i in range(lenline): outrow.append(i_to_ka[i])
        for i in range(lenline): outrow.append(i_ka[i])
        for i in range(lenline): outrow.append(loading_percent[i])
        self.linewriter.writerow(outrow)

        p_from_mw   = line_list.p_from_mw.tolist()
        q_from_mvar = line_list.q_from_mvar.tolist()

        outrow = []
        outrow.append(sdatetimenow)
        lenline = len(p_from_mw)
        for i in range(lenline): outrow.append(p_from_mw[i])
        for i in range(lenline): outrow.append(q_from_mvar[i])
        self.linewriterpower.writerow(outrow)

        outrow = []
        outrow.append(sdatetimenow)
        for status in brkrlist:
            outrow.append(status)
        self.breakerwriter.writerow(outrow)
        self.breakerFile.flush()


def mqtt_publish_voltages(buffer):
    # CHANGE 3: no-op — mosquitto_pub not available in container.
    # Voltages are instead visible in SimOutputBus.csv on the shared volume.
    pass


if __name__ == "__main__":

    pgt = PGT()
    net = pgt.create_pgtv2()
    # pplt.simple_plot(net, plot_line_switches=True)   # CHANGE 2: removed, no GUI
    pgt.prep_csv_files(net)

    runpp(net)
    # pplt.simple_plot(net, plot_line_switches=True)   # CHANGE 2: removed, no GUI
    pgt.write_to_csv_files(net)
    numloads = len(net.load)

    iteration = 1
    runpp(net)
    print("[PGTwin] 7-substation grid simulator running. EV load injected at Load4 (Bus 44).")
    print(f"[PGTwin] Watching: {EV_LOAD_FILE}")
    print(f"[PGTwin] CSV output: {os.environ.get('CSV_DIR', '/shared')}/SimOutput*.csv")

    try:
        while True:
            pgt.write_to_csv_files(net)

            real, reactive = pgt.get_pair("line", 11)

            # ── CHANGE 5: EV load injection ──────────────────────────────────
            ev_kw = read_ev_load_kw()
            net.load.at[EV_LOAD_IDX, 'p_mw'] = EV_LOAD_BASELINE_MW + (ev_kw / 1000.0)
            # ─────────────────────────────────────────────────────────────────

            runpp(net)
            # pplt.simple_plot(net, plot_line_switches=True)   # CHANGE 2: removed

            pgt.write_to_csv_files(net)
            real, reactive = pgt.get_pair("line", 11)
            buffervoltages = []
            buffercurrents = []

            bus_list = net.res_bus
            vm_pu = bus_list.vm_pu.tolist()

            for i in range(numloads):
                idx = load_buslist[i]
                val = vm_pu[idx]
                buffervoltages.append(val)

            line_list = net.res_line
            i_ka_list = line_list.i_ka.tolist()

            for i in range(numloads):
                idx = load_linelist[i]
                val = i_ka_list[idx]
                buffercurrents.append(val)

            # Print grid state for Docker logs
            ev_bus_vm = vm_pu[44]   # Bus 44 = EV injection point
            print(f"[PGTwin] iter={iteration:4d} | "
                  f"EV={ev_kw:7.1f} kW | "
                  f"Load4(Bus44) vm_pu={ev_bus_vm:.4f} | "
                  f"total_load={net.load.p_mw.sum()*1000:.0f} kW")

            mqtt_publish_voltages(buffervoltages)   # no-op in Docker

            iteration += 1

    except KeyboardInterrupt:
        print('[PGTwin] Exiting ......')
        pgt.close_csv_files(net)
