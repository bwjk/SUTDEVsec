import pandapower as pp
import pandapower.plotting.plotly as pplot
import pandapower.plotting.generic_geodata as gd

# -------------------------
# Create network
# -------------------------
net = pp.create_empty_network()

# -------------------------
# Buses
# -------------------------
bus_220 = pp.create_bus(net, vn_kv=220, name="Grid_220kV")
bus_66  = pp.create_bus(net, vn_kv=66, name="Main_66kV")
bus_22  = pp.create_bus(net, vn_kv=22, name="EV_Hub_22kV")

# -------------------------
# Transformer types
# -------------------------
trafo_220_66 = {
    "sn_mva": 1000,
    "vn_hv_kv": 220,
    "vn_lv_kv": 66,
    "vk_percent": 12,
    "vkr_percent": 0.3,
    "pfe_kw": 0,
    "i0_percent": 0,
    "shift_degree": 0
}

trafo_66_22 = {
    "sn_mva": 500,
    "vn_hv_kv": 66,
    "vn_lv_kv": 22,
    "vk_percent": 10,
    "vkr_percent": 0.3,
    "pfe_kw": 0,
    "i0_percent": 0,
    "shift_degree": 0
}

pp.create_std_type(net, trafo_220_66, "220_66", element="trafo")
pp.create_std_type(net, trafo_66_22, "66_22", element="trafo")

# -------------------------
# Transformers + breakers
# -------------------------
for i in range(2):
    tid = pp.create_transformer(net, bus_220, bus_66,
                                std_type="220_66",
                                name=f"T{i+1}")
    pp.create_switch(net, bus_220, tid, et="t", closed=True)
    pp.create_switch(net, bus_66, tid, et="t", closed=True)

tid = pp.create_transformer(net, bus_66, bus_22,
                           std_type="66_22",
                           name="T_66_22")

pp.create_switch(net, bus_66, tid, et="t", closed=True)
pp.create_switch(net, bus_22, tid, et="t", closed=True)

# -------------------------
# Slack
# -------------------------
pp.create_ext_grid(net, bus_220)

# -------------------------
# Town loads (brown)
# -------------------------
for i in range(7):

    town_bus = pp.create_bus(net, vn_kv=66, name=f"Town_{i+1}")
    load_bus = pp.create_bus(net, vn_kv=66, name=f"TownLoad_{i+1}")

    line1 = pp.create_line_from_parameters(
        net, bus_66, town_bus,
        length_km=10,
        r_ohm_per_km=0.02,
        x_ohm_per_km=0.04,
        c_nf_per_km=0,
        max_i_ka=3
    )
    pp.create_switch(net, bus_66, line1, et="l", closed=True)

    line2 = pp.create_line_from_parameters(
        net, town_bus, load_bus,
        length_km=0.1,
        r_ohm_per_km=0.01,
        x_ohm_per_km=0.02,
        c_nf_per_km=0,
        max_i_ka=3
    )
    pp.create_switch(net, town_bus, line2, et="l", closed=True)

    pp.create_load(net, load_bus, p_mw=200, q_mvar=60,
                   name=f"Town_Load_{i+1}")

# -------------------------
# EV network (blue)
# -------------------------
ev_feeders = []

for i in range(10):

    b = pp.create_bus(net, vn_kv=22, name=f"EV_Feeder_{i+1}")
    ev_feeders.append(b)

    line = pp.create_line_from_parameters(
        net, bus_22, b,
        length_km=2,
        r_ohm_per_km=0.1,
        x_ohm_per_km=0.05,
        c_nf_per_km=0,
        max_i_ka=1
    )
    pp.create_switch(net, bus_22, line, et="l", closed=True)

# EV substations
for i, feeder in enumerate(ev_feeders):
    for j in range(50):

        lv_bus = pp.create_bus(net, vn_kv=0.4,
                               name=f"EV_{i+1}_{j+1}")

        line = pp.create_line_from_parameters(
            net, feeder, lv_bus,
            length_km=0.1,
            r_ohm_per_km=0.05,
            x_ohm_per_km=0.025,
            c_nf_per_km=0,
            max_i_ka=0.2
        )
        pp.create_switch(net, feeder, line, et="l", closed=True)

        P = 20 * 0.011
        pp.create_load(net, lv_bus, p_mw=P, q_mvar=P * 0.6)

# -------------------------
# Power flow
# -------------------------
pp.runpp(net)

# -------------------------
# Coordinates
# -------------------------
gd.create_generic_coordinates(net)

# -------------------------
# Identify line groups
# -------------------------
town_lines = []
for i, row in net.line.iterrows():
    fb = net.bus.at[row.from_bus, "name"]
    tb = net.bus.at[row.to_bus, "name"]
    if "Town" in fb or "Town" in tb:
        town_lines.append(i)

ev_lines = list(set(net.line.index) - set(town_lines))

# -------------------------
# Create traces
# -------------------------
ev_trace = pplot.create_line_trace(net, lines=ev_lines,
                                   color="blue", width=1)

town_trace = pplot.create_line_trace(net, lines=town_lines,
                                     color="#5A3A1B", width=3)

bus_trace = pplot.create_bus_trace(net, size=6, color="black")

trafo_trace = pplot.create_trafo_trace(net, width=3)

# -------------------------
# Draw & Save
# -------------------------
#fig = pplot.draw_traces(
#    [ev_trace, town_trace, bus_trace, trafo_trace],
#    figsize=1.2  # IMPORTANT: avoid Plotly width error
#)

# Flatten all traces into a single list
all_traces = []

for tr in [ev_trace, town_trace, bus_trace, trafo_trace]:
    if isinstance(tr, list):
        all_traces.extend(tr)
    else:
        all_traces.append(tr)

fig = pplot.draw_traces(all_traces, figsize=1.2)

# Save to HTML
fig.write_html("grid_visualization.html")

# Show in browser
fig.show()
