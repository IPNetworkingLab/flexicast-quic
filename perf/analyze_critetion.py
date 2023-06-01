import matplotlib.pyplot as plt
import matplotlib
import os
import json
import numpy as np
import argparse
from utils import latexify

# COLORS = ["#1b9e77", "#d95f02", "#7570b3", "#e7298a"]
COLORS = ["#d7191c", "#fdae61", "#2b83ba", "#abdda4", "#999999"]
MARKERS = ["^", "v", ">", "<", 's']
LINESTYLES = ["-", "--", "-.", (0, (1, 1)), (0, (2, 1))]


def parse_json(filename, convert=False, factor=1):
    with open(filename) as fd:
        data = json.load(fd)
    times = [i / 1000000000 for i in data["times"]]
    if convert:
        times = [8 / (i * 100 / factor) for i in times]
    return np.median(times), np.std(times)


def read_unicast(dirname, convert=False, factor=1):
    all_data = dict()
    for subdir in os.listdir(dirname):
        file_path = os.path.join(dirname, subdir, "new", "sample.json")
        all_data[int(subdir)] = parse_json(file_path, convert, factor)
    return all_data


def read_multicast(dirname, convert=False, factor=1):
    # `convert` converts the time to send 10MB to a Gbps rate
    auth_asym = dict()
    no_auth = dict()
    auth_sym = dict()
    auth_stream = dict()
    
    for subdir in os.listdir(dirname):
        filepath = os.path.join(dirname, subdir, "new", "sample.json")
        if "100000000" in filepath:
            data = parse_json(filepath, convert, factor * 10)
        else:
            data = parse_json(filepath, convert, factor)

        auth_tag = subdir.split("-")[0]
        nb_recv = int(subdir.split("-")[1])
        if auth_tag == "AsymSign":
            auth_asym[nb_recv] = data
        elif auth_tag == "SymSign":
            auth_sym[nb_recv] = data
        elif auth_tag == "None":
            no_auth[nb_recv] = data
        elif auth_tag == "StreamAsym":
            auth_stream[nb_recv] = data
        else:
            print(auth_tag)
    
    return auth_asym, auth_sym, no_auth, auth_stream


def read_multicast_repair(dirname, convert=False, factor=1):
    # `convert` converts the time to send 10MB to a Gbps rate
    fixed = dict()
    baseline = dict()
    
    
    for subdir in os.listdir(dirname):
        filepath = os.path.join(dirname, subdir, "new", "sample.json")
        data = parse_json(filepath, convert, factor)

        auth_tag = subdir.split("-")[0]
        loss = int(subdir.split("-")[1])
        rst = subdir.split("-")[2]
        if rst == "false":
            rst = int(subdir.split("-")[3])
            baseline[loss] = data
        else:
            rst = int(rst)
            fixed_value = fixed.get(rst, dict())
            fixed_value[loss] = data
            fixed[rst] = fixed_value

    
    return baseline, fixed


def cmp_mc_uc(root, convert=False, factor=1, scale=False):
    mc_auth_asym, mc_auth_sym, mc_no_auth, _ = read_multicast(os.path.join(root, "multicast-1G"), convert, factor)
    uc = read_unicast(os.path.join(root, "unicast-1G"), convert, factor)

    data = [
        (mc_no_auth, "Multicast no authentication"),
        (mc_auth_asym, "Multicast asymmetric"),
        (mc_auth_sym, "Multicast symmetric"),
        (uc, "Unicast"),
    ]

    if scale:
        data2 = list()
        baseline, _ = data[0]
        for v, label in data:
            v_scaled = {i: (v[i][0] / baseline[i][0], v[i][1] / baseline[i][0]) for i in v}
            data2.append((v_scaled, label))
        data = data2

    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] for i in k]
        std = [d[i][1] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=MARKERS[i], color=COLORS[i], linestyle=LINESTYLES[i])

    legend = ax.legend(fancybox=True, loc=(0.43, 0.4))
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)

    ax.set_xlabel("Number of receivers")
    if convert and not scale:
        ax.set_ylabel("Goodput [Gbps]")
        ax.set_yscale("log")
    elif scale:
        ax.set_ylabel("Gootput ratio")
        ax.set_yscale("log")
    else:
        ax.set_ylabel("Time to send 10MB [s]")

    ax.grid(True, which="both", ls="-")
    if scale:
        pass
    else:
        ax.set_yticks([0.1, 0.2, 0.5, 1, 2, 5, 10])
        ax.set_ylim((0.1, 10.0))
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.tight_layout()

    plt.savefig("bench-server.pdf")


def cmp_mc_uc_client(root, convert=False, factor=1):
    mc_auth_asym, mc_auth_sym, mc_no_auth, _ = read_multicast(os.path.join(root, "multicast-client-1G"), convert, factor)
    uc = read_unicast(os.path.join(root, "unicast-client-1G"), convert, factor)

    data = [
        (mc_auth_asym, "Multicast asymmetric"),
        (mc_no_auth, "Multicast no authentication"),
        (mc_auth_sym, "Multicast symmetric"),
        (uc, "Unicast"),
    ]

    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] for i in k]
        std = [d[i][1] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=MARKERS[i], color=COLORS[i], linestyle=LINESTYLES[i])

    legend = ax.legend(fancybox=True, loc=(0.1, 0.15))
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)

    ax.set_xlabel("Number of receivers")
    if convert:
        ax.set_ylabel("Goodput [Gbps]")
        ax.set_yscale("log")
    else:
        ax.set_ylabel("Time to send 10MB [s]")

    ax.grid(True, which="both", ls="-")
    ax.set_yticks([0.1, 0.2, 0.5, 1, 2, 5, 10])
    ax.set_ylim((0.1, 10.0))
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.tight_layout()

    plt.savefig("bench-clients.pdf")


def cmp_mc_asym(root, convert=False, factor=1, save_as="bench-asym-server.pdf"):
    mc_auth_asym, _, mc_no_auth, mc_auth_stream  = read_multicast(root, convert, factor)

    data = [
        (mc_auth_asym, "Multicast asymmetric"),
        (mc_no_auth, "Multicast no authentication"),
        (mc_auth_stream, "Multicast stream"),
    ]

    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] for i in k]
        std = [d[i][1] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=MARKERS[i], color=COLORS[i], linestyle=LINESTYLES[i])

    legend = ax.legend(fancybox=True, loc=(0.43, 0.1))
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)

    ax.set_xlabel("Stream size")
    if convert:
        ax.set_ylabel("Goodput [Gbps]")
        ax.set_yscale("log")
        ax.set_xscale("log")
    else:
        ax.set_ylabel("Time to send 10MB [s]")

    ax.grid(True, which="both", ls="-")
    #ax.set_yticks([0.1, 0.2, 0.5, 1, 2, 5, 10])
    #ax.set_ylim((0.1, 10.0))
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.tight_layout()
    plt.savefig(save_as)


def cmp_mc_repair(root, convert=False, factor=1, save_as="bench-repair.pdf"):
    baseline, fixed = read_multicast_repair(root, convert, factor)

    data = []

    ks = sorted(fixed.keys())
    for k in ks:
        v = fixed[k]
        data.append((v, f"Fixed ({k})"))

    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] / baseline[i][0] for i in k]
        std = [d[i][1] / baseline[i][0] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=MARKERS[i], color=COLORS[i], linestyle=LINESTYLES[i])

    legend = ax.legend(fancybox=True, loc=(0.65, 0.05))
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)

    ax.set_xlabel("Loss percentage")
    if convert:
        ax.set_ylabel("Goodput ratio")
        # ax.set_yscale("log")
        ax.set_xscale("log")
    else:
        ax.set_ylabel("Time to send 10MB [s]")

    ax.grid(True, which="both", ls="-")
    # ticks = sorted(list(no_reset.keys()))
    # ticks = [i for j, i in enumerate(ticks) if j % 2 == 0]
    ticks = [10, 100, 1000, 10000]
    ax.set_xticks(ticks)
    ticks_labels = [100 / i for i in ticks]
    ticks_labels = [round(i, 3) for i in ticks_labels]
    ax.set_xticklabels(ticks_labels)
    # ax.set_ylim((0.001, 1.0))
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.tight_layout()
    plt.savefig(save_as)


def cmp_mc_asym_client(root, convert=False, factor=1):
    mc_auth_asym, _, mc_no_auth, mc_auth_stream  = read_multicast(os.path.join(root, "multicast-client-asym"), convert, factor)

    data = [
        (mc_auth_asym, "Multicast asymmetric"),
        (mc_no_auth, "Multicast no authentication"),
        (mc_auth_stream, "Multicast stream"),
    ]

    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] for i in k]
        std = [d[i][1] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=MARKERS[i], color=COLORS[i], linestyle=LINESTYLES[i])

    legend = ax.legend(fancybox=True, loc=(0.43, 0.06))
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)

    ax.set_xlabel("Stream size")
    if convert:
        ax.set_ylabel("Goodput [Gbps]")
        ax.set_yscale("log")
        ax.set_xscale("log")
    else:
        ax.set_ylabel("Time to send 10MB [s]")

    ax.grid(True, which="both", ls="-")
    #ax.set_yticks([0.1, 0.2, 0.5, 1, 2, 5, 10])
    #ax.set_ylim((0.1, 10.0))
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.tight_layout()
    plt.savefig("bench-asym-client.pdf")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--latex", help="Latex output", action="store_true")
    parser.add_argument("--clients", help="Client benchmark instead of server", action="store_true")
    parser.add_argument("--asym", help="Compare asymmetric with stream size", action="store_true")
    parser.add_argument("--repair", help="Reparation FEC", action="store_true")
    args = parser.parse_args()

    if args.latex:
        latexify()
    if args.repair:
            cmp_mc_repair("../target/criterion/multicast-repair", convert=True, factor=3, save_as="bench-repair-server.pdf")
    elif args.clients:
        if args.asym:
            cmp_mc_asym_client("../target/criterion", convert=True, factor=1)
        else:
            cmp_mc_uc_client("../target/criterion", convert=True, factor=10)
    else:
        if args.asym:
            cmp_mc_asym("../target/criterion/multicast-asym", convert=True, factor=1)
        else:
            cmp_mc_uc("../target/criterion", convert=True, factor=10, scale=True)