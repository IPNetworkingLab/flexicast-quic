import matplotlib.pyplot as plt
import matplotlib
import os
import json
import numpy as np
import argparse
from utils import latexify

COLORS = ["#1b9e77", "#d95f02", "#7570b3", "#e7298a"]
MARKERS = ["^", "v", ">", "<"]
LINESTYLES = ["-", "--", "-.", (0, (1, 1))]


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
    
    for subdir in os.listdir(dirname):
        filepath = os.path.join(dirname, subdir, "new", "sample.json")
        data = parse_json(filepath, convert, factor)

        auth_tag = subdir.split("-")[0]
        nb_recv = int(subdir.split("-")[1])
        if auth_tag == "AsymSign":
            auth_asym[nb_recv] = data
        elif auth_tag == "SymSign":
            auth_sym[nb_recv] = data
        elif auth_tag == "None":
            no_auth[nb_recv] = data
    
    return auth_asym, auth_sym, no_auth


def cmp_mc_uc(root, convert=False, factor=1):
    mc_auth_asym, mc_auth_sym, mc_no_auth = read_multicast(os.path.join(root, "multicast-1G"), convert, factor)
    uc = read_unicast(os.path.join(root, "unicast-1G"), convert, factor)

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

    legend = ax.legend(fancybox=True, loc=(0.43, 0.4))
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

    plt.savefig("bench-server.pdf")


def cmp_mc_uc_client(root, convert=False, factor=1):
    mc_auth_asym, mc_auth_sym, mc_no_auth = read_multicast(os.path.join(root, "multicast-client-1G"), convert, factor)
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--latex", help="Latex output", action="store_true")
    parser.add_argument("--clients", help="Client benchmark instead of server", action="store_true")
    args = parser.parse_args()

    if args.latex:
        latexify()
    if args.clients:
        cmp_mc_uc_client("../target/criterion", convert=True, factor=10)
    else:
        cmp_mc_uc("../target/criterion", convert=True, factor=10)