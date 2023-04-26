import matplotlib.pyplot as plt
import os
import json
import numpy as np

COLORS = ["#1b9e77", "#d95f02", "#7570b3", "#e7298a"]
MARKERS = ["^", "v", ">", "<"]
LINESTYLES = ["-", "--", "-.", (0, (1, 1))]


def parse_json(filename):
    with open(filename) as fd:
        data = json.load(fd)
    return np.median(data["times"]) / 1000000000, np.std(data["times"]) / 1000000000


def read_unicast(dirname):
    all_data = dict()
    for subdir in os.listdir(dirname):
        file_path = os.path.join(dirname, subdir, "new", "sample.json")
        all_data[int(subdir)] = (parse_json(file_path))
    return all_data


def read_multicast(dirname):
    auth_asym = dict()
    no_auth = dict()
    auth_sym = dict()
    
    for subdir in os.listdir(dirname):
        filepath = os.path.join(dirname, subdir, "new", "sample.json")
        data = parse_json(filepath)

        auth_tag = subdir.split("-")[0]
        nb_recv = int(subdir.split("-")[1])
        if auth_tag == "AsymSign":
            auth_asym[nb_recv] = data
        elif auth_tag == "SymSign":
            auth_sym[nb_recv] = data
        elif auth_tag == "None":
            no_auth[nb_recv] = data
    
    return auth_asym, auth_sym, no_auth


def cmp_mc_uc(root):
    mc_auth_asym, mc_auth_sym, mc_no_auth = read_multicast(os.path.join(root, "multicast-1G"))
    uc = read_unicast(os.path.join(root, "unicast-1G"))

    data = [
        (mc_auth_asym, "Multicast asymetric"),
        (mc_no_auth, "Multicast no authentication"),
        (mc_auth_sym, "Multicast symetric"),
        (uc, "Unicast"),
    ]

    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] for i in k]
        std = [d[i][1] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=f"-{MARKERS[i]}", color=COLORS[i], linestyle=LINESTYLES[i])

    ax.legend()
    ax.set_xlabel("Number of receivers")
    ax.set_ylabel("Time to send 10MB [s]")

    plt.savefig("bench-server.pdf")


def cmp_mc_uc_client(root):
    mc_auth_asym, mc_auth_sym, mc_no_auth = read_multicast(os.path.join(root, "multicast-client-1G"))
    uc = read_unicast(os.path.join(root, "unicast-client-1G"))

    data = [
        (mc_auth_asym, "Multicast asymetric"),
        (mc_no_auth, "Multicast no authentication"),
        (mc_auth_sym, "Multicast symetric"),
        (uc, "Unicast"),
    ]

    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] for i in k]
        std = [d[i][1] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=f"-{MARKERS[i]}", color=COLORS[i], linestyle=LINESTYLES[i])

    ax.legend()
    ax.set_xlabel("Number of receivers")
    ax.set_ylabel("Time to send 10MB [s]")
    ax.set_title("Client")

    plt.savefig("bench-client.pdf")

if __name__ == "__main__":
    cmp_mc_uc("../target/criterion")
    # cmp_mc_uc_client("../target/criterion")