import math
import matplotlib.pyplot as plt
import numpy as np
import argparse
import os

COLORS = ["#1b9e77", "#d95f02", "#7570b3", "#e7298a"]
MARKERS = ["^", "v", ">", "<"]
LINESTYLES = ["-", "--", "-.", (0, (1, 1))]


def get_files_labels(directory, server_only):
    res = dict()
    ttl = None
    nb_frames = None
    for file in os.listdir(directory):
        if not "tixeo" in file:
            continue
        path = os.path.join(directory, file)

        tab = file.split("-")
        if tab[-2] == "server" and server_only == "clients" or tab[-2] != "server" and server_only == "server": 
            continue
        if tab[1] == "mc":
            label = f"MC {tab[2]}"
        else:
            label = "UC"

        if nb_frames == None:
            nb_frames = int(tab[3])
        elif nb_frames != int(tab[3]):
            print("ERROR: found different NB FRAMES values", nb_frames, tab[3])

        if ttl == None:
            ttl = int(tab[4])
        elif ttl != int(tab[4]):
            print("ERROR: found different TTL values", ttl, tab[4])
        
        if not label in res.keys():
            res[label] = [path]
        else:
            res[label].append(path)
    
    res = [(v, l) for (l, v) in res.items()]

    # Sort by name.
    res = sorted(res, key=lambda n: n[1])

    return res, ttl, nb_frames


def read_data_brut(filename):
    with open(filename) as fd:
        data = fd.read().strip().split("\n")
    res = dict()
    for line in data:
        tab = line.split(" ")
        res[int(tab[0])] = int(tab[1])
    
    # Remove minimum value
    min_v = min(list(res.values()))
    return {i: (res[i] - min_v) / 1000000 for i in res.keys()}


def read_and_rm_delay(trace_file, res_file):
    with open(trace_file) as fd:
        data_trace = fd.read().strip().split("\n")
    with open(res_file) as fd:
        data_res = fd.read().strip().split("\n")
    
    if len(data_res) == 1: return {}, list()
    
    # Map timestamp to stream id.
    sid_time_res = dict()
    max_recv_stream_id = -1
    for line in data_res:
        tab = line.split(" ")
        sid_time_res[int(tab[0])] = (int(tab[1]), int(tab[2]))
        max_recv_stream_id = max(max_recv_stream_id, int(tab[0]))
    
    sid_time_trace = dict()
    for i, line in enumerate(data_trace[:max_recv_stream_id + 1]):
        tab = line[1:].split(",")
        sid_time_trace[i] = (int(tab[0]), int(tab[1]))

    # Get the minimum "delay" between the theoric trace and the result.
    min_dist = math.inf
    lost_frames = list()
    for i in range(len(sid_time_trace.keys())):
        if not i in sid_time_res.keys():
            lost_frames.append(i)
            continue

        (time_res, bytes_res) = sid_time_res[i]
        (time_trace, bytes_trace) = sid_time_trace[i]

        # if bytes_res != bytes_trace:
        #     print(f"Different number of bytes for stream {i}: {bytes_res} vs {bytes_trace}")

        min_dist = min(min_dist, time_res - time_trace)
    
    print("LOST FRAMES: ", lost_frames)
    print("Min distance:", min_dist)

    # Remove the "delay" from all collected samples in the result file.
    # Also remove the trace timestamp to get the lateness.
    return {
        i: (sid_time_res[i][0] - min_dist - sid_time_trace[i][0]) / 1000 for i in sid_time_res.keys() if sid_time_res[i][1] > 1
    }, lost_frames


def compute_cdf(values, nb_bins: int = 200, add_zero: bool = False):
    hist, bin_edges = np.histogram(values, bins=nb_bins, range=(
        min(values), max(values)), density=True)
    dx = bin_edges[1] - bin_edges[0]
    cdf = np.cumsum(hist) * dx
    if add_zero:
        cdf = np.insert(cdf, 0, 0)
        return bin_edges, cdf
    return bin_edges[1:], cdf


def plot_distribution(all_files_labels, trace, title="", save_as="cdf_lat.pdf", ylim=None, xlim=None):
    res = dict()
    for (files, label) in all_files_labels:
        tmp = list()
        for file in files:
            r, _ = read_and_rm_delay(trace, file)
            frames_too_long = [i for i in r if r[i] > 50]
            # print("Frames too long:", frames_too_long)
            tmp += list(r.values())

        # tmp = [i for i in tmp if i < 300]
        print(f"Nb points for {label}: {len(tmp)}")
        res[label] = compute_cdf(tmp, add_zero=True, nb_bins=7000)

    fig, ax = plt.subplots()

    for i, (label, (bins, cdf)) in enumerate(res.items()):
        ax.plot(bins, cdf, label=label, color=COLORS[i], linestyle=LINESTYLES[i])
    
    ax.set_xlabel("Lateness [ms]")
    ax.set_ylabel("CDF")
    ax.set_title(title)
    if ylim is not None:
        ax.set_ylim(ylim)
    if xlim is not None:
        ax.set_xlim(xlim)
    plt.legend()
    plt.savefig(save_as, dpi=500)


def plot_stream_recv_time(all_files_labels, title="", save_as="recv_stream.pdf", ylim=None, xlim=None, cmp_uc=None, ylabel=""):
    res = dict()
    for (file, label) in all_files_labels:
        r = read_data_brut(file[0])
        res[label] = r
    
    if cmp_uc is not None:
        res2 = dict()
        baseline = res[cmp_uc]
        for other in res:
            if other == cmp_uc: continue
            v = res[other]
            d = dict()
            for i in v.keys():
                try:
                    d[i] = v[i] - baseline[i]
                except KeyError:
                    continue
            res2[other] = d
        res = res2
        
    fig, ax = plt.subplots()

    scaling = 1 if cmp_uc is None else 1000
    for i, (label, (values)) in enumerate(res.items()):
        stream_ids = sorted(values.keys())
        timestamps = [values[i] * scaling for i in stream_ids]
        lost_frames = list()
        for stream_id in range(stream_ids[0], stream_ids[-1] + 1):
            if stream_id not in stream_ids:
                lost_frames.append(stream_id)

        for lost_frame in lost_frames:
            if not "UC" in label:
                ax.axvline(lost_frame, linewidth=0.3, color=COLORS[i], linestyle=LINESTYLES[i])
        ax.scatter(stream_ids, timestamps, s=0.2, label=label, color=COLORS[i], marker=MARKERS[i])
    
    ax.set_xlabel("Frame ID")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if ylim is not None:
        ax.set_ylim(ylim)
    if xlim is not None:
        ax.set_xlim(xlim)
    
    louis = plt.legend()
    for i in range(len(res)):
        louis.legend_handles[i]._sizes = [30]
    plt.savefig(save_as, dpi=500)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("directory", help="Directory containing the files to parse", type=str)
    parser.add_argument("--trace", help="Path to the tixeo trace", type=str, default="/home/louisna/multicast-quic/perf/tixeo_trace.repr")
    parser.add_argument("--xlim", type=float, help="Maximum xlim for the plot distribution", default=100)
    parser.add_argument("--ylim", type=float, help="Maximum ylim for the plot distribution", default=0.0)
    parser.add_argument("--filter", help="Server or client lateness", default="clients", choices=["clients", "server"])
    args = parser.parse_args()

    all_files_labels, ttl, nb_frames = get_files_labels(args.directory, args.filter)

    # all_files_labels = [(i, j) for (i, j) in all_files_labels if (j == "MC none" or j == "UC")]

    # plot_distribution(all_files_labels, args.trace, title=f"Cloudlab server <-> INGI ({nb_frames} frames, ttl={ttl})", save_as=f"cdf_lat_{nb_frames}_{ttl}.pdf", ylim=(args.ylim, 1), xlim=(0, args.xlim))
    # plot_stream_recv_time(all_files_labels, title="Recv timestamp", save_as=f"recv_stream_{nb_frames}_{ttl}.png", ylabel="Time received since start [s]", ylim=(0, 0.100))
    plot_stream_recv_time(all_files_labels, title="Recv timestamp compared to unicast", save_as=f"recv_stream-uc_{nb_frames}_{ttl}.png", cmp_uc="UC", ylabel="Lateness of reception with respect to UC [ms]")

    # Mininet
    plot_distribution(all_files_labels, args.trace, title=f"Mininet ({nb_frames} frames, ttl={ttl})", save_as=f"cdf_lat_{nb_frames}_{ttl}_{args.filter}.png", ylim=(args.ylim, 1), xlim=(0, args.xlim))
