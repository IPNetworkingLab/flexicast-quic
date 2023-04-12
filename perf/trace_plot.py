import math
import matplotlib.pyplot as plt
import numpy as np

COLORS = ["#1b9e77", "#d95f02", "#7570b3", "#e7298a"]


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
            print("LOST FRAME", i)
            lost_frames.append(i)
            continue

        (time_res, bytes_res) = sid_time_res[i]
        (time_trace, bytes_trace) = sid_time_trace[i]

        if bytes_res != bytes_trace:
            print(f"Different number of bytes for stream {i}: {bytes_res} vs {bytes_trace}")

        min_dist = min(min_dist, time_res - time_trace)

    print("This is min dist", min_dist)

    # Remove the "delay" from all collected samples in the result file.
    # Also remove the trace timestamp to get the lateness.
    return {
        i: (sid_time_res[i][0] - min_dist - sid_time_trace[i][0]) / 1000 for i in sid_time_res.keys()
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


def plot_distribution(all_files_labels, trace, title="", save_as="cdf_lat.pdf", ylim=None):
    res = dict()
    for (file, label) in all_files_labels:
        r, _ = read_and_rm_delay(trace, file)
        print(r.values())
        res[label] = compute_cdf(list(r.values()), add_zero=True)

    fig, ax = plt.subplots()

    for i, (label, (bins, cdf)) in enumerate(res.items()):
        ax.plot(bins, cdf, label=label, color=COLORS[i])
    
    ax.set_xlabel("Lateness [ms]")
    ax.set_ylabel("CDF")
    ax.set_title(title)
    if ylim is not None:
        ax.set_ylim(ylim)
    plt.legend()
    plt.savefig(save_as)


def plot_stream_recv_time(all_files_labels, title="", save_as="recv_stream.pdf", ylim=None, cmp_uc=None):
    res = dict()
    for (file, label) in all_files_labels:
        r = read_data_brut(file)
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

    for i, (label, (values)) in enumerate(res.items()):
        stream_ids = sorted(values.keys())
        timestamps = [values[i] for i in stream_ids]
        lost_frames = list()
        for stream_id in range(stream_ids[0], stream_ids[-1] + 1):
            if stream_id not in stream_ids:
                lost_frames.append(stream_id)

        for lost_frame in lost_frames:
            ax.axvline(lost_frame, linewidth=0.3, color=COLORS[i])
        ax.scatter(stream_ids, timestamps, s=0.2, label=label, color=COLORS[i])
    
    ax.set_xlabel("Frame ID")
    ax.set_ylabel("Time received since start [s]")
    ax.set_title(title)
    if ylim is not None:
        ax.set_ylim(ylim)
    
    louis = plt.legend()
    for i in range(len(res)):
        louis.legendHandles[i]._sizes = [30]
    plt.savefig(save_as, dpi=500)


if __name__ == "__main__":
    # all_files_labels = [
    #     ("/home/louisna/multicast-quic/perf/client-asym.trace", "Asymetric MC"),
    #     ("/home/louisna/multicast-quic/perf/client-sym.trace", "Symetric MC"),
    #     ("/home/louisna/multicast-quic/perf/client-none.trace", "No auth MC"),
    #     ("/home/louisna/multicast-quic/perf/client-uc.trace", "Unicast"),
    # ]
    all_files_labels = [
        ("/home/louisna/multicast-quic/perf/cloudlab-mc-none.trace", "Mc None"),
        ("/home/louisna/multicast-quic/perf/cloudlab-mc-asym.trace", "Mc Asym"),
        ("/home/louisna/multicast-quic/perf/cloudlab-mc-sym.trace", "Mc Sym"),
        ("/home/louisna/multicast-quic/perf/cloudlab-uc.trace", "Unicast"),
    ]
    trace = "/home/louisna/multicast-quic/perf/tixeo_trace.repr"
    plot_distribution(all_files_labels, trace, title="VMs INGI 1000 frames (timeout=4s)", save_as="cdf_lat_4s.pdf", ylim=((0.9, 1.001)))
    plot_stream_recv_time(all_files_labels, title="Recv timestamp", save_as="recv_stream.png")
    plot_stream_recv_time(all_files_labels, title="Recv timestamp compared to unicast", save_as="recv_stream-uc.png", cmp_uc="Unicast")
