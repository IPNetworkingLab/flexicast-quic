import math
import matplotlib.pyplot as plt
import numpy as np


def read_and_rm_delay(trace_file, res_file):
    with open(trace_file) as fd:
        data_trace = fd.read().strip().split("\n")
    with open(res_file) as fd:
        data_res = fd.read().strip().split("\n")

    # Get the minimum "delay" between the theoric trace and the result.
    min_dist = math.inf
    for i, (line_trace, line_res) in enumerate(zip(data_trace, data_res)):
        tab_trace = line_trace[1:].split(",")
        tab_res = line_res.split(" ")

        if i != int(tab_res[0]):
            print(f"Different 0: {i} vs {tab_res[0]}")
        if tab_trace[1] != tab_res[2]:
            print(f"DIFFERENT 2: {line_trace} vs {line_res}")

        min_dist = min(min_dist, int(tab_res[1]) - int(tab_trace[0]))
    print("this is min dist", min_dist)
    # Remove the "delay" from all collected samples in the result file.
    # Also remove the trace timestamp to get the lateness.

    return [
        (int(line_res.split(" ")[1]) - min_dist - int(line_trace[1:].split(",")[0])) / 1000
        for (line_res, line_trace) in zip(data_res, data_trace)
    ]


def compute_cdf(values, nb_bins: int = 200, add_zero: bool = False):
    hist, bin_edges = np.histogram(values, bins=nb_bins, range=(
        min(values), max(values)), density=True)
    dx = bin_edges[1] - bin_edges[0]
    cdf = np.cumsum(hist) * dx
    if add_zero:
        cdf = np.insert(cdf, 0, 0)
        return bin_edges, cdf
    return bin_edges[1:], cdf


def plot_distribution(all_files_labels, trace):
    res = dict()
    for (file, label) in all_files_labels:
        r = read_and_rm_delay(trace, file)
        print(r)
        res[label] = compute_cdf(r, add_zero=True)

    fig, ax = plt.subplots()

    for label, (bins, cdf) in res.items():
        ax.plot(bins, cdf, label=label)
    
    ax.set_xlabel("Lateness [ms]")
    ax.set_ylabel("CDF")
    ax.set_title("Lateness 1 client (VMs INGI)")
    plt.legend()
    plt.savefig("cdf_lat.pdf")


if __name__ == "__main__":
    # all_files_labels = [
    #     ("/home/louisna/multicast-quic/perf/client-asym.trace", "Asymetric MC"),
    #     ("/home/louisna/multicast-quic/perf/client-sym.trace", "Symetric MC"),
    #     ("/home/louisna/multicast-quic/perf/client-none.trace", "No auth MC"),
    #     ("/home/louisna/multicast-quic/perf/client-uc.trace", "Unicast"),
    # ]
    all_files_labels = [
        # ("/home/louisna/multicast-quic/quiche/client-4000.trace", "Timeout 4000 (200 samples)"),
        ("/home/louisna/multicast-quic/quiche/client-4000-400.trace", "Timeout 4000 (400 samples)"),
        ("/home/louisna/multicast-quic/quiche/client-4000-1000.trace", "Timeout 4000 (1000 samples)"),
    ]
    trace = "/home/louisna/multicast-quic/perf/tixeo_trace.repr"
    plot_distribution(all_files_labels, trace)
