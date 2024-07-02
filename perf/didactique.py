import math
import matplotlib.pyplot as plt
import numpy as np
import argparse
import os
import subprocess
import tqdm
from utils import *
import seaborn as sns
import pandas as pd
import matplotlib
from trace_plot import plot_distribution, get_files_labels, convert_label


def find_label_files(directory):
    res_2 = dict()
    res_1 = dict()
    for subdir in os.listdir(directory):
        tab = subdir.split("-")
        if tab[-1] == "pkt.txt": continue
        if not "results2" in subdir: continue
        id = int(tab[-1])
        method = tab[-2]
        one_client = tab[1] == "1"

        if method == "mcquic":
            label = r"$MC_N$"
        else:
            label = f"$UC$"

        if one_client:
            res_1.setdefault(label, list())
            for file in os.listdir(os.path.join(directory, subdir)):
                res_1[label].append(os.path.join(directory, subdir, file))
        else:
            res_2.setdefault(label, list())
            for file in os.listdir(os.path.join(directory, subdir)):
                res_2[label].append(os.path.join(directory, subdir, file))
    
    return res_1, res_2


def compute_throughput(filename):
    with open(filename) as fd:
        data = fd.read().strip().split("\n")

    line_1 = data[10000]
    nb_bytes = int(line_1.split(" ")[-1])
    time_1 = int(line_1.split(" ")[1])
    line_2 = data[-10000]
    time_2 = int(line_2.split(" ")[1])
    nb_lines = len(data[10000:-10000])
    time = time_2 - time_1
    nb_bits = nb_lines * 8 * nb_bytes
    d = nb_bits / (time / 1000000) / 1000000

    return d


def throughput(directory, from_ax):
    # Find sub directories.
    label_files_1, label_files_2 = find_label_files(directory)

    # Get the maximum throughput of unicast with 1 client.
    max_th = 0
    for file in label_files_1[r"$UC$"]:
        print("e", file)
        try:
            max_th = max(max_th, compute_throughput(file))
        except IndexError: continue
    max_th = 1

    mega_values = list()
    for label_files, nb_clients in zip([label_files_1, label_files_2], [1, 2]):
        for label, files in label_files.items():
            for file in files:
                try:
                    mega_values.append((nb_clients, label, compute_throughput(file) / max_th))
                except IndexError:
                    print(file)
    print(len(mega_values))
    df = pd.DataFrame(mega_values, columns=["Nb clients", "Method", "Throughput [Mbps]"])

    sns.boxplot(data=df, x="Nb clients", y="Throughput [Mbps]", hue="Method", palette=COLORS_SEQUENTIAL_2, ax=from_ax)
    # sns.barplot(data=df, x="Nb clients", y="Goodput ratio", hue="Method", palette=COLORS_SEQUENTIAL_2, ax=from_ax)
    

def plot_didactique_3(directory, trace):
    fig, axs = plt.subplots(1, 3)

    axs = [axs[2], axs[0], axs[1]]
    # axs[1].sharey(axs[0])
    
    # Source latency.
    # files = [([os.path.join(args.directory, "latency", "latency-4-mc-stream.txt")], r"$MC_S$"), ([os.path.join(args.directory, "latency", "latency-4-mc-none.txt")], r"$MC_N$"), ([os.path.join(args.directory, "latency", "latency-4-uc.txt")], r"$UC$")]
    # plot_distribution(files, trace, from_ax=axs[0])
    plot_service(os.path.join(args.directory, "service-70"), from_ax=axs[0])

    # Receiver latency.
    files = [([os.path.join(args.directory, "latency", "latency-2-mc-stream.txt")], r"$MC_{S,2}$"), ([os.path.join(args.directory, "latency", "latency-3-mc-stream.txt")], r"$MC_{S,3}$"), ([os.path.join(args.directory, "latency", "latency-2-mc-none.txt")], r"$MC_{N,2}$"), ([os.path.join(args.directory, "latency", "latency-3-mc-none.txt")], r"$MC_{N,3}$"), ([os.path.join(args.directory, "latency", "latency-2-uc.txt")], r"$UC_{2}$"), ([os.path.join(args.directory, "latency", "latency-3-uc.txt")], r"$UC_{3}$")]
    plot_distribution(files, trace, from_ax=axs[1])

    axs[1].set_xlim((0, 5))

    # Throughput.
    throughput(os.path.join(directory, "throughput"), from_ax=axs[2])

    # Axes.
    locs = [
        (0.05, 0.75),
        (0.475, 0.043),
        (0.1, 0.37),
    ]
    legend = axs[1].legend(fancybox=True, loc=locs[1], handletextpad=0.2)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)
    axs[1].set_xlabel(r"Lateness [ms]")
    axs[1].set_axisbelow(True)
    
    legend = axs[2].legend(fancybox=True, loc=locs[-1], handletextpad=0.2, ncol=2, columnspacing=0.5)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)
    axs[2].set_xlabel(r"Nb clients")
    axs[2].set_axisbelow(True)

    axs[0].set_ylim((-0.05, 1))
    legend = axs[0].legend(fancybox=True, loc=locs[0], handletextpad=0.2, ncol=2, columnspacing=0.5)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)
    axs[1].set_axisbelow(True)

    # Background for boxplot.
    # xlims = axs[2].get_xlim()
    # axs[2].axvspan(0.5, xlims[1], color='black', alpha=0.075, zorder=1)
    # axs[2].set_xlim(xlims)

    axs[0].grid(True)
    axs[1].grid(True)
    axs[2].yaxis.grid(True, ls="-")

    axs[0].set_title("(c) Tixeo goodput (PC 2).")
    axs[1].set_title("(a) Clients Tixeo.")
    axs[2].set_title("(b) Maximum goodput.")

    plt.tight_layout()
    plt.savefig("didactique.pdf", bbox_inches='tight')


def get_stream_channel(filename, start):
    with open(filename) as fd:
        data = fd.read().strip().split("\n")
    res_uc = list()
    res_mc = list()

    for line in data:
        tab = line.split(" ")
        t = int(tab[0])
        nb = int(tab[1])
        sock = int(tab[2])
        if sock == 1:
            res_uc.append(((t - start) / 1000000, nb))
        else:
            res_mc.append(((t - start) / 1000000, nb))
    
    return res_uc, res_mc


def measure_throughput(data, interval=0.1, max_time=None):
    data = sorted(data, key=lambda x: x[0])
    
    t = 0
    idx = 0
    res = list()
    tmp = 0
    while idx < len(data):
        while data[idx][0] < t:
            tmp += data[idx][1]
            idx += 1
            if idx >= len(data):
                break
        res.append((t, tmp / interval * 8 / 1000000))
        t += interval
        tmp = 0
    
    if max_time is not None:
        while t < max_time:
            res.append((t, 0))
            t += interval
    
    return res


def plot_service(directory, from_ax=None):
    # Get changes.
    with open(os.path.join(directory, "active-70.txt-times-change-uc-pkt.txt")) as fd:
        data = fd.read().strip().split("\n")
    start = int(data[0])
    to_mc = int(data[1])
    to_uc = int(data[2])

    # Get time, nb_bytes and from which socket.
    res_uc, res_mc = get_stream_channel(os.path.join(directory, "active-70.txt-pns-uc-pkt.txt"), start)

    if from_ax is None:
        fig, ax = plt.subplots(1, 1)
    else:
        ax = from_ax
    interval = 1.5
    th_uc = measure_throughput(res_uc, interval=interval)
    max_time = max([i[0] for i in th_uc])
    th_mc = measure_throughput(res_mc, interval=interval, max_time=max_time)
    
    sns.set_palette("colorblind")
    colors = sns.color_palette("colorblind")

    ax.plot([i[0] for i in th_mc], [i[1] for i in th_mc], label=r"$MC_{N,2}$", linewidth=LINEWIDTH, linestyle=(0, (5, 1)), color=colors[2])
    ax.plot([i[0] for i in th_uc], [i[1] for i in th_uc], label=r"$UC_2$", linewidth=LINEWIDTH, color=colors[4])
    ax.legend()
    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Goodput [Mbps]")

    plt.tight_layout()
    plt.savefig("didactique-service.pdf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--trace", type=str)
    parser.add_argument("--latex", action="store_true")
    parser.add_argument("--service", action="store_true")
    args = parser.parse_args()

    if args.service:
        latexify(fig_height=FIG_HEIGHT, nb_subplots_line=3, columns=1)
        plot_service(args.directory, args)
    else:
        if args.latex:
            latexify(fig_height=FIG_HEIGHT, nb_subplots_line=3, columns=1)
        plot_didactique_3(args.directory, args.trace)