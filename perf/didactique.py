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
        id = int(tab[-1])
        method = tab[-2]
        one_client = tab[1] == "1"

        if method == "mcquic":
            label = r"$MC$"
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
    time_1 = int(line_1.split(" ")[1])
    line_2 = data[-10000]
    time_2 = int(line_2.split(" ")[1])
    nb_lines = len(data[10000:-10000])
    time = time_2 - time_1
    nb_bits = nb_lines * 800
    d = nb_bits / (time / 1000000) / 1000000

    return d


def throughput(directory, from_ax):
    # Find sub directories.
    label_files_1, label_files_2 = find_label_files(directory)


    mega_values = list()
    for label_files, nb_clients in zip([label_files_1, label_files_2], [1, 2]):
        for label, files in label_files.items():
            for file in files:
                mega_values.append((nb_clients, label, compute_throughput(file)))

    df = pd.DataFrame(mega_values, columns=["Nb clients", "Method", "Goodput [Mbps]"])

    sns.boxplot(data=df, x="Nb clients", y="Goodput [Mbps]", hue="Method", palette=COLORS_SEQUENTIAL_2, ax=from_ax)
    

def plot_didactique_3(directory, trace):
    fig, axs = plt.subplots(1, 3)
    axs[1].sharey(axs[0])
    
    # Source latency.
    files = [([os.path.join(args.directory, "latency", "latency-4-mc-stream.txt")], r"$MC_S$"), ([os.path.join(args.directory, "latency", "latency-4-mc-none.txt")], r"$MC_N$"), ([os.path.join(args.directory, "latency", "latency-4-uc.txt")], r"$UC$")]
    plot_distribution(files, trace, from_ax=axs[0])

    # Receiver latency.
    files = [([os.path.join(args.directory, "latency", "latency-2-mc-stream.txt")], r"$MC_{S,2}$"), ([os.path.join(args.directory, "latency", "latency-3-mc-stream.txt")], r"$MC_{S,3}$"), ([os.path.join(args.directory, "latency", "latency-2-mc-none.txt")], r"$MC_{N,2}$"), ([os.path.join(args.directory, "latency", "latency-3-mc-none.txt")], r"$MC_{N,3}$"), ([os.path.join(args.directory, "latency", "latency-2-uc.txt")], r"$UC_{2}$"), ([os.path.join(args.directory, "latency", "latency-3-uc.txt")], r"$UC_{3}$")]
    plot_distribution(files, trace, from_ax=axs[1])

    axs[0].set_xlim((0, 5))
    axs[1].set_xlim((0, 5))

    # Throughput.
    throughput(os.path.join(directory, "throughput"), from_ax=axs[2])

    # Axes.
    locs = [
        (0.5, 0.05),
        (0.475, 0.043),
        (0.2, 0.18),
    ]
    for ax, loc in zip(axs[:2], locs[:2]):
        legend = ax.legend(fancybox=True, loc=loc, handletextpad=0.2)
        frame = legend.get_frame()
        frame.set_alpha(1)
        frame.set_color('white')
        frame.set_edgecolor('black')
        frame.set_boxstyle('Square', pad=0.1)
        ax.set_xlabel(r"Lateness [ms]")
        ax.set_axisbelow(True)
    
    legend = axs[2].legend(fancybox=True, loc=locs[-1], handletextpad=0.2, ncol=2, columnspacing=0.5)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)
    axs[2].set_xlabel(r"Nb clients")
    axs[2].set_axisbelow(True)

    # Background for boxplot.
    # xlims = axs[2].get_xlim()
    # axs[2].axvspan(0.5, xlims[1], color='black', alpha=0.075, zorder=1)
    # axs[2].set_xlim(xlims)

    axs[0].grid(True)
    axs[1].grid(True)
    axs[2].yaxis.grid(True, ls="-")

    axs[0].set_title("(a) Server.")
    axs[1].set_title("(b) Clients.")
    axs[2].set_title("(c) Goodput.")

    plt.tight_layout()
    plt.savefig("didactique.pdf", bbox_inches='tight')




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--trace", type=str)
    parser.add_argument("--latex", action="store_true")
    args = parser.parse_args()

    if args.latex:
        latexify(fig_height=FIG_HEIGHT, nb_subplots_line=3, columns=1)

    plot_didactique_3(args.directory, args.trace)