import matplotlib.pyplot as plt
import matplotlib
import os
import json
import numpy as np
import argparse
from utils import *
import seaborn as sns
import math

sns.set_palette("colorblind")


def parse_json(filename, convert=False, factor=1):
    with open(filename) as fd:
        data = json.load(fd)
    return (8 / (data["median"]["point_estimate"] * 100), 0)
    # times = [i / 1000000000 for i in data["times"]]
    # if convert:
    #     times = [8 / (i * 100 / factor) for i in times]
    # return np.median(times), np.std(times)


def read_unicast(dirname, convert=False, factor=1):
    all_data = dict()
    for subdir in os.listdir(dirname):
        file_path = os.path.join(dirname, subdir, "new", "estimates.json")
        all_data[int(subdir)] = parse_json(file_path, convert, factor)
    return all_data


def read_multicast(dirname, convert=False, factor=1):
    # `convert` converts the time to send 10MB to a Gbps rate
    auth_asym = dict()
    no_auth = dict()
    auth_sym = dict()
    auth_stream = dict()
    
    for subdir in os.listdir(dirname):
        filepath = os.path.join(dirname, subdir, "new", "estimates.json")
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
        filepath = os.path.join(dirname, subdir, "new", "estimates.json")
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


def plot_generic(root, xlabel, ylabel="Gootput ratio", save_as="bench.pdf", factor=1, do_read_unicast=None, read_repair=False, ylog=False, legend_loc=None, xlog=True, ylim=None):
    if read_repair:
        baseline, fixed = read_multicast_repair(root, True, factor)
        data = list()
        ks = sorted(fixed.keys())
        for k in ks:
            v = fixed[k]
            data.append((v, f"Fixed ({k})"))
    else:
        mc_auth_asym, mc_auth_sym, mc_no_auth, mc_auth_stream  = read_multicast(root, True, factor)
        data = [
            (mc_auth_asym, "Multicast asymmetric"),
            (mc_no_auth, "Multicast no authentication"),
            (mc_auth_sym, "Multicast symmetric"),
            (mc_auth_stream, "Multicast stream"),
        ]
        data = list(filter(lambda x: len(x[0]) > 0, data))
        baseline = data[1][0]
        if do_read_unicast is not None:
            uc = read_unicast(do_read_unicast, convert=True, factor=factor)
            print(uc)
            data.append((uc, "Unicast"))
        
    fig, ax = plt.subplots()
    for i, (d, label) in enumerate(data):
        k = sorted(d.keys())
        v = [d[i][0] / baseline[i][0] for i in k]
        std = [d[i][1] / baseline[i][0] for i in k]

        ax.errorbar(k, v, yerr=std, label=label, fmt=MARKERS[i], color=COLORS[i], linestyle=LINESTYLES[i])

    if legend_loc is None:
        legend = ax.legend(fancybox=True)
    else:
        legend = ax.legend(fancybox=True, loc=legend_loc)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if xlog:
        ax.set_xscale("log")
    if ylog:
        ax.set_yscale("log")
    if ylim is not None:
        ax.set_ylim(ylim)

    ax.grid(True, which="both", ls="-")
    if read_repair:
        ticks = [10, 100, 1000, 10000]
        ax.set_xticks(ticks)
        ticks_labels = [100 / i for i in ticks]
        ticks_labels = [round(i, 3) for i in ticks_labels]
        ax.set_xticklabels(ticks_labels)
    # ax.set_ylim((0.001, 1.0))
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    # ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    plt.tight_layout()
    plt.savefig(save_as)


def plot_generic_both(root_server, root_client, baselines, xlabel, ylabel="Gootput ratio", save_as="bench.pdf", factor=1, do_read_unicast=None, read_repair=False, ylog=False, legend_loc=None, xlog=True, ylim=None, stream_if_forgot=False):
    def read_one(root, unicast, baseline_file):
        if read_repair:
            baseline, fixed = read_multicast_repair(root, True, factor)
            print(sorted(fixed[100].keys()))
            data = list()
            ks = sorted(fixed.keys())
            for k in ks:
                v = fixed[k]
                l = math.log(k, 10)
                if abs(l - round(l)) < 0.0001:
                    data.append((v, rf"$10^{round(l)}$"))
                else:
                    data.append((v, k))
        else:
            f2 = 2 if stream_if_forgot and root_server == root else factor
            mc_auth_asym, mc_auth_sym, mc_no_auth, mc_auth_stream  = read_multicast(root, True, f2)
            data = [
                (mc_auth_asym, r"$MC_A$"),
                (mc_no_auth, r"$MC_N$"),
                (mc_auth_sym, r"$MC_Y$"),
                (mc_auth_stream, r"$MC_S$"),
            ]
            data = list(filter(lambda x: len(x[0]) > 0, data))
            baseline = data[1][0]
            if unicast is not None:
                uc = read_unicast(unicast, convert=True, factor=factor)
                print(uc)
                data.append((uc, r"$UC$"))
        b = parse_json(baseline_file, factor=10, convert=True)
        baseline = {i: b for i in baseline}
        print(f"Baseline is: {baseline} and none: {data[1][0]}")
        return data, baseline

    data_server, baseline_server = read_one(root_server, do_read_unicast[0] if do_read_unicast is not None else None, baselines[0])
    print("-----------------------------------")
    data_client, baseline_client = read_one(root_client, do_read_unicast[1] if do_read_unicast is not None else None, baselines[1])
    
    fix, (ax1, ax2) = plt.subplots(1, 2, sharey=True)

    for data, baseline, ax in zip([data_server, data_client], [baseline_server, baseline_client], [ax1, ax2]):
        for i, (d, label) in enumerate(data):
            k = sorted(d.keys())
            v = [d[i][0] / baseline[k[0]][0] for i in k]
            std = [d[i][1] / baseline[k[0]][0] for i in k]

            ax.errorbar(k, v, yerr=std, label=label, fmt=MARKERS[i], linestyle=LINESTYLES[i], linewidth=LINEWIDTH, markersize=MARKERSIZE)
    
    if stream_if_forgot:
        ax_leg = ax1
    else:
        ax_leg = ax2
    if legend_loc is None:
        legend = ax_leg.legend(fancybox=True, handletextpad=HANDLETEXTPAD, handlelength=HANDLELENGTH)
    else:
        legend = ax_leg.legend(fancybox=True, loc=legend_loc, handletextpad=HANDLETEXTPAD, handlelength=HANDLELENGTH, columnspacing=0.5, ncol=2)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)

    ax1.set_xlabel(xlabel)
    ax2.set_xlabel(xlabel)
    ax1.set_ylabel(ylabel)
    if xlog:
        ax1.set_xscale("log")
        ax2.set_xscale("log")
    if ylog:
        ax1.set_yscale("log")
    if ylim is not None:
        ax.set_ylim(ylim)
    
    if read_repair:
        for ax in [ax1, ax2]:
            ticks = [10, 100, 1000, 10000]
            ax.set_xticks(ticks)
            ticks_labels = [100 / i for i in ticks]
            ticks_labels = [round(i, 3) for i in ticks_labels]
            ax.set_xticklabels(ticks_labels)
    
    ax1.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())

    ax1.set_title("Server")
    ax2.set_title("Client")

    ax1.grid(True, which="both", ls="-")
    ax2.grid(True, which="both", ls="-")
    plt.tight_layout()

    plt.savefig(save_as, bbox_inches='tight')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--latex", help="Latex output", action="store_true")
    parser.add_argument("--clients", help="Client benchmark instead of server", action="store_true")
    parser.add_argument("--asym", help="Compare asymmetric with stream size", action="store_true")
    parser.add_argument("--repair", help="Reparation FEC", action="store_true")
    parser.add_argument("--both", help="Both client and server in the same plot", action="store_true")
    args = parser.parse_args()

    if args.latex:
        latexify(nb_subplots_line=2, columns=1, fig_height=FIG_HEIGHT)
    
    # baselines = ("../target/criterion/unicast-1G-fec/1/new/estimates.json", "../target/criterion/unicast-client-1G-fec/1/new/estimates.json")
    baselines = ("../target/criterion/unicast-1G/1/new/estimates.json", "../target/criterion/unicast-client-1G/1/new/estimates.json")
    if args.repair:
            if args.both:
                plot_generic_both("../target/criterion/multicast-repair", "../target/criterion/multicast-repair-client", baselines, factor=10, xlabel=r"Loss [\%]", save_as="bench-repair-both.pdf", read_repair=True, ylog=True, ylim=(0.0025, 1.1))
            elif args.clients:
                plot_generic("../target/criterion/multicast-repair-client", factor=10, xlabel=r"Loss [\%]", save_as="bench-repair-client.pdf", read_repair=True)
            else:
                # cmp_mc_repair("../target/criterion/multicast-repair", convert=True, factor=3, save_as="bench-repair-server.pdf")
                plot_generic("../target/criterion/multicast-repair", factor=10, xlabel="Loss percentage", save_as="bench-repair-server.pdf", read_repair=True)
    elif args.asym:
        if args.both:
            plot_generic_both("../target/criterion/multicast-asym", "../target/criterion/multicast-client-asym", baselines, factor=1, xlabel="Stream size", save_as="bench-asym-both.pdf", ylog=True, legend_loc=(0.53, 0.1), ylim=(0, 1.1), stream_if_forgot=True)
        elif args.clients:
            plot_generic("../target/criterion/multicast-client-asym", factor=1, xlabel="Stream size", save_as="bench-asym-clients.pdf", ylog=True, legend_loc=(0.42, 0.2), ylim=(0, 1.1))
            # cmp_mc_asym_client("../target/criterion", convert=True, factor=1)
        else:
            plot_generic("../target/criterion/multicast-asym", factor=1, xlabel="Stream size", save_as="bench-asym-server.pdf", ylog=True, legend_loc=(0.42, 0.35), ylim=(0, 1.1))
            # cmp_mc_uc_client("../target/criterion", convert=True, factor=10)
    else:
        if args.both:
            # plot_generic_both("../target/criterion/multicast-1G-fec", "../target/criterion/multicast-client-1G-fec", baselines, factor=10, xlabel="Number of receivers", save_as="bench-nb-recv-both.pdf", ylog=True, do_read_unicast=("../target/criterion/unicast-1G-fec", "../target/criterion/unicast-client-1G-fec"), xlog=False, legend_loc=(0.1, 0.15))
            plot_generic_both("../target/criterion/multicast-1G", "../target/criterion/multicast-client-1G", baselines, factor=10, xlabel="Number of receivers", save_as="bench-nb-recv-both.pdf", ylog=True, do_read_unicast=("../target/criterion/unicast-1G", "../target/criterion/unicast-client-1G"), xlog=False, legend_loc=(0.1, 0.15))
        elif args.clients:
            plot_generic("../target/criterion/multicast-client-1G", factor=10, xlabel="Number of receivers", save_as="bench-nb-recv-client.pdf", ylog=True, do_read_unicast="../target/criterion/unicast-client-1G", xlog=False, legend_loc=(0.15, 0.25))
            # cmp_mc_asym("../target/criterion/multicast-asym", convert=True, factor=1)
        else:
            # cmp_mc_uc("../target/criterion", convert=True, factor=10, scale=True)
            plot_generic("../target/criterion/multicast-1G", factor=1, xlabel="Number of receivers", save_as="bench-nb-recv-server.pdf", ylog=True, do_read_unicast="../target/criterion/unicast-1G", xlog=False, legend_loc=(0.4, 0.45))