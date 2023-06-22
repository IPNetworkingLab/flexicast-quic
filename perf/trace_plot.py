import math
import matplotlib.pyplot as plt
import numpy as np
import argparse
import os
import subprocess
import tqdm
from utils import latexify
import seaborn as sns
import pandas as pd
import matplotlib

COLORS = ["#d7191c", "#fdae61", "#2b83ba", "#abd9e9", "#abdda4", "#999999"]
COLORS_GREY = ["dimgray", "silver", "whitesmoke"]
MARKERS = ["^", "v", ">", "<", 's']
LINESTYLES = ["solid", (0, (1, 1)), "dashed", "dashdot", (5, (10, 3)), (0, (3, 1, 1, 1))]
LINEWIDTH = 4

sns.set_palette("colorblind")


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
        if len(tab) < 2:
            print(f"Error with line {line} from {filename}")
            continue
        res[int(tab[0])] = int(tab[1])
    
    # Remove minimum value
    if len(res) == 0:
        return res
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

        #if bytes_res != bytes_trace:
        #    print(f"Different number of bytes for stream {i}: {bytes_res} vs {bytes_trace} (filename is {res_file})")

        min_dist = min(min_dist, time_res - time_trace)
    
    #print("LOST FRAMES: ", lost_frames)
    #print("Min distance:", min_dist)

    # Remove the "delay" from all collected samples in the result file.
    # Also remove the trace timestamp to get the lateness.
    for i in sid_time_res.keys():
        if sid_time_res[i][1] <= 1:
            print(sid_time_res[i])
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
    print(save_as, xlim)
    res = dict()
    for (files, label) in all_files_labels:
        # if not label == "UC": continue
        tmp = list()
        total_loss = 0
        for file in files:
            r, lost_frames = read_and_rm_delay(trace, file)
            frames_too_long = sorted([(i, r[i]) for i in r if r[i] > 200])
            if len(frames_too_long) > 0:
                print(f"Frames too long for {file}:", frames_too_long, len(frames_too_long))
            if len(lost_frames) > 0:
                print(f"Lost frames {file}", lost_frames)

            # Add frames with a result.
            tmp += list(r.values())

            # Add lost frames outside the limit for a non-finishing curve.
            if xlim is not None:
                tmp += [xlim[1] + 10] * len(lost_frames)
            total_loss += len(lost_frames)
        if xlim is not None:
            # Too long = also lost video frames.
            too_long = [i for i in tmp if i > xlim[1]]
            print("Too long:", label, len(too_long))
            # Replace really too long frames because otherwise the bins is bad.
            tmp = [i if i <= xlim[1] else xlim[1] + 10 for i in tmp]
            print(f"Nb points for {label}: {len(tmp)}")
            print(f"Nb lost frames for {label}: {total_loss}")
        res[label] = compute_cdf(tmp, add_zero=True, nb_bins=1000)

    fig, ax = plt.subplots()

    for i, (label, (bins, cdf)) in enumerate(res.items()):
        ax.plot(bins, cdf, label=label, linestyle=LINESTYLES[i], linewidth=LINEWIDTH)
    
    ax.set_xlabel("Lateness [ms]")
    ax.set_ylabel("CDF")
    ax.set_title(title)
    if ylim is not None:
        ax.set_ylim(ylim)
    if xlim is not None:
        ax.set_xlim(xlim)
    plt.legend()
    # plt.savefig("test.pdf")
    plt.tight_layout()
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


def read_tshark_out(s):
    s = s.decode("utf-8")
    return int(s.split("\n")[-3].split("|")[2])


def plot_pcap(all_files_labels, trace, title="", save_as="bytes.pdf"):
    res = dict()

    # for (files, label) in all_files_labels:
    #     total_uc = 0
    #     total_mc_data = 0
    #     total_mc_auth = 0
    #     for file in tqdm.tqdm(files):
    #         # Call tshark to get the expected results.
    #         cmd = lambda i: f'tshark -r {file} -qz io,stat,0,"SUM(frame.len)frame.len && {i}"'
            
    #         out = subprocess.check_output(cmd("udp.port == 4433"), shell=True)
    #         total_uc += read_tshark_out(out)

    #         out = subprocess.check_output(cmd("udp.dstport == 8889"), shell=True)
    #         total_mc_data += read_tshark_out(out)

    #         out = subprocess.check_output(cmd("udp.dstport == 8890"), shell=True)
    #         total_mc_auth += read_tshark_out(out)
    #     res[label] = (total_uc, total_mc_data, total_mc_auth)

    # res = {'MC none': (24656352, 1210067600, 0), 'UC': (5636354844, 0, 0)}
    # res = {'MC asymmetric': (19882098, 1785258200, 0), 'MC none': (19856060, 1679857800, 0), 'MC symmetric': (19884532, 1678992632, 1631735100), 'UC': (7447411584, 0, 0)}

    res = {
        0: {'MC none': (6292526, 1201353900, 0), 'UC': (5979727826, 0, 0)},
        1: {'MC none': (24656352, 1210067600, 0), 'UC': (5636354844, 0, 0)},
        2: {'MC none': (40882932, 1219662500, 0), 'UC': (5667614838, 0, 0)},
        3: {'MC none': (64450485, 1232994880, 0), 'UC': (5684334016, 0, 0)},
        4: {'MC none': (79492908, 1246982700, 0), 'UC': (5706839872, 0, 0)},
        5: {'MC none': (89114122, 1256883550, 0), 'UC': (5717149050, 0, 0)}
    }
    print(res)
    
    mega_values = list()
    for loss, data in res.items():
        for label, (val1, val2, val3) in data.items():
            mega_values.append((loss, label, val1 + val2 + val3))
    
    df = pd.DataFrame(mega_values, columns=["Loss [%]", "Method", "Nb bytes"])

    fig, ax = plt.subplots()

    sns.barplot(data=df, x="Loss [%]", y="Nb bytes", hue="Method")
    
    # ax.set_xlabel("Communication type")
    # ax.set_ylabel("Number of bytes")
    # ax.set_title(title)
    # ax.grid(axis="y")
    # ax.set_axisbelow(True)
    ax.set_yscale("log")
    # plt.legend()
    plt.savefig(save_as, dpi=500)



def plot_losses(directories, trace, filter, save_as):
    res = dict()
    for subdir in directories:
        files_labels, ttl, nb_frames = get_files_labels(subdir, filter)
        loss = int(subdir.split("-")[-1])
        res_this_loss = dict()
        for (files, label) in files_labels:
            tmp = list()
            for file in files:
                r, _ = read_and_rm_delay(trace, file)
                if len(r.values()) == 0:
                    print(file)
                    continue

                # Keep only th percentile.
                perc = np.percentile(list(r.values()), args.perc)
                r2 = {k: v for k, v in r.items() if v >= perc}
                # print(f"Before {len(r)}. After: {len(r2)}")
                r = r2
                tmp += list(r.values())
            res_this_loss[label] = tmp
        res[loss] = res_this_loss
        # if len(res) > 1: break
    
    fig, ax = plt.subplots()

    keys = sorted(list(res.keys()))

    # Convert to df.
    mega_values = list()
    in_timer = dict()
    for loss, data in res.items():
        tmp = dict()
        for label, values in data.items():
            for value in values:
                if value >= 350:
                    tmp[label] = tmp.get(label, 0) + 1
                    print(value, loss, label)
                else:
                    mega_values.append((loss, label, value))
        in_timer[loss] = tmp
    df = pd.DataFrame(mega_values, columns=["Loss [%]", "Method", "Lateness [ms]"])
    print(df)
    print(in_timer)

    # sns.violinplot(data=df, x="loss", y="Lateness [ms]", hue="method")
    sns.boxplot(data=df, x="Loss [%]", y="Lateness [ms]", hue="Method", showfliers=False, palette=COLORS_GREY)
    # ax.set_ylim((-10, 300))
    ax.get_yaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())

    legend = ax.legend(fancybox=True, ncol = 3)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)
    plt.tight_layout()
    ax.yaxis.grid(True, ls="-")
    ax.set_xlabel(r"Loss [\%]")
    ax.set_axisbelow(True)
    plt.savefig(save_as)


def get_files_labels_file(directory):
    res = dict()
    for subdir in os.listdir(directory):
        # if not "4-1000" in subdir: continue
        for file in os.listdir(os.path.join(directory, subdir)):
            if "server" in file: continue
            path = os.path.join(directory, subdir, file)
            tab = file.split("-")
            label = subdir[5:]
            print(label)
                
            ttl = None
            nb_frames = None
            if ttl == None:
                ttl = int(tab[4])
            elif ttl != int(tab[4]):
                print("ERROR: found different TTL values", ttl, tab[4])
            
            if label in res.keys():
                res[label].append(path)
            else:
                res[label] = [path]
            
            if nb_frames == None:
                nb_frames = int(tab[3])
            elif nb_frames != int(tab[3]):
                print("ERROR: found different NB FRAMES values", nb_frames, tab[3])

    return res, ttl, nb_frames


def plot_file_losses(args):
    all_files_labels, ttl, nb_frames = get_files_labels_file(args.directory)
    print(all_files_labels)

    res = dict()
    keys = sorted(all_files_labels.keys())

    for label in keys:
        files = all_files_labels[label]
        for file in files:
            if "stream-400" in file:
                continue
            data = read_data_brut(file)
            (complete, total) = res.get(label, (0, 0))
            if len(data) == 5000:
                complete += 1
            else:
                print(len(data), file)
            res[label] = (complete, total + 1)
    
    # Split into appropriate representation.
    res_per_timer = dict()
    for label, (complete, total) in res.items():
        tab = label.split("-")
        loss = int(tab[0])
        timer = int(tab[1])
        this_timer = res_per_timer.get(timer, dict())
        this_timer[loss] = complete / total
        res_per_timer[timer] = this_timer
    
    fig, ax = plt.subplots()
    labels = sorted(res_per_timer.keys())

    # Convert to df.
    mega_values = list()
    for timer in labels:
        data = res_per_timer[timer]
        for loss, data_loss in data.items():
            mega_values.append((timer, loss, data_loss))
    df = pd.DataFrame(mega_values, columns=["Exp. timer", "Loss [%]", "Ratio of clients"])
    print(df)
    
    sns.set_palette("colorblind")
    sns.barplot(data=df, x="Loss [%]", y="Ratio of clients", hue="Exp. timer")

    # for label in labels:
    #     loss_data = res_per_timer[label]
    #     keys = sorted(loss_data.keys())
    #     v = [loss_data[k] for k in keys]
    #     ax.plot(keys, v, label=label)
    #     # ax.scatter(keys, v, label=label)
    
    legend = ax.legend(fancybox=True, loc=(0.03, 0.03), ncol=4, columnspacing=0.5, handletextpad=0.1)
    frame = legend.get_frame()
    frame.set_alpha(1)
    frame.set_color('white')
    frame.set_edgecolor('black')
    frame.set_boxstyle('Square', pad=0.1)
    plt.tight_layout()
    ax.yaxis.grid(True, ls="-")
    ax.set_xlabel(r"Loss [\%]")
    ax.set_axisbelow(True)
    plt.savefig("file-losses.pdf")



if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("directory", help="Directory containing the files to parse", type=str)
    parser.add_argument("--trace", help="Path to the tixeo trace", type=str, default="/home/louisna/multicast-quic/perf/tixeo_trace.repr")
    parser.add_argument("--xlim", type=float, help="Maximum xlim for the plot distribution", default=None)
    parser.add_argument("--ylim", type=float, help="Maximum ylim for the plot distribution", default=0.0)
    parser.add_argument("--filter", help="Server or client lateness", default="clients", choices=["clients", "server"])
    parser.add_argument("--pcap", help="Plot using the PCAPs", action="store_true")
    parser.add_argument("--latex", help="Latex rendering", type=float, default=None)
    parser.add_argument("--losses", help="Losses plot", action="store_true")
    parser.add_argument("--perc", help="Percentile to filter", type=int, default=0)
    parser.add_argument("--save", help="Save as file", type=str, default="fig.pdf")
    parser.add_argument("--file", help="File plot", action="store_true")
    args = parser.parse_args()

    if args.latex is not None:
        latexify(columns=args.latex)

    # File.
    if args.file:
        plot_file_losses(args)
    # Pcaps.
    elif args.losses:
        # Get all directories with this prefix.
        all_subdirs = list()
        for subdir in os.listdir(args.directory):
            all_subdirs.append(os.path.join(args.directory, subdir))
        plot_losses(all_subdirs, args.trace, args.filter, save_as=args.save)
    elif args.pcap:
        # for subdir in os.listdir(args.directory):
        #     path = os.path.join(args.directory, subdir)
        #     print(path)
        #     all_files_labels, ttl, nb_frames = get_files_labels(os.path.join(path, "pcaps"), False)
        all_files_labels = list()
        nb_frames = 5000
        ttl = 350

        plot_pcap(all_files_labels, args.trace, title=f"Mininet ({nb_frames} frames, ttl={ttl})", save_as=f"bytes_{nb_frames}_{ttl}.png")
    else:
        all_files_labels, ttl, nb_frames = get_files_labels(args.directory, args.filter)

        # all_files_labels = [(i, j) for (i, j) in all_files_labels if (j == "MC none" or j == "UC")]

        # plot_distribution(all_files_labels, args.trace, title=f"Cloudlab server <-> INGI ({nb_frames} frames, ttl={ttl})", save_as=f"cdf_lat_{nb_frames}_{ttl}.pdf", ylim=(args.ylim, 1), xlim=(0, args.xlim))
        # plot_stream_recv_time(all_files_labels, title="Recv timestamp", save_as=f"recv_stream_{nb_frames}_{ttl}.png", ylabel="Time received since start [s]")
        # plot_stream_recv_time(all_files_labels, title="Recv timestamp compared to unicast", save_as=f"recv_stream-uc_{nb_frames}_{ttl}.png", cmp_uc="UC", ylabel="Lateness of reception with respect to UC [ms]")

        # Mininet.
        xlim = (0, args.xlim) if args.xlim is not None else None
        plot_distribution(all_files_labels, args.trace, title=f"", save_as=f"cdf_lat_{nb_frames}_{ttl}_{args.filter}.pdf", ylim=(args.ylim, 1), xlim=xlim)
