from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI
from mininet.node import OVSController
from mininet.link import TCLink

import argparse
import os
import shutil
import time
import shlex
import sys
import subprocess


PCAP_DIR = "pcaps"
MC_TABLE_NAME = "smcroute"
APP_PATH = "/home/louisna/multicast-quic/apps/"
MANIFEST_PATH = os.path.join(APP_PATH, "Cargo.toml")
CARGO_PATH = "/home/louisna/.cargo/bin/cargo"
CERT_PATH = os.path.join(APP_PATH, "src", "bin/")


def my_cmd(net, node, cmd, wait=False):
    if wait:
        full_cmd = f'{cmd}'
        print("Full command", full_cmd)
        net[node].cmd(cmd)
    else:
        full_cmd = f'{cmd} &'
        print("Full command", shlex.split(cmd))
        net[node].popen(cmd, shell=True)


class MyAutoTopo(Topo):
    def build(self, **kwargs):
        with open(kwargs["loopbacks"]) as fd:
            txt = fd.read().split("\n")
        all_nodes = dict()
        for node_info in txt:
            if len(node_info) == 0:
                continue
            node_id, loopback = node_info.split(" ")
            node = self.addHost(node_id, ip=loopback,
                                mac=f"00:00:00:00:00:{node_id}")
            all_nodes[node_id] = node

        all_links = set()
        bw = kwargs["args"].bw
        loss = kwargs["args"].u_loss
        with open(kwargs["links"]) as fd:
            txt = fd.read().split("\n")
        for link_info in txt:
            if len(link_info) == 0:
                continue
            id1, id2, _, _, _ = link_info.split(" ")
            if (id1, id2) in all_links or (id2, id1) in all_links:
                continue
            self.addLink(all_nodes[id1], all_nodes[id2], cls=TCLink, bw=bw, loss=loss, delay="3ms")
            all_links.add((id1, id2))


def build_topo(args):
    ipv4 = args.ipv4
    print("USE IPV4", ipv4)

    args_dict = {
        "loopbacks": args.loopbacks,
        "links": args.links,
        "paths": args.paths,
        "multicast-paths": args.multicast,
        "args": args,
    }
    topo = MyAutoTopo(**args_dict)
    net = Mininet(topo=topo, controller=OVSController)
    net.start()

    dumpNodeConnections(net.hosts)

    nb_nodes = 0
    loopbacks = dict()

    with open(args_dict["loopbacks"]) as fd:
        txt = fd.read().split("\n")
        for loopback_info in txt:
            if len(loopback_info) == 0:
                continue
            id1, loopback = loopback_info.split(" ")
            if ipv4:
                cmd = f"ip addr add {loopback} dev lo"
            else:
                cmd = f"ip -6 addr add {loopback} dev lo"
            loopbacks[id1] = loopback[:-3]
            print(cmd)
            net[id1].cmd(cmd)
            # Enable IPv6 forwarding
            cmd = "sysctl net.ipv4.ip_forward=1"
            net[id1].cmd(cmd)
            cmd = "sysctl net.ipv6.conf.all.forwarding=1"
            net[id1].cmd(cmd)
            cmd = "sysctl net.ipv6.conf.all.mc_forwarding=1"
            net[id1].cmd(cmd)
            cmd = "sysctl net.ipv6.conf.lo.forwarding=1"
            net[id1].cmd(cmd)
            cmd = "sysctl net.ipv6.conf.lo.mc_forwarding=1"
            net[id1].cmd(cmd)
            cmd = "sysctl -w net.ipv4.udp_rmem_min=4096000 net.core.rmem_max=26214400 net.core.rmem_default=26214400 net.core.netdev_max_backlog=2000"
            net[id1].cmd(cmd)
            nb_nodes += 1
    
    links = dict()
    links_per_itf = dict()

    with open(args_dict["links"]) as fd:
        txt = fd.read().split("\n")
        for link_info in txt:
            if len(link_info) == 0:
                continue
            id1, id2, itf, link, loopback = link_info.split(" ")
            cmd = f"sysctl net.ipv6.conf.{id1}-eth{itf}.forwarding=1"
            net[id1].cmd(cmd)
            cmd = f"sysctl net.ipv6.conf.{id1}-eth{itf}.mc_forwarding=1"
            net[id1].cmd(cmd)

            cmd = f"sysctl net.ipv4.{id1}-eth{itf}.ip_forward=1"
            net[id1].cmd(cmd)
            if ipv4:
                cmd = f"ip addr add {link} dev {id1}-eth{itf}"
            else:
                cmd = f"ip -6 addr add {link} dev {id1}-eth{itf}"
            links[(id1, id2)] = link[:-3]
            links_per_itf[(id1, itf)] = link[:-3]
            print(id1, cmd)
            net[id1].cmd(cmd)

            # Start a tcpdump capture for each interface
            # From https://stackoverflow.com/questions/43765117/how-to-check-existence-of-a-folder-and-then-remove-it
            if args.traces:
                if os.path.exists(PCAP_DIR) and os.path.isdir(PCAP_DIR):
                    shutil.rmtree(PCAP_DIR)
                os.makedirs(PCAP_DIR)
                net[id1].cmd(f"tcpdump -i {id1}-eth{itf} -w {id1}-{itf}.pcap &")

    with open(args_dict["paths"]) as fd:
        txt = fd.read().split("\n")
        for path_info in txt:
            if len(path_info) == 0:
                continue
            id1, itf, link, loopback = path_info.split(" ")
            if ipv4:
                cmd = f"ip route add {loopback} via {link}"
            else:
                cmd = f"ip -6 route add {loopback} via {link}"
            print(id1, cmd)
            net[id1].cmd(cmd)
    
    # Install multicast routes.
    key = args_dict["multicast-paths"]
    if key is not None:
        # Add the multicast route for each entry of the file.
        with open(key) as fd:
            txt = fd.read().split("\n")
            for path_info in txt:
                if len(path_info) == 0:
                    continue
                tab = path_info.split()
                node_id, in_itf, mc_group, out_itf = tab[0], tab[1], tab[2], tab[3:]
                out_itf_txt = ""
                for itf_idx in out_itf:
                    out_itf_txt += f"{node_id}-eth{itf_idx} "
                cmd = f"smcrouted -l debug -I {MC_TABLE_NAME}-{node_id}"
                print(node_id, cmd)
                net[node_id].cmd(cmd)
                time.sleep(0.25)
                cmd = f"smcroutectl -I {MC_TABLE_NAME}-{node_id} add {node_id}-eth{in_itf} {mc_group.split('/')[0]} {out_itf_txt}"
                print(node_id, cmd)
                net[node_id].cmd(cmd)
                time.sleep(0.25)
    print(links_per_itf)
    # The multicast source must have a path to send the data to the network.
    cmd = "ip route add default dev 0-eth0"
    net["0"].cmd(cmd)

    return net, nb_nodes, links, links_per_itf

def simpleRun(args, core_range):

    if True:
        # Share the available cores to the nodes. Give an entire core to the server, and share the remaining cores among the clients.
        # First core for the server.
        server_core = core_range[0]
        client_cores = core_range[1:]

        # Compile the server code.
        cmd = f"{CARGO_PATH} build --bins --manifest-path {MANIFEST_PATH} {'--release' if args.release else ''}"
        print(cmd)
        os.system(cmd)

        # Communication method.
        methods = list()
        if args.method == "both":
            methods = ["mc", "uc"]
        else:
            methods = [args.method]

        # Create dir if not exists.
        os.makedirs(args.out, exist_ok=True)

        log_trace = "RUST_LOG=error" if args.log else ""

        for i_run in range(args.nb_run):
            for method in methods:
                # Authentication methods to execute.
                # No importance if unicast, so we avoid looping if all methods were asked.
                auths = list()
                if args.auth == "all" and method == "mc":
                    auths = ["symmetric", "asymmetric", "none"]
                elif args.auth == "all" and method == "uc":
                    auths = ["none"]
                else:
                    auths = [args.auth]
                
                for auth in auths:
                    # Create the mininet topology from scratch.
                    net, nb_nodes, links, links_per_itf = build_topo(args)

                    # Output filename of the experiment.
                    output_file_without_dir = lambda idx: f"{args.app}-{method}-{auth}-{args.nb_frames}-{args.ttl}-{'wait' if args.wait else 'nowait'}-{i_run}-{args.bw}-{args.u_loss}-{args.nb_rs}-{idx}.txt"
                    output_file = lambda idx: os.path.join(args.out, output_file_without_dir(idx))

                    # Start the quiche server on CloudLab.
                    cmd = f"{log_trace} taskset -c {server_core} {CARGO_PATH} run --manifest-path {MANIFEST_PATH} --bin mc-server {'--release' if args.release else ''} -- --ttl-data {args.ttl} --authentication {auth} {'--multicast' if method == 'mc' else ''} -f {args.file} -s {links[('0', '1')]}:4433 --app {args.app} --cert-path {CERT_PATH} {'-w ' + str(nb_nodes - 1) if args.wait else ''} -n {args.nb_frames} -r {output_file('server-0')} -k my-server.txt --max-fec-rs {args.nb_rs} > {'log-server.log 2>&1' if args.log else '/dev/null'}"
                    print("Command to start the server on CloudLab:", cmd)
                    my_cmd(net, "0", cmd, wait=False)

                    cmd = f"tcpdump -w test-server.pcap"
                    print(cmd)
                    my_cmd(net, "0", cmd, wait=False)

                    print("Wait for the server to setup...", end=" ", flush=True)
                    time.sleep(3)
                    print("Done")

                    # Start the clients on cloudlab.
                    for client in range(1, nb_nodes - 1):  # Not the source
                        cmd = f"{log_trace} {CARGO_PATH} run --manifest-path {MANIFEST_PATH} --bin mc-client {'--release' if args.release else ''} -- {links[('0', '1')]}:4433 -o {output_file(client)} {'--multicast' if method == 'mc' else ''} --app {args.app} --local {links_per_itf[(str(client), '0')]} > {f'log-{client}.log 2>&1' if args.log else '/dev/null'}"
                        print("Client command:", client, cmd)
                        my_cmd(net, str(client), cmd, wait=False)  # Act as a daemon

                    # Start the client locally and wait for completion.
                    # Last client always performs source authentication.
                    client = nb_nodes - 1
                    cmd = f"{log_trace} taskset -c {client_cores[client % len(client_cores)]} {CARGO_PATH} run --manifest-path {MANIFEST_PATH} --bin mc-client {'--release' if args.release else ''} -- {links[('0', '1')]}:4433 -o {output_file(client)} {'--multicast' if method == 'mc' else ''} --app {args.app} --local {links_per_itf[(str(client), '0')]} > {f'log-{client}.log 2>&1' if args.log else '/dev/null'}"
                    print("Client command:", client, cmd)
                    my_cmd(net, str(client), cmd, wait=True)

                    # Clean the topology.
                    cmd = "pgrep mc-server"
                    while True:
                        try: 
                            _ = len(subprocess.check_output(cmd, shell=True)) == 0

                        except Exception:
                            break
                        print("OK")
                        time.sleep(1)
                    net.stop()
    else:
        net, nb_nodes, links, links_per_itf = build_topo(args)
        CLI(net)
        net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--loopbacks", type=str,
                        default="configs/topo-loopbacks.txt")
    parser.add_argument("-i", "--links", type=str, default="configs/topo-links.txt")
    parser.add_argument("-p", "--paths", type=str, default="configs/topo-paths.txt")
    parser.add_argument("-t", "--traces", action="store_true", help="Activate tracing with tcpdump")
    parser.add_argument("--ipv4", action="store_true", help="Indicates that the scripts use IPv4 instead of IPv6")
    parser.add_argument("-m", "--multicast", help="Add multicast routes in the given path", default=None)
    parser.add_argument("--log", help="Enable logging on nodes", action="store_true")
    
    parser.add_argument("--app", choices=["tixeo", "file"], default="tixeo", help="Application of the test", type=str)
    parser.add_argument("--nb-frames", type=int, help="Number of frames of the test. Default: all", default=None)
    parser.add_argument("--file", type=str, help="File name to send/trace", default="../perf/tixeo_trace.repr")
    parser.add_argument("--wait", help="Make server wait for the client to connect", action="store_true")
    parser.add_argument("--auth", help="Authentication methods to test. Default: all", choices=["asymmetric", "symmetric", "none", "all"])
    parser.add_argument("--method", help="Multicast or unicast delivery. Default: both", choices=["mc", "uc", "both"])
    parser.add_argument("--out", help="Output directory", default="results", type=str)
    parser.add_argument("--ttl", help="Data expiration for multicast (in ms). Default: 1000", default="1000", type=int)
    parser.add_argument("--release", help="Compile and execute the code in release mode", action="store_true")
    parser.add_argument("--nb-run", help="Number of repetitions of each experiment", type=int, default=1)
    parser.add_argument("--bw", help="Set the same bandwidth value on each link (Mbps)", type=float, default=100)
    parser.add_argument("--u-loss", help="Uniform loss on each link (%)", type=int, default=0)
    parser.add_argument("--cores", help="Cores available for the experiment, following Python range synthax (e.g., '1,10')", type=str, default="1,2")
    parser.add_argument("--nb-rs", help="Number of FEC repair symbols to send", type=int, default=5)

    args = parser.parse_args() 

    tab = args.cores.split(",")
    if len(tab) != 2:
        print("This is not a valid range", args.core)
        sys.exit()
    
    range_a = int(tab[0])
    range_b = int(tab[1])
    if range_a + 1 >= range_b:
        print(f"The range is not valid: {range_a} -> {range_b}")
        sys.exit()

    simpleRun(args, list(range(range_a, range_b)))

