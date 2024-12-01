# Experiments with Flexicast QUIC.

This directory contains the material and instructions to start the experiments that were used in this paper.

I personally hope that all information will be enough. This is still a work in progress, I will continue adding more information to make everything work.

There are two main experiments in the paper: scalability benchmark and robustness evaluation.

## Getting ready

Several tools are required to run the experiments.
First, you require the Network Performance Framework (NPF), a Python module that orchestrates the experiments.
You might either install NPF and other related tools manually, or use the provided requirements:

```
pip install -r requirements.txt
```

You may also want to install GStreamer and FFMPEG:

```
apt-get install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libgstreamer-plugins-bad1.0-dev gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav gstreamer1.0-tools gstreamer1.0-x gstreamer1.0-alsa gstreamer1.0-gl gstreamer1.0-gtk3 gstreamer1.0-qt5 gstreamer1.0-pulseaudio ffmpeg
```

To compute the SSIM, you may want to use parallel to fasten the process:

```
apt install parallel
```

Finally, you also need to get the video. Because it is quite heavy, I am not able to add it to the GIT repository.
The video can be anonymously downloaded on the following link, on my institutional OneDrive account:
```
https://uclouvain-my.sharepoint.com/:f:/g/personal/louis_navarre_uclouvain_be/Et1RCljLGOZDu01-f-WIO3UB9f5qLlkKQD-hQ76gU2IM2A?e=GgUYgr
```
Please put this video under the name `train_5M.avi` in the [robustness](robustness/) folder.

Other software may be required, which I will consider as "generic", e.g., having a working Rust installation with the Cargo toolchain.
I will try to provide more information in the future.

## The `dummy` directory

The [dummy](dummy/) directory contains several pieces of code that are not that smart, but that we use for the purpose of these experiments.

For example, [the code to send an RTP stop message](dummy/src/bin/send_stop.rs) to stop the experiments from Section 6.2.

The [mc_failure](dummy/src/bin/mc_failure.rs) generates the link failures for the experiments from Section 6.2.

The [simple_mc](dummy/src/bin/simple_mc.rs/) and [listen_uc](dummy/src/bin/listen_uc.rs) are used when we benchmark Flexicast QUIC in Section 2 with the Baseline.

## Scalability of FCQUIC (Section 6.1)

This part relies on the Cloudlab infrastructure.
We use 6 d6515 nodes, which are quite popular, so you might need a reservation to be able to get those.

The [topology XML file](scaling/cloudlab.xml) provides the topology we use.

The [installation file](scaling/install.sh) provides all the commands to have an up and running setup on Cloudlab.
Run this file on every node of the cloudlab instance.

We also have to install FastClick, which is used to emulate an entire network on a single node.
For the moment, this is quite tricky, because we need to install DPDK before...
Then, we must execute the [FastClick installation script](scaling/install_fastclick.sh) on node-1.

With this topology, you are now able to start the NPF script. All the orchestration is performed by the [scaling.npf](scaling/scaling.npf) file. The command to start it is quite complex at first, but it is still okay. 

Several files are provided to help:
- [Execute Baseline benchmark](scaling/baseline.sh)
- [Execute QUIC benchmark](scaling/quic.sh)
- [Execute FC-QUIC benchmark with and without ack delay](scaling/fcquic.sh)
- [Execute FC-QUIC benchmark with sendmmsg](scaling/fcquic-sendmmsg.sh)

You have to modify the content of the files with the right ssh commands to get SSH access to the nodes.
Replace the `<ssh-addr node-2>` by, the command provided by Cloudlab, e.g., `loginname@amd014.utah.cloudlab.us`, following the index of the nodes in the bash file.

## Robustness of FCQUIC

The other experiment runs on a single machine, so it's much simpler.

You first need to get the video, which is available on this link:
```
https://uclouvain-my.sharepoint.com/:f:/g/personal/louis_navarre_uclouvain_be/Et1RCljLGOZDu01-f-WIO3UB9f5qLlkKQD-hQ76gU2IM2A?e=EsDOal
```

Because the video is heavy, I could not load it on the Git.
You can put the video inside the [robustness/](robustness/) directory.

Then, simply run the [run.sh](robustness/run.sh) file to execute the evaluation.

To compute the SSIM value, we use the `ssim.py` script, which was also defined by the authors of the paper releasing the video (please see the paper for the reference).

We use `parallel` to fasten the process:

```
parallel -j 20 --eta "python3" "ssim.py" "train_5M.avi" "{}" --method qr --save ::: res-*/out_*.avi
```