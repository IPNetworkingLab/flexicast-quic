# Flexicast QUIC

This repository contains the source code of Flexicast QUIC, accepted at SIGCOMM CCR for the April 2025 volume.

**Disclamer: we are currently working on an updated version of Flexicast QUIC to contain the last updates from Multipath QUIC and Cloudflare quiche. It will be released soon.**

## From quiche and multipath

This project builds upon quiche and multipath. The core implementation of flexicast-quic relies on quiche and its multipath branch (see the paper).

The core implementation, [quiche], is extended to support flexicast QUIC.
The applications are in the [apps](apps/) repository.
For this paper, we implemented and used the [fc-client-rtp](apps/src/bin/fc-client-rtp.rs) and [fc-server-rtp-tokio](apps/src/bin/fc-server-rtp-tokio.rs) applications. The other applications are initially part of quiche or rely on applications not evaluated.

Please use the __refactoring__ branch of this project, as other branches contain outdated code.
We will make sure to clean as well as possible the repository in the future.

## Main contributions

The main contributions inside the code repository of quiche lies in the [multicast](quiche/src/multicast) module.
This module contains as much as possible of the control of flexicast to avoid modifying to much the main part of quiche.
However, we still had to modify the main functions (in [lib.rs](quiche/src/lib.rs)) at some point; as well as the frames, the recovery, etc...

The message passing implementation to enable processing Flexicast QUIC on multiple threads is in the [asynchronous](apps/src/mc_app/asynchronous) module of the applications.

## Compilation

Do __not forget__ to pull the submodules (boringssl in particular), otherwise the code won't compile!

```
git submodule update --init
```

The source historically relies on network coding, even if this is not supported anymore in the implementation. Normally, you should have access thanks to the access token. Do not hesitate to send us an email if this is not the case.
At the time of writing, the token is still valid and works perfectly.

To compile the code, simply run

```
cargo build [--release] [--bin fc-server-rtp-tokio/fc-client-rtp]
```

## Experiments from the paper

We provide as much information as possible to reproduce the experiments from the paper. More information is available in the [README from the experiments folder](experiments/README.md).

They rely on the Network Performance Framework (a Python module).

## Cite Flexicast QUIC

Please use the following bibtex input to cite this work:

```
@article{navarre2025taking,
  title={Taking the Best of Multicast and Unicast with Flexicast QUIC},
  author={Navarre, Louis and De Coninck, Quentin and Barbette, Tom and Bonaventure, Olivier},
  journal={ACM SIGCOMM Computer Communication Review},
  volume={55},
  number={2},
  pages={},
  year={2025},
  note={Postprint},
  publisher={ACM New York, NY, USA}
}
```

----------------------------------------------------


![quiche](quiche.svg)

[![crates.io](https://img.shields.io/crates/v/quiche.svg)](https://crates.io/crates/quiche)
[![docs.rs](https://docs.rs/quiche/badge.svg)](https://docs.rs/quiche)
[![license](https://img.shields.io/github/license/cloudflare/quiche.svg)](https://opensource.org/licenses/BSD-2-Clause)
![build](https://img.shields.io/github/actions/workflow/status/cloudflare/quiche/stable.yml?branch=master)

[quiche] is an implementation of the QUIC transport protocol and HTTP/3 as
specified by the [IETF]. It provides a low level API for processing QUIC packets
and handling connection state. The application is responsible for providing I/O
(e.g. sockets handling) as well as an event loop with support for timers.

For more information on how quiche came about and some insights into its design
you can read a [post] on Cloudflare's blog that goes into some more detail.

[quiche]: https://docs.quic.tech/quiche/
[ietf]: https://quicwg.org/
[post]: https://blog.cloudflare.com/enjoy-a-slice-of-quic-and-rust/

Who uses quiche?
----------------

### Cloudflare

quiche powers Cloudflare edge network's [HTTP/3 support][cloudflare-http3]. The
[cloudflare-quic.com](https://cloudflare-quic.com) website can be used for
testing and experimentation.

### Android

Android's DNS resolver uses quiche to [implement DNS over HTTP/3][android-http3].

### curl

quiche can be [integrated into curl][curl-http3] to provide support for HTTP/3.

### NGINX (unofficial)

quiche can be [integrated into NGINX](nginx/) using an unofficial patch to
provide support for HTTP/3.

[cloudflare-http3]: https://blog.cloudflare.com/http3-the-past-present-and-future/
[android-http3]: https://security.googleblog.com/2022/07/dns-over-http3-in-android.html
[curl-http3]: https://github.com/curl/curl/blob/master/docs/HTTP3.md#quiche-version

Getting Started
---------------

### Command-line apps

Before diving into the quiche API, here are a few examples on how to use the
quiche tools provided as part of the [quiche-apps](apps/) crate.

After cloning the project according to the command mentioned in the [building](#building) section, the client can be run as follows:

```bash
 $ cargo run --bin quiche-client -- https://cloudflare-quic.com/
```

while the server can be run as follows:

```bash
 $ cargo run --bin quiche-server -- --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key
```

(note that the certificate provided is self-signed and should not be used in
production)

Use the `--help` command-line flag to get a more detailed description of each
tool's options.

### Configuring connections

The first step in establishing a QUIC connection using quiche is creating a
[`Config`] object:

```rust
let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
config.set_application_protos(&[b"example-proto"]);

// Additional configuration specific to application and use case...
```

The [`Config`] object controls important aspects of the QUIC connection such
as QUIC version, ALPN IDs, flow control, congestion control, idle timeout
and other properties or features.

QUIC is a general-purpose transport protocol and there are several
configuration properties where there is no reasonable default value. For
example, the permitted number of concurrent streams of any particular type
is dependent on the application running over QUIC, and other use-case
specific concerns.

quiche defaults several properties to zero, applications most likely need
to set these to something else to satisfy their needs using the following:

- [`set_initial_max_streams_bidi()`]
- [`set_initial_max_streams_uni()`]
- [`set_initial_max_data()`]
- [`set_initial_max_stream_data_bidi_local()`]
- [`set_initial_max_stream_data_bidi_remote()`]
- [`set_initial_max_stream_data_uni()`]

[`Config`] also holds TLS configuration. This can be changed by mutators on
the an existing object, or by constructing a TLS context manually and
<<<<<<< HEAD
creating a configuration using [`with_boring_ssl_ctx()`].
=======
creating a configuration using [`with_boring_ssl_ctx_builder()`].
>>>>>>> multipath

A configuration object can be shared among multiple connections.

### Connection setup

On the client-side the [`connect()`] utility function can be used to create
a new connection, while [`accept()`] is for servers:

```rust
// Client connection.
let conn = quiche::connect(Some(&server_name), &scid, local, peer, &mut config)?;

// Server connection.
let conn = quiche::accept(&scid, None, local, peer, &mut config)?;
```

### Handling incoming packets

Using the connection's [`recv()`] method the application can process
incoming packets that belong to that connection from the network:

```rust
let to = socket.local_addr().unwrap();

loop {
    let (read, from) = socket.recv_from(&mut buf).unwrap();

    let recv_info = quiche::RecvInfo { from, to };

    let read = match conn.recv(&mut buf[..read], recv_info) {
        Ok(v) => v,

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };
}
```

### Generating outgoing packets

Outgoing packet are generated using the connection's [`send()`] method
instead:

```rust
loop {
    let (write, send_info) = match conn.send(&mut out) {
        Ok(v) => v,

        Err(quiche::Error::Done) => {
            // Done writing.
            break;
        },

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };

    socket.send_to(&out[..write], &send_info.to).unwrap();
}
```

When packets are sent, the application is responsible for maintaining a
timer to react to time-based connection events. The timer expiration can be
obtained using the connection's [`timeout()`] method.

```rust
let timeout = conn.timeout();
```

The application is responsible for providing a timer implementation, which
can be specific to the operating system or networking framework used. When
a timer expires, the connection's [`on_timeout()`] method should be called,
after which additional packets might need to be sent on the network:

```rust
// Timeout expired, handle it.
conn.on_timeout();

// Send more packets as needed after timeout.
loop {
    let (write, send_info) = match conn.send(&mut out) {
        Ok(v) => v,

        Err(quiche::Error::Done) => {
            // Done writing.
            break;
        },

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };

    socket.send_to(&out[..write], &send_info.to).unwrap();
}
```

#### Pacing

It is recommended that applications [pace] sending of outgoing packets to
avoid creating packet bursts that could cause short-term congestion and
losses in the network.

quiche exposes pacing hints for outgoing packets through the [`at`] field
of the [`SendInfo`] structure that is returned by the [`send()`] method.
This field represents the time when a specific packet should be sent into
the network.

Applications can use these hints by artificially delaying the sending of
packets through platform-specific mechanisms (such as the [`SO_TXTIME`]
socket option on Linux), or custom methods (for example by using user-space
timers).

[pace]: https://datatracker.ietf.org/doc/html/rfc9002#section-7.7
[`SO_TXTIME`]: https://man7.org/linux/man-pages/man8/tc-etf.8.html

### Sending and receiving stream data

After some back and forth, the connection will complete its handshake and
will be ready for sending or receiving application data.

Data can be sent on a stream by using the [`stream_send()`] method:

```rust
if conn.is_established() {
    // Handshake completed, send some data on stream 0.
    conn.stream_send(0, b"hello", true)?;
}
```

The application can check whether there are any readable streams by using
the connection's [`readable()`] method, which returns an iterator over all
the streams that have outstanding data to read.

The [`stream_recv()`] method can then be used to retrieve the application
data from the readable stream:

```rust
if conn.is_established() {
    // Iterate over readable streams.
    for stream_id in conn.readable() {
        // Stream is readable, read until there's no more data.
        while let Ok((read, fin)) = conn.stream_recv(stream_id, &mut buf) {
            println!("Got {} bytes on stream {}", read, stream_id);
        }
    }
}
```

### HTTP/3

The quiche [HTTP/3 module] provides a high level API for sending and
receiving HTTP requests and responses on top of the QUIC transport protocol.

[`Config`]: https://docs.quic.tech/quiche/struct.Config.html
[`set_initial_max_streams_bidi()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_bidi
[`set_initial_max_streams_uni()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_uni
[`set_initial_max_data()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_data
[`set_initial_max_stream_data_bidi_local()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_bidi_local
[`set_initial_max_stream_data_bidi_remote()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_bidi_remote
[`set_initial_max_stream_data_uni()`]: https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_stream_data_uni
<<<<<<< HEAD
[`with_boring_ssl_ctx()`]: https://docs.quic.tech/quiche/struct.Config.html#method.with_boring_ssl_ctx
=======
[`with_boring_ssl_ctx_builder()`]: https://docs.quic.tech/quiche/struct.Config.html#method.with_boring_ssl_ctx_builder
>>>>>>> multipath
[`connect()`]: https://docs.quic.tech/quiche/fn.connect.html
[`accept()`]: https://docs.quic.tech/quiche/fn.accept.html
[`recv()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.recv
[`send()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.send
[`timeout()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.timeout
[`on_timeout()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.on_timeout
[`stream_send()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.stream_send
[`readable()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.readable
[`stream_recv()`]: https://docs.quic.tech/quiche/struct.Connection.html#method.stream_recv
[HTTP/3 module]: https://docs.quic.tech/quiche/h3/index.html

Have a look at the [quiche/examples/] directory for more complete examples on
how to use the quiche API, including examples on how to use quiche in C/C++
applications (see below for more information).

[examples/]: quiche/examples/

Calling quiche from C/C++
-------------------------

quiche exposes a [thin C API] on top of the Rust API that can be used to more
easily integrate quiche into C/C++ applications (as well as in other languages
that allow calling C APIs via some form of FFI). The C API follows the same
design of the Rust one, modulo the constraints imposed by the C language itself.

When running ``cargo build``, a static library called ``libquiche.a`` will be
built automatically alongside the Rust one. This is fully stand-alone and can
be linked directly into C/C++ applications.

Note that in order to enable the FFI API, the ``ffi`` feature must be enabled (it
is disabled by default), by passing ``--features ffi`` to ``cargo``.

[thin C API]: https://github.com/cloudflare/quiche/blob/master/quiche/include/quiche.h

Building
--------

quiche requires Rust 1.66 or later to build. The latest stable Rust release can
be installed using [rustup](https://rustup.rs/).

Once the Rust build environment is setup, the quiche source code can be fetched
using git:

```bash
 $ git clone --recursive https://github.com/cloudflare/quiche
```

and then built using cargo:

```bash
 $ cargo build --examples
```

cargo can also be used to run the testsuite:

```bash
 $ cargo test
```

Note that [BoringSSL], which is used to implement QUIC's cryptographic handshake
based on TLS, needs to be built and linked to quiche. This is done automatically
when building quiche using cargo, but requires the `cmake` command to be
available during the build process. On Windows you also need
[NASM](https://www.nasm.us/). The [official BoringSSL
documentation](https://github.com/google/boringssl/blob/master/BUILDING.md) has
more details.

In alternative you can use your own custom build of BoringSSL by configuring
the BoringSSL directory with the ``QUICHE_BSSL_PATH`` environment variable:

```bash
 $ QUICHE_BSSL_PATH="/path/to/boringssl" cargo build --examples
```

[BoringSSL]: https://boringssl.googlesource.com/boringssl/

### Building for Android

Building quiche for Android (NDK version 19 or higher, 21 recommended), can be
done using [cargo-ndk] (v2.0 or later).

First the [Android NDK] needs to be installed, either using Android Studio or
directly, and the `ANDROID_NDK_HOME` environment variable needs to be set to the
NDK installation path, e.g.:

```bash
 $ export ANDROID_NDK_HOME=/usr/local/share/android-ndk
```

Then the Rust toolchain for the Android architectures needed can be installed as
follows:

```bash
 $ rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Note that the minimum API level is 21 for all target architectures.

[cargo-ndk] (v2.0 or later) also needs to be installed:

```bash
 $ cargo install cargo-ndk
```

Finally the quiche library can be built using the following procedure. Note that
the `-t <architecture>` and `-p <NDK version>` options are mandatory.

```bash
 $ cargo ndk -t arm64-v8a -p 21 -- build --features ffi
```

See [build_android_ndk19.sh] for more information.

[Android NDK]: https://developer.android.com/ndk
[cargo-ndk]: https://docs.rs/crate/cargo-ndk
[build_android_ndk19.sh]: https://github.com/cloudflare/quiche/blob/master/tools/android/build_android_ndk19.sh

### Building for iOS

To build quiche for iOS, you need the following:

- Install Xcode command-line tools. You can install them with Xcode or with the
  following command:

```bash
 $ xcode-select --install
```

- Install the Rust toolchain for iOS architectures:

```bash
 $ rustup target add aarch64-apple-ios x86_64-apple-ios
```

- Install `cargo-lipo`:

```bash
 $ cargo install cargo-lipo
```

To build libquiche, run the following command:

```bash
 $ cargo lipo --features ffi
```

or

```bash
 $ cargo lipo --features ffi --release
```

iOS build is tested in Xcode 10.1 and Xcode 11.2.

### Building Docker images

In order to build the Docker images, simply run the following command:

```bash
 $ make docker-build
```

You can find the quiche Docker images on the following Docker Hub repositories:

- [cloudflare/quiche](https://hub.docker.com/repository/docker/cloudflare/quiche)
- [cloudflare/quiche-qns](https://hub.docker.com/repository/docker/cloudflare/quiche-qns)

The `latest` tag will be updated whenever quiche master branch updates.

**cloudflare/quiche**

Provides a server and client installed in /usr/local/bin.

**cloudflare/quiche-qns**

Provides the script to test quiche within the [quic-interop-runner](https://github.com/marten-seemann/quic-interop-runner).

Copyright
---------

Copyright (C) 2018-2019, Cloudflare, Inc.

See [COPYING] for the license.

[COPYING]: https://github.com/cloudflare/quiche/tree/master/COPYING
