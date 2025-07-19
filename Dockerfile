FROM rust:1.86 AS build

WORKDIR /build

COPY Cargo.toml ./
COPY apps/ ./apps/
COPY buffer-pool ./buffer-pool/
COPY datagram-socket/ ./datagram-socket/
COPY h3i/ ./h3i/
COPY octets/ ./octets/
COPY qlog/ ./qlog/
COPY quiche/ ./quiche/
COPY task-killswitch ./task-killswitch/
COPY tokio-quiche ./tokio-quiche/

RUN apt-get update && apt-get install -y cmake && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --manifest-path apps/Cargo.toml

##
## quiche-base: quiche image for apps
##
FROM debian:latest AS quiche-base

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/target/release/quiche-client \
     /build/target/release/quiche-server \
     /build/target/release/fc-recv-file-transfer \
     /usr/local/bin/

ENV PATH="/usr/local/bin/:${PATH}"
ENV RUST_LOG=debug

WORKDIR /quiche

COPY --from=build \
     /build/target/release/quiche-client \
     /build/target/release/quiche-server \
     /build/target/release/fc-recv-file-transfer \
     /build/apps/run_endpoint.sh \
     /build/apps/run_fc_quic_recv.sh \
     /build/apps/run_fc_quic.sh \
     ./

ENV RUST_LOG=trace

ENTRYPOINT [ "./run_fc_quic_recv.sh" ]
