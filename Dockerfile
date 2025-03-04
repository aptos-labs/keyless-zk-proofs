# syntax=docker/dockerfile:1.7

FROM alpine:latest as build_prover_service
ARG TARGETARCH

RUN apk add --no-cache clang meson cmake make yaml nasm gmp-dev openssl rustup curl git \
 && curl https://sh.rustup.rs -sSf | sh -s -- -y

#RUN apt-get update \
#    && apt-get install -y clang meson cmake make libyaml-dev nasm libgmp-dev libomp-dev

COPY --link . .

# Build gmp separately so that docker will cache this step
RUN cd rust-rapidsnark/rapidsnark && \
    chmod a+x build_lib.sh && \
    source ./build_lib.sh
    # && \
    #cp target/release/prover-service /prover-service-bin

# FROM debian:12.4
# 
# RUN apt-get update \
#     && apt-get install -y libgmp-dev libsodium-dev libomp-dev curl python3 python3-pip
# 
# # copy prover server
# COPY --link --from=build_prover_service ./prover-service-bin ./prover-service-bin
# COPY --link --from=build_prover_service ./prover/rust-rapidsnark/rapidsnark/build/subprojects/subprojects/oneTBB-2022.0.0 ./rapidsnark-libdir
# 
# ARG GIT_COMMIT
# ENV GIT_COMMIT=$GIT_COMMIT
# 
# COPY scripts scripts
# ENV RESOURCES_DIR=/resources
# RUN python3 scripts/prepare_setups.py
# 
# COPY --link ./prover/config.yml ./config.yml
# 
# EXPOSE 8080
# 
# # Add Tini to make sure the binaries receive proper SIGTERM signals when Docker is shut down
# ADD --chmod=755 https://github.com/krallin/tini/releases/download/v0.19.0/tini-amd64 /tini
# ENTRYPOINT ["/tini", "--"]
# 
# ENV LD_LIBRARY_PATH="./rapidsnark-libdir"
# CMD ["./prover-service-bin"]
