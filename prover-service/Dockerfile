# syntax=docker/dockerfile:1.7

# The image used for building
FROM debian:bookworm as build_prover_service
ARG TARGETARCH
ARG RELEASE_DEFAULT
ARG RELEASE_NEW

# copy the entire cargo workspace into the image
COPY --link . .

# Install deps for building prover service
RUN ./scripts/task.sh prover-service install-deps 

# Build prover service
RUN /root/.cargo/bin/cargo build --release -p prover-service \
 && cp target/release/prover-service /prover-service-bin

# Download trusted setup and witness gen binaries
ENV RESOURCES_DIR=/resources
RUN ./scripts/task.sh setup download-ceremonies-for-releases \
        "$RELEASE_DEFAULT"                                   \
        "$RELEASE_NEW"                                       \
        --witness-gen-type "c"




# The image that is actually deployed
FROM debian:bookworm
 

# need libyaml, gmp, and openssl dylibs to run prover service
RUN apt-get update \
 && apt-get install -y libyaml-dev libgmp-dev libssl-dev

# copy prover service binary
COPY --link --from=build_prover_service ./prover-service-bin ./prover-service-bin
# copy oneTBB dylib
COPY --link --from=build_prover_service ./rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0 ./rapidsnark-libdir
# copy trusted setup and witness generation binaries
COPY --link --from=build_prover_service ./resources ./resources
# copy prover service config file
COPY --link ./prover-service/config.yml ./config.yml
# copy prover service config file for running the automated docker test (not needed I think)
#COPY --link ./prover-service/config_docker_test.yml ./config_docker_test.yml

ARG GIT_COMMIT
ENV GIT_COMMIT=$GIT_COMMIT

EXPOSE 8080

# Add Tini to make sure the binaries receive proper SIGTERM signals when Docker is shut down
# note this needs the buildx tool. On e.g. arch linux it's installed separately via the 
# docker-buildx package
# TODO remove this after confirming with prod-eng that it is not necessary anymore
ADD --chmod=755 https://github.com/krallin/tini/releases/download/v0.19.0/tini-amd64 /tini
ENTRYPOINT ["/tini", "--"]

ENV LD_LIBRARY_PATH="./rapidsnark-libdir"
CMD ["./prover-service-bin"]
