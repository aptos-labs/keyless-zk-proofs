# syntax=docker/dockerfile:1.7

FROM archlinux:base-devel as build_prover_service
ARG TARGETARCH

run pacman -Syu --noconfirm \
 && pacman -S --noconfirm rustup clang lld meson cmake make libyaml nasm gmp openssl curl git \
 && rustup default stable

COPY --link . .

# Build gmp separately so that docker will cache this step
RUN cargo build --release -p prover-service \
 && cp target/release/prover-service /prover-service-bin

FROM archlinux:base-devel
 
run pacman -Syu --noconfirm \
 && pacman -S --noconfirm libyaml gmp curl python

# copy prover server
COPY --link --from=build_prover_service ./prover-service-bin ./prover-service-bin
COPY --link --from=build_prover_service ./rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0 ./rapidsnark-libdir

ARG GIT_COMMIT
ENV GIT_COMMIT=$GIT_COMMIT

COPY scripts scripts
ENV RESOURCES_DIR=/resources
RUN python3 scripts/prepare_setups.py

COPY --link ./prover-service/config.yml ./config.yml

EXPOSE 8080

# Add Tini to make sure the binaries receive proper SIGTERM signals when Docker is shut down
# note this needs the buildx tool. On e.g. arch linux it's installed separately via the 
# docker-buildx package
ADD --chmod=755 https://github.com/krallin/tini/releases/download/v0.19.0/tini-amd64 /tini
ENTRYPOINT ["/tini", "--"]

ENV LD_LIBRARY_PATH="./rapidsnark-libdir"
CMD ["./prover-service-bin"]
