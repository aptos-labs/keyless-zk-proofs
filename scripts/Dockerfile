
# syntax=docker/dockerfile:1.7

FROM archlinux:base-devel 
ARG TARGETARCH


COPY --link . .

RUN ./scripts/setup_environment.sh prover-service:install-deps

