
# syntax=docker/dockerfile:1.7

FROM archlinux:base-devel 
ARG TARGETARCH

COPY --link . .

ENV RESOURCES_DIR=/resources
RUN ./scripts/task.sh prover-service install-deps
RUN /root/.cargo/bin/cargo build
    
ENV LD_LIBRARY_PATH="/rust-rapidsnark/rapidsnark/build/subprojects/oneTBB-2022.0.0"
CMD cd automated-docker-test; /root/.cargo/bin/cargo run request "prover-service:8080"
