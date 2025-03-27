# syntax=docker/dockerfile:1.7

FROM archlinux:base-devel 
ARG TARGETARCH

COPY --link ./test-staging .
EXPOSE 4444

RUN pacman -Syy && \
    pacman -S --noconfirm python

CMD python3 -m http.server 4444
