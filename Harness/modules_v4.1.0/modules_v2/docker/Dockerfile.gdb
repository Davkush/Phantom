# Dockerfile.gdb — GDB pour extraction mémoire (module 4).
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb python3 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /harness
