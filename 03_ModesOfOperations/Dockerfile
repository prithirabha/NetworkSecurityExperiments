FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        make \
        g++ \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

CMD bash -c "make clean && make && ./aes_modes"
