# ---------- build stage ----------
FROM debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y build-essential libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN make


# ---------- runtime stage ----------
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y libssl3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/aes_modes .

CMD ["./aes_modes"]