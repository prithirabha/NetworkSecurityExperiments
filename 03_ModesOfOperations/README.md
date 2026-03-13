# AES Modes of Operation

![C++23](https://img.shields.io/badge/C%2B%2B-23-blue?logo=cplusplus)
![OpenSSL](https://img.shields.io/badge/OpenSSL-libcrypto-green?logo=openssl)
![Build](https://img.shields.io/badge/build-make-orange?logo=gnu)
![Docker](https://img.shields.io/badge/docker-supported-2496ED?logo=docker&logoColor=white)

Implementation and experimentation with multiple **AES block cipher modes of operation** using **OpenSSL's libcrypto** in C++.

This project demonstrates the behavior, requirements, and weaknesses of common AES modes.

---

## Table of Contents

* [Overview](#overview)
* [Implemented Modes](#implemented-modes)
* [Security Experiments](#security-experiments)
* [Mode Inputs](#mode-inputs)
* [Prerequisites](#prerequisites)

  * [System Dependencies](#system-dependencies)
  * [Install Dependencies](#install-dependencies)
* [Build Instructions](#build-instructions)

  * [Run the Program](#run-the-program)
* [Docker (Optional)](#docker-optional)

  * [Prerequisites](#docker-prerequisites)
  * [Build the Image](#build-the-image)
  * [Run with Docker Compose](#run-with-docker-compose)
* [Project Structure](#project-structure)
* [Clean Build](#clean-build)

---

## Overview

This project implements several **AES encryption modes** and demonstrates their **security properties, weaknesses, and practical considerations**.

Each mode is implemented using OpenSSL primitives and evaluated through experiments illustrating known vulnerabilities.

---

## Implemented Modes

The following AES modes are implemented:

* **ECB** — Electronic Codebook
* **CBC** — Cipher Block Chaining
* **CFB** — Cipher Feedback
* **OFB** — Output Feedback
* **CTR** — Counter Mode

---

## Security Experiments

The following cryptographic behaviors are demonstrated:

* **ECB:** Pattern leakage
* **CBC:** Error propagation and bit-flipping attack
* **CFB:** Error propagation and malleability
* **OFB:** Keystream reuse and malleability
* **CTR:** Nonce reuse and malleability

---

## Mode Inputs

| Mode | Required Inputs                |
| ---- | ------------------------------ |
| ECB  | plaintext, key                 |
| CBC  | plaintext, key, IV             |
| CFB  | plaintext, key, IV             |
| OFB  | plaintext, key, IV             |
| CTR  | plaintext, key, nonce, counter |

---

# Prerequisites

## System Dependencies

Ensure the following tools are installed:

* **C++ compiler with C++23 support** (e.g., `g++`)
* **Make**
* **OpenSSL development libraries (`libcrypto`)**

## Install Dependencies

### Ubuntu / Debian

```bash
sudo apt install build-essential make libssl-dev
```

### Arch

```bash
sudo pacman -S base-devel openssl
```

### macOS (Homebrew)

```bash
brew install openssl
```

---

# Build Instructions

Compile the project using `make`:

```bash
make
```

This will generate the executable:

```
aes_modes
```

## Run the Program

```bash
./aes_modes
```

The program runs **interactively** and will prompt for the required inputs depending on the selected AES mode.

---

# Docker (Optional)

You may optionally run the project inside Docker instead of installing dependencies locally.

## Docker Prerequisites

Install the following tools if they are not already available:

* **Docker Engine** – https://docs.docker.com/engine/install/
* **Docker Compose (v2+)** – https://docs.docker.com/compose/

Verify installation:

```bash
docker --version
docker compose version
```

## Build the Image

```bash
docker compose build
```

## Run with Docker Compose

```bash
docker compose run --rm aes-modes
```

This will:

1. Start an interactive container
2. Run `make clean`
3. Rebuild the project
4. Launch the `aes_modes` program

No cleanup is required because the container is automatically removed.

---

# Project Structure

```
.
├── Makefile
├── README.md
├── main.cpp
├── crypto_utils.cpp
├── aes/
│   └── aes_wrapper.cpp
└── modes/
    ├── ecb.cpp
    ├── cbc.cpp
    ├── cfb.cpp
    ├── ofb.cpp
    └── ctr.cpp
```

---

# Clean Build

Remove the compiled binary:

```bash
make clean
```
