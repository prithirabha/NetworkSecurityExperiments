# AES Modes of Operation

Implementation and experimentation with multiple **AES block cipher modes of operation** using **OpenSSL's libcrypto** in C++.

This project demonstrates the behavior, requirements, and weaknesses of common AES modes.

---

## Table of Contents
- [Overview](#overview)
- [Implemented Modes](#implemented-modes)
- [Security Experiments](#security-experiments)
- [Mode Inputs](#mode-inputs)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Project Structure](#project-structure)
- [Clean Build](#clean-build)

---

## Overview

This project implements several **AES encryption modes** and demonstrates their **security properties, weaknesses, and practical considerations**.

Each mode is implemented using OpenSSL primitives and evaluated through experiments illustrating known vulnerabilities.

---

## Implemented Modes

The following AES modes are implemented:

- **ECB** — Electronic Codebook  
- **CBC** — Cipher Block Chaining  
- **CFB** — Cipher Feedback  
- **OFB** — Output Feedback  
- **CTR** — Counter Mode  

---

## Security Experiments

The following cryptographic behaviors are demonstrated:

- **ECB:** Pattern leakage
- **CBC:** Error propagation and bit-flipping attack
- **CFB:** Error propagation and malleability
- **OFB:** Keystream reuse and malleability
- **CTR:** Nonce reuse and malleability

---

## Mode Inputs

| Mode | Required Inputs |
|-----|----------------|
| ECB | plaintext, key |
| CBC | plaintext, key, IV |
| CFB | plaintext, key, IV |
| OFB | plaintext, key, IV |
| CTR | plaintext, key, nonce, counter |

---

## Prerequisites

Ensure the following tools are installed:

- **C++ compiler with C++23 support** (e.g., `g++`)
- **Make**
- **OpenSSL development libraries (`libcrypto`)**

### Ubuntu / Debian

```bash
sudo apt install build-essential make libssl-dev
````

### Arch

```bash
sudo pacman -S base-devel openssl
```

### macOS (Homebrew)

```bash
brew install openssl
```

---

## Build Instructions

Compile the project using `make`:

```bash
make
```

This will generate the executable:

```
aes_modes
```

Run it with:

```bash
./aes_modes
```

---

## Project Structure

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

## Clean Build

Remove the compiled binary:

```bash
make clean
```