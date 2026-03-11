<style>
	body {
            font-family: "Times New Roman", Times, serif;
        }
</style>
# Implementation and Analysis of AES Modes of Operation

## Author
Name: <Your Name>  
Course: <Course Name>
Subject: CS850 - Network Security   
Instructor: <Instructor Name>  
Date: <Date>

---

# 1. Introduction

Advanced Encryption Standard (AES) is a symmetric block cipher that operates on fixed-size blocks of 128 bits. Since most real-world data is larger than a single block, **modes of operation** are used to securely encrypt sequences of blocks.

This project implements the following AES modes:

- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback)
- CTR (Counter Mode)

Only the AES block cipher is imported using OpenSSL, while all mode logic such as:

- block splitting
- XOR operations
- padding
- chaining
- counters

is implemented manually in C++.

Additionally, the project demonstrates **practical weaknesses of each mode**.

Repository:   **[prithirabha/NetworkSecurityExperiments/03_ModesOfOperations](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations)**

---

# 2. Project Structure

```bash

	.
	├── aes
	│   ├── aes_wrapper.cpp
	│   └── aes_wrapper.hpp
	├── crypto_utils.cpp
	├── crypto_utils.hpp
	├── main.cpp
	├── Makefile
	├── modes
	│   ├── ecb.cpp
	│   ├── ecb.hpp
	│   ├── cbc.cpp
	│   ├── cbc.hpp
	│   ├── cfb.cpp
	│   ├── cfb.hpp
	│   ├── ofb.cpp
	│   ├── ofb.hpp
	│   ├── ctr.cpp
	│   └── ctr.hpp
	├── README.md
	└── REPORT.md

```bash
    
### Directory Description

| Component | Description |
|---|---|
`main.cpp` | Entry point with menu interface |
`crypto_utils.*` | Utility functions (XOR, padding, block handling, hex conversion) |
`aes/` | AES block encryption wrapper using OpenSSL |
`modes/` | Implementations of AES modes of operation |
`Makefile` | Build configuration |
`README.md` | Project documentation |
`REPORT.md` | Detailed project report |

### Modes Implemented

The `modes` directory contains implementations of the five AES modes:

- [ECB (Electronic Codebook)](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/ecb.cpp)
- [CBC (Cipher Block Chaining)](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/cbc.cpp)
- [CFB (Cipher Feedback)](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/cfb.cpp)
- [OFB (Output Feedback)](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/ofb.cpp)
- [CTR (Counter Mode)](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/ctr.cpp)

---


# 3. Utility Functions

The utility module provides core cryptographic helpers:

- XOR of blocks
- PKCS7 padding
- block splitting and merging
- hex conversion utilities

Implementation:  
[crypto_utils.cpp](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/crypto_utils.cpp)

Example utility operation:

```cpp
    result[i] = first_block[i] ^ second_block[i];
````bash
    
---

# 4. AES Block Encryption

AES encryption and decryption of individual blocks is handled through a wrapper around OpenSSL.

Implementation:

[aes_wrapper.cpp](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/aes/aes_wrapper.cpp)

AES operates on:

* Block size: **128 bits (16 bytes)**
* Key size used in project: **AES-128**

---

# 5. AES Modes of Operation

Each mode was implemented manually using AES block encryption.

---

# 5.1 ECB Mode

Implementation:
[modes/ecb.cpp](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/ecb.cpp)

Encryption:

```bash
    Ci = AES(K, Pi)
```bash
    
### Weakness Demonstrated

Pattern leakage.

Example output:

```bash
	ECB Weakness Demonstration
	Plaintext: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	Key: 0123456789012345
	
	Plaintext blocks:
	Block 1: AAAAAAAAAAAAAAAA
	Block 2: AAAAAAAAAAAAAAAA
	Block 3: AAAAAAAAAAAAAAAA
	
	Ciphertext blocks:
	Block 1: e8c1351537a22cfde28bf297f4e1242d
	Block 2: e8c1351537a22cfde28bf297f4e1242d
	Block 3: e8c1351537a22cfde28bf297f4e1242d
	Block 4: 963a216d1799a1e9d15bad1444126f29
```bash
    
Observation:

> Identical plaintext blocks produce identical ciphertext blocks.

---

# 5.2 CBC Mode

Implementation:
[modes/cbc.cpp](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/cbc.cpp)

Encryption:

```bash
    Ci = AES(K, Pi ⊕ Ci−1)
```bash
    
### Demonstrated Weaknesses

* Error propagation
  
Example demonstration:
```bash
	=== CBC Error Propagation Demo ===
	
	Original plaintext:
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	
	Decrypted after corruption:
	AAAAAAAAAAAAAAAA, F[�@�U��N�-*cDAAAA�AAAAAAAAAAA
```bash
    
* Bit-flipping attack

Example demonstration:

```bash
	=== CBC Bit-Flipping Attack Demo ===
	
	Original plaintext:
	role=user;access=limited;
	
	Plaintext after attack:
	role=root;access=limited;
```bash
    
Observation:

> Modifying a ciphertext block alters the decrypted plaintext.

---

# 5.3 CFB Mode

Implementation:
[modes/cfb.cpp](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/cfb.cpp)

Encryption:

```bash
    Ci = Pi ⊕ AES(K, Ci−1)
```bash
    
Characteristics:

* AES encryption used for both encryption and decryption
* Self-synchronizing

### Weakness Demonstrated
* Error Propagation

Example Demonstration:
```bash
	=== CFB Error Propagation Demo ===
	
	Original plaintext:
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	
	Plaintext after corruption:
	AAAAAAAAAAAAAAAAAAAA�AAAAAAAAAAAC��M4 }j�c * �l
```bash
    * Malleability.
```bash
	=== CFB Malleability Demo ===
	
	Original plaintext:
	access=limited;role=user
	
	Plaintext after attack:
	access=limited;role=root
```bash
    

Observation:

> Modifying ciphertext flips corresponding bits in plaintext.

---

# 5.4 OFB Mode

Implementation:
[modes/ofb.cpp](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/ofb.cpp)

Keystream generation:

```bash
    Oi = AES(K, Oi−1)
```bash
    
Encryption:

```bash
    Ci = Pi ⊕ Oi
```bash
    
### Weakness Demonstrated

* Keystream reuse.

Example Demonstration:
```bash
	=== OFB Keystream Reuse Demo ===
	
	Plaintext1:
	attack at dawn!!!!
	
	Plaintext2:
	attack at dusk!!!!
	
	C1 XOR C2 (reveals P1 XOR P2):
	0000000000000000000000140405000000000000000000000000000000000000
	
	C1 XOR C2:
	0000000000000000000000140405000000000000000000000000000000000000
	
	P1 XOR P2:
	000000000000000000000014040500000000
```bash
    
* Malleability
Example demonstration:
```bash
	=== OFB Bit-Flipping Attack Demo ===
	
	Original plaintext:
	role=user;access=limited;
	
	Plaintext after attack:
	role=root;access=limited;
```bash
    
Observation:

> Reusing the same IV results in identical keystreams.

---

# 5.5 CTR Mode

Implementation:
[modes/ctr.cpp](https://github.com/prithirabha/NetworkSecurityExperiments/blob/main/03_ModesOfOperations/modes/ctr.cpp)

Keystream:

```bash
    Oi = AES(K, nonce || counter)
```bash
    
Encryption:

```bash
    Ci = Pi ⊕ Oi
```bash
    
### Weakness Demonstrated

* Nonce reuse.

Example demonstration:
```bash
	=== CTR Nonce Reuse Demo ===
	
	Plaintext1:
	attack at dawn!!!!
	
	Plaintext2:
	attack at dusk!!!!
	
	C1 XOR C2:
	0000000000000000000000140405000000000000000000000000000000000000
	
	P1 XOR P2:
	000000000000000000000014040500000000
```bash
    
* Malleability

Example demonstration:
```bash
	=== CTR Bit-Flipping Attack Demo ===
	
	Original plaintext:
	role=user;access=limited;
	
	Plaintext after attack:
	role=root;access=limited;
```bash
    
Observation:

> Reusing the same nonce causes keystream reuse, revealing relationships between encrypted messages.

---

# 6. Experimental Demonstrations

The program provides demonstrations for:

* ECB pattern leakage
* CBC error propagation & malleability
* CFB error propagation & malleability
* OFB keystream reuse & malleability
* CTR nonce reuse & malleability

These can be accessed through the program's interactive menu.

Example menu:

```bash
	===== AES Modes of Operation =====
	1. ECB
	2. CBC
	3. CFB
	4. OFB
	5. CTR
	0. Exit
	Select mode:
```bash
    
---

# 7. Security Observations

| Mode | Weakness            |
| ---- | ------------------- |
| ECB  | Pattern leakage     |
| CBC  | Error Propagation & Bit-flipping attack |
| CFB  | Error Propagation & Malleability        |
| OFB  | Keystream reuse & Malleability    |
| CTR  | Nonce reuse & Malleability        |

Key insights:

* AES itself is secure, but incorrect mode usage can create vulnerabilities.
* Modes based on XOR operations are **malleable**.
* Reusing IVs or nonces can **break confidentiality**.

---

# 8. Recommendations

# 8. Inputs and Use Cases of AES Modes

## ECB (Electronic Codebook)

### Inputs
- Plaintext
- Encryption key (128-bit AES key)

### Characteristics
- No IV or nonce required
- Each block encrypted independently

### Use Cases
- Rarely used for general data encryption
- Sometimes used internally inside cryptographic constructions
- Useful for demonstrations and testing block ciphers

### Security Note
ECB is **not recommended for real-world data encryption** because it leaks patterns in plaintext.

---

## CBC (Cipher Block Chaining)

### Inputs
- Plaintext
- Encryption key
- Initialization Vector (IV)

### Characteristics
- Each block depends on the previous ciphertext block
- Requires padding for block alignment

### Use Cases
- Secure file encryption
- Disk encryption (older systems)
- SSL/TLS implementations before authenticated encryption modes

### Security Note
IV must be **random and unique** to prevent attacks.

---

## CFB (Cipher Feedback)

### Inputs
- Plaintext
- Encryption key
- Initialization Vector (IV)

### Characteristics
- Converts block cipher into a stream cipher
- Does not require padding

### Use Cases
- Secure communication channels
- Streaming data encryption
- Systems where data arrives in small units

### Security Note
IV reuse weakens security.

---

## OFB (Output Feedback)

### Inputs
- Plaintext
- Encryption key
- Initialization Vector (IV)

### Characteristics
- Generates a keystream independent of plaintext
- Encryption and decryption are identical operations

### Use Cases
- Secure communication over noisy channels
- Environments where error propagation must be minimized

### Security Note
Reusing the same IV results in **keystream reuse attacks**.

---

## CTR (Counter Mode)

### Inputs
- Plaintext
- Encryption key
- Nonce
- Counter value

### Characteristics
- Generates keystream using AES(key, nonce || counter)
- Blocks can be processed in parallel
- No padding required

### Use Cases
- High-performance encryption
- Disk encryption
- Network protocols
- Cloud storage encryption

### Security Note
The nonce must **never be reused with the same key**.


### Recommendations
Secure cryptographic implementations should:

* Avoid ECB mode
* Use random IVs
* Never reuse nonces
* Provide message integrity protection

Modern systems typically use **authenticated encryption** such as:

* [AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
* [ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)

---

# 9. Conclusion

This project demonstrates the implementation of AES modes of operation and highlights how improper usage can lead to significant vulnerabilities.

While AES itself remains cryptographically strong, security depends heavily on the correct design and use of modes of operation.

Understanding these weaknesses is essential for designing secure cryptographic systems.

---

# 10. References

* [NIST SP 800-38A – Recommendation for Block Cipher Modes of Operation](https://doi.org/10.6028/NIST.SP.800-38A)
* [Pearson Publications - Network Security: Private Communications in a Public World, 3rd edition](https://www.pearson.com/en-us/subject-catalog/p/network-security-private-communications-in-a-public-world/P200000000360/9780136643524)
* [OpenSSL Documentation](https://docs.openssl.org/master/)

