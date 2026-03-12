# Modes Of Operations

## Implemented Modes

The following AES modes of operation were implemented:

- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback)
- CTR (Counter Mode)

## Experiments Performed

The following security properties and weaknesses were demonstrated:

- ECB Pattern leakage
- CBC Error Propagation & Bit-flipping attack
- CFB Error Propagation & Malleability
- OFB Keystream reuse & Malleability
- CTR Nonce reuse & Malleability

## Inputs Identified

The required inputs for each mode were analyzed:

| Mode | Inputs |
|-----|------|
ECB | plaintext, key |
CBC | plaintext, key, IV |
CFB | plaintext, key, IV |
OFB | plaintext, key, IV |
CTR | plaintext, key, nonce, counter |

## Use Cases Identified

Typical use cases for each mode were documented in the report.