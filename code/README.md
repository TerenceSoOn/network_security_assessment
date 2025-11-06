# Implementation Code

This folder contains the implementation code for demonstrating attacks on Diffie-Hellman and RSA protocols.

## Files

- `rsa_utils.py` - Helper functions for RSA key generation (prime testing, modular inverse, etc.)
- `dh_exchange.py` - Implementation of Diffie-Hellman protocol, MitM attack, and authentication defense
- `rsa_attacks.py` - Implementation of RSA timing attack and blinding defense

## Requirements

- Python 3.8 or higher
- No external libraries required (uses only standard library)

## How to Run

### 1. Diffie-Hellman Exchange and MitM Attack

```bash
python3 dh_exchange.py
```

### 2. RSA Timing Attack and Blinding Defense

```bash
python3 rsa_attacks.py
```
