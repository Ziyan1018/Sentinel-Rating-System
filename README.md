# Sentinel-Rating-System
Prototype code for dissertation: Sentinel——A Decentralized Rating System with a Cryptographic Authentication Mechanism
# Sentinel – Decentralized Rating System (Prototype Code)

This repository contains the prototype code accompanying the dissertation:

> **Sentinel: A Decentralized Rating System with a Cryptographic Authentication Mechanism**

It includes two main components:

- `sentinel_implementation.html` – Browser-based prototype implementation (Implementation chapter)  
- `experiment.py` – Python simulation script (Experiments chapter)  

---

##  1. Implementation Prototype (`sentinel_implementation.html`)

A browser-based JavaScript prototype that demonstrates the key mechanisms described in the dissertation:

- Ed25519 key generation and persistent storage in the client  
- DID-style representation of public keys (`did:key`)  
- Construction of rating events with metadata and SHA-256 content hash  
- Event signing and verification using Ed25519  
- Example relay transmission via WebSocket (illustrative only)  

### How to run
1. Download `sentinel_implementation.html`.  
2. Open it in a modern browser (Chrome/Edge).  
3. Open **Developer Tools → Console**.  

### Outputs include
- Public key in hex format  
- DID identifier (`did:key:...`)  
- Constructed rating event object  
- Signed event with `sig` field  
- Verification result (`true` if signature is valid)  

*Note:* The relay connection uses `wss://relay.example.org` as an example endpoint.  
It is not functional; the dissertation focuses on authentication rather than relay storage.  

---

##  2. Experiment Script (`experiment.py`)

Python-based simulation used in the dissertation’s **Experiments** chapter.  
It evaluates verification reliability under different adversarial scenarios.  

### Features
- Generates synthetic rating events (legitimate + malicious)  
- Implements three adversarial models:
  - Forged signatures  
  - Tampered content  
  - Forged public keys  
- Verifies events using Ed25519 (PyNaCl)  
- Computes accuracy, precision, recall, F1-score  
- Produces detection rate tables and confusion matrices  

### How to run
1. Install dependencies:
   ```bash
   pip install pynacl faker scikit-learn matplotlib seaborn
2. Run the script
   python experiment.py

Output Include:
Console logs with accuracy, precision, recall, F1
Detection rate tables under varying malicious event ratios
