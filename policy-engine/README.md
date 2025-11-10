# Adaptive Cryptographic Confidential Computing Framework (ACCCF)

This project implements a secure pipeline for classifying, encrypting, and processing sensitive data using adaptive cryptographic policies and simulated trusted execution.

## Features
- AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305 encryption
- Key management using Azure Key Vault
- Secure blob storage with Azure
- Confidential VM emulation via environment validation
- PII keyword scanning in protected memory

## Setup
1. Clone the repo
2. Install dependencies: `pip install -r requirements.txt`
3. Add `.env` file with Azure credentials
4. Upload a 32-byte master key to Azure Key Vault
5. Run: `python main.py`

## Requirements
- Python 3.11+
- Azure for Students subscription
- VS Code / CLI access to Azure
