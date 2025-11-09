# 🔐 Hybrid Classical Cipher Design and Cryptanalysis

## 🧠 Overview
This project implements a **custom hybrid cipher** that combines **Vigenère** and **Affine** classical encryption techniques into a dual-layer encryption system.  
The design increases resistance to traditional cryptanalysis while preserving efficiency and simplicity.  
It also includes an **attack simulation** using both **frequency analysis** and **known-plaintext attacks** to evaluate real-world resilience.

---

## 📘 Table of Contents
- [Features](#features)
- [Cipher Architecture](#cipher-architecture)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Attack Simulation](#attack-simulation)
- [Security Analysis](#security-analysis)
- [Performance Metrics](#performance-metrics)
- [Future Improvements](#future-improvements)
- [Author](#author)
- [License](#license)

---

## 🚀 Features
- ✅ Dual-layer encryption using **Vigenère → Affine** combination  
- ✅ Supports **A–Z and 0–9** character set (total 36 characters)  
- ✅ Handles **variable-length plaintext** and **10+ character keys**  
- ✅ Includes **encryption**, **decryption**, and **attack simulation**  
- ✅ Implements both **frequency analysis** and **known-plaintext** attacks  
- ✅ Efficient with **O(n)** time complexity for encryption/decryption  

---

🧩 Cipher Architecture
Plaintext → Vigenère → Intermediate Text → Affine → Ciphertext
Ciphertext → Affine⁻¹ → Intermediate Text → Vigenère⁻¹ → Plaintext


Stage 1: **Vigenère Cipher**
- Provides polyalphabetic substitution  
- Reduces frequency concentration  
- Formula: `(P + K) mod 38`

Stage 2: **Affine Cipher**
- Adds mathematical transformation  
- Destroys repeating Vigenère patterns  
- Formula: `(a × x + b) mod 38`

---

⚙️ How It Works
Example:
Plaintext: HASNAIN RAZA KHAN
Vigenère Key: CRYPTOCIPHER
Affine Key: a = 5, b = 8

Ciphertext: OGXZGYPCTDVQBAP
Decrypted: HASNAIN RAZA KHAN

🖥️ Usage
Encrypt a Message
from custom_cipher import CustomCipher
cipher = CustomCipher(vigenere_key="CRYPTOCIPHER", affine_key=(5, 8))
ciphertext = cipher.encrypt("HELLO WORLD 123")
print("Ciphertext:", ciphertext)

Decrypt a Message
decrypted = cipher.decrypt(ciphertext)
print("Decrypted:", decrypted)

🔍 Attack Simulation
1. Frequency Analysis Attack
Analyzes ciphertext letter frequencies
Compares with English distribution
Result: Failed — distribution nearly uniform

2. Known-Plaintext Attack
Attacker knows part of plaintext and ciphertext
Brute-forces all 684 valid (a, b) pairs
Result: Successful — full key recovery in milliseconds

🧮 Security Analysis
Attack Method	Resistance	Reason
Frequency Analysis	🔒 High	Flattened by Vigenère, scrambled by Affine
Kasiski Examination	🔒 High	Affine breaks repeating key patterns
Known-Plaintext	⚠️ Low	Small affine key space
Ciphertext-Only	⚙️ Medium	Statistical flattening makes direct analysis difficult
⚡ Performance Metrics
Operation	Average Time	Complexity	Throughput
Encryption	0.15 ms	O(n)	~166,000 chars/sec
Decryption	0.18 ms	O(n)	~138,000 chars/sec
Attack (known-plaintext)	<100 ms	O(684 × n)	-

Memory Usage: ~50 KB (constant)

🔧 Future Improvements
Expand character set to include symbols and punctuation (mod 64)
Add transposition stage for diffusion
Use dynamic affine parameters per character
Introduce key derivation and padding for randomness
Increase minimum key length to 20 characters

👨‍💻 Author

Hasnain Raza Khan
Cybersecurity Student — Karachi, Pakistan
Email: [hasnainrazahrk1@gmail.com]
GitHub: github.com/Hasnain-raza1

📜 License

This project is released under the MIT License — feel free to use and modify it for academic or educational purposes.
Note: This cipher is for educational and research use only. It is not secure for real-world encryption.



