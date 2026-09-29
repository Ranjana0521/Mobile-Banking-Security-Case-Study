# SecureBank: Mobile Banking Security Case Study
## College Viva Presentation Guide & Cryptographic Specification

---

### Project Overview
* **Title:** Cryptographic Architecture for Mobile Banking Security
* **Problem Statement:** *Secure mobile banking applications against malware, phishing, and unauthorized transactions.*
* **Target Audience:** College Examination Panel, Project Evaluators, Cybersecurity & Cryptography Course Reviewers.
* **Technology Stack:** Python 3 (Flask), Cryptography HAZMAT (`AESGCM`), Scrypt (`hashlib.scrypt`), HMAC-SHA256 (`hmac`), Vanilla CSS3 (Custom Cyber-Fintech Glassmorphism Design System), Modern Vanilla JS (Real-Time Typing Listeners, WebCrypto, Event-Driven Risk Engine), SQLite3 (ACID-compliant with secure deletion).

---

## 1. Problem Statement Mapping & Solution Architecture

| Threat Vector (From Problem Statement) | Attack Vector in Mobile Banking | Proposed Engineering & Cryptographic Solution | Real-Time UI Demonstration |
| :--- | :--- | :--- | :--- |
| **1. Mobile Malware** | Accessibility Service abuse (TeaBot, SharkBot), Keyloggers, Floating overlay windows, Frida dynamic hooking, Root compromise | • **Anti-Keylogger Scrambled Keypad:** Dynamic Fisher-Yates randomization of digit coordinates.<br>• **RASP (Runtime Application Self-Protection):** Root & hook detection simulation.<br>• **Anti-Overlay Shield:** Prevents tap-jacking overlays. | In Mobile App: Toggle "Anti-Malware Scrambled Keypad".<br>In Attack Lab: Click "Simulate Trojan Hook Injection" and watch RASP trigger instantly. |
| **2. Phishing & Spoofing** | Cloned banking portals, SMS smishing links, homoglyph typosquatting, MITM proxies | • **Mutual Visual Authentication:** Unique server-held personal secret badge (e.g. *🛡️ Emerald Falcon*) rendered only on genuine sessions.<br>• **SSL/TLS Public Key Pinning:** SHA-256 certificate fingerprint verification.<br>• **Real-Time Phishing Link Scanner:** Evaluates domain entropy, punycode lookalikes, IP hosts. | In App Bar: Anti-phishing badge proves genuine bank domain.<br>In Attack Lab: Test suspicious URLs live; inspect heuristic score & homoglyph alerts. |
| **3. Unauthorized Transactions** | Session hijacking, replay attacks, database tampering / ciphertext bit-flipping, balance spoofing | • **AES-256-GCM AEAD:** Authenticated encryption at rest with 96-bit random nonce & 128-bit GHASH tag.<br>• **Transaction-Bound HMAC-SHA256 OTP:** One-time code cryptographically tied to recipient, amount, and timestamp.<br>• **Tamper-Evident SHA-256 Ledger:** Blockchain-style Merkle chaining.<br>• **Adaptive Risk Scoring Engine:** Real-time screening of velocity and amounts $\ge ₹2,000$. | While typing amount: Real-time risk gauge adjusts.<br>When transfer initiates: Simulated push notification slides down on phone with live 180s countdown.<br>In Attack Lab: "Simulate 1-Bit Ciphertext Flip" shows `InvalidTag` rejection! |

---

## 2. Mathematical & Cryptographic Specifications

### A. Scrypt Password Key Derivation Function (RFC 7914)
Standard hashes (MD5, SHA-1, SHA-256) are computationally lightweight, allowing modern GPU/ASIC clusters to test billions of guesses per second. SecureBank employs **Scrypt**:
$$\text{Key} = \text{scrypt}(P, S, N=16384, r=8, p=1, dklen=32)$$
* **$P$:** Plaintext password string.
* **$S$:** 16-byte cryptographically secure pseudorandom salt (`secrets.token_bytes(16)`).
* **$N = 2^{14} = 16,384$:** CPU/memory cost parameter (requires sequential memory lookups).
* **$r = 8$:** Block size parameter (1024 bytes per block).
* **$p = 1$:** Parallelization parameter.
* **Memory Requirement:** $128 \times r \times N \approx 16 \text{ MB}$ RAM per derivation attempt. This memory-hard barrier prevents parallel execution on hardware cracking rigs.

### B. AES-256-GCM Authenticated Encryption (NIST SP 800-38D)
Transaction details stored in the database must guarantee both **Confidentiality** (malware with root storage access cannot read data) and **Integrity** (malware cannot manipulate amounts or recipients):
$$\text{Ciphertext, AuthTag} = \text{AES-GCM-Encrypt}(K_{256}, \text{Nonce}_{96}, \text{Plaintext}, \text{AAD})$$
* **Key ($K$):** 256-bit symmetric key (`AESGCM`).
* **Nonce:** 96-bit (12-byte) cryptographically unique random nonce per transaction (`secrets.token_bytes(12)`). Prevents replay and key-stream reuse.
* **Authentication Tag:** 128-bit (16-byte) GHASH polynomial authentication tag.
* **Tamper Proof:** If an attacker modifies even a single bit in the ciphertext, the decryption algorithm fails the GHASH verification equation and throws `cryptography.exceptions.InvalidTag`. The system terminates decryption and triggers an unauthorized transaction alert.

### C. Dynamic Transaction-Bound HMAC-SHA256 OTP (RFC 2104)
Standard OTPs verify only identity, not transaction intent. SecureBank cryptographically binds the verification code:
$$\text{Tag} = \text{HMAC-SHA256}(K_{\text{OTP}}, \text{Salt} \parallel \text{OTP} \parallel \text{User} \parallel \text{Recipient} \parallel \text{Amount} \parallel \text{Timestamp})$$
* **Constant-Time Verification:** Verified using `hmac.compare_digest(A, B)` to eliminate side-channel timing attacks.
* **180-Second Expiration:** Stored with an epoch expiration timestamp.
* **Brute-Force Lockout:** Limited to 5 attempts before the pending transfer is purged.

### D. Tamper-Evident SHA-256 Chained Audit Ledger
Every completed transaction $i$ forms a block chained to the previous block $i-1$:
$$H_0 = \text{Genesis Hash} = \text{000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f}$$
$$H_i = \text{SHA-256}(H_{i-1} \parallel \text{tx\_id} \parallel \text{user\_id} \parallel \text{EncryptedRecord}_{\text{hex}} \parallel \text{Status})$$
* Clicking **"Verify Entire Ledger Chain"** traverses all blocks from $0 \dots N$ and recalculates every hash. Any unauthorized row insertion, modification, or deletion breaks the chain at that exact index.

---

## 3. Step-by-Step Viva Presentation Walkthrough (Demo Script)

### Step 1: Open the Application (Landing Page)
1. Navigate to `http://127.0.0.1:5000`.
2. **Explain to Evaluator:**
   > *"Good morning professors. This project implements a secure mobile banking architecture directly addressing the case study: protecting against malware, phishing, and unauthorized transactions. Here on the landing page, we showcase the three core threat mitigation pillars and an interactive real-time cryptographic playground."*
3. Type any text in the **Interactive Cryptographic Playground** at the bottom to demonstrate real-time Scrypt derivation and AES-256-GCM 96-bit nonce + 128-bit tag generation.

### Step 2: Authentication & Anti-Phishing Secret Phrase
1. Click **Sign In** or **Open Demo Account**.
2. Point out the **Mutual Authentication Banner**:
   > *"To protect against phishing and rogue clone websites, SecureBank uses mutual visual authentication. Each user selects a personal security phrase and emblem at enrollment. If this badge does not appear, or the SSL pinning fails, the user knows they are on a fake phishing portal."*
3. Type into the password field: show the **Real-Time Password Entropy Meter** updating dynamically (calculating Shannon entropy in bits based on character pool diversity).
4. Click **"Anti-Keylogger Keypad"**: show the randomized scrambled numeric keypad.
5. Click **"User: Ranjana"** (preloaded account) and hit **"Sign In Securely"**.

### Step 3: Mobile Banking Smartphone Interface
1. Once on `/dashboard`, show the left column:
   > *"Here on the left, we built a high-fidelity mobile device simulator representing the customer's mobile banking app. Notice the holographic platinum card, masked account number, live balance (₹4,000), and the anti-phishing secret badge (🛡️ Emerald Falcon)."*
2. Click the eye icon next to the balance to toggle privacy masking.

### Step 4: Real-Time Risk Engine Demonstration
1. In the **Make a Transfer** card:
   - Type recipient: `Aly`.
   - In amount, type `100`: The gauge indicates **LOW RISK (10/100)**.
   - Now type `2500`: The gauge instantly turns red: **HIGH RISK (85/100)** with explanation: *"Amount ≥ ₹2,000 triggers strict demo risk review rule."*
   - Set amount back to `150.00` and click **"Review & Request One-Time Code"**.

### Step 5: Real-Time Mobile Push Notification & Dynamic OTP
1. Watch the top of the smartphone screen:
   > *"Notice the high-priority simulated push notification sliding down onto the smartphone screen with the 6-digit OTP and an active 180-second countdown timer."*
2. Click **[Auto-Fill Code]**: the 6 individual digit boxes automatically populate.
3. Click **"Verify & Complete Transfer"**.
4. The transfer completes, the balance updates to ₹3,850.00, and the transaction is encrypted and recorded.
5. Click **"Inspect Cipher"** on the recent transaction to show the raw 96-bit nonce, AES ciphertext, and 16-byte GHASH tag stored in SQLite.

### Step 6: Attack & Threat Simulation Lab (The Evaluator's Favorite!)
Switch to the **Threat & Attack Simulation Lab** tab on the right:
1. **Malware Vector:** Click **"Simulate Trojan Hook Injection"**:
   - The device telemetry immediately flags: `⚠️ COMPROMISED (HOOK/OVERLAY DETECTED)`.
   - The RASP engine log displays the blocked Accessibility Service attack.
   - The anti-keylogger scrambled keypad is automatically enforced.
2. **Phishing Vector:** Click **"Scan URL Live"** with a test URL (e.g. `http://secure-bαnk-verify.xyz/login`):
   - The heuristic engine detects the Cyrillic homoglyph, non-standard TLD, and SSL certificate pinning mismatch, rating it as a High-Threat Phishing attack.
3. **Unauthorized Vector (Ciphertext Bit-Flipping):** Click **"Simulate 1-Bit Ciphertext Flip"**:
   - The system flips 1 bit in the encrypted transaction blob and attempts decryption.
   - Show the result: `cryptography.exceptions.InvalidTag` is caught live!
   - Explain: *"This proves that even if an attacker alters the encrypted amount in the database or during transmission, AES-256-GCM authentication detects the tampering mathematically and rejects the unauthorized transaction."*

### Step 7: Tamper-Evident SHA-256 Chained Ledger
1. Click the **Tamper-Evident Ledger** tab.
2. Show the visual blockchain-like chain of transaction blocks.
3. Click **"Verify Entire Ledger Chain"**:
   - The backend re-hashes all blocks sequentially and confirms: *"✓ 100% Cryptographic Integrity Verified: Zero unauthorized injections or modifications detected."*

---

## 4. Key Questions & Viva Defense Answers

**Q1: Why is Scrypt preferred over SHA-256 or bcrypt for mobile banking authentication?**
> *Answer:* Standard SHA-256 can be computed at gigahash speeds on modern graphics cards (GPUs) and ASICs. Bcrypt is memory-harder than SHA-256, but its memory requirement is capped at 4 KB. Scrypt allows configuring CPU/Memory cost parameters ($N=16384, r=8$), requiring $\approx 16 \text{ MB}$ of high-speed RAM per attempt. This makes massive parallel cracking clusters economically and hardware-wise infeasible.

**Q2: What is the difference between AES-CBC and AES-GCM? Why is AES-GCM critical for banking?**
> *Answer:* AES-CBC provides confidentiality only, but no cryptographic integrity. In CBC mode, an active attacker can perform bit-flipping attacks to alter transaction amounts without knowing the key. AES-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher. It computes a 128-bit GHASH authentication tag over the ciphertext and nonce. If even one bit is changed, the tag verification equation fails and decryption throws `InvalidTag`.

**Q3: How does the randomized scrambled keypad defeat mobile trojans?**
> *Answer:* Banking trojans like TeaBot and SharkBot abuse Android Accessibility Services to read touchscreen tap coordinates $(x, y)$. If the keypad is static, $(150, 420)$ always maps to digit '5'. By randomizing the 0–9 keypad layout using the Fisher-Yates shuffle on every interaction, coordinate-based keylogging is completely blinded.

**Q4: How does mutual visual authentication stop credential phishing?**
> *Answer:* Phishing sites can copy logos and styling, but they cannot predict the user's secret phrase (e.g. *🛡️ Emerald Falcon*) stored solely in the bank's database before the user types their credentials. When an authentic server loads, it presents the secret badge. If the user does not see their chosen phrase, they immediately identify the site as an unauthorized fake.
