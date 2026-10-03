# OWASP Juice Shop - Secure Login Feature & Dual-Layer Validation

[![Node.js](https://img.shields.io/badge/Node.js-v18+-green.svg)](https://nodejs.org)
[![Security](https://img.shields.io/badge/Security-OWASP%20Top%2010%20Mitigations-blue.svg)](https://owasp.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Course:** CS 477 - Information Security  
**Assignment:** HW 2-B: OWASP Juice Shop / OWASP Top 10  
**Author:** Owen Zhang  
**Repository:** [https://github.com/owenzhang04/owasp-juice-shop-login](https://github.com/owenzhang04/owasp-juice-shop-login)

---

## 📌 Project Overview

This project implements a secure login module inspired by the UI/UX of **OWASP Juice Shop**. It demonstrates defensive software engineering principles by enforcing strict **dual-layer validation** (client-side and server-side), secure password hashing using salted cryptographic key derivation (`scrypt` / `bcrypt`), parameterized lookup architecture immune to SQL Injection (SQLi), and strict output handling preventing Cross-Site Scripting (XSS).

---

## 🔒 Security Architecture & Features

### 1. Client-Side Validation (`public/app.js`)
- **Non-Empty Checks:** Rejects blank submissions instantly before network requests are dispatched.
- **Email Syntax Validation:** Ensures the email field contains the mandatory `@` symbol and conforms to expected structure.
- **Password Length Enforcement:** Rejects passwords under 8 characters (`password.length >= 8`).
- **XSS Defense:** Dynamically updates error feedback and alerts using `textContent` instead of dangerous sinks like `innerHTML`.

### 2. Server-Side Validation & Defense (`server.js`)
- **Zero-Trust Validation:** Never relies solely on front-end checks. Re-validates all parameters on the backend to defend against direct API exploitation (e.g., via `curl` or Postman).
- **SQL Injection Prevention:** Implements parameterized matching. User input is treated strictly as literal data, preventing query structure tampering.
- **Secure Password Hashing:** Uses salted cryptographic key derivation (`scrypt` / `PBKDF2` / `bcrypt`), eliminating vulnerability to plaintext exposure and precomputed rainbow tables.
- **Timing Attack Resistance:** Employs `crypto.timingSafeEqual` for constant-time hash comparisons.
- **HTTP Security Headers:** Transmits `Content-Security-Policy (CSP)`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `X-XSS-Protection`.

---

## 🚀 Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (version 18 or newer)
- No third-party dependencies required (built using standard library for maximum reliability)

### Installation & Execution

1. **Clone the repository:**
   ```bash
   git clone https://github.com/owenzhang04/owasp-juice-shop-login.git
   cd owasp-juice-shop-login
   ```

2. **Start the server:**
   ```bash
   npm start
   # or directly:
   node server.js
   ```

3. **Open the application:**
   Navigate to [http://localhost:3000](http://localhost:3000) in your web browser.

4. **Run automated security test suite:**
   ```bash
   npm test
   ```

---

## 🧪 Demo Accounts & Test Payloads

### Legitimate Credentials
| Role | Email | Password |
|---|---|---|
| Administrator | `admin@juice-sh.op` | `AdminPass123!` |
| Standard User | `user@juice-sh.op` | `RegularUser2026!` |

### Security Exploit Tests (Part 3)
1. **SQL Injection Attempt:**
   - **Payload:** `' OR 1=1 --`
   - **Result:** Intercepted at client-side because it lacks `@`. Even if sent directly via `curl`, the backend validator rejects malformed email and executes parameterized comparison, returning HTTP 400/401.
2. **Cross-Site Scripting (XSS) Attempt:**
   - **Payload:** `<script>alert('XSS')</script>@juice-sh.op`
   - **Result:** Rendered safely as plain text via `textContent` and protected by CSP headers; no script executes.

---

## 📂 Project Directory Structure

```
cs477-hw2b/
├── public/
│   ├── index.html        # Responsive Juice Shop themed login interface
│   ├── style.css         # Modern styling mimicking Juice Shop color scheme
│   └── app.js            # Client-side input validation and safe DOM updates
├── server.js             # HTTP server with server-side validation & auth
├── test.js               # Automated security & validation test suite
├── package.json          # Project metadata and run scripts
├── README.md             # Project documentation and instructions
└── screenshots/          # Exploit attempt documentation and screenshots
```

---

## 📜 License
This project is licensed under the MIT License.
