# 🛡️ Phishing URL Detector

A Python-based cybersecurity tool that analyzes website URLs for common phishing indicators and provides a risk assessment.

The application uses a graphical interface built with Tkinter and evaluates URLs using multiple heuristic security checks.

---

## 📌 Project Overview

Phishing attacks often use deceptive URLs to trick users into visiting malicious websites or sharing sensitive information.

This project provides a simple security analysis tool that checks a URL for several suspicious characteristics and assigns a risk score.

The tool is designed for **educational and cybersecurity learning purposes**.

---

## ✨ Features

- 🔍 URL analysis
- 🔐 HTTPS encryption check
- 📏 URL length analysis
- ⚠️ Suspicious keyword detection
- 🌐 IP address detection
- 🔣 Special character (`@`) detection
- 🌳 Domain structure analysis
- ➖ Domain hyphen detection
- 📊 Risk score from 0–7
- 🟢 Low Risk classification
- 🟠 Suspicious classification
- 🔴 High Risk classification
- 💡 Security recommendations
- 📜 Recent scan history
- 🗑️ Clear scan history
- 🖥️ Dark cybersecurity dashboard interface

---

## 🧠 How It Works

The application analyzes the entered URL using seven security indicators:

| Security Check | Purpose |
|---|---|
| HTTPS Encryption | Checks whether the URL uses HTTPS |
| URL Length | Identifies unusually long URLs |
| Special Character Check | Detects the `@` symbol |
| IP Address Detection | Checks whether an IP address is used instead of a domain |
| Suspicious Keywords | Detects words such as `login`, `verify`, `account`, and `password` |
| Domain Structure | Checks for an unusually high number of dots/subdomains |
| Domain Character Check | Checks for hyphens in the domain |

Each suspicious indicator increases the risk score.

### Risk Classification

- **0–1:** 🟢 Low Risk
- **2–3:** 🟠 Suspicious
- **4–7:** 🔴 High Risk

---

## 🖥️ Interface

The application provides a dark-themed cybersecurity dashboard containing:

- URL input field
- Risk score
- Risk classification
- Detection results
- Security findings
- Recommendation
- Recent scan history

---

## 📸 Screenshots

### Security Assessment

![Security Assessment](Screenshot%20%28117%29.png)

### URL Analysis

![URL Analysis](Screenshot%20%28118%29.png)

### Suspicious URL Detection

![Suspicious URL](Screenshot%20%28119%29.png)

### Main Dashboard

![Main Dashboard](Screenshot%20%28121%29.png)

---

## ⚙️ Technologies Used

- **Python**
- **Tkinter**
- **Regular Expressions**
- **URL Parsing**
- **Basic Cybersecurity Concepts**

No external Python packages are required.

---

## ▶️ How to Run

### 1. Install Python

Download Python from:

https://www.python.org/downloads/

### 2. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/phishing-url-detector.git
