# Phishing Email Detection System (Python)

A rule-based phishing email detection system built using Python.  
This project analyzes emails and classifies them as **SAFE**, **SUSPICIOUS**, or **PHISHING** using heuristic scoring.

Designed for cybersecurity beginners and students to understand how phishing detection works internally.

---

## 🔍 Features

- Rule-based phishing detection
- Risk scoring system
- Detects:
  - Urgency language
  - Credential harvesting attempts
  - Malicious links (HTTP, IP-based, shortened URLs)
  - Domain spoofing
  - Suspicious sender patterns
- Multi-line email body input
- CLI and GUI (Tkinter) support
- CSV logging for scan history
- Modular & reusable detection function

---

## 🧠 Detection Logic

Each email is scored based on indicators:

| Indicator | Risk Points |
|---------|-------------|
| Urgency words | +1 |
| Credential request | +3 |
| HTTP link | +2 |
| IP-based URL | +4 |
| URL shortener | +3 |
| Too many links | +2 |
| Domain spoofing | +3 |
| Numeric domain | +2 |
| Suspicious structure | +1 |

### Verdict Logic:
- **SAFE** → Score < 4  
- **SUSPICIOUS** → Score 4–7  
- **PHISHING** → Score ≥ 8  

---

## 🛠️ Tech Stack

- Python 3
- Regex (`re`)
- CSV logging
- Tkinter (GUI)
- CLI-based input handling

---

## 🚀 How to Run

```bash
python detector.py
