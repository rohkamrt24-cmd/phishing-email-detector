import re
import csv
import tkinter as tk
from tkinter import messagebox

# ===== CONFIG =====
DEBUG = True  # Set to False to disable debug prints
trusted_brands = ["paypal", "google", "amazon", "bank"]

# ===== HELPER FUNCTION =====
def debug(msg):
    if DEBUG:
        print("[DEBUG]", msg)

# ===== CORE DETECTION FUNCTION =====
def analyze_email(subject, body, sender):
    subject = subject.lower()
    body = body.lower()
    sender = sender.lower()

    score = 0
    reasons = []

    # Urgency detection
    urgency_words = ["urgent", "immediately", "act now", "verify", "suspended", "limited time", "warning"]
    for word in urgency_words:
        if word in subject or word in body:
            score += 1
            reasons.append(f"Urgency word detected: '{word}'")
            debug(f"Urgency detected (+1): {word}")

    # Credential request detection
    credential_words = ["password", "otp", "pin", "login", "verify account", "update details"]
    for word in credential_words:
        if word in body:
            score += 3
            reasons.append(f"Credential request detected: '{word}'")
            debug(f"Credential request detected (+3): {word}")

    # Link detection
    links = re.findall(r'(https?://\S+)', body)
    shorteners = ["bit.ly", "tinyurl", "goo.gl"]
    for link in links:
        if link.startswith("http://"):
            score += 2
            reasons.append("Insecure HTTP link used")
            debug("Insecure HTTP link (+2) detected")
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
            score += 4
            reasons.append("IP-based URL detected")
            debug("IP-based URL (+4) detected")
        for short in shorteners:
            if short in link:
                score += 3
                reasons.append("Shortened URL detected")
                debug(f"Shortened URL (+3) detected: {link}")
    if len(links) > 2:
        score += 2
        reasons.append("Too many links in email")
        debug("Too many links (+2) detected")

    # Sender domain checks
    if "@" in sender:
        domain = sender.split("@")[1]
        for brand in trusted_brands:
            if brand in domain and domain != f"{brand}.com":
                score += 3
                reasons.append(f"Possible domain spoofing of {brand}")
                debug(f"Domain spoofing detected (+3): {domain}")
        if any(char.isdigit() for char in domain):
            score += 2
            reasons.append("Sender domain contains numbers")
            debug("Domain contains numbers (+2)")
        if domain.count(".") > 2:
            score += 1
            reasons.append("Suspicious sender domain structure")
            debug("Suspicious domain structure (+1)")

    # Text formatting checks
    if body.isupper():
        score += 1
        reasons.append("Email body written in ALL CAPS")
        debug("ALL CAPS detected (+1)")
    if body.count("!!!") >= 1:
        score += 1
        reasons.append("Excessive exclamation marks detected")
        debug("Exclamation marks detected (+1)")

    # Verdict
    if score >= 8:
        verdict = "PHISHING"
    elif score >= 4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return verdict, score, reasons

# ===== CLI INPUT FUNCTION =====
def cli_input():
    subject = input("Enter email subject: ")
    print("Enter email body (type END on a new line to finish):")
    body_lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        body_lines.append(line)
    body = " ".join(body_lines)
    sender = input("Enter sender email: ")
    return subject, body, sender

# ===== CLI EXECUTION =====
def run_cli():
    subject, body, sender = cli_input()
    verdict, score, reasons = analyze_email(subject, body, sender)

    print(f"\nVerdict: {verdict}")
    print(f"Risk Score: {score}")
    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(f"- {r}")
    else:
        print("\nNo suspicious indicators found.")

    # CSV Logging
    with open("scan_report.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([subject, sender, verdict, score, "; ".join(reasons)])

# ===== GUI VERSION =====
def run_gui():
    def on_analyze():
        subject = subject_entry.get()
        body = body_text.get("1.0", tk.END)
        sender = sender_entry.get()
        verdict, score, reasons = analyze_email(subject, body, sender)
        messagebox.showinfo(
            "Result",
            f"Verdict: {verdict}\nScore: {score}\n\n" + "\n".join(reasons)
        )
        # CSV Logging for GUI input as well
        with open("scan_report.csv", "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([subject, sender, verdict, score, "; ".join(reasons)])

    root = tk.Tk()
    root.title("Phishing Email Detector")
    root.geometry("500x450")

    tk.Label(root, text="Subject").pack()
    subject_entry = tk.Entry(root, width=60)
    subject_entry.pack()

    tk.Label(root, text="Body").pack()
    body_text = tk.Text(root, height=10, width=60)
    body_text.pack()

    tk.Label(root, text="Sender Email").pack()
    sender_entry = tk.Entry(root, width=60)
    sender_entry.pack()

    tk.Button(root, text="Analyze Email", command=on_analyze).pack(pady=10)

    root.mainloop()

# ===== MAIN MENU =====
def main():
    print("=== Phishing Email Detector ===")
    print("1. CLI Mode")
    print("2. GUI Mode")
    choice = input("Choose mode (1/2): ")
    if choice == "1":
        run_cli()
    elif choice == "2":
        run_gui()
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
