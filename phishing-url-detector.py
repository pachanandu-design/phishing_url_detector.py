import tkinter as tk
from tkinter import messagebox
from urllib.parse import urlparse
import re

# ============================================================
# PHISHING URL DETECTOR
# Professional Cybersecurity Dashboard
# ============================================================

scan_history = []

# ---------------- COLORS ----------------

BG = "#0b1120"
CARD = "#111827"
CARD_LIGHT = "#1f2937"
TEXT = "#f8fafc"
SECONDARY = "#94a3b8"
BORDER = "#263449"

GREEN = "#22c55e"
ORANGE = "#f59e0b"
RED = "#ef4444"
BLUE = "#38bdf8"


# ============================================================
# ANALYZE URL
# ============================================================

def analyze_url():

    url = url_entry.get().strip()

    if not url:
        messagebox.showwarning(
            "Input Required",
            "Please enter a website URL."
        )
        return

    check_url = (
        url
        if re.match(r"^https?://", url, re.IGNORECASE)
        else "http://" + url
    )

    parsed = urlparse(check_url)
    domain = parsed.netloc.lower()
    clean_domain = domain.split(":")[0]

    if not clean_domain or "." not in clean_domain:

        messagebox.showerror(
            "Invalid URL",
            "Please enter a valid website URL.\n\n"
            "Example: https://example.com"
        )
        return

    score = 0
    warnings = []
    checks = []

    # --------------------------------------------------------
    # 1. HTTPS
    # --------------------------------------------------------

    if parsed.scheme == "https":
        checks.append(("HTTPS Encryption", "PASS"))
    else:
        score += 1
        checks.append(("HTTPS Encryption", "REVIEW"))
        warnings.append("URL does not use HTTPS encryption.")

    # --------------------------------------------------------
    # 2. URL LENGTH
    # --------------------------------------------------------

    if len(url) <= 75:
        checks.append(("URL Length", "PASS"))
    else:
        score += 1
        checks.append(("URL Length", "REVIEW"))
        warnings.append("URL is unusually long.")

    # --------------------------------------------------------
    # 3. @ SYMBOL
    # --------------------------------------------------------

    if "@" not in url:
        checks.append(("Special Character Check", "PASS"))
    else:
        score += 1
        checks.append(("Special Character Check", "REVIEW"))
        warnings.append("URL contains an '@' symbol.")

    # --------------------------------------------------------
    # 4. IP ADDRESS
    # --------------------------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, clean_domain):
        score += 1
        checks.append(("IP Address Detection", "REVIEW"))
        warnings.append(
            "URL uses an IP address instead of a domain name."
        )
    else:
        checks.append(("IP Address Detection", "PASS"))

    # --------------------------------------------------------
    # 5. SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "account",
        "update",
        "secure",
        "bank",
        "password",
        "confirm"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        score += 1
        checks.append(("Suspicious Keywords", "REVIEW"))
        warnings.append(
            "Suspicious keyword(s): "
            + ", ".join(found_words)
        )
    else:
        checks.append(("Suspicious Keywords", "PASS"))

    # --------------------------------------------------------
    # 6. DOMAIN STRUCTURE
    # --------------------------------------------------------

    if url.count(".") <= 4:
        checks.append(("Domain Structure", "PASS"))
    else:
        score += 1
        checks.append(("Domain Structure", "REVIEW"))
        warnings.append(
            "URL contains an unusually high number of "
            "subdomains."
        )

    # --------------------------------------------------------
    # 7. DOMAIN CHARACTER
    # --------------------------------------------------------

    if "-" in clean_domain:
        score += 1
        checks.append(("Domain Character Check", "REVIEW"))
        warnings.append(
            "Domain contains a hyphen."
        )
    else:
        checks.append(("Domain Character Check", "PASS"))

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score <= 1:

        risk = "LOW RISK"
        risk_color = GREEN
        risk_symbol = "●"

        recommendation = (
            "The URL shows few suspicious indicators. "
            "Always verify the website before sharing "
            "sensitive information."
        )

    elif score <= 3:

        risk = "SUSPICIOUS"
        risk_color = ORANGE
        risk_symbol = "▲"

        recommendation = (
            "Be cautious. Carefully verify the website "
            "before entering personal or financial information."
        )

    else:

        risk = "HIGH RISK"
        risk_color = RED
        risk_symbol = "!"

        recommendation = (
            "Avoid entering passwords, banking details, "
            "or other sensitive information on this URL."
        )

    # ========================================================
    # UPDATE RISK
    # ========================================================

    risk_value.config(
        text=f"{score}/7",
        fg=risk_color
    )

    risk_status.config(
        text=f"{risk_symbol}  {risk}",
        fg=risk_color
    )

    scan_status.config(
        text="●  SCAN COMPLETE",
        fg=GREEN
    )

    # ========================================================
    # PROGRESS BAR
    # ========================================================

    bar_width = 280
    progress = int((score / 7) * bar_width)

    progress_canvas.delete("all")

    progress_canvas.create_rectangle(
        0,
        0,
        bar_width,
        10,
        fill=CARD_LIGHT,
        outline=""
    )

    progress_canvas.create_rectangle(
        0,
        0,
        progress,
        10,
        fill=risk_color,
        outline=""
    )

    # ========================================================
    # DETECTION RESULTS
    # ========================================================

    for widget in checks_frame.winfo_children():
        widget.destroy()

    for check_name, status in checks:

        if status == "PASS":
            symbol = "✓"
            color = GREEN
            status_text = "PASS"
        else:
            symbol = "!"
            color = ORANGE
            status_text = "REVIEW"

        row = tk.Frame(
            checks_frame,
            bg=CARD
        )

        row.pack(
            fill="x",
            pady=4
        )

        tk.Label(
            row,
            text=symbol,
            font=("Segoe UI", 11, "bold"),
            fg=color,
            bg=CARD,
            width=3
        ).pack(side="left")

        tk.Label(
            row,
            text=check_name,
            font=("Segoe UI", 10),
            fg=TEXT,
            bg=CARD
        ).pack(side="left")

        tk.Label(
            row,
            text=status_text,
            font=("Segoe UI", 9, "bold"),
            fg=color,
            bg=CARD
        ).pack(side="right")

    # ========================================================
    # SECURITY FINDINGS
    # ========================================================

    for widget in findings_frame.winfo_children():
        widget.destroy()

    if warnings:

        for warning in warnings:

            row = tk.Frame(
                findings_frame,
                bg=CARD_LIGHT,
                padx=10,
                pady=8
            )

            row.pack(
                fill="x",
                pady=3
            )

            tk.Label(
                row,
                text="!",
                font=("Segoe UI", 10, "bold"),
                fg=ORANGE,
                bg=CARD_LIGHT,
                width=3
            ).pack(side="left")

            tk.Label(
                row,
                text=warning,
                font=("Segoe UI", 9),
                fg=TEXT,
                bg=CARD_LIGHT,
                justify="left",
                anchor="w",
                wraplength=390
            ).pack(
                side="left",
                fill="x",
                expand=True
            )

    else:

        tk.Label(
            findings_frame,
            text="✓ No major suspicious indicators detected.",
            font=("Segoe UI", 10),
            fg=GREEN,
            bg=CARD
        ).pack(
            anchor="w",
            pady=10
        )

    # ========================================================
    # RECOMMENDATION
    # ========================================================

    recommendation_label.config(
        text=recommendation
    )

    # ========================================================
    # HISTORY
    # ========================================================

    scan_history.append(
        (url, score, risk)
    )

    update_history()


# ============================================================
# HISTORY
# ============================================================

def update_history():

    for widget in history_frame.winfo_children():
        widget.destroy()

    if not scan_history:

        tk.Label(
            history_frame,
            text="No scans performed yet.",
            font=("Segoe UI", 9),
            fg=SECONDARY,
            bg=CARD
        ).pack(
            pady=5
        )

        return

    for url, score, risk in reversed(scan_history[-5:]):

        if risk == "LOW RISK":
            color = GREEN
        elif risk == "SUSPICIOUS":
            color = ORANGE
        else:
            color = RED

        row = tk.Frame(
            history_frame,
            bg=CARD_LIGHT,
            padx=10,
            pady=7
        )

        row.pack(
            fill="x",
            pady=2
        )

        tk.Label(
            row,
            text=url,
            font=("Segoe UI", 9),
            fg=TEXT,
            bg=CARD_LIGHT,
            anchor="w"
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        tk.Label(
            row,
            text=f"{score}/7  {risk}",
            font=("Segoe UI", 9, "bold"),
            fg=color,
            bg=CARD_LIGHT
        ).pack(
            side="right"
        )


def clear_history():

    scan_history.clear()
    update_history()


# ============================================================
# CLEAR SCAN
# ============================================================

def clear_scan():

    url_entry.delete(
        0,
        tk.END
    )

    risk_value.config(
        text="—",
        fg=SECONDARY
    )

    risk_status.config(
        text="Awaiting Scan",
        fg=SECONDARY
    )

    scan_status.config(
        text="●  READY TO SCAN",
        fg=SECONDARY
    )

    progress_canvas.delete("all")

    progress_canvas.create_rectangle(
        0,
        0,
        280,
        10,
        fill=CARD_LIGHT,
        outline=""
    )

    for widget in checks_frame.winfo_children():
        widget.destroy()

    for widget in findings_frame.winfo_children():
        widget.destroy()

    tk.Label(
        findings_frame,
        text="Enter a URL and click ANALYZE URL.",
        font=("Segoe UI", 10),
        fg=SECONDARY,
        bg=CARD
    ).pack(
        anchor="w",
        pady=10
    )

    recommendation_label.config(
        text="Your security recommendation will appear here."
    )


# ============================================================
# MAIN WINDOW
# ============================================================

root = tk.Tk()

root.title(
    "Phishing URL Detector | Cybersecurity Tool"
)

root.geometry(
    "1050x850"
)

root.configure(
    bg=BG
)

root.minsize(
    900,
    750
)


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    root,
    bg=BG
)

header.pack(
    fill="x",
    padx=40,
    pady=(22, 8)
)


tk.Label(
    header,
    text="🛡",
    font=("Segoe UI", 28),
    fg=BLUE,
    bg=BG
).pack(
    side="left",
    padx=(0, 12)
)


title_frame = tk.Frame(
    header,
    bg=BG
)

title_frame.pack(
    side="left"
)


tk.Label(
    title_frame,
    text="PHISHING URL DETECTOR",
    font=("Segoe UI", 22, "bold"),
    fg=TEXT,
    bg=BG
).pack(
    anchor="w"
)


tk.Label(
    title_frame,
    text="Cybersecurity URL Risk Assessment",
    font=("Segoe UI", 10),
    fg=SECONDARY,
    bg=BG
).pack(
    anchor="w"
)


# ============================================================
# SCAN STATUS
# ============================================================

scan_status = tk.Label(
    header,
    text="●  READY TO SCAN",
    font=("Segoe UI", 9, "bold"),
    fg=SECONDARY,
    bg=BG
)

scan_status.pack(
    side="right",
    anchor="n"
)


# ============================================================
# URL INPUT
# ============================================================

input_card = tk.Frame(
    root,
    bg=CARD,
    padx=25,
    pady=18
)

input_card.pack(
    fill="x",
    padx=40,
    pady=10
)


tk.Label(
    input_card,
    text="WEBSITE URL",
    font=("Segoe UI", 10, "bold"),
    fg=SECONDARY,
    bg=CARD
).pack(
    anchor="w"
)


url_entry = tk.Entry(
    input_card,
    font=("Segoe UI", 12),
    bg=CARD_LIGHT,
    fg=TEXT,
    insertbackground=TEXT,
    relief="flat"
)

url_entry.pack(
    fill="x",
    pady=(8, 14),
    ipady=9
)


button_frame = tk.Frame(
    input_card,
    bg=CARD
)

button_frame.pack(
    anchor="w"
)


tk.Button(
    button_frame,
    text="🔍  ANALYZE URL",
    font=("Segoe UI", 10, "bold"),
    bg=BLUE,
    fg="#06111f",
    activebackground=BLUE,
    relief="flat",
    padx=20,
    pady=9,
    cursor="hand2",
    command=analyze_url
).pack(
    side="left",
    padx=(0, 10)
)


tk.Button(
    button_frame,
    text="CLEAR",
    font=("Segoe UI", 10),
    bg=CARD_LIGHT,
    fg=TEXT,
    activebackground=BORDER,
    relief="flat",
    padx=20,
    pady=9,
    cursor="hand2",
    command=clear_scan
).pack(
    side="left"
)


# ============================================================
# CONTENT
# ============================================================

content = tk.Frame(
    root,
    bg=BG
)

content.pack(
    fill="both",
    expand=True,
    padx=40,
    pady=8
)


# ============================================================
# LEFT COLUMN
# ============================================================

left_column = tk.Frame(
    content,
    bg=BG
)

left_column.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 8)
)


# ---------------- SECURITY ASSESSMENT ----------------

risk_card = tk.Frame(
    left_column,
    bg=CARD,
    padx=25,
    pady=15
)

risk_card.pack(
    fill="x",
    pady=(0, 8)
)


tk.Label(
    risk_card,
    text="SECURITY ASSESSMENT",
    font=("Segoe UI", 10, "bold"),
    fg=SECONDARY,
    bg=CARD
).pack(
    anchor="w"
)


risk_value = tk.Label(
    risk_card,
    text="—",
    font=("Segoe UI", 34, "bold"),
    fg=SECONDARY,
    bg=CARD
)

risk_value.pack(
    pady=(5, 0)
)


tk.Label(
    risk_card,
    text="RISK SCORE",
    font=("Segoe UI", 8),
    fg=SECONDARY,
    bg=CARD
).pack()


risk_status = tk.Label(
    risk_card,
    text="Awaiting Scan",
    font=("Segoe UI", 14, "bold"),
    fg=SECONDARY,
    bg=CARD
)

risk_status.pack(
    pady=(5, 4)
)


progress_canvas = tk.Canvas(
    risk_card,
    width=280,
    height=10,
    bg=CARD,
    highlightthickness=0
)

progress_canvas.pack()

progress_canvas.create_rectangle(
    0,
    0,
    280,
    10,
    fill=CARD_LIGHT,
    outline=""
)


# ---------------- DETECTION RESULTS ----------------

checks_card = tk.Frame(
    left_column,
    bg=CARD,
    padx=20,
    pady=15
)

checks_card.pack(
    fill="both",
    expand=True
)


tk.Label(
    checks_card,
    text="DETECTION RESULTS",
    font=("Segoe UI", 10, "bold"),
    fg=SECONDARY,
    bg=CARD
).pack(
    anchor="w",
    pady=(0, 7)
)


checks_frame = tk.Frame(
    checks_card,
    bg=CARD
)

checks_frame.pack(
    fill="both",
    expand=True
)


# ============================================================
# RIGHT COLUMN
# ============================================================

right_column = tk.Frame(
    content,
    bg=BG
)

right_column.pack(
    side="right",
    fill="both",
    expand=True,
    padx=(8, 0)
)


# ---------------- SECURITY FINDINGS ----------------

findings_card = tk.Frame(
    right_column,
    bg=CARD,
    padx=20,
    pady=15
)

findings_card.pack(
    fill="both",
    expand=True,
    pady=(0, 8)
)


tk.Label(
    findings_card,
    text="SECURITY FINDINGS",
    font=("Segoe UI", 10, "bold"),
    fg=SECONDARY,
    bg=CARD
).pack(
    anchor="w"
)


findings_frame = tk.Frame(
    findings_card,
    bg=CARD
)

findings_frame.pack(
    fill="both",
    expand=True,
    pady=(8, 0)
)


tk.Label(
    findings_frame,
    text="Enter a URL and click ANALYZE URL.",
    font=("Segoe UI", 10),
    fg=SECONDARY,
    bg=CARD
).pack(
    anchor="w",
    pady=10
)


# ---------------- RECOMMENDATION ----------------

recommendation_card = tk.Frame(
    right_column,
    bg=CARD,
    padx=20,
    pady=15
)

recommendation_card.pack(
    fill="x"
)


tk.Label(
    recommendation_card,
    text="💡 RECOMMENDATION",
    font=("Segoe UI", 10, "bold"),
    fg=BLUE,
    bg=CARD
).pack(
    anchor="w"
)


recommendation_label = tk.Label(
    recommendation_card,
    text="Your security recommendation will appear here.",
    font=("Segoe UI", 10),
    fg=TEXT,
    bg=CARD,
    justify="left",
    wraplength=420
)

recommendation_label.pack(
    anchor="w",
    pady=(8, 0)
)


# ============================================================
# HISTORY
# ============================================================

history_card = tk.Frame(
    root,
    bg=CARD,
    padx=20,
    pady=10
)

history_card.pack(
    fill="x",
    padx=40,
    pady=(8, 8)
)


history_header = tk.Frame(
    history_card,
    bg=CARD
)

history_header.pack(
    fill="x"
)


tk.Label(
    history_header,
    text="📜 RECENT SCANS",
    font=("Segoe UI", 9, "bold"),
    fg=SECONDARY,
    bg=CARD
).pack(
    side="left"
)


tk.Button(
    history_header,
    text="Clear History",
    font=("Segoe UI", 8),
    bg=CARD_LIGHT,
    fg=TEXT,
    relief="flat",
    padx=10,
    cursor="hand2",
    command=clear_history
).pack(
    side="right"
)


history_frame = tk.Frame(
    history_card,
    bg=CARD
)

history_frame.pack(
    fill="x",
    pady=(5, 0)
)


# ============================================================
# FOOTER
# ============================================================

footer = tk.Frame(
    root,
    bg=BG
)

footer.pack(
    fill="x",
    padx=40,
    pady=(0, 10)
)


tk.Label(
    footer,
    text="Phishing URL Detector • Heuristic Security Analysis • Educational Tool",
    font=("Segoe UI", 8),
    fg=SECONDARY,
    bg=BG
).pack(
    side="left"
)


tk.Label(
    footer,
    text="v1.0",
    font=("Segoe UI", 8),
    fg=SECONDARY,
    bg=BG
).pack(
    side="right"
)


# ============================================================
# START
# ============================================================

update_history()

root.mainloop()
