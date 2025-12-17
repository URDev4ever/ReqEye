<h1 align="center">ReqEye</h1>
<p align="center">
  <img width="395" height="137" alt="image" src="https://github.com/user-attachments/assets/5d01f6ab-d229-4ca1-894e-d99b6059cfad" />
</p>
<h2 align="center">
ReqEye is a **CLI assistant for HTTP request analysis**, designed to help security researchers, bug bounty hunters, and pentesters **identify high‑value entry points** worth manual testing.

It does **not** scan targets, send traffic, or claim vulnerabilities.
ReqEye focuses on **where to look**, not on making assumptions.
</h2>

## Philosophy

> ReqEye does not find bugs.
> It finds **places where bugs are likely to exist**.

Modern web vulnerabilities — especially IDOR, auth bypasses, and logic flaws — are highly **context‑dependent**. Fully automated scanners fail at this.

ReqEye acts as a **thinking assistant**:

* It analyzes raw HTTP requests
* Detects security‑relevant patterns
* Highlights **attack surfaces and entry points**
* Suggests **manual tests** a human should try

No noise. No blind scanning. No false authority.

---

## Key Features

* Parse raw HTTP requests (Burp / DevTools style)
* Classify endpoints by **risk and purpose**
* Identify **high‑value entry points** (IDOR, auth, roles, state changes)
* Detect **security‑relevant indicators** without overclaiming
* Generate **offline mutated requests** for manual testing
* Compare HTTP responses to spot behavioral changes
* Produce clean, terminal‑friendly reports

---

## What ReqEye Is NOT

* ❌ Not an automated vulnerability scanner
* ❌ Not a fuzzer that sends traffic
* ❌ Not a replacement for Burp, manual analysis, or brain usage

ReqEye is meant to be used **before or during manual testing** to prioritize effort.

---

## Installation

ReqEye is written in **pure Python**.

```bash
git clone https://github.com/urdev4ever/reqeye.git
cd reqeye
python reqeye.py
```

### Optional Dependency

On Windows systems, ReqEye will **optionally** use `colorama` for proper ANSI color support.

If `colorama` is not installed, colors are automatically disabled.

```bash
pip install colorama
```

This dependency is **optional**.

---

## Usage

```bash
python reqeye.py --help
```
<img width="500" height="509" alt="image" src="https://github.com/user-attachments/assets/cac15c51-953b-40be-be13-7b2acdac495d" />

### Parse a Request

```bash
python reqeye.py parse request.txt
```

Parses and displays:

* Method
* Path
* Headers
* Query parameters
* Body parameters

---

### Analyze an Endpoint

```bash
python reqeye.py analyze request.txt
```

Outputs:

* Endpoint classification
* Risk score
  
  <img width="434" height="93" alt="image" src="https://github.com/user-attachments/assets/25a401bb-ce4d-45be-88a1-388f3f8a0631" />

* Identified entry points
  
  <img width="371" height="125" alt="image" src="https://github.com/user-attachments/assets/5b24dd68-a515-499a-9928-ef6afd41c586" />
  
* Security indicators
  
  <img width="622" height="363" alt="image" src="https://github.com/user-attachments/assets/a28b96bd-d708-4e7a-aaf5-8e6d20cb2e01" />

* Manual testing recommendations
  
  <img width="354" height="161" alt="image" src="https://github.com/user-attachments/assets/a0bcab52-2715-4f1b-a1ff-f20209dc299e" />

> The follow results are from an authorized request (thx Mercado Libre)
---

### Generate Mutated Requests (Offline)

```bash
python reqeye.py mutate request.txt
```

Creates modified versions of the request for:

* IDOR testing
* Auth bypass attempts
* Role / privilege manipulation
* State and logic testing

These requests are **not sent** — they are meant to be copied into Burp or similar tools.

---

### Compare Responses

```bash
python reqeye.py diff response1.txt response2.txt
```

Highlights:

* Status code changes
* Significant length differences
* Structural changes

Useful for detecting behavior changes after manual tampering.

---

### Generate a Report

```bash
python reqeye.py report request.txt
```

Produces a concise report including:

* Endpoint summary
* Entry points found
* Risk evaluation
* Testing checklist

---

## Risk Scoring

ReqEye assigns a **heuristic risk score (0–100)** based on:

* Endpoint sensitivity
* Presence of entry points
* Authorization context
* Parameter control indicators

The score is meant for **prioritization**, not proof.

---

## Output Philosophy

ReqEye intentionally avoids statements like:

* "This endpoint is vulnerable"
* "Critical security flaw found"

Instead, it uses wording such as:

* "High‑risk entry point"
* "Manual verification recommended"
* "Security‑relevant indicator"

This makes it safe and appropriate for **bug bounty workflows**.
(No fluff, no BS)

---

## Typical Workflow

1. Capture a request (Burp / DevTools)
2. Run `reqeye analyze`
3. Review entry points and recommendations
4. Use `reqeye mutate` for test variants
5. Manually test using Burp or similar tools
6. Compare responses if needed

---

## Use Cases

* Bug bounty hunting
* Manual web pentesting
* API security reviews
* Learning web vulnerability logic

---

## Disclaimer

ReqEye is a **research assistance tool**.

You are responsible for:

* Staying within scope
* Following program rules
* Validating all findings manually

---

This tool exists to help humans focus where it matters most.

## Final Note

ReqEye is built around a simple idea:

> **Good bugs are found by humans — not scanners.**

---
Made with <3 by URDev
