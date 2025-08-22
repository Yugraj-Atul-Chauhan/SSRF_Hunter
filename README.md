# SSRF Hunter (Burp Suite Extension)

**SSRF Hunter** is a Burp Suite Jython extension designed for **active detection of Server-Side Request Forgery (SSRF) vulnerabilities**.  
It performs batch-based, one-request-per-parameter/header injections with support for JSON, XML, form data, and custom headers.

⚠️ **Disclaimer:** This tool is for authorized security testing only. Do not use it on systems without permission.

---

## Features
- Automated SSRF payload injection in:
  - Query parameters
  - Form data (x-www-form-urlencoded)
  - JSON bodies
  - XML bodies
  - Custom headers (e.g., `X-Forwarded-For`, `Origin`, etc.)
- Integration with **Burp Collaborator** for blind SSRF detection
- Verbose logging for transparency of operations
- Synthetic parameter injection if no parameters exist
- Batch scanning with global wait time to reduce noise

---

## Requirements
- **Burp Suite Professional**
- **Jython 2.7** (standalone JAR)
- Configured **Burp Collaborator** for blind SSRF detection

---

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/SSRF_Hunter.git
   cd SSRF_Hunter
   ```

2. Open Burp Suite → `Extender` tab → `Extensions`.

3. Click **Add**:
   - Extension type: `Python`
   - Extension file: `SSRF_Hunter.py`

4. Confirm that the extension loads successfully (check the Burp Extender output).

---

## Usage
1. Start a Burp Active Scan on your target scope.
2. The extension will automatically inject SSRF payloads across parameters/headers.
3. Collaborator hits or in-band reflections will appear as **custom issues** in the Burp dashboard.

---

## Example Output (Logs)
```
[*] === New Active Scan ===
[*] Target URL: http://example.com/test
[*] Building URL param injections …
[+] CONFIRMED via Collaborator (Firm): query:redirect
[*] Summary => Confirmed(Firm): 1 | Tentative: 0
```

---

## Remediation Advice
- Use **allowlists** for outbound destinations.
- Block internal/link-local address ranges.
- Validate & re-validate after redirects.
- Restrict **egress network access**.
- Use **IMDSv2** for cloud metadata access in AWS.

---

## Author
Developed by **Atul Chauhan**  
🔗 [LinkedIn](https://www.linkedin.com/in/atul-chauhan-cyber-security/)  

---

## License
This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
