# Nmap NSE Reference and Enhanced Scripts

> **Coursework Project:** Cybersecurity Lab Assignment  
> **Author:** Dhanishkanth (24BCE1348)  
> **Repository:** https://github.com/dhanish0104/nmap-nse-scripts  

This repository contains both base (normal) reference Nmap Scripting Engine (NSE) scripts and their newly generated enhanced security audit scripts.

---

## 📂 Scripts Catalog

| # | Script Name | Script Type | Target Service | Original / Extended Authors | Key Features / Enhancement |
|---|:---|:---:|:---:|:---|:---|
| 1 | [smtp-commands.nse](./smtp-commands.nse) | **Base Reference Script 1** | SMTP (25, 465, 587) | Jasey DePriest | Standard banner querying & EHLO/HELP command enumeration |
| 2 | [smtp-risk-check.nse](./smtp-risk-check.nse) | **Enhanced Script 1** | SMTP (25, 465, 587) | Dhanishkanth (based on Jasey DePriest) | Automated security risk analysis: flags user enumeration (VRFY/EXPN) and unencrypted mail transport (STARTTLS missing) |
| 3 | [tp-anon.nse](./ftp-anon.nse) | **Base Reference Script 2** | FTP (21, 990) | Eddie Bell, Rob Nicholls, Ange Gutek, David Fifield | Standard anonymous FTP login check & directory listing |
| 4 | [tp-anon-plus.nse](./ftp-anon-plus.nse) | **Enhanced Script 2** | FTP (21, 990) | Dhanishkanth (based on Eddie Bell et al.) | Automated file risk assessment: identifies sensitive filenames (.env, id_rsa, ackup.zip, etc.) with [NSE: sensitive] and summary alert |

---

## 🚀 Script Direct Links

- **First Normal Script:** [smtp-commands.nse](https://github.com/dhanish0104/nmap-nse-scripts/blob/main/smtp-commands.nse)
- **First Enhanced Script:** [smtp-risk-check.nse](https://github.com/dhanish0104/nmap-nse-scripts/blob/main/smtp-risk-check.nse)
- **Second Normal Script:** [ftp-anon.nse](https://github.com/dhanish0104/nmap-nse-scripts/blob/main/ftp-anon.nse)
- **Second Enhanced Script:** [ftp-anon-plus.nse](https://github.com/dhanish0104/nmap-nse-scripts/blob/main/ftp-anon-plus.nse)

---

## 💻 Usage Instructions

### 1. SMTP Security Risk Check
`ash
nmap -Pn --script=smtp-risk-check.nse -p 25,465,587 <target-ip>
`

### 2. FTP Anonymous & Sensitive File Audit
`ash
nmap -Pn --script=ftp-anon-plus.nse -p 21,990 <target-ip>
`

---

## 📜 Acknowledgements & Disclaimer
Base scripts are part of the open-source Nmap Project. Enhancements are developed for educational coursework and authorized security evaluation purposes.
