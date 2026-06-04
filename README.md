# 🔒 Center for Internet Security (CIS) Benchmark Hardening Audit Script

A lightweight, dependency-free Bash script that audits **RHEL / CentOS / Rocky Linux / AlmaLinux** systems against **CIS Benchmark Level 1** controls. It produces a colour-coded console report with actionable remediation hints and a final compliance score, and saves the full output to `/var/log/`.

---

## ✨ Features

| Module | Controls Checked | CIS Reference |
|---|---|---|
| SSH Hardening | PermitRootLogin, empty passwords, protocol version, MaxAuthTries, idle timeout, and more | CIS 5.2 |
| Open Ports & Firewall | Listening ports vs whitelist, firewalld/iptables status | CIS 2.2 / 3.6 |
| Password Policy | Max/min age, warn age, PAM complexity, minimum length, SHA-512 hashing, lockout policy | CIS 5.3 / 5.4 |
| Unnecessary Services | 20 risky/legacy services (telnet, rsh, NFS, FTP, CUPS, etc.) | CIS 2.2 |
| Filesystem Permissions | Critical file modes (`/etc/shadow`, `/etc/passwd`, etc.), sticky bits, SUID/SGID binaries | CIS 6.1 / 6.2 |
| Kernel Sysctl Parameters | IP forwarding, ICMP redirects, SYN cookies, ASLR, core dump restrictions | CIS 1.6 / 3.1 / 3.2 |

**Output includes:**
- Colour-coded `[PASS]` / `[FAIL]` / `[WARN]` per control
- Inline remediation commands on every failure
- Summary table with total PASS / FAIL / WARN counts and a **% compliance score**
- Persistent log file at `/var/log/cis_audit_<timestamp>.log`

---

## 🖥️ Supported Platforms

- Red Hat Enterprise Linux (RHEL) 7, 8, 9
- CentOS 7 / CentOS Stream 8, 9
- Rocky Linux 8, 9
- AlmaLinux 8, 9
- Fedora (best-effort)

> The script reads `/etc/os-release` at runtime and will display the detected OS in the report header.

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/cis-audit.git
cd cis-audit

# 2. Make the script executable
chmod +x cis_audit.sh

# 3. Run as root (required for reading /etc/shadow, ss -p output, etc.)
sudo ./cis_audit.sh
```

The colour report streams to your terminal in real time. When the script finishes, the full log is saved to `/var/log/cis_audit_<YYYYMMDD_HHMMSS>.log`.

---

## 📋 Sample Output

```
══════════════════════════════════════════════
  MODULE 1 · SSH Configuration (CIS 5.2)
══════════════════════════════════════════════
  [PASS] PermitRootLogin is disabled (CIS 5.2.2)
  [PASS] PermitEmptyPasswords is disabled (CIS 5.2.3)
  [FAIL] MaxAuthTries <= 4 (CIS 5.2.5) [current: not set]
         → Fix: Set: MaxAuthTries 4
  ...

══════════════════════════════════════════════
  AUDIT SUMMARY
══════════════════════════════════════════════
  PASS : 38
  FAIL : 9
  WARN : 4
  TOTAL: 51 controls checked
  SCORE: 74% compliance
  ▲ Good — some controls need attention
```

---

## ⚙️ Configuration

Two areas of the script are intended to be customised before running:

### Allowed Ports (Module 2)

Edit the `ALLOWED_PORTS` array to match your environment:

```bash
ALLOWED_PORTS=(22 80 443 8080 8443)
```

### Known-safe SUID Binaries (Module 5)

The `KNOWN_SUID` array lists binaries whose SUID bit is expected. Add or remove entries to suit your installed software:

```bash
KNOWN_SUID=(
    "/usr/bin/sudo"
    "/usr/bin/passwd"
    # add your own safe binaries here
)
```

---

## 🛠️ Remediation

Every `[FAIL]` line is followed by a `→ Fix:` hint with the exact command needed. For sysctl parameters, the recommended approach is to persist settings in a dedicated drop-in file:

```bash
# Example: apply all CIS sysctl recommendations
cat >> /etc/sysctl.d/99-cis-hardening.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF
sysctl -p /etc/sysctl.d/99-cis-hardening.conf
```

---

## 📁 Repository Structure

```
.
├── cis_audit.sh      # Main audit script
└── README.md         # This file
```

---

## ⚠️ Disclaimer

This script is a **read-only audit tool** — it makes no changes to your system. All remediation steps require manual action. Results should be reviewed by a qualified security engineer before applying changes in production environments.

This tool is intended to assist with CIS Benchmark compliance assessments and is not a substitute for a full security audit.

---

## 📜 License

This project is released under the MIT License.

---

## 🤝 Contributing

Pull requests are welcome. If you add checks for additional CIS controls or other distros (Debian/Ubuntu), please include the CIS reference number and a brief comment explaining the check.
