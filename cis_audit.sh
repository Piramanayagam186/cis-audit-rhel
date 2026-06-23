#!/usr/bin/env bash
# ==============================================================================
#  CIS Benchmark Hardening Audit Script for RHEL/CentOS/Rocky Linux
#  Author  : Security Audit Tool
#  Version : 1.0
#  Purpose : Audits the system against key CIS Benchmark Level 1 controls
#            and outputs a colour-coded PASS/FAIL report.
#
#  Usage   : sudo ./cis_audit.sh
#  Output  : Console (colour) + /var/log/cis_audit_<timestamp>.log
# ==============================================================================

# ──────────────────────────────────────────────────────────────────────────────
# SECTION 0 ▸ COLOUR CODES & GLOBALS
# ──────────────────────────────────────────────────────────────────────────────
# Colour codes using ANSI escape sequences
RED='\033[0;31m'       # Failures
GREEN='\033[0;32m'     # Passes
YELLOW='\033[1;33m'    # Warnings / info
CYAN='\033[0;36m'      # Section headers
BOLD='\033[1m'         # Bold text
RESET='\033[0m'        # Reset to default

# Counters for the summary report
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Report file written to /var/log (persistent across reboots)
REPORT_FILE="/var/log/cis_audit_$(date +%Y%m%d_%H%M%S).log"

# ──────────────────────────────────────────────────────────────────────────────
# SECTION 1 ▸ HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

# check_result()
#   $1 = description of the control being checked
#   $2 = "pass" or "fail"
#   $3 = (optional) remediation hint shown on FAIL
#
# HOW IT WORKS:
#   Uses a case statement to branch on pass/fail, increments counters,
#   prints colour output to stdout AND plain text to the log file via tee.
check_result() {
    local description="$1"
    local status="$2"
    local remediation="${3:-}"

    case "$status" in
        pass)
            echo -e "${GREEN}  [PASS]${RESET} $description" | tee -a "$REPORT_FILE"
            ((PASS_COUNT++))
            ;;
        fail)
            echo -e "${RED}  [FAIL]${RESET} $description" | tee -a "$REPORT_FILE"
            [[ -n "$remediation" ]] && \
                echo -e "         ${YELLOW}→ Fix:${RESET} $remediation" | tee -a "$REPORT_FILE"
            ((FAIL_COUNT++))
            ;;
        warn)
            echo -e "${YELLOW}  [WARN]${RESET} $description" | tee -a "$REPORT_FILE"
            [[ -n "$remediation" ]] && \
                echo -e "         ${YELLOW}→ Note:${RESET} $remediation" | tee -a "$REPORT_FILE"
            ((WARN_COUNT++))
            ;;
    esac
}

# section_header()
#   Prints a bold cyan banner to visually separate audit sections
section_header() {
    echo "" | tee -a "$REPORT_FILE"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}" | tee -a "$REPORT_FILE"
    echo -e "${CYAN}${BOLD}  $1${RESET}" | tee -a "$REPORT_FILE"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}" | tee -a "$REPORT_FILE"
}

# ──────────────────────────────────────────────────────────────────────────────
# SECTION 2 ▸ PRE-FLIGHT CHECKS
# ──────────────────────────────────────────────────────────────────────────────

# Check script is run as root (UID 0).
# Many checks require reading /etc/shadow, /etc/sudoers, ss output etc.
# HOW IT WORKS: $EUID is a bash built-in holding the effective user ID.
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}[ERROR]${RESET} This script must be run as root or with sudo."
    echo "        Run: sudo $0"
    exit 1
fi

# Detect the distro family (RHEL/CentOS/Rocky/AlmaLinux/Fedora)
# HOW IT WORKS: /etc/os-release is a standard file on all modern Linux distros.
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_NAME="${NAME:-Unknown}"
    DISTRO_VERSION="${VERSION_ID:-Unknown}"
else
    DISTRO_NAME="Unknown"
    DISTRO_VERSION="Unknown"
fi

# ──────────────────────────────────────────────────────────────────────────────
# SECTION 3 ▸ REPORT HEADER
# ──────────────────────────────────────────────────────────────────────────────
{
    echo "CIS Benchmark Audit Report"
    echo "Generated : $(date)"
    echo "Hostname  : $(hostname -f)"
    echo "OS        : $DISTRO_NAME $DISTRO_VERSION"
    echo "Kernel    : $(uname -r)"
    echo "Log file  : $REPORT_FILE"
    echo "──────────────────────────────────────────────────"
} | tee -a "$REPORT_FILE"

echo -e "${BOLD}Starting CIS Benchmark audit ...${RESET}"

# ──────────────────────────────────────────────────────────────────────────────
# MODULE 1 ▸ SSH HARDENING (CIS 5.2)
# ──────────────────────────────────────────────────────────────────────────────
# HOW IT WORKS:
#   grep reads /etc/ssh/sshd_config and uses -P (Perl regex) or -E (extended
#   regex) to find specific directives. The pattern looks for a non-commented
#   line (^[[:space:]]*) containing the exact directive and value.
#   -q suppresses output so we only use the exit code: 0 = found, 1 = not found.
# ──────────────────────────────────────────────────────────────────────────────
section_header "MODULE 1 · SSH Configuration (CIS 5.2)"

SSHD_CONFIG="/etc/ssh/sshd_config"

if [[ ! -f "$SSHD_CONFIG" ]]; then
    check_result "sshd_config file exists" "fail" "Install openssh-server package"
else
    # CIS 5.2.2 ▸ PermitRootLogin should be 'no'
    # WHY: Direct root login over SSH removes accountability (no audit trail).
    if grep -qiP '^\s*PermitRootLogin\s+no' "$SSHD_CONFIG"; then
        check_result "PermitRootLogin is disabled (CIS 5.2.2)" "pass"
    else
        check_result "PermitRootLogin is disabled (CIS 5.2.2)" "fail" \
            "Add or set: PermitRootLogin no in $SSHD_CONFIG, then: systemctl restart sshd"
    fi

    # CIS 5.2.3 ▸ PermitEmptyPasswords must be 'no'
    # WHY: Empty passwords allow brute-force-free account takeover.
    if grep -qiP '^\s*PermitEmptyPasswords\s+no' "$SSHD_CONFIG"; then
        check_result "PermitEmptyPasswords is disabled (CIS 5.2.3)" "pass"
    else
        check_result "PermitEmptyPasswords is disabled (CIS 5.2.3)" "fail" \
            "Set: PermitEmptyPasswords no"
    fi

    # CIS 5.2.4 ▸ Only Protocol 2 (SSHv2) should be used
    # WHY: SSHv1 has known cryptographic weaknesses (BEAST, etc.)
    # Protocol directive is implicit on modern OpenSSH, but explicit is safer.
    if grep -qiP '^\s*Protocol\s+2' "$SSHD_CONFIG" || \
       ssh -V 2>&1 | grep -qP 'OpenSSH_[7-9]'; then
        check_result "SSH Protocol 2 only (CIS 5.2.4)" "pass"
    else
        check_result "SSH Protocol 2 only (CIS 5.2.4)" "warn" \
            "Verify OpenSSH >= 7.4; older versions need: Protocol 2 explicitly set"
    fi

    # CIS 5.2.5 ▸ MaxAuthTries <= 4
    # WHY: Limits brute-force guessing attempts per connection.
    max_auth=$(grep -iP '^\s*MaxAuthTries\s+\d+' "$SSHD_CONFIG" | awk '{print $2}')
    if [[ -n "$max_auth" && "$max_auth" -le 4 ]]; then
        check_result "MaxAuthTries <= 4 (CIS 5.2.5) [current: $max_auth]" "pass"
    else
        check_result "MaxAuthTries <= 4 (CIS 5.2.5) [current: ${max_auth:-not set}]" "fail" \
            "Set: MaxAuthTries 4"
    fi

    # CIS 5.2.6 ▸ IgnoreRhosts must be 'yes'
    if grep -qiP '^\s*IgnoreRhosts\s+yes' "$SSHD_CONFIG"; then
        check_result "IgnoreRhosts is enabled (CIS 5.2.6)" "pass"
    else
        check_result "IgnoreRhosts is enabled (CIS 5.2.6)" "fail" \
            "Set: IgnoreRhosts yes"
    fi

    # CIS 5.2.7 ▸ HostbasedAuthentication must be 'no'
    if grep -qiP '^\s*HostbasedAuthentication\s+no' "$SSHD_CONFIG"; then
        check_result "HostbasedAuthentication disabled (CIS 5.2.7)" "pass"
    else
        check_result "HostbasedAuthentication disabled (CIS 5.2.7)" "fail" \
            "Set: HostbasedAuthentication no"
    fi

    # CIS 5.2.8 ▸ X11Forwarding should be 'no' (reduces attack surface)
    if grep -qiP '^\s*X11Forwarding\s+no' "$SSHD_CONFIG"; then
        check_result "X11Forwarding disabled (CIS 5.2.8)" "pass"
    else
        check_result "X11Forwarding disabled (CIS 5.2.8)" "fail" \
            "Set: X11Forwarding no (unless GUI forwarding is required)"
    fi

    # CIS 5.2.13 ▸ LoginGraceTime <= 60 seconds
    grace=$(grep -iP '^\s*LoginGraceTime\s+\d+' "$SSHD_CONFIG" | awk '{print $2}')
    # NOTE: LoginGraceTime 0 disables the timeout entirely (infinite grace period).
    # A value of 0 must be treated as a FAIL, not a PASS.
    if [[ -n "$grace" && "$grace" -gt 0 && "$grace" -le 60 ]]; then
        check_result "LoginGraceTime <= 60s (CIS 5.2.13) [current: ${grace}s]" "pass"
    else
        check_result "LoginGraceTime <= 60s (CIS 5.2.13) [current: ${grace:-not set}]" "fail" \
            "Set: LoginGraceTime 60  (0 disables timeout — avoid it)"
    fi

    # CIS 5.2.14 ▸ Idle session timeout via ClientAliveInterval
    interval=$(grep -iP '^\s*ClientAliveInterval\s+\d+' "$SSHD_CONFIG" | awk '{print $2}')
    maxcount=$(grep -iP '^\s*ClientAliveCountMax\s+\d+' "$SSHD_CONFIG" | awk '{print $2}')
    # NOTE: ClientAliveInterval 0 disables keepalive probes entirely — idle sessions
    # never time out. Require interval > 0 to ensure the timeout is actually active.
    if [[ -n "$interval" && "$interval" -gt 0 && "$interval" -le 300 && \
          -n "$maxcount" && "$maxcount" -le 3 ]]; then
        check_result "SSH idle timeout configured (CIS 5.2.14)" "pass"
    else
        check_result "SSH idle timeout configured (CIS 5.2.14)" "fail" \
            "Set: ClientAliveInterval 300  and  ClientAliveCountMax 3  (0 disables probes)"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# MODULE 2 ▸ OPEN PORTS (CIS 2.2 – Minimize Network Services)
# ──────────────────────────────────────────────────────────────────────────────
# HOW IT WORKS:
#   `ss` (socket statistics) replaces the deprecated `netstat` on modern RHEL.
#   Flags: -t = TCP, -u = UDP, -l = listening only, -n = no DNS resolution,
#          -p = show process name (requires root).
#   We pipe to awk to extract unique port numbers and compare against a whitelist.
# ──────────────────────────────────────────────────────────────────────────────
section_header "MODULE 2 · Open Ports (CIS 2.2)"

# Define ports considered acceptable in a typical hardened server.
# Adjust this array to match your environment's requirements.
ALLOWED_PORTS=(22 80 443 8080 8443)

# Collect all listening TCP/UDP ports into an array
# awk '{print $5}' gets the Local Address:Port column; we then extract the port
mapfile -t OPEN_PORTS < <(ss -tulnp | awk 'NR>1 {print $5}' | \
    grep -oP '(?<=:)\d+$' | sort -nu)

echo -e "  ${YELLOW}Listening ports found:${RESET} ${OPEN_PORTS[*]}" | tee -a "$REPORT_FILE"

for port in "${OPEN_PORTS[@]}"; do
    allowed=false
    for allowed_port in "${ALLOWED_PORTS[@]}"; do
        if [[ "$port" -eq "$allowed_port" ]]; then
            allowed=true
            break
        fi
    done

    if $allowed; then
        check_result "Port $port is in the allowed list" "pass"
    else
        # Find which process is using the port
        proc=$(ss -tulnp | grep ":${port} " | grep -oP 'users:\(\(".*?"\)' | head -1)
        check_result "Port $port is open but NOT in whitelist [$proc]" "fail" \
            "Identify the service with: ss -tulnp | grep :$port  then disable if unneeded"
    fi
done

# Check if firewalld or iptables is active (CIS 3.6)
section_header "MODULE 2b · Firewall Status (CIS 3.6)"

if systemctl is-active --quiet firewalld 2>/dev/null; then
    check_result "firewalld is active and running (CIS 3.6)" "pass"
elif systemctl is-active --quiet iptables 2>/dev/null; then
    check_result "iptables service is active (CIS 3.6)" "pass"
else
    check_result "No active firewall detected (CIS 3.6)" "fail" \
        "Enable firewalld: systemctl enable --now firewalld"
fi

# ──────────────────────────────────────────────────────────────────────────────
# MODULE 3 ▸ PASSWORD POLICIES (CIS 5.3 / 5.4)
# ──────────────────────────────────────────────────────────────────────────────
# HOW IT WORKS:
#   Password complexity is enforced by PAM (Pluggable Authentication Modules).
#   On RHEL, this is configured in /etc/pam.d/system-auth and /etc/pam.d/password-auth.
#   Ageing policies live in /etc/login.defs.
#   We use grep + awk to extract specific values and validate them numerically.
# ──────────────────────────────────────────────────────────────────────────────
section_header "MODULE 3 · Password Policy (CIS 5.3 / 5.4)"

LOGIN_DEFS="/etc/login.defs"

# CIS 5.4.1.1 ▸ Maximum password age (PASS_MAX_DAYS <= 365)
pass_max=$(grep -P '^\s*PASS_MAX_DAYS\s+' "$LOGIN_DEFS" | awk '{print $2}')
if [[ -n "$pass_max" && "$pass_max" -le 365 && "$pass_max" -gt 0 ]]; then
    check_result "PASS_MAX_DAYS <= 365 (CIS 5.4.1.1) [current: $pass_max]" "pass"
else
    check_result "PASS_MAX_DAYS <= 365 (CIS 5.4.1.1) [current: ${pass_max:-not set}]" "fail" \
        "Set PASS_MAX_DAYS 90 in $LOGIN_DEFS"
fi

# CIS 5.4.1.2 ▸ Minimum password age (PASS_MIN_DAYS >= 7)
pass_min=$(grep -P '^\s*PASS_MIN_DAYS\s+' "$LOGIN_DEFS" | awk '{print $2}')
if [[ -n "$pass_min" && "$pass_min" -ge 7 ]]; then
    check_result "PASS_MIN_DAYS >= 7 (CIS 5.4.1.2) [current: $pass_min]" "pass"
else
    check_result "PASS_MIN_DAYS >= 7 (CIS 5.4.1.2) [current: ${pass_min:-not set}]" "fail" \
        "Set PASS_MIN_DAYS 7 in $LOGIN_DEFS"
fi

# CIS 5.4.1.4 ▸ Password warn age (PASS_WARN_AGE >= 7)
pass_warn=$(grep -P '^\s*PASS_WARN_AGE\s+' "$LOGIN_DEFS" | awk '{print $2}')
if [[ -n "$pass_warn" && "$pass_warn" -ge 7 ]]; then
    check_result "PASS_WARN_AGE >= 7 (CIS 5.4.1.4) [current: $pass_warn]" "pass"
else
    check_result "PASS_WARN_AGE >= 7 (CIS 5.4.1.4) [current: ${pass_warn:-not set}]" "fail" \
        "Set PASS_WARN_AGE 7 in $LOGIN_DEFS"
fi

# CIS 5.3.1 ▸ PAM password complexity (pam_pwquality / pam_cracklib)
# WHY: Enforces minimum length, complexity requirements (uppercase, digit, special char)
PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"

if grep -qP 'pam_pwquality|pam_cracklib' "$PAM_SYSTEM_AUTH" "$PAM_PASSWORD_AUTH" 2>/dev/null; then
    check_result "PAM password quality module is configured (CIS 5.3.1)" "pass"
else
    check_result "PAM password quality module is configured (CIS 5.3.1)" "fail" \
        "Install libpwquality and add: password requisite pam_pwquality.so try_first_pass retry=3 minlen=14"
fi

# CIS 5.3.2 ▸ Password minimum length >= 14
# HOW IT WORKS: Checks /etc/security/pwquality.conf which pam_pwquality reads
PWQUALITY_CONF="/etc/security/pwquality.conf"
if [[ -f "$PWQUALITY_CONF" ]]; then
    minlen=$(grep -P '^\s*minlen\s*=' "$PWQUALITY_CONF" | awk -F'=' '{print $2}' | tr -d ' ')
    if [[ -n "$minlen" && "$minlen" -ge 14 ]]; then
        check_result "Password minlen >= 14 (CIS 5.3.2) [current: $minlen]" "pass"
    else
        check_result "Password minlen >= 14 (CIS 5.3.2) [current: ${minlen:-not set}]" "fail" \
            "Set minlen = 14 in $PWQUALITY_CONF"
    fi
else
    check_result "pwquality.conf exists for password complexity" "fail" \
        "Install libpwquality: yum install libpwquality"
fi

# CIS 5.4.2 ▸ Lock out accounts after failed attempts
# Checks for pam_faillock (modern RHEL 8+) or pam_tally2 (RHEL 7)
if grep -qP 'pam_faillock|pam_tally2' "$PAM_SYSTEM_AUTH" "$PAM_PASSWORD_AUTH" 2>/dev/null; then
    check_result "Account lockout policy configured (CIS 5.4.2)" "pass"
else
    check_result "Account lockout policy configured (CIS 5.4.2)" "fail" \
        "Add pam_faillock.so to system-auth with deny=5 unlock_time=900"
fi

# CIS 5.4.3 ▸ Password hashing algorithm must be SHA-512
# HOW IT WORKS: authconfig --test shows current settings on RHEL 7; 
# on RHEL 8+ check /etc/login.defs ENCRYPT_METHOD
encrypt_method=$(grep -P '^\s*ENCRYPT_METHOD\s+' "$LOGIN_DEFS" | awk '{print $2}')
if [[ "${encrypt_method^^}" == "SHA512" ]]; then
    check_result "Password encryption uses SHA-512 (CIS 5.4.3)" "pass"
else
    check_result "Password encryption uses SHA-512 (CIS 5.4.3) [current: ${encrypt_method:-not set}]" "fail" \
        "Set ENCRYPT_METHOD SHA512 in $LOGIN_DEFS"
fi

# ──────────────────────────────────────────────────────────────────────────────
# MODULE 4 ▸ UNNECESSARY SERVICES (CIS 2.2)
# ──────────────────────────────────────────────────────────────────────────────
# HOW IT WORKS:
#   Uses systemctl is-active/is-enabled to check the state of known-risky services.
#   `systemctl is-active` returns 0 (active) or non-zero (inactive/not found).
#   We want these services to NOT be active, so we invert the test (!).
# ──────────────────────────────────────────────────────────────────────────────
section_header "MODULE 4 · Unnecessary Services (CIS 2.2)"

# List of services that should NOT be running on a hardened server.
# Each entry: "service_name|CIS Reference|Reason"
RISKY_SERVICES=(
    "telnet|CIS 2.2.18|Sends credentials in plaintext; use SSH instead"
    "rsh|CIS 2.2.16|Legacy remote shell; no encryption"
    "rlogin|CIS 2.2.16|Legacy remote login; no encryption"
    "ypbind|CIS 2.2.14|NIS client; insecure directory service"
    "tftp|CIS 2.2.18|Trivial FTP; no authentication"
    "talk|CIS 2.2.20|Deprecated messaging service"
    "ntalk|CIS 2.2.20|Deprecated messaging service"
    "chargen|CIS 2.2.3|Character generator; can be abused for amplification"
    "daytime|CIS 2.2.4|Time protocol; unnecessary if ntpd/chrony is used"
    "echo|CIS 2.2.5|Echo service; amplification attack vector"
    "discard|CIS 2.2.6|Discard service; no operational value"
    "time|CIS 2.2.7|Older time service; use chrony/ntpd"
    "avahi-daemon|CIS 2.2.15|mDNS; usually not needed on servers"
    "cups|CIS 2.2.9|Print server; rarely needed on headless servers"
    "dhcpd|CIS 2.2.12|DHCP server; disable if not hosting DHCP"
    "slapd|CIS 2.2.13|LDAP server; disable if not hosting directory"
    "nfs|CIS 2.2.8|NFS; disable if not sharing filesystems"
    "rpcbind|CIS 2.2.21|RPC portmapper; needed only if NFS/NIS in use"
    "vsftpd|CIS 2.2.8|FTP server; use SFTP (built into sshd) instead"
    "named|CIS 2.2.11|DNS server; disable if not a DNS resolver"
)

for entry in "${RISKY_SERVICES[@]}"; do
    svc=$(echo "$entry"   | cut -d'|' -f1)
    ref=$(echo "$entry"   | cut -d'|' -f2)
    reason=$(echo "$entry" | cut -d'|' -f3)

    # systemctl is-active returns exit code 0 if the service is running
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        check_result "$svc should not be running ($ref)" "fail" \
            "Stop and disable: systemctl disable --now $svc  |  Reason: $reason"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        check_result "$svc is enabled but not running ($ref)" "warn" \
            "Disable entirely: systemctl disable $svc  |  Reason: $reason"
    else
        check_result "$svc is not active ($ref)" "pass"
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
# MODULE 5 ▸ FILESYSTEM PERMISSIONS & SUID/SGID (CIS 6.1)
# ──────────────────────────────────────────────────────────────────────────────
# HOW IT WORKS:
#   Permission checks use `stat -c "%a"` which returns octal permission mode.
#   We compare against expected values using -eq (numeric comparison).
#   SUID/SGID scan uses `find` with -perm flags:
#     -4000 = SUID bit set,  -2000 = SGID bit set
#     /u+s  = any SUID,      /g+s  = any SGID
# ──────────────────────────────────────────────────────────────────────────────
section_header "MODULE 5 · Filesystem Permissions (CIS 6.1)"

# Check critical file permissions
# Format: "path|expected_octal_perms|cis_ref"
CRITICAL_FILES=(
    "/etc/passwd|644|CIS 6.1.2"
    "/etc/shadow|000|CIS 6.1.3"
    "/etc/group|644|CIS 6.1.4"
    "/etc/gshadow|000|CIS 6.1.5"
    "/etc/passwd-|644|CIS 6.1.6"
    "/etc/shadow-|000|CIS 6.1.7"
    "/etc/group-|644|CIS 6.1.8"
    "/etc/gshadow-|000|CIS 6.1.9"
)

for entry in "${CRITICAL_FILES[@]}"; do
    filepath=$(echo "$entry" | cut -d'|' -f1)
    expected=$(echo "$entry" | cut -d'|' -f2)
    ref=$(echo "$entry"      | cut -d'|' -f3)

    if [[ ! -e "$filepath" ]]; then
        check_result "$filepath exists ($ref)" "warn" "File missing — may not apply to this distro version"
        continue
    fi

    # stat -c "%a" returns octal permissions without leading zeros (e.g. 644, 0, 755).
    # Normalise to 3-digit octal for display, then compare numerically in octal.
    # BUG-FIX: the original used -le on octal strings treated as decimal integers,
    # which caused false FAILs (e.g. 700 > 644 decimally, but 700 is *more* restrictive).
    # CIS mandates exact permissions, so we require an exact match.
    actual=$(stat -c "%a" "$filepath")
    # stat returns octal without leading zeros (e.g. 0 instead of 000).
    # Pad to 3 digits so "0" == "000" and "4" == "004" for a correct string compare.
    actual_norm=$(printf '%03d' "$actual")
    if [[ "$actual_norm" == "$expected" ]]; then
        check_result "$filepath permissions ($ref) [mode: $actual_norm]" "pass"
    else
        check_result "$filepath permissions ($ref) [expected: $expected, got: $actual_norm]" "fail" \
            "Run: chmod $expected $filepath"
    fi
done

# CIS 6.1.1 ▸ Sticky bit on world-writable directories
# HOW IT WORKS: find searches for directories (-type d) that are world-writable
#   (-perm -0002) but lack the sticky bit (-not -perm -1000).
#   The sticky bit (1000) prevents users from deleting each other's files in /tmp.
echo -e "\n  ${YELLOW}Scanning for world-writable dirs without sticky bit ...${RESET}" | tee -a "$REPORT_FILE"
STICKY_ISSUES=$(find / -xdev -type d -perm -0002 -not -perm -1000 \
    -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null)

if [[ -z "$STICKY_ISSUES" ]]; then
    check_result "All world-writable dirs have sticky bit (CIS 6.1.1)" "pass"
else
    check_result "World-writable dirs without sticky bit found (CIS 6.1.1)" "fail" \
        "Run: chmod a+t <directory> for each listed below"
    echo "$STICKY_ISSUES" | while read -r d; do
        echo -e "         ${RED}→${RESET} $d" | tee -a "$REPORT_FILE"
    done
fi

# CIS 6.1.10 ▸ Audit SUID/SGID executables
# WHY: SUID binaries run with owner's privileges (often root).
#      Any unexpected SUID binary is a privilege escalation risk.
echo -e "\n  ${YELLOW}Scanning for SUID/SGID binaries (this may take a moment) ...${RESET}" | tee -a "$REPORT_FILE"

# Known-safe SUID binaries commonly found on RHEL
KNOWN_SUID=(
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/chage"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/pkexec"
    "/usr/sbin/unix_chkpwd"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    "/usr/libexec/dbus-daemon-launch-helper"
)

mapfile -t SUID_FILES < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | sort)

unexpected_suid=()
for suid_file in "${SUID_FILES[@]}"; do
    is_known=false
    for known in "${KNOWN_SUID[@]}"; do
        [[ "$suid_file" == "$known" ]] && is_known=true && break
    done
    $is_known || unexpected_suid+=("$suid_file")
done

if [[ ${#unexpected_suid[@]} -eq 0 ]]; then
    check_result "No unexpected SUID/SGID binaries found (CIS 6.1.10)" "pass"
else
    check_result "${#unexpected_suid[@]} unexpected SUID/SGID binaries found (CIS 6.1.10)" "fail" \
        "Review each and remove SUID if unnecessary: chmod u-s <file>"
    for f in "${unexpected_suid[@]}"; do
        echo -e "         ${RED}→${RESET} $f" | tee -a "$REPORT_FILE"
    done
fi

# CIS 6.2 ▸ Check for accounts with empty passwords
echo -e "\n  ${YELLOW}Checking for accounts with empty passwords ...${RESET}" | tee -a "$REPORT_FILE"
# BUG-FIX: '!' and '!!' are locked-account markers — not empty passwords.
# Flagging them as a problem produces false positives on every normal locked
# system account (e.g. bin, daemon, nobody).  Only a truly empty field is a risk.
EMPTY_PASS=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [[ -z "$EMPTY_PASS" ]]; then
    check_result "No accounts with empty password fields (CIS 6.2.1)" "pass"
else
    check_result "Accounts with empty/locked password field found (CIS 6.2.1)" "warn" \
        "Lock or set password for: $EMPTY_PASS"
fi

# CIS 6.2.4 ▸ Check for UID 0 accounts other than root
EXTRA_ROOT=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$')
if [[ -z "$EXTRA_ROOT" ]]; then
    check_result "Only root has UID 0 (CIS 6.2.4)" "pass"
else
    check_result "Non-root accounts with UID 0 found (CIS 6.2.4)" "fail" \
        "Investigate and remove or reassign: $EXTRA_ROOT"
fi

# ──────────────────────────────────────────────────────────────────────────────
# BONUS MODULE ▸ KERNEL HARDENING PARAMETERS (CIS 3.1 / 3.2)
# ──────────────────────────────────────────────────────────────────────────────
# HOW IT WORKS:
#   sysctl reads kernel parameters from /proc/sys/*.
#   We compare actual values against CIS-recommended values.
# ──────────────────────────────────────────────────────────────────────────────
section_header "BONUS · Kernel Sysctl Parameters (CIS 3.1 / 3.2)"

# Format: "sysctl_key|expected_value|cis_ref|description"
SYSCTL_CHECKS=(
    "net.ipv4.ip_forward|0|CIS 3.1.1|IP forwarding (disable unless router)"
    "net.ipv4.conf.all.send_redirects|0|CIS 3.1.2|Send ICMP redirects"
    "net.ipv4.conf.all.accept_redirects|0|CIS 3.2.2|Accept ICMP redirects"
    "net.ipv4.conf.all.accept_source_route|0|CIS 3.2.1|Accept source-routed packets"
    "net.ipv4.conf.all.log_martians|1|CIS 3.2.4|Log martian packets"
    "net.ipv4.icmp_echo_ignore_broadcasts|1|CIS 3.2.5|Ignore ICMP broadcast pings"
    "net.ipv4.tcp_syncookies|1|CIS 3.2.8|SYN cookie protection (prevents SYN floods)"
    "kernel.randomize_va_space|2|CIS 1.6.3|Address space layout randomisation (ASLR)"
    "fs.suid_dumpable|0|CIS 1.6.4|Prevent SUID programs creating core dumps"
)

for entry in "${SYSCTL_CHECKS[@]}"; do
    key=$(echo "$entry"   | cut -d'|' -f1)
    expected=$(echo "$entry" | cut -d'|' -f2)
    ref=$(echo "$entry"   | cut -d'|' -f3)
    desc=$(echo "$entry"  | cut -d'|' -f4)

    actual=$(sysctl -n "$key" 2>/dev/null)
    if [[ "$actual" == "$expected" ]]; then
        check_result "$key = $expected ($ref) [$desc]" "pass"
    else
        check_result "$key = $expected ($ref) [$desc] [current: ${actual:-not set}]" "fail" \
            "Add to /etc/sysctl.d/99-cis-hardening.conf: $key = $expected  then: sysctl -p"
    fi
done

# ──────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
SCORE=0
[[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS_COUNT * 100) / TOTAL ))

echo "" | tee -a "$REPORT_FILE"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}" | tee -a "$REPORT_FILE"
echo -e "${CYAN}${BOLD}  AUDIT SUMMARY${RESET}" | tee -a "$REPORT_FILE"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}" | tee -a "$REPORT_FILE"
echo -e "  ${GREEN}${BOLD}PASS :${RESET} $PASS_COUNT" | tee -a "$REPORT_FILE"
echo -e "  ${RED}${BOLD}FAIL :${RESET} $FAIL_COUNT" | tee -a "$REPORT_FILE"
echo -e "  ${YELLOW}${BOLD}WARN :${RESET} $WARN_COUNT" | tee -a "$REPORT_FILE"
echo -e "  ${BOLD}TOTAL:${RESET} $TOTAL controls checked" | tee -a "$REPORT_FILE"
echo -e "  ${BOLD}SCORE:${RESET} ${SCORE}% compliance" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

if [[ $SCORE -ge 90 ]]; then
    echo -e "  ${GREEN}${BOLD}★ Excellent — system is well-hardened${RESET}" | tee -a "$REPORT_FILE"
elif [[ $SCORE -ge 70 ]]; then
    echo -e "  ${YELLOW}${BOLD}▲ Good — some controls need attention${RESET}" | tee -a "$REPORT_FILE"
else
    echo -e "  ${RED}${BOLD}✗ Needs work — significant hardening required${RESET}" | tee -a "$REPORT_FILE"
fi

echo "" | tee -a "$REPORT_FILE"
echo -e "  Full report saved to: ${BOLD}$REPORT_FILE${RESET}" | tee -a "$REPORT_FILE"
echo -e "${CYAN}${BOLD}══════════════════════════════════════════════${RESET}" | tee -a "$REPORT_FILE"
