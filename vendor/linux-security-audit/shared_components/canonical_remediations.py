"""
canonical_remediations.py - Single-source-of-truth remediation registry.

SYNOPSIS
    Maps a normalized remediation TOPIC to one canonical, detailed, robust
    remediation string, and classifies an AuditResult into a topic so the
    orchestrator can normalize remediation guidance to be consistent across
    every framework module.

DESCRIPTION
    Many frameworks independently audit the same underlying control (e.g.
    "disable IP forwarding", "enable ASLR", "no world-writable files").
    Historically each module wrote its own remediation text, so the same fix
    appeared a dozen different ways - different config-file targets, different
    persistence methods (sysctl -w vs >> /etc/sysctl.conf vs /etc/sysctl.d),
    and sometimes contradictory values. This registry resolves that: each
    topic has ONE canonical remediation, chosen as the most informative and
    robust version found across the modules and enhanced where the best
    existing version was still insufficient (e.g. always persisting sysctl
    settings under /etc/sysctl.d/ and applying with `sysctl --system`, and
    always explaining WHY).

    The registry is applied as a normalization pass at result-collection time
    (see the orchestrator). Each check keeps its own framework control ID and
    message; only the remediation text is normalized - and only when the
    topic is classified with high confidence AND the fix is genuinely
    value-independent across frameworks. Topics whose remediation legitimately
    carries a framework-specific value (e.g. PASS_MAX_DAYS, which CIS sets to
    365, PCI/CMMC to 90, STIG to 60) are NOT force-normalized; instead a
    consistent FORMAT is encouraged at authoring time.

PARAMETERS
    classify_topic(message, category, remediation) -> Optional[str]
    canonical_for(topic) -> Optional[str]
    normalize_remediation(message, category, remediation) -> str
    all_topics() -> List[str]
    topic_index() -> Dict[str, dict]   # for the cross-map index document

NOTES
    Version: 3.9
    Stdlib only. Pure functions; no I/O.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional


def _sysctl(settings: Dict[str, str], rationale: str,
            conf_name: str = "99-hardening") -> str:
    """Build a consistent, robust sysctl remediation block.

    Always: set at runtime, persist under /etc/sysctl.d/, apply with
    `sysctl --system`, and state the rationale.
    """
    runtime = "\n".join(f"  sysctl -w {k}={v}" for k, v in settings.items())
    persist = "\n".join(f"  {k} = {v}" for k, v in settings.items())
    return (
        f"{rationale}\n"
        f"Apply now:\n{runtime}\n"
        f"Persist across reboots in /etc/sysctl.d/{conf_name}.conf:\n"
        f"{persist}\n"
        f"Then reload: sysctl --system"
    )


# ---------------------------------------------------------------------------
# Canonical remediation registry.
# Each entry: topic -> {"remediation": <text>, "value_independent": bool,
#                       "summary": <short>, "keywords": [regex,...]}
# value_independent=True topics are safe to force-normalize (the fix is the
# same regardless of framework). value_independent=False are classified for
# the cross-map index but NOT force-overwritten.
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, dict] = {
    # ---- sysctl network hardening (value-independent) ----
    "ip_forwarding": {
        "summary": "Disable IP forwarding on non-router hosts",
        "value_independent": True,
        "keywords": [r"ip_forward", r"ip forwarding"],
        "remediation": _sysctl(
            {"net.ipv4.ip_forward": "0", "net.ipv6.conf.all.forwarding": "0"},
            "Disable IP forwarding unless this host is an intended router/"
            "gateway. Forwarding lets the host route packets between networks, "
            "which can bypass segmentation controls.",
            "99-network-hardening",
        ),
    },
    "syn_cookies": {
        "summary": "Enable TCP SYN cookies",
        "value_independent": True,
        "keywords": [r"syncookies", r"syn cookie", r"syn flood"],
        "remediation": _sysctl(
            {"net.ipv4.tcp_syncookies": "1"},
            "Enable TCP SYN cookies to harden against SYN-flood denial-of-"
            "service attacks.",
            "99-network-hardening",
        ),
    },
    "icmp_redirects": {
        "summary": "Disable ICMP redirect accept/send",
        "value_independent": True,
        "keywords": [r"accept_redirects", r"send_redirects", r"icmp redirect"],
        "remediation": _sysctl(
            {
                "net.ipv4.conf.all.accept_redirects": "0",
                "net.ipv4.conf.default.accept_redirects": "0",
                "net.ipv6.conf.all.accept_redirects": "0",
                "net.ipv4.conf.all.send_redirects": "0",
                "net.ipv4.conf.default.send_redirects": "0",
            },
            "Disable acceptance and sending of ICMP redirects. Accepting "
            "redirects allows an attacker to alter routing; sending them is "
            "only needed on routers.",
            "99-network-hardening",
        ),
    },
    "source_routing": {
        "summary": "Disable source-routed packet acceptance",
        "value_independent": True,
        "keywords": [r"accept_source_route", r"source rout"],
        "remediation": _sysctl(
            {
                "net.ipv4.conf.all.accept_source_route": "0",
                "net.ipv4.conf.default.accept_source_route": "0",
                "net.ipv6.conf.all.accept_source_route": "0",
                "net.ipv6.conf.default.accept_source_route": "0",
            },
            "Disable acceptance of source-routed packets. Source routing lets "
            "a sender dictate the path a packet takes and can be used to "
            "bypass network controls.",
            "99-network-hardening",
        ),
    },
    "rp_filter": {
        "summary": "Enable reverse-path filtering",
        "value_independent": True,
        "keywords": [r"rp_filter", r"reverse path", r"martian"],
        "remediation": _sysctl(
            {
                "net.ipv4.conf.all.rp_filter": "1",
                "net.ipv4.conf.default.rp_filter": "1",
            },
            "Enable strict reverse-path filtering so the kernel drops packets "
            "whose source address is not reachable via the receiving "
            "interface (anti-spoofing).",
            "99-network-hardening",
        ),
    },
    "aslr": {
        "summary": "Enable full ASLR",
        "value_independent": True,
        "keywords": [r"randomize_va_space", r"\baslr\b",
                     r"address space layout randomization"],
        "remediation": _sysctl(
            {"kernel.randomize_va_space": "2"},
            "Enable full Address Space Layout Randomization (value 2 = "
            "randomize stack, heap, mmap, and brk). ASLR is a foundational "
            "exploit mitigation. If the prelink package is installed, remove "
            "it (it defeats ASLR): prelink -ua && (apt-get purge -y prelink | "
            "dnf remove -y prelink). For kernel ASLR (KASLR), ensure 'nokaslr' "
            "is NOT present on the GRUB kernel command line.",
            "99-memory-hardening",
        ),
    },
    "core_dumps": {
        "summary": "Restrict core dumps",
        "value_independent": True,
        "keywords": [r"suid_dumpable", r"core dump", r"core_pattern",
                     r"coredump"],
        "remediation": (
            "Restrict core dumps to prevent leaking memory contents (which "
            "may contain secrets) and to stop SUID programs from dumping:\n"
            "Disable SUID core dumps (sysctl): \n"
            "  sysctl -w fs.suid_dumpable=0\n"
            "Persist in /etc/sysctl.d/99-coredump.conf:\n"
            "  fs.suid_dumpable = 0\n"
            "Disable core dumps for all users in /etc/security/limits.d/"
            "99-coredump.conf:\n"
            "  * hard core 0\n"
            "  * soft core 0\n"
            "If systemd-coredump is present, also set Storage=none in "
            "/etc/systemd/coredump.conf. Then: sysctl --system"
        ),
    },
    # ---- SSH (value-independent core directives) ----
    "ssh_root_login": {
        "summary": "Disable direct root login over SSH",
        "value_independent": True,
        "keywords": [r"permitrootlogin", r"root login.*ssh", r"ssh.*root login"],
        "remediation": (
            "Disable direct root login over SSH. Set in /etc/ssh/sshd_config "
            "(or a drop-in under /etc/ssh/sshd_config.d/):\n"
            "  PermitRootLogin no\n"
            "Use 'prohibit-password' instead only if key-only root login is "
            "explicitly required. Administrators should log in as a normal "
            "user and escalate with sudo. Apply with:\n"
            "  systemctl reload sshd   (or: systemctl reload ssh)"
        ),
    },
    "ssh_password_auth": {
        "summary": "Disable SSH password authentication (prefer keys)",
        "value_independent": True,
        "keywords": [r"passwordauthentication", r"ssh password auth"],
        "remediation": (
            "Prefer key-based authentication and disable password auth over "
            "SSH. In /etc/ssh/sshd_config (or a drop-in under "
            "/etc/ssh/sshd_config.d/):\n"
            "  PasswordAuthentication no\n"
            "  PubkeyAuthentication yes\n"
            "Ensure authorized keys are deployed for required users BEFORE "
            "applying, then: systemctl reload sshd"
        ),
    },
    # ---- empty / null passwords ----
    "empty_passwords": {
        "summary": "Eliminate empty/null passwords",
        "value_independent": True,
        "keywords": [r"empty password", r"nullok", r"passwordless",
                     r"blank password"],
        "remediation": (
            "Eliminate empty passwords. Identify affected accounts:\n"
            "  awk -F: '($2==\"\"){print $1}' /etc/shadow\n"
            "Lock or set a password for each: passwd -l <user>  (or assign a "
            "strong password). Remove any 'nullok' option from PAM "
            "configuration in /etc/pam.d/ (e.g. pam_unix.so lines) so blank "
            "passwords are never accepted."
        ),
    },
    # ---- legacy/cleartext services ----
    "legacy_services": {
        "summary": "Remove legacy cleartext services",
        "value_independent": True,
        "keywords": [r"\btelnet\b", r"\brsh\b", r"\brlogin\b", r"\btftp\b",
                     r"\bfinger\b", r"\btalk\b", r"rexec"],
        "remediation": (
            "Remove legacy cleartext services (telnet, rsh/rlogin, tftp, "
            "finger, talk) - they transmit credentials and data in plaintext. "
            "Use SSH/SFTP instead. Disable any inetd/xinetd entries, then "
            "remove the packages (OS-aware):\n"
            "  Debian/Ubuntu: apt-get purge -y telnetd rsh-server tftpd-hpa "
            "finger talkd\n"
            "  RHEL/Fedora:   dnf remove -y telnet-server rsh-server tftp-"
            "server finger-server talk-server\n"
            "Verify nothing is still listening: ss -tlnp"
        ),
    },
    # ---- value-bearing topics: classified for the index but NOT
    #      force-normalized (the value is framework-specific) ----
    "password_max_days": {
        "summary": "Maximum password age (framework-specific value)",
        "value_independent": False,
        "keywords": [r"pass_max_days", r"maximum password age"],
        "remediation": (
            "Set the maximum password age in /etc/login.defs (PASS_MAX_DAYS) "
            "to your framework's required value, then apply it to existing "
            "accounts with: chage --maxdays <N> <user>. (Note: NIST SP 800-63B "
            "and PCI DSS v4.0.1 8.3.9 permit longer/again-less-frequent "
            "rotation when phishing-resistant MFA and monitoring are in place.)"
        ),
    },
    "password_min_days": {
        "summary": "Minimum password age (framework-specific value)",
        "value_independent": False,
        "keywords": [r"pass_min_days", r"minimum password age"],
        "remediation": (
            "Set the minimum password age in /etc/login.defs (PASS_MIN_DAYS) "
            "to your framework's required value and apply to existing accounts "
            "with: chage --mindays <N> <user>."
        ),
    },
    "umask": {
        "summary": "Default umask (framework-specific value)",
        "value_independent": False,
        "keywords": [r"\bumask\b"],
        "remediation": (
            "Set a restrictive default umask. In /etc/login.defs set "
            "UMASK 027 (or 077 for stricter privacy-by-default), and ensure "
            "/etc/profile.d/ and /etc/bashrc apply the same. 027 prevents "
            "group/other write and other read on new files; 077 restricts to "
            "the owner entirely."
        ),
    },
    "password_complexity": {
        "summary": "Password complexity (framework-specific values)",
        "value_independent": False,
        "keywords": [r"pwquality", r"password complexity", r"minlen",
                     r"cracklib"],
        "remediation": (
            "Configure password quality in /etc/security/pwquality.conf (e.g. "
            "minlen, minclass/dcredit/ucredit/lcredit/ocredit) to your "
            "framework's requirements and enforce via pam_pwquality in "
            "/etc/pam.d/. Prefer length (>=14) over complex character-class "
            "rules per modern guidance (NIST 800-63B)."
        ),
    },
    # ---- v3.9 additional value-independent topics ----
    "ntp_time_sync": {
        "summary": "Enable authenticated time synchronization",
        "value_independent": True,
        "keywords": [r"\bntp\b", r"chrony", r"time synchron", r"timesyncd",
                     r"time sync", r"time source"],
        "remediation": (
            "Enable an authenticated, monotonic time source so audit "
            "timestamps, certificate validation, and Kerberos remain "
            "reliable. Prefer chrony:\n"
            "Install (OS-aware): apt-get install -y chrony | dnf install -y "
            "chrony | zypper install -y chrony\n"
            "Configure /etc/chrony/chrony.conf (Debian) or /etc/chrony.conf "
            "(RHEL) with authenticated upstreams:\n"
            "  server time.cloudflare.com iburst nts\n"
            "  pool pool.ntp.org iburst\n"
            "  makestep 1.0 3\n"
            "  rtcsync\n"
            "Enable and start: systemctl enable --now chronyd (RHEL) or "
            "chrony (Debian/Ubuntu). Verify: chronyc tracking; chronyc "
            "sources. Run exactly one time daemon - if using chrony, disable "
            "systemd-timesyncd."
        ),
    },
    "password_hashing": {
        "summary": "Strong password hashing algorithm",
        "value_independent": True,
        "keywords": [r"encrypt_method", r"yescrypt",
                     r"sha_crypt", r"password hash", r"hashing algorithm",
                     r"hashing round"],
        "remediation": (
            "Use a strong password-hashing algorithm. On modern Debian/Ubuntu "
            "(libpam >= 1.5) and Fedora, prefer yescrypt; otherwise SHA-512.\n"
            "In /etc/login.defs:\n"
            "  ENCRYPT_METHOD YESCRYPT      (or SHA512 where yescrypt is "
            "unavailable)\n"
            "  SHA_CRYPT_MIN_ROUNDS 100000  (applies to SHA512 only)\n"
            "Ensure the PAM password stack's pam_unix.so uses the matching "
            "option (yescrypt or sha512). Existing passwords are re-hashed on "
            "next change; force rotation for sensitive accounts: "
            "chage -d 0 <user>."
        ),
    },
    "ssh_strong_crypto": {
        "summary": "Restrict SSH to strong ciphers/MACs/KEX",
        "value_independent": True,
        "keywords": [r"kexalgorithm", r"\bciphers\b", r"ssh.*\bmacs\b",
                     r"ssh.*cipher", r"weak.*ssh.*(cipher|mac|algorithm)",
                     r"strong.*ssh.*(cipher|mac|kex)",
                     r"ssh.*key exchange"],
        "remediation": (
            "Restrict SSH to strong, modern cryptographic primitives. Use a "
            "drop-in (/etc/ssh/sshd_config.d/50-crypto.conf) so it survives "
            "package upgrades:\n"
            "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
            "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n"
            "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh."
            "com,umac-128-etm@openssh.com\n"
            "  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
            "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\n"
            "Remove all CBC ciphers, arcfour, 3des, and MD5/SHA1 MACs, and DH "
            "group1/group14-sha1. Validate and reload:\n"
            "  sshd -t && systemctl reload sshd\n"
            "(For CNSA 2.0 environments, restrict to aes256-gcm and "
            "hmac-sha2-512 only.)"
        ),
    },
    "mac_enforcement": {
        "summary": "Enable Mandatory Access Control in enforcing mode",
        "value_independent": True,
        "keywords": [
            r"selinux.*(enforc|disabled|permissive|not active|inactive)",
            r"(enforc|enable).*selinux",
            r"apparmor.*(enforc|disabled|not active|inactive|not loaded)",
            r"(enforc|enable).*apparmor",
            r"mandatory access control",
            r"\bmac\b.{0,12}(enforc|active|framework|not)",
        ],
        "remediation": (
            "Enable kernel-enforced access/execution control.\n"
            "Mandatory Access Control (MAC):\n"
            "  RHEL/Fedora/SUSE (SELinux): set SELINUX=enforcing in "
            "/etc/selinux/config, ensure no 'selinux=0' or 'enforcing=0' on "
            "the GRUB kernel cmdline, then setenforce 1 (reboot to apply "
            "persistently). Verify: getenforce.\n"
            "  Debian/Ubuntu (AppArmor): systemctl enable --now apparmor; "
            "enforce all profiles: aa-enforce /etc/apparmor.d/*. Verify: "
            "aa-status.\n"
            "Application allowlisting (defense-in-depth execution control):\n"
            "  RHEL family: dnf install -y fapolicyd && systemctl enable "
            "--now fapolicyd (allowlist trusted paths/packages).\n"
            "  Or rely on a strict SELinux/AppArmor policy that confines "
            "every daemon.\n"
            "Do not disable the MAC layer to clear denials - create targeted "
            "policy modules or set the appropriate booleans instead."
        ),
    },
    "mount_options": {
        "summary": "Restrictive mount options (nodev/nosuid/noexec)",
        "value_independent": True,
        "keywords": [r"\bnodev\b", r"\bnosuid\b", r"\bnoexec\b",
                     r"mount option"],
        "remediation": (
            "Apply restrictive mount options to non-root, user-writable, and "
            "pseudo filesystems so they cannot host executables, setuid "
            "binaries, or device nodes. In /etc/fstab (or a systemd .mount "
            "unit) add nodev,nosuid,noexec as appropriate:\n"
            "  tmpfs  /dev/shm  tmpfs  defaults,nodev,nosuid,noexec  0 0\n"
            "  tmpfs  /tmp      tmpfs  defaults,nodev,nosuid,noexec  0 0\n"
            "  <dev>  /var/tmp  <fs>   defaults,nodev,nosuid,noexec  0 0\n"
            "  <dev>  /home     <fs>   defaults,nodev,nosuid           0 2\n"
            "(/home usually keeps exec for user scripts.) Apply without "
            "reboot: mount -o remount <mountpoint>. /tmp may need a dedicated "
            "partition or the tmp.mount unit: systemctl enable --now "
            "tmp.mount."
        ),
    },
    "grub_password": {
        "summary": "Set a GRUB bootloader password",
        "value_independent": True,
        "keywords": [r"grub.{0,15}password", r"bootloader password",
                     r"boot.{0,5}password", r"grub2-setpassword",
                     r"grub-mkpasswd", r"single-user mode"],
        "remediation": (
            "Set a bootloader (GRUB) superuser password so an attacker with "
            "console access cannot edit kernel parameters or enter "
            "single-user mode to bypass controls.\n"
            "RHEL/Fedora: grub2-setpassword (writes /boot/grub2/user.cfg).\n"
            "Debian/Ubuntu: grub-mkpasswd-pbkdf2 to generate a hash, then in "
            "/etc/grub.d/40_custom add:\n"
            "  set superusers=\"root\"\n"
            "  password_pbkdf2 root <generated-hash>\n"
            "Regenerate config: update-grub (Debian) or grub2-mkconfig -o "
            "/boot/grub2/grub.cfg (RHEL). Restrict the config file: chmod 600 "
            "/boot/grub/grub.cfg."
        ),
    },
    # ---- value-bearing (classified for the index, not force-overwritten) ----
    "ssh_idle_timeout": {
        "summary": "SSH idle session timeout (framework-specific value)",
        "value_independent": False,
        "keywords": [r"clientaliveinterval", r"ssh.*idle", r"ssh.*timeout"],
        "remediation": (
            "Configure an SSH idle session timeout to your policy's maximum "
            "(commonly 300-900 seconds). In /etc/ssh/sshd_config (or a "
            "drop-in): ClientAliveInterval <seconds>; ClientAliveCountMax 0 "
            "(terminate on first missed probe). Apply: systemctl reload sshd. "
            "Optionally enforce a shell TMOUT in /etc/profile.d/ for non-SSH "
            "sessions."
        ),
    },
    "account_lockout": {
        "summary": "Account lockout via pam_faillock (framework-specific value)",
        "value_independent": False,
        "keywords": [r"faillock", r"pam_tally", r"account lockout",
                     r"lockout.*(fail|threshold|account)", r"failed login"],
        "remediation": (
            "Configure account lockout via pam_faillock to your framework's "
            "threshold. In /etc/security/faillock.conf set deny=<N> and "
            "unlock_time=<seconds> (e.g. deny=5, unlock_time=900). Ensure "
            "pam_faillock.so is in the auth stack: RHEL family via "
            "'authselect enable-feature with-faillock' (or /etc/pam.d/"
            "system-auth); Debian/Ubuntu via /etc/pam.d/common-auth. Verify "
            "with: faillock."
        ),
    },
    # ---- v3.9 finer-grained sub-topics (auditd) ----
    # NOTE: ordered specific-first so a log/immutable/retention check is not
    # swallowed by the broader service-enable topic. The distinct per-event
    # audit RULES (time-change, identity, logins, execve, ...) and the
    # framework-specific ruleset CHOICE (CIS vs MITRE ATT&CK vs custom) are
    # intentionally NOT unified - they carry each framework's specific intent.
    "auditd_rules_immutable": {
        "summary": "Make the audit ruleset immutable (-e 2)",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"audit.*immutab", r"immutab.*audit",
                     r"ruleset (immutab|locked)", r"\(-e 2\)",
                     r"auditd immutable"],
        "remediation": (
            "Make the audit configuration immutable so rules cannot be "
            "changed at runtime without a reboot (tamper resistance). Add "
            "'-e 2' as the LAST line of the final rules file:\n"
            "  echo '-e 2' > /etc/audit/rules.d/99-finalize.rules\n"
            "Reload: augenrules --load (a reboot is then required to change "
            "rules again). Verify: auditctl -s | grep enabled  (expect 2).\n"
            "For additional tamper resistance, also make the on-disk audit "
            "logs append-only/immutable: chattr +a /var/log/audit/audit.log "
            "(or +i on rotated logs)."
        ),
    },
    "auditd_log_permissions": {
        "summary": "Restrict audit log file permissions",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"audit\.?log.*(perm|mode|0600)", r"log_file_mode",
                     r"audit log file perm", r"permission.*audit\.?log",
                     r"chmod.*audit\.?log"],
        "remediation": (
            "Restrict access to the audit logs so only root can read them.\n"
            "  chmod 0600 /var/log/audit/audit.log\n"
            "  chown root:root /var/log/audit/audit.log\n"
            "In /etc/audit/auditd.conf set: log_file_mode = 0600\n"
            "Restart: systemctl restart auditd."
        ),
    },
    "auditd_log_retention": {
        "summary": "Bound audit log retention (framework-specific value)",
        "value_independent": False,
        "message_only": True,
        "keywords": [r"max_log_file", r"num_logs", r"audit log rotation",
                     r"audit log storage size", r"auditd.*retention",
                     r"keep_logs"],
        "remediation": (
            "Bound audit log retention to your framework's requirement. In "
            "/etc/audit/auditd.conf set max_log_file (MB per file), num_logs "
            "(rotated files kept), and max_log_file_action = keep_logs (or "
            "rotate). For long-term retention, forward logs to centralized "
            "storage rather than relying solely on local rotation; ensure "
            "/etc/logrotate.d covers audit logs if logrotate manages them. "
            "Restart auditd to apply."
        ),
    },
    "auditd_failure_action": {
        "summary": "Audit storage-failure action (framework-specific value)",
        "value_independent": False,
        "message_only": True,
        "keywords": [r"disk_full_action", r"space_left", r"admin_space",
                     r"audit.*failure action", r"audit.*disk-full",
                     r"fail-safe action"],
        "remediation": (
            "Configure auditd's behavior when audit storage is exhausted, per "
            "your framework's tolerance. In /etc/audit/auditd.conf set "
            "space_left_action (e.g. email/syslog), admin_space_left_action "
            "(e.g. single/halt), and disk_full_action (halt for strict "
            "environments, or syslog where halting is operationally "
            "unacceptable). Restart auditd to apply."
        ),
    },
    "auditd_service_enable": {
        "summary": "Install and enable the audit daemon",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"audit daemon",
                     r"auditd (service|package|installed|enabled|active|"
                     r"running)",
                     r"auditd.*(not running|inactive)",
                     r"auditd.*currently running",
                     r"audit (logging|infrastructure).*(active|service)",
                     r"system audit logging active",
                     r"auditing.*enabled", r"auditing for processes prior",
                     r"audit.*service.*(active|enabled|running)",
                     r"kernel audit system enabled"],
        "remediation": (
            "Install and enable the Linux Audit daemon so security-relevant "
            "events are recorded.\n"
            "Install (OS-aware): apt-get install -y auditd audispd-plugins | "
            "dnf install -y audit | zypper install -y audit\n"
            "Enable at boot and start now: systemctl enable --now auditd\n"
            "To capture events occurring before auditd starts, add to the "
            "GRUB kernel cmdline (GRUB_CMDLINE_LINUX in /etc/default/grub): "
            "audit=1 audit_backlog_limit=8192, then regenerate grub config. "
            "Verify: systemctl is-active auditd; auditctl -s."
        ),
    },
    # ---- v3.9 finer-grained sub-topics (rsyslog) ----
    # PII-redaction (mmanon) is GDPR-specific intent and stays separate.
    "rsyslog_service_enable": {
        "summary": "Install and enable rsyslog",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"rsyslog.*(active|running|installed|enabled|"
                     r"not running|inactive|\bservice\b|generate log)",
                     r"enable.*rsyslog", r"install.*rsyslog",
                     r"start.*rsyslog"],
        "remediation": (
            "Install and enable rsyslog so system and security events are "
            "recorded.\n"
            "Install (OS-aware): apt-get install -y rsyslog | dnf install -y "
            "rsyslog | zypper install -y rsyslog\n"
            "Enable at boot and start now: systemctl enable --now rsyslog\n"
            "Verify: systemctl is-active rsyslog."
        ),
    },
    "rsyslog_remote_forward": {
        "summary": "Forward logs to a central server / SIEM",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"remote logging", r"remote syslog", r"log forward",
                     r"forward.*(log|siem|central)", r"centralized log",
                     r"central.*log server", r"rsyslog.*(forward|remote)",
                     r"@@.*:[0-9]", r"\bomfwd\b", r"siem.*forward",
                     r"log.*forward.*(siem|server|central)"],
        "remediation": (
            "Forward logs to a central log server / SIEM so they survive host "
            "compromise and support correlation. In "
            "/etc/rsyslog.d/50-remote.conf, prefer encrypted forwarding over "
            "TCP/6514:\n"
            "  *.* action(type=\"omfwd\" target=\"logserver.example.com\" "
            "port=\"6514\" protocol=\"tcp\"\n"
            "            StreamDriver=\"gtls\" StreamDriverMode=\"1\" "
            "StreamDriverAuthMode=\"x509/name\")\n"
            "(Plain TCP without TLS: *.* @@logserver.example.com:514 ; UDP: "
            "*.* @logserver.example.com:514.) Provision the client "
            "certificate/CA for TLS, then restart: systemctl restart rsyslog."
        ),
    },
    # ---- v3.9 finer-grained sub-topics (SSH directives) ----
    "ssh_x11_forwarding": {
        "summary": "Disable SSH X11 forwarding",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"x11forwarding", r"x11 forwarding"],
        "remediation": (
            "Disable SSH X11 forwarding unless explicitly required - it "
            "exposes the server's X display to connecting clients. In "
            "/etc/ssh/sshd_config (or a drop-in): X11Forwarding no. Apply: "
            "systemctl reload sshd."
        ),
    },
    "ssh_permit_empty_passwords": {
        "summary": "Disallow SSH login to empty-password accounts",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"permitemptypasswords", r"ssh.*empty password"],
        "remediation": (
            "Never allow SSH logins to accounts with empty passwords. In "
            "/etc/ssh/sshd_config (or a drop-in): PermitEmptyPasswords no. "
            "Apply: systemctl reload sshd. Also ensure no account actually "
            "has an empty password."
        ),
    },
    "ssh_banner": {
        "summary": "Present a pre-authentication SSH banner",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"ssh.*banner", r"banner.*sshd",
                     r"banner /etc/issue\.net"],
        "remediation": (
            "Present an authorized-use banner before SSH authentication. In "
            "/etc/ssh/sshd_config: Banner /etc/issue.net, and populate "
            "/etc/issue.net with your organization's approved legal warning. "
            "Apply: systemctl reload sshd."
        ),
    },
    "ssh_protocol": {
        "summary": "Use only SSH protocol version 2",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"ssh.*protocol [12]", r"protocol version 2",
                     r"\bprotocol 2\b", r"\bprotocol 1\b"],
        "remediation": (
            "Use only SSH protocol version 2 (version 1 is cryptographically "
            "broken). Modern OpenSSH supports only v2, but if 'Protocol' is "
            "set explicitly in /etc/ssh/sshd_config, ensure it reads: "
            "Protocol 2 (remove any 'Protocol 1' or '1,2'). Apply: systemctl "
            "reload sshd."
        ),
    },
    "ssh_login_grace": {
        "summary": "Limit SSH login grace time",
        "value_independent": True,
        "message_only": True,
        "keywords": [r"logingracetime", r"login grace"],
        "remediation": (
            "Limit the time allowed to complete SSH authentication to reduce "
            "exposure to slow brute-force and connection-slot exhaustion. In "
            "/etc/ssh/sshd_config (or a drop-in): LoginGraceTime 60. Apply: "
            "systemctl reload sshd."
        ),
    },
    "ssh_max_auth_tries": {
        "summary": "Limit SSH auth attempts (framework-specific value)",
        "value_independent": False,
        "message_only": True,
        "keywords": [r"maxauthtries", r"max auth tries",
                     r"ssh.*authentication attempts"],
        "remediation": (
            "Limit the number of authentication attempts per SSH connection "
            "to your framework's threshold. In /etc/ssh/sshd_config (or a "
            "drop-in): MaxAuthTries <N> (commonly 3-4). Apply: systemctl "
            "reload sshd."
        ),
    },
    "ssh_max_sessions": {
        "summary": "Limit SSH sessions per connection (framework value)",
        "value_independent": False,
        "message_only": True,
        "keywords": [r"maxsessions", r"ssh.*max session"],
        "remediation": (
            "Limit the number of multiplexed sessions per SSH connection to "
            "your framework's value. In /etc/ssh/sshd_config (or a drop-in): "
            "MaxSessions <N> (commonly 10). Apply: systemctl reload sshd."
        ),
    },
}

# Build a fast keyword->topic matcher (compiled regexes), preserving order so
# more specific topics are tried first.
_COMPILED = [
    (topic, [re.compile(p, re.IGNORECASE) for p in meta["keywords"]],
     bool(meta.get("message_only")))
    for topic, meta in _REGISTRY.items()
]


def classify_topic(message: str, category: str = "",
                   remediation: str = "") -> Optional[str]:
    """Classify a check into a canonical remediation topic, or None.

    High-precision: matches keyword regexes against the check text. For most
    topics the haystack is message + remediation + category. For topics
    flagged ``message_only`` (e.g. the auditd/rsyslog/ssh sub-topics, whose
    remediation text is frequently a shared multi-line block reused across
    many distinct checks), only message + category is matched - the
    remediation field is too noisy to be a reliable signal there.
    """
    full = " ".join([message or "", remediation or "", category or ""])
    msg_only = " ".join([message or "", category or ""])
    for topic, patterns, message_only in _COMPILED:
        hay = msg_only if message_only else full
        for pat in patterns:
            if pat.search(hay):
                return topic
    return None


def canonical_for(topic: str) -> Optional[str]:
    """Return the canonical remediation text for a topic, or None."""
    meta = _REGISTRY.get(topic)
    return meta["remediation"] if meta else None


def is_value_independent(topic: str) -> bool:
    meta = _REGISTRY.get(topic)
    return bool(meta and meta.get("value_independent"))


def normalize_remediation(message: str, category: str,
                          remediation: str) -> str:
    """Return the canonical remediation for a check when it is confidently
    classified into a value-independent topic; otherwise return the original
    remediation unchanged.

    This is the normalization pass applied by the orchestrator so the same
    fix reads identically across every framework.
    """
    topic = classify_topic(message, category, remediation)
    if topic and is_value_independent(topic):
        canon = canonical_for(topic)
        if canon:
            return canon
    return remediation


def all_topics() -> List[str]:
    return list(_REGISTRY.keys())


def topic_index() -> Dict[str, dict]:
    """Return the full registry (for generating the cross-map index doc)."""
    return {t: dict(m) for t, m in _REGISTRY.items()}
