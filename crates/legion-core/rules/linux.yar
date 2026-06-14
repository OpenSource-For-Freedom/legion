/*
 * Legion baseline YARA rules — Linux.
 */

rule Linux_ELF_Header
{
    meta:
        description = "ELF executable header (informational; pairs with heuristics)"
        severity = "Info"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf
}

rule Linux_LD_Preload_Hijack
{
    meta:
        description = "Possible LD_PRELOAD shared-object hijack (T1574.006)"
        severity = "High"
    strings:
        $pre = "LD_PRELOAD="
        $so  = ".so"
        $etc = "/etc/ld.so.preload"
    condition:
        ($pre and $so) or $etc
}

rule Linux_Cron_Persistence
{
    meta:
        description = "Cron-based persistence fetching and executing remote code (T1053.003)"
        severity = "High"
    strings:
        $cron = "* * * * *"
        $curl = "curl " nocase
        $wget = "wget " nocase
        $sh   = "| sh"
    condition:
        $cron and (any of ($curl, $wget)) and $sh
}

rule Linux_Disable_History
{
    meta:
        description = "Shell history tampering (anti-forensics, T1070.003)"
        severity = "Medium"
    strings:
        $h1 = "unset HISTFILE"
        $h2 = "export HISTSIZE=0"
        $h3 = "history -c"
        $h4 = "HISTFILE=/dev/null"
        $h5 = "set +o history"
    condition:
        any of them
}

rule Linux_Reverse_Shell
{
    meta:
        description = "Language-specific reverse shells on Linux (T1059)"
        severity = "Critical"
    strings:
        $a = "socket.socket(socket.AF_INET" nocase
        $b = "os.dup2(s.fileno()"
        $c = "subprocess.call([\"/bin/sh\""
        $d = "perl -e 'use Socket"
        $e = "php -r '$sock=fsockopen"
        $f = "ruby -rsocket"
        $g = "mkfifo /tmp/"
        $h = "/bin/sh -i"
    condition:
        2 of them
}

rule Linux_Systemd_Persistence
{
    meta:
        description = "systemd unit persistence executing remote/staged payload (T1543.002)"
        severity = "High"
    strings:
        $svc1 = "/etc/systemd/system/"
        $svc2 = ".config/systemd/user/"
        $exec = "ExecStart="
        $curl = "curl " nocase
        $wget = "wget " nocase
        $tmp  = "ExecStart=/tmp/"
        $shm  = "ExecStart=/dev/shm/"
    condition:
        ((any of ($svc1, $svc2)) and $exec and (any of ($curl, $wget))) or $tmp or $shm
}

rule Linux_Profile_Persistence
{
    meta:
        description = "Persistence via shell rc / profile files (T1546.004)"
        severity = "Medium"
    strings:
        $f1 = "/etc/rc.local"
        $f2 = "/etc/profile.d/"
        $f3 = ".bashrc"
        $f4 = ".bash_profile"
        $f5 = ".zshrc"
        $curl = "curl " nocase
        $wget = "wget " nocase
        $b64  = "base64 -d" nocase
    condition:
        (any of ($f1, $f2, $f3, $f4, $f5)) and (any of ($curl, $wget, $b64))
}

rule Linux_SSH_AuthorizedKeys_Tamper
{
    meta:
        description = "Backdoor SSH key injection into authorized_keys (T1098.004)"
        severity = "High"
    strings:
        $ak  = ".ssh/authorized_keys"
        $app = ">>"
        $key = "ssh-rsa "
        $ed  = "ssh-ed25519 "
        $echo = "echo "
    condition:
        $ak and ($app or $echo) and (any of ($key, $ed))
}

rule Linux_Rootkit_Indicators
{
    meta:
        description = "Userland/LKM rootkit indicators (T1014)"
        severity = "Critical"
    strings:
        $r1 = "diamorphine" nocase
        $r2 = "/proc/modules"
        $r3 = "ld.so.preload"
        $r4 = "PROC_HIDE"
        $r5 = "hide_module"
        $r6 = "kill -31"
        $r7 = "kill -63"
        $r8 = "MAGIC_PREFIX"
    condition:
        2 of them
}

rule Linux_Kernel_Module_Load
{
    meta:
        description = "Kernel module load/unload activity (T1547.006)"
        severity = "Medium"
    strings:
        $m1 = "insmod " nocase
        $m2 = "modprobe " nocase
        $m3 = "rmmod " nocase
        $m4 = "init_module"
        $m5 = "finit_module"
        $ko = ".ko"
    condition:
        (any of ($m1, $m2, $m3, $m4, $m5)) and $ko
}

rule Linux_Audit_Log_Tamper
{
    meta:
        description = "Disabling/clearing audit, journal or logs (T1562.001/T1070)"
        severity = "High"
    strings:
        $a1 = "auditctl -e 0"
        $a2 = "systemctl stop auditd"
        $a3 = "service auditd stop"
        $a4 = "journalctl --vacuum"
        $a5 = "rm -rf /var/log/"
        $a6 = "truncate -s 0 /var/log/"
        $a7 = "> /var/log/"
    condition:
        any of them
}

rule Linux_Defense_Evasion
{
    meta:
        description = "Disabling host defenses / firewall / SELinux (T1562)"
        severity = "High"
    strings:
        $d1 = "setenforce 0"
        $d2 = "SELINUX=disabled"
        $d3 = "systemctl stop firewalld"
        $d4 = "ufw disable"
        $d5 = "iptables -F"
        $d6 = "chattr +i"
        $d7 = "aa-disable"
    condition:
        any of them
}

rule Linux_Privilege_Escalation
{
    meta:
        description = "SUID/capability privilege-escalation tradecraft (T1548)"
        severity = "High"
    strings:
        $p1 = "find / -perm -4000"
        $p2 = "chmod u+s "
        $p3 = "chmod 4755 "
        $p4 = "setcap cap_setuid"
        $p5 = "cap_sys_admin+ep"
        $p6 = "/etc/sudoers.d/"
        $p7 = "nopasswd: all" nocase
    condition:
        2 of them
}

rule Linux_Container_Escape
{
    meta:
        description = "Container breakout / Docker socket abuse (T1611)"
        severity = "Critical"
    strings:
        $c1 = "/var/run/docker.sock"
        $c2 = "docker.sock"
        $c3 = "release_agent"
        $c4 = "/sys/fs/cgroup"
        $c5 = "nsenter --target 1"
        $c6 = "--privileged"
        $c7 = "cap_sys_admin"
    condition:
        ($c1 or $c2) or ($c3 and $c4) or $c5 or ($c6 and $c7)
}

rule Linux_Fileless_Exec
{
    meta:
        description = "In-memory / fileless execution primitives (T1620)"
        severity = "High"
    strings:
        $m1 = "memfd_create"
        $m2 = "/dev/shm/"
        $m3 = "/proc/self/fd/"
        $m4 = "ld-linux"
        $m5 = "--library-path"
    condition:
        $m1 or ($m2 and $m3) or ($m4 and $m5)
}
