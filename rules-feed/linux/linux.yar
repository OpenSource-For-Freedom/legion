/*
 * Legion dynamic rule feed — Linux.
 * Fetched from <rules_repo>/linux/linux.yar.
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
        description = "Possible LD_PRELOAD shared-object hijack"
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
        description = "Cron-based persistence fetching and executing remote code"
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
        description = "Shell history tampering (anti-forensics)"
        severity = "Medium"
    strings:
        $h1 = "unset HISTFILE"
        $h2 = "export HISTSIZE=0"
        $h3 = "history -c"
    condition:
        any of them
}

rule Linux_SSH_AuthorizedKeys_Tamper
{
    meta:
        description = "Backdoor SSH access by writing to authorized_keys"
        severity = "High"
    strings:
        $ak = ".ssh/authorized_keys"
        $w1 = ">> "
        $w2 = "echo "
        $key = "ssh-rsa "
    condition:
        $ak and ($key or (any of ($w1, $w2)))
}

rule Linux_Bashrc_Persistence
{
    meta:
        description = "Persistence via shell rc files invoking remote payloads"
        severity = "Medium"
    strings:
        $rc1 = ".bashrc"
        $rc2 = ".bash_profile"
        $rc3 = "/etc/profile.d/"
        $net = "curl " nocase
        $net2 = "wget " nocase
    condition:
        (any of ($rc1, $rc2, $rc3)) and (any of ($net, $net2))
}
