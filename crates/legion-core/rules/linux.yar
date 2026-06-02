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
