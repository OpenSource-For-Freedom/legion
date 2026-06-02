/*
 * Legion baseline YARA rules — Windows.
 */

rule Windows_PE_Header
{
    meta:
        description = "PE/DOS executable header (informational; pairs with heuristics)"
        severity = "Info"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz
}

rule Windows_PowerShell_Encoded
{
    meta:
        description = "Obfuscated/encoded PowerShell execution"
        severity = "High"
    strings:
        $enc1 = "powershell -enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $enc3 = "-nop -w hidden" nocase
        $enc4 = "IEX (New-Object Net.WebClient)" nocase
    condition:
        any of them
}

rule Windows_Download_Cradle
{
    meta:
        description = "Native download cradle APIs used by droppers"
        severity = "Medium"
    strings:
        $mz  = { 4D 5A }
        $u1  = "URLDownloadToFile" nocase
        $u2  = "WinHttpConnect" nocase
        $u3  = "InternetOpenUrl" nocase
    condition:
        $mz and (any of ($u1, $u2, $u3))
}

rule Windows_Persistence_Run_Key
{
    meta:
        description = "Registry Run-key persistence"
        severity = "Medium"
    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "reg add" nocase
    condition:
        $run1 and $run2
}
