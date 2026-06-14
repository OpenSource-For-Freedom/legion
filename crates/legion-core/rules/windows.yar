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
        description = "Obfuscated/encoded PowerShell execution (T1059.001/T1027)"
        severity = "High"
    strings:
        $enc1 = "powershell -enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $enc3 = "-nop -w hidden" nocase
        $enc4 = "IEX (New-Object Net.WebClient)" nocase
        $enc5 = "FromBase64String" nocase
        $enc6 = "-ExecutionPolicy Bypass" nocase
        $enc7 = "Invoke-Expression" nocase
    condition:
        any of them
}

rule Windows_Download_Cradle
{
    meta:
        description = "Native download cradle APIs used by droppers (T1105)"
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
        description = "Registry Run-key persistence (T1547.001)"
        severity = "Medium"
    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "reg add" nocase
        $run3 = "New-ItemProperty" nocase
    condition:
        $run1 and (any of ($run2, $run3))
}

rule Windows_Reverse_Shell
{
    meta:
        description = "Reverse shell tradecraft on Windows (T1059)"
        severity = "Critical"
    strings:
        $a = "System.Net.Sockets.TCPClient" nocase
        $b = "GetStream()"
        $c = "powercat" nocase
        $d = "nc.exe -e" nocase
        $e = "cmd.exe /c" nocase
        $f = "$client = New-Object System.Net.Sockets" nocase
    condition:
        ($a and $b) or $c or $d or ($f and $e)
}

rule Windows_Credential_Dumping
{
    meta:
        description = "LSASS / credential dumping (Mimikatz, T1003)"
        severity = "Critical"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::" nocase
        $m3 = "kerberos::" nocase
        $m4 = "mimikatz" nocase
        $m5 = "privilege::debug" nocase
        $l1 = "MiniDumpWriteDump" nocase
        $l2 = "comsvcs.dll, MiniDump" nocase
        $l3 = "procdump" nocase
        $l4 = "lsass.exe" nocase
    condition:
        (any of ($m1, $m2, $m3, $m4, $m5)) or ($l1 and $l4) or $l2 or ($l3 and $l4)
}

rule Windows_Defender_Tamper
{
    meta:
        description = "Disabling/excluding Microsoft Defender (T1562.001)"
        severity = "High"
    strings:
        $d1 = "Set-MpPreference -DisableRealtimeMonitoring" nocase
        $d2 = "Add-MpPreference -ExclusionPath" nocase
        $d3 = "DisableAntiSpyware" nocase
        $d4 = "sc stop WinDefend" nocase
        $d5 = "Set-MpPreference -DisableIOAVProtection" nocase
        $d6 = "MpCmdRun.exe -RemoveDefinitions" nocase
    condition:
        any of them
}

rule Windows_AMSI_Bypass
{
    meta:
        description = "AMSI bypass / patching (T1562.001)"
        severity = "High"
    strings:
        $a1 = "amsiInitFailed" nocase
        $a2 = "AmsiScanBuffer" nocase
        $a3 = "System.Management.Automation.AmsiUtils" nocase
        $a4 = "VirtualProtect" nocase
    condition:
        $a1 or $a3 or ($a2 and $a4)
}

rule Windows_UAC_Bypass
{
    meta:
        description = "UAC bypass via auto-elevating handlers (T1548.002)"
        severity = "High"
    strings:
        $u1 = "fodhelper.exe" nocase
        $u2 = "eventvwr.exe" nocase
        $u3 = "computerdefaults.exe" nocase
        $u4 = "ms-settings\\shell\\open\\command" nocase
        $u5 = "DelegateExecute" nocase
        $u6 = "sdclt.exe" nocase
    condition:
        2 of them
}

rule Windows_LOLBin_Abuse
{
    meta:
        description = "Living-off-the-land binary abuse for download/exec (T1218)"
        severity = "High"
    strings:
        $c1 = "certutil -urlcache" nocase
        $c2 = "certutil -decode" nocase
        $b1 = "bitsadmin /transfer" nocase
        $m1 = "mshta http" nocase
        $m2 = "mshta vbscript" nocase
        $r1 = "regsvr32 /s /n /u /i:http" nocase
        $r2 = "rundll32 javascript:" nocase
        $w1 = "wmic process call create" nocase
    condition:
        any of them
}

rule Windows_Scheduled_Task_Service_Persistence
{
    meta:
        description = "Scheduled-task / service persistence (T1053.005/T1543.003)"
        severity = "Medium"
    strings:
        $t1 = "schtasks /create" nocase
        $t2 = "/sc onlogon" nocase
        $t3 = "/sc onstart" nocase
        $s1 = "sc create" nocase
        $s2 = "New-Service" nocase
        $s3 = "binPath=" nocase
    condition:
        ($t1 and (any of ($t2, $t3))) or ($s1 and $s3) or $s2
}

rule Windows_Ransomware_Indicators
{
    meta:
        description = "Shadow-copy deletion / recovery sabotage (T1490)"
        severity = "Critical"
    strings:
        $v1 = "vssadmin delete shadows" nocase
        $v2 = "wbadmin delete catalog" nocase
        $v3 = "bcdedit /set" nocase
        $v4 = "recoveryenabled no" nocase
        $v5 = "wmic shadowcopy delete" nocase
        $v6 = "cipher /w:" nocase
    condition:
        any of them
}

rule Windows_SAM_Registry_Theft
{
    meta:
        description = "Offline SAM/SYSTEM hive theft (T1003.002)"
        severity = "Critical"
    strings:
        $r1 = "reg save hklm\\sam" nocase
        $r2 = "reg save hklm\\system" nocase
        $r3 = "reg save hklm\\security" nocase
    condition:
        any of them
}
