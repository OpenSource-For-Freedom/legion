/*
 * Legion baseline YARA rules — macOS.
 */

rule MacOS_MachO_Header
{
    meta:
        description = "Mach-O executable header (informational; pairs with heuristics)"
        severity = "Info"
    strings:
        $macho32 = { CE FA ED FE }
        $macho64 = { CF FA ED FE }
        $fat     = { CA FE BA BE }
    condition:
        any of them
}

rule MacOS_LaunchAgent_Persistence
{
    meta:
        description = "LaunchAgent/Daemon persistence with remote payload (T1543.001)"
        severity = "High"
    strings:
        $plist = "<key>RunAtLoad</key>"
        $la    = "Library/LaunchAgents"
        $ld    = "Library/LaunchDaemons"
        $curl  = "curl " nocase
    condition:
        (any of ($la, $ld)) and ($plist or $curl)
}

rule MacOS_Osascript_Abuse
{
    meta:
        description = "osascript used to spawn shells or prompt for credentials (T1059.002)"
        severity = "High"
    strings:
        $os1 = "osascript -e" nocase
        $os2 = "do shell script" nocase
        $os3 = "with administrator privileges" nocase
    condition:
        $os1 and (any of ($os2, $os3))
}

rule MacOS_TCC_Tamper
{
    meta:
        description = "Tampering with the TCC privacy database (T1548.006)"
        severity = "High"
    strings:
        $tcc = "TCC.db"
        $sql = "sqlite3" nocase
    condition:
        $tcc and $sql
}

rule MacOS_Reverse_Shell
{
    meta:
        description = "Reverse shell tradecraft on macOS (T1059)"
        severity = "Critical"
    strings:
        $a = "socket.socket(socket.AF_INET" nocase
        $b = "os.dup2(s.fileno()"
        $c = "bash -i >& /dev/tcp/"
        $d = "ruby -rsocket"
        $e = "zsh -c"
        $f = "/bin/sh -i"
    condition:
        2 of them
}

rule MacOS_Gatekeeper_Quarantine_Bypass
{
    meta:
        description = "Gatekeeper / quarantine attribute bypass (T1553.001)"
        severity = "High"
    strings:
        $g1 = "spctl --master-disable"
        $g2 = "spctl --add"
        $q1 = "xattr -d com.apple.quarantine"
        $q2 = "xattr -cr"
        $q3 = "com.apple.quarantine"
    condition:
        any of ($g1, $g2, $q1, $q2) or ($q3 and $q2)
}

rule MacOS_Credential_Phish
{
    meta:
        description = "Credential phishing / Keychain dumping (T1555.001)"
        severity = "High"
    strings:
        $p1 = "display dialog" nocase
        $p2 = "with hidden answer" nocase
        $p3 = "password" nocase
        $k1 = "security find-generic-password" nocase
        $k2 = "security dump-keychain" nocase
        $k3 = "login.keychain"
    condition:
        ($p1 and $p2 and $p3) or (any of ($k1, $k2)) or ($k3 and $p3)
}

rule MacOS_Dylib_Hijack
{
    meta:
        description = "Dylib injection / search-order hijack (T1574.004)"
        severity = "High"
    strings:
        $d1 = "DYLD_INSERT_LIBRARIES"
        $d2 = "DYLD_FRAMEWORK_PATH"
        $d3 = "DYLD_LIBRARY_PATH"
    condition:
        any of them
}

rule MacOS_Defense_Evasion
{
    meta:
        description = "Disabling SIP / system protections (T1562.001)"
        severity = "Critical"
    strings:
        $c1 = "csrutil disable"
        $c2 = "csrutil enable --without"
        $c3 = "nvram boot-args"
        $c4 = "log erase"
        $c5 = "rm -rf /var/db/diagnostics"
    condition:
        any of them
}

rule MacOS_Persistence_Misc
{
    meta:
        description = "emond / periodic / login-item persistence (T1546)"
        severity = "Medium"
    strings:
        $e1 = "/etc/emond.d/"
        $e2 = "/etc/periodic/"
        $e3 = "loginwindow" nocase
        $e4 = "osascript -e 'tell application \"System Events\" to make login item"
        $e5 = "/Library/StartupItems/"
    condition:
        any of them
}

rule MacOS_Browser_Data_Theft
{
    meta:
        description = "Browser cookie / credential store access (T1539/T1555.003)"
        severity = "High"
    strings:
        $b1 = "Cookies.binarycookies"
        $b2 = "Library/Application Support/Google/Chrome"
        $b3 = "Library/Application Support/Firefox/Profiles"
        $b4 = "Login Data"
        $b5 = "key4.db"
    condition:
        2 of them
}
