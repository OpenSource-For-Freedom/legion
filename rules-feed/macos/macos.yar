/*
 * Legion dynamic rule feed — macOS.
 * Fetched from <rules_repo>/macos/macos.yar.
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
        description = "LaunchAgent/Daemon persistence with remote payload"
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
        description = "osascript used to spawn shells or prompt for credentials"
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
        description = "Tampering with the TCC privacy database"
        severity = "High"
    strings:
        $tcc = "TCC.db"
        $sql = "sqlite3" nocase
    condition:
        $tcc and $sql
}

rule MacOS_Stealer_Keychain_Strings
{
    meta:
        description = "Info-stealer strings targeting the macOS keychain / browser data"
        severity = "Critical"
    strings:
        $k1 = "login.keychain-db"
        $k2 = "security find-generic-password" nocase
        $k3 = "Cookies.binarycookies"
        $k4 = "Library/Application Support/Google/Chrome"
    condition:
        2 of them
}
