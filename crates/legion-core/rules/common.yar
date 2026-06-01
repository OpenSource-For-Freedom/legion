/*
 * Legion baseline YARA rules — common (all OS).
 *
 * These are compiled into the binary as an offline fallback. The live rule set
 * is fetched dynamically from the GitHub-hosted rules repo declared in
 * yara_config.json and cached under <data_dir>/rules/<os>/.
 *
 * Only the Legion pure-Rust engine subset is used here (text + hex strings,
 * nocase/wide/ascii/fullword modifiers, and any/all/N-of + and/or/not/filesize
 * conditions) so these rules always compile on every platform.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file signature"
        severity = "Medium"
        author = "legion"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_Base64_Shell
{
    meta:
        description = "Base64-encoded shell / interpreter invocation (dropper indicator)"
        severity = "High"
    strings:
        $ps  = "cG93ZXJzaGVsbA" nocase   // "powershell"
        $sh  = "L2Jpbi9zaA" nocase        // "/bin/sh"
        $bsh = "L2Jpbi9iYXNo" nocase      // "/bin/bash"
        $b64 = "FromBase64String" nocase
    condition:
        any of them
}

rule Reverse_Shell_Oneliner
{
    meta:
        description = "Common reverse-shell one-liner patterns"
        severity = "Critical"
    strings:
        $a = "bash -i >& /dev/tcp/"
        $b = "nc -e /bin/sh"
        $c = "/dev/tcp/"
        $d = "socket.SOCK_STREAM"
        $e = "exec(\"/bin/sh\")"
    condition:
        any of them
}

rule Suspicious_Curl_Pipe_Shell
{
    meta:
        description = "Remote payload piped directly into a shell"
        severity = "High"
    strings:
        $curl = "curl " nocase
        $wget = "wget " nocase
        $pipe1 = "| sh"
        $pipe2 = "| bash"
        $pipe3 = "|sh"
        $pipe4 = "|bash"
    condition:
        (any of ($curl, $wget)) and (any of ($pipe1, $pipe2, $pipe3, $pipe4))
}
