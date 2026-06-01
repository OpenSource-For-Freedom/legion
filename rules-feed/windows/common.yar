/*
 * Legion dynamic rule feed — common (all OS).
 *
 * Fetched at runtime by the Legion YARA engine from
 *   <rules_repo>/<os>/common.yar
 * and cached under <data_dir>/rules/<os>/. A copy of these baseline rules is
 * also compiled into the Legion binary as an offline fallback. Keep every rule
 * within the engine subset documented in legion-core/src/yara.rs (text + hex
 * strings; any/all/N-of + and/or/not/filesize conditions) so the feed always
 * compiles on every platform.
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

rule Embedded_PE_Base64
{
    meta:
        description = "Base64-encoded Windows PE (MZ) header embedded in a script/document"
        severity = "High"
    strings:
        $mz_b64 = "TVqQAA"    // base64 of MZ\x90\x00
        $mz_b64b = "TVpB"     // base64 of "MZA" variants
    condition:
        any of them
}

rule Generic_Webshell_Eval
{
    meta:
        description = "Generic PHP/JSP webshell eval-on-input pattern"
        severity = "Critical"
    strings:
        $p1 = "eval($_POST" nocase
        $p2 = "eval($_REQUEST" nocase
        $p3 = "eval($_GET" nocase
        $p4 = "system($_GET" nocase
        $p5 = "assert($_POST" nocase
        $p6 = "Runtime.getRuntime().exec" nocase
    condition:
        any of them
}
