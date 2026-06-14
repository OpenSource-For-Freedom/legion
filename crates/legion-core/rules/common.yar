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
        description = "Common reverse-shell one-liner patterns (T1059)"
        severity = "Critical"
    strings:
        $a = "bash -i >& /dev/tcp/"
        $b = "nc -e /bin/sh"
        $c = "/dev/tcp/"
        $d = "socket.SOCK_STREAM"
        $e = "exec(\"/bin/sh\")"
        $f = "pty.spawn(\"/bin/bash\")"
        $g = "fsockopen("
        $h = "IO.popen("
        $i = "Net::Telnet"
        $j = "TCPClient" nocase
    condition:
        any of them
}

rule Suspicious_Curl_Pipe_Shell
{
    meta:
        description = "Remote payload piped directly into a shell (T1059)"
        severity = "High"
    strings:
        $curl = "curl " nocase
        $wget = "wget " nocase
        $pipe1 = "| sh"
        $pipe2 = "| bash"
        $pipe3 = "|sh"
        $pipe4 = "|bash"
        $pipe5 = "| python"
    condition:
        (any of ($curl, $wget)) and (any of ($pipe1, $pipe2, $pipe3, $pipe4, $pipe5))
}

rule Inline_Interpreter_Exec
{
    meta:
        description = "Inline interpreter execution of obfuscated code (T1059/T1027)"
        severity = "High"
    strings:
        $py1 = "python -c" nocase
        $py2 = "python3 -c" nocase
        $exec = "exec(" nocase
        $eval = "eval(" nocase
        $b64d = "base64.b64decode" nocase
        $zlib = "zlib.decompress" nocase
        $marshal = "marshal.loads" nocase
        $perl = "perl -e" nocase
        $ruby = "ruby -e" nocase
    condition:
        (any of ($py1, $py2, $perl, $ruby)) and (any of ($exec, $eval, $b64d, $zlib, $marshal))
}

rule Credential_File_Theft
{
    meta:
        description = "Access to multiple credential stores / secrets (T1552)"
        severity = "High"
    strings:
        $aws  = ".aws/credentials"
        $awsenv = "AWS_SECRET_ACCESS_KEY"
        $gcp  = "gcloud/credentials"
        $kube = ".kube/config"
        $ssh1 = "id_rsa"
        $ssh2 = ".ssh/authorized_keys"
        $npmrc = ".npmrc"
        $netrc = ".netrc"
        $docker = ".docker/config.json"
        $env  = ".env"
    condition:
        3 of them
}

rule Exfil_Webhook_Channel
{
    meta:
        description = "Data staged for exfil to a webhook / paste / tunnel service (T1567)"
        severity = "High"
    strings:
        $discord  = "discord.com/api/webhooks" nocase
        $discord2 = "discordapp.com/api/webhooks" nocase
        $telegram = "api.telegram.org/bot" nocase
        $pastebin = "pastebin.com/raw" nocase
        $ngrok    = "ngrok.io" nocase
        $transfer = "transfer.sh" nocase
        $burp     = "burpcollaborator" nocase
        $oast     = "oast.fun" nocase
    condition:
        any of them
}

rule Crypto_Miner_Indicators
{
    meta:
        description = "Cryptocurrency miner configuration / pool traffic (T1496)"
        severity = "High"
    strings:
        $x1 = "xmrig" nocase
        $x2 = "stratum+tcp://" nocase
        $x3 = "stratum+ssl://" nocase
        $x4 = "minerd" nocase
        $x5 = "cryptonight" nocase
        $x6 = "--donate-level" nocase
        $x7 = "nicehash" nocase
        $x8 = "randomx" nocase
    condition:
        any of them
}

rule Env_Variable_Exfil
{
    meta:
        description = "Environment variable harvesting piped to network (T1552.001)"
        severity = "Medium"
    strings:
        $printenv = "printenv" nocase
        $env = "env | " nocase
        $procenv = "/proc/self/environ"
        $curl = "curl " nocase
        $wget = "wget " nocase
    condition:
        (any of ($printenv, $env, $procenv)) and (any of ($curl, $wget))
}
