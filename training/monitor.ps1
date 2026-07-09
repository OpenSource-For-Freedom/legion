# Live-monitor a Legion training run. Usage:
#   .\monitor.ps1            # vision run (default)
#   .\monitor.ps1 dev        # coding-agent run
#   .\monitor.ps1 vision -raw   # full log incl. per-step loss (noisy)
param([string]$run = "vision", [switch]$raw)

$root = "F:\dev\legion\training\legion-dev\reports"
$logs = @{ vision = "$root\vision-live.log"; dev = "$root\dev-live.log" }
if (-not $logs.ContainsKey($run)) { Write-Host "unknown run '$run' (use: vision | dev)"; exit 1 }
$log = $logs[$run]; $err = $log -replace '\.log$', '.err.log'
if (-not (Test-Path $log)) { Write-Host "no log yet at $log"; exit 1 }

# quick status
$proc = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*iterate_$( if($run -eq 'dev'){'agent'}else{'vl'} )*" } | Select-Object -First 1
Write-Host ("== $run training ==  " + ($(if ($proc) { "RUNNING pid $($proc.ProcessId)" } else { "not running" }))) -ForegroundColor Cyan
Write-Host "log: $log`n(Ctrl+C to stop watching; this does not stop the training)`n"

if ($raw) {
    Get-Content $log -Tail 40 -Wait
} else {
    # milestones only: phases, dataset, evals, epochs/loss, completion, failures
    Get-Content $log -Tail 60 -Wait | Select-String -Pattern `
        'phase |dataset:|baseline|eval:|pass@1|new best|epoch.:|train_loss|train_runtime|cycle |DONE|promot|clears|Traceback|Error|CUDA out of memory|MemoryError|OutOfMemory|Fetching|Downloading'
}
