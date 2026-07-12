# train_sequence.ps1 - sequential Legion training orchestrator.
# Runs each (tier : minutes) step in order using the time-boxed iterate loop
# (fills the budget with synth -> train -> eval cycles, keeps the best adapter).
# One step failing does NOT block the next. Every begin/end is logged to a manifest.
#
# Usage:
#   .\train_sequence.ps1                       # default plan: 1.5B for 6h, then 3B for 4h
#   .\train_sequence.ps1 -Plan '1.5b:360,3b:240'
#   .\train_sequence.ps1 -Plan '3b:120'        # single step
#
param([string]$Plan = '1.5b:360,3b:240')

$ErrorActionPreference = 'Continue'
$py      = 'C:\Python314\python.exe'
$dev     = 'F:\dev\legion\training\legion-dev'
$reports = "$dev\reports"
$env:PYTHONPATH                     = 'F:\dev\legion\training;F:\dev\legion\training\legion-dev'
$env:PYTHONUNBUFFERED               = '1'
$env:LEGION_DEV_GPU_FRACTION        = '0.75'
$env:OLLAMA_HOST                    = 'http://127.0.0.1:11434'
$env:HF_HUB_DISABLE_SYMLINKS_WARNING = '1'

# short alias -> full tier id (extend here as models are added)
$tierMap = @{
  '1.5b' = 'legion-dev:qwen2.5-coder-1.5b'
  '3b'   = 'legion-dev:qwen2.5-coder-3b'
}

$manifest = "$reports\train_sequence.log"
function Log($m) {
  $line = "[{0:yyyy-MM-ddTHH:mm:ss}] {1}" -f (Get-Date), $m
  Add-Content -Path $manifest -Value $line -Encoding utf8
  Write-Host $line
}

# teacher (Ollama server) must be up for the synthesis phase
try { Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 4 | Out-Null }
catch { Start-Process "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" -ArgumentList 'serve' -WindowStyle Hidden; Start-Sleep 6 }

Push-Location $dev
Log "===== train_sequence START | plan=$Plan ====="
$total = 0
foreach ($step in $Plan.Split(',')) {
  $p     = $step.Split(':')
  $alias = $p[0].Trim()
  $mins  = [int]$p[1].Trim()
  $tier  = if ($tierMap.ContainsKey($alias)) { $tierMap[$alias] } else { $alias }
  $log   = "$reports\seq-$alias.log"
  $total += $mins
  Log ">>> BEGIN $alias  ($tier)  budget=${mins}min  -> seq-$alias.log"
  $t0 = Get-Date
  & $py -u -m legion_dev.iterate --tier $tier --time-budget-min $mins --teacher-model qwen2.5-coder:7b *>> $log
  $code = $LASTEXITCODE
  $elapsed = [int]((Get-Date) - $t0).TotalMinutes
  Log "<<< END   $alias  exit=$code  elapsed=${elapsed}min"
}
Log "===== train_sequence COMPLETE | planned ${total}min ====="
Pop-Location
