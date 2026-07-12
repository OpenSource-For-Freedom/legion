# run_agent.ps1 - trigger a Legion Dev AGENTIC training run (the tool-driving coder:
# understand -> edit -> run tests -> fix). Fills the whole budget with fresh
# synth -> train -> eval rounds and keeps the best adapter.
#
#   .\run_agent.ps1                 # 2 hours, 1.5B  (default)
#   .\run_agent.ps1 -Hours 4        # 4 hours
#   .\run_agent.ps1 -Hours 2 -Tier 3b
#
param([double]$Hours = 2, [string]$Tier = '1.5b')

$root = 'F:\dev\legion\training\legion-dev'
$env:PYTHONPATH = 'F:\dev\legion\training;F:\dev\legion\training\legion-dev'
$env:PYTHONUNBUFFERED = '1'; $env:LEGION_DEV_GPU_FRACTION = '0.75'
$env:OLLAMA_HOST = 'http://127.0.0.1:11434'
$env:PYTHONIOENCODING = 'utf-8'; $env:PYTHONUTF8 = '1'

$tierMap = @{ '1.5b' = 'legion-dev:qwen2.5-coder-1.5b'; '3b' = 'legion-dev:qwen2.5-coder-3b'; '7b' = 'legion-dev:qwen2.5-coder-7b' }
$tier = if ($tierMap.ContainsKey($Tier)) { $tierMap[$Tier] } else { $Tier }
$mins = [int]($Hours * 60)

# teacher server (Ollama) up for synthesis
try { Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 4 | Out-Null }
catch { Start-Process "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" -ArgumentList 'serve' -WindowStyle Hidden; Start-Sleep 6 }

$p = Start-Process 'C:\Python314\python.exe' `
  -ArgumentList '-u','-m','legion_dev.iterate_agent','--tier',$tier,'--time-budget-min',"$mins" `
  -WorkingDirectory $root -RedirectStandardOutput "$root\reports\dev-live.log" -RedirectStandardError "$root\reports\dev-live.err.log" `
  -WindowStyle Hidden -PassThru
Write-Host "Legion Dev AGENTIC training started: pid $($p.Id) | $tier | $Hours h (fills the budget, keeps best)"
Write-Host "Monitor:  F:\dev\legion\training\monitor.ps1 dev"
Write-Host "Stop:     Stop-Process -Id $($p.Id) -Force"
