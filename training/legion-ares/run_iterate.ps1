# Robust launcher for the Ares iterate run. Spawned detached (WMI Win32_Process)
# so it survives the Claude Code session ending. Logs to reports/iterate-live.log.
$ErrorActionPreference = 'Continue'
$env:PYTHONUNBUFFERED = '1'
$env:PYTHONPATH = 'F:\dev\legion\training\legion-ares'
$env:PATH = 'C:\Python314;C:\Python314\Scripts;' + "$env:LOCALAPPDATA\Programs\Ollama;" + $env:PATH
Set-Location 'F:\dev\legion\training\legion-ares'
$log = 'F:\dev\legion\training\legion-ares\reports\iterate-live.log'
& 'C:\Python314\python.exe' -u -m ares_train.iterate --tier legion-ares:qwen3-1.7b --time-budget-min 360 --teacher-model qwen3:14b *> $log
