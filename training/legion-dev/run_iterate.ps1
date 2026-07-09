# Robust launcher for the Legion Dev iterate run. Spawn detached (WMI Win32_Process)
# so it survives the terminal/session ending. Logs to reports/iterate-live.log.
$ErrorActionPreference = 'Continue'
$env:PYTHONUNBUFFERED = '1'
$env:PYTHONPATH = 'F:\dev\legion\training\legion-dev'
$env:PATH = 'C:\Python314;C:\Python314\Scripts;' + "$env:LOCALAPPDATA\Programs\Ollama;" + $env:PATH
Set-Location 'F:\dev\legion\training\legion-dev'
$log = 'F:\dev\legion\training\legion-dev\reports\iterate-live.log'
& 'C:\Python314\python.exe' -u -m legion_dev.iterate --tier legion-dev:qwen2.5-coder-1.5b --time-budget-min 360 --teacher-model qwen2.5-coder:7b --publish *> $log
