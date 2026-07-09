@echo off
REM Ares iterate launcher for Task Scheduler. Runs in the user's interactive
REM session (GPU + loopback Ollama work) and survives the Claude session ending.
set PYTHONUNBUFFERED=1
set PYTHONPATH=F:\dev\legion\training\legion-ares
set PATH=C:\Python314;C:\Python314\Scripts;%LOCALAPPDATA%\Programs\Ollama;%PATH%
cd /d F:\dev\legion\training\legion-ares
C:\Python314\python.exe -u -m ares_train.iterate --tier legion-ares:qwen3-1.7b --time-budget-min 360 --teacher-model qwen3:14b --publish > reports\iterate-live.log 2>&1
