@echo off
REM Legion Dev iterate launcher (cmd). Edit tier / budget as needed.
set PYTHONUNBUFFERED=1
set PYTHONPATH=F:\dev\legion\training;F:\dev\legion\training\legion-dev
set PATH=C:\Python314;C:\Python314\Scripts;%LOCALAPPDATA%\Programs\Ollama;%PATH%
cd /d F:\dev\legion\training\legion-dev
C:\Python314\python.exe -u -m legion_dev.iterate --tier legion-dev:qwen2.5-coder-1.5b --time-budget-min 360 --teacher-model qwen2.5-coder:7b --publish > reports\iterate-live.log 2>&1
