:: wwqgtxx-goagent.bat
:: Main Batch File
   
@echo off
title greatagent-ga

set PYTHONDONTWRITEBYTECODE=x
cd /D "%~dp0"

:: autoupdate.inc.bat
:: Step1 - Try to generate hash table until success

python27.exe autoupdate.py

:: startgoagent.inc.bat
:: Step2 - Start GoAgent
echo Starting GoAgent...
cd goagent-local
python27.exe check_google_ip.py
start goagent.exe
cd..

:: startfirefox.inc.bat
:: Step3 - Start Firefox
echo Starting FirefoxPortable...
python27.exe startfirefox.py
exit