@echo off
cd /D "%~dp0"
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

pause

exit