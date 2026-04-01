@echo off
cd /d "%~dp0"
set TCL_LIBRARY=%~dp0python\tcl\tcl8.6
set TK_LIBRARY=%~dp0python\tcl\tk8.6
set PATH=%~dp0python;%PATH%
python\pythonw.exe app\saml_assertion_gui.py
