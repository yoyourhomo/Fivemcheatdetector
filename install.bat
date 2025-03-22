@echo off
echo Installing FiveM Cheat Detector...

REM Create program files directory if it doesn't exist
set INSTALL_DIR=%ProgramFiles%\FiveM Cheat Detector
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Copy executable
echo Copying files...
copy /Y "dist\FiveM_Cheat_Detector.exe" "%INSTALL_DIR%"

REM Create desktop shortcut
echo Creating desktop shortcut...
cscript //nologo create_shortcut.vbs "%INSTALL_DIR%\FiveM_Cheat_Detector.exe" "%INSTALL_DIR%"

REM Create start menu shortcut
echo Creating start menu shortcut...
set START_MENU=%APPDATA%\Microsoft\Windows\Start Menu\Programs\FiveM Cheat Detector
if not exist "%START_MENU%" mkdir "%START_MENU%"
cscript //nologo create_shortcut.vbs "%INSTALL_DIR%\FiveM_Cheat_Detector.exe" "%INSTALL_DIR%" "%START_MENU%\FiveM Cheat Detector.lnk"

echo.
echo Installation completed!
echo The application has been installed to: %INSTALL_DIR%
echo Shortcuts have been created on your desktop and in the Start Menu.
pause
