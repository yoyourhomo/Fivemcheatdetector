@echo off
echo Building FiveM Cheat Detector...

REM Install required packages
echo Installing dependencies...
pip install -r requirements.txt
pip install pyinstaller

REM Clean previous build files
echo Cleaning previous build files...
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"
if exist "*.spec" del *.spec

REM Build executable
echo Building executable...
pyinstaller --noconfirm --onefile --windowed --icon="icon.ico" --name="FiveM_Cheat_Detector" ^
  --add-data="README.md;." ^
  "fivem_cheat_detector.py"

REM Create shortcut
echo Creating desktop shortcut...
cscript create_shortcut.vbs

echo.
echo Build completed successfully!
echo Executable is located at: dist\FiveM_Cheat_Detector.exe
pause
