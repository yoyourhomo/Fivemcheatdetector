@echo off
echo Building FiveM Cheat Detector v2.0...

REM Install PyInstaller if not already installed
pip install pyinstaller

REM Clean previous build files
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "*.spec" del /q "*.spec"

REM Build the executable
pyinstaller --onefile --windowed --name="FiveM_Cheat_Detector_v2" fivem_detector_v2.py

echo Build completed!
if exist "dist\FiveM_Cheat_Detector_v2.exe" (
    echo Executable created successfully: dist\FiveM_Cheat_Detector_v2.exe
) else (
    echo Failed to create executable!
)

pause
