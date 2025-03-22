#!/usr/bin/env python
import os
import sys
import subprocess
import shutil
from pathlib import Path

def build_executable():
    """Build a standalone executable using PyInstaller"""
    print("Building FiveM Cheat Detector v2.0 executable...")
    
    # Change to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"Working directory: {os.getcwd()}")
    
    # Install required packages if not already installed
    print("Checking and installing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    
    # Clean up previous build artifacts if they exist
    build_dir = Path("build")
    dist_dir = Path("dist")
    spec_file = Path("fivem_cheat_detector.spec")
    
    if build_dir.exists():
        print("Removing previous build directory...")
        shutil.rmtree(build_dir)
    
    if dist_dir.exists():
        print("Removing previous dist directory...")
        shutil.rmtree(dist_dir)
    
    if spec_file.exists():
        print("Removing previous spec file...")
        spec_file.unlink()
    
    # Build the executable
    print("Building executable with PyInstaller...")
    
    # Use direct pyinstaller command instead of module
    pyinstaller_cmd = [
        "pyinstaller",
        "--onefile",  # Create a single executable file
        "--windowed",  # Windows application (no console)
        "--name", "FiveM_Cheat_Detector_v2",  # New name for version 2
        "--clean",  # Clean PyInstaller cache
        "fivem_cheat_detector.py"
    ]
    
    # Add icon if it exists
    if Path("icon.ico").exists():
        pyinstaller_cmd.extend(["--icon", "icon.ico"])
    
    # Run PyInstaller
    try:
        subprocess.run(pyinstaller_cmd, check=True)
        print("\nBuild completed successfully!")
        print(f"Executable created at: {os.path.abspath(os.path.join('dist', 'FiveM_Cheat_Detector_v2.exe'))}")
    except subprocess.CalledProcessError as e:
        print(f"\nError building executable: {e}")
        print("\nTrying alternative method...")
        
        # Try using the -m method with sys.executable
        alt_cmd = [
            sys.executable, 
            "-m", 
            "PyInstaller",
            "--onefile",
            "--windowed",
            "--name", "FiveM_Cheat_Detector_v2",
            "--clean",
            "fivem_cheat_detector.py"
        ]
        
        if Path("icon.ico").exists():
            alt_cmd.extend(["--icon", "icon.ico"])
        
        try:
            subprocess.run(alt_cmd, check=True)
            print("\nBuild completed successfully with alternative method!")
            print(f"Executable created at: {os.path.abspath(os.path.join('dist', 'FiveM_Cheat_Detector_v2.exe'))}")
        except subprocess.CalledProcessError as e2:
            print(f"\nError building executable with alternative method: {e2}")
            print("\nPlease try running: pip install pyinstaller --user")
            print("Then run this script again.")

if __name__ == "__main__":
    build_executable()
