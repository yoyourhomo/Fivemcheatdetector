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
    
    # Check if requirements.txt exists
    if not os.path.exists("requirements.txt"):
        print("Error: requirements.txt not found in the current directory.")
        print(f"Current directory: {os.getcwd()}")
        print("Creating a basic requirements.txt file...")
        with open("requirements.txt", "w") as f:
            f.write("pywin32>=305\npsutil>=5.9.0\n")
    
    # Install required packages if not already installed
    print("Checking and installing dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        print("Continuing with build process anyway...")
    
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
    print("\nBuilding executable...")
    
    # Define PyInstaller command
    pyinstaller_cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=FiveM_Cheat_Detector_v2",
        "--onefile",
        "--windowed",
        "--add-data=icon.ico;.",
        "fivem_cheat_detector.py"
    ]
    
    try:
        # Run PyInstaller
        subprocess.run(pyinstaller_cmd, check=True)
        print("\nBuild completed successfully!")
        print(f"Executable created at: {os.path.abspath(os.path.join('dist', 'FiveM_Cheat_Detector_v2.exe'))}")
    except subprocess.CalledProcessError as e:
        print(f"\nError building executable: {e}")
        print("\nTrying alternative method...")
        
        # Try alternative build command
        alt_cmd = [
            sys.executable, "-m", "PyInstaller",
            "--name=FiveM_Cheat_Detector_v2",
            "--onefile",
            "--noconsole",
            "fivem_cheat_detector.py"
        ]
        
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
