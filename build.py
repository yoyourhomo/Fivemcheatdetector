"""
Build script for creating a standalone executable of the FiveM Cheat Detector
"""

import os
import sys
import subprocess

def build_standalone():
    """Build a standalone executable"""
    print("Building FiveM Cheat Detector standalone executable...")
    
    # Run PyInstaller
    subprocess.call([
        sys.executable, 
        "-m", 
        "PyInstaller", 
        "main.py", 
        "--name=FiveM_Cheat_Detector", 
        "--onefile", 
        "--windowed",
        "--clean"
    ])
    
    print("Build complete! Executable is in the dist folder.")

if __name__ == "__main__":
    build_standalone()