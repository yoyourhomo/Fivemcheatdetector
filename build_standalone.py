"""
Build script for creating a standalone executable of the FiveM Cheat Detector
"""

import os
import sys
import shutil
import subprocess

def build_standalone():
    """Build a standalone executable"""
    print("Building FiveM Cheat Detector standalone executable...")
    
    # Ensure PyInstaller is installed
    try:
        import PyInstaller
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # Create spec file for PyInstaller
    spec_content = """
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['standalone.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='FiveM_Cheat_Detector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
)
"""
    
    # Write spec file
    with open("fivem_cheat_detector.spec", "w") as f:
        f.write(spec_content)
    
    # Create a simple icon file if it doesn't exist
    if not os.path.exists("icon.ico"):
        print("Creating placeholder icon...")
        try:
            from PIL import Image
            img = Image.new('RGB', (256, 256), color = (53, 59, 72))
            img.save('icon.png')
            
            # Convert PNG to ICO
            img.save('icon.ico')
        except ImportError:
            print("PIL not installed, skipping icon creation")
    
    # Run PyInstaller
    print("Running PyInstaller...")
    subprocess.call([
        sys.executable, 
        "-m", 
        "PyInstaller", 
        "fivem_cheat_detector.spec", 
        "--onefile", 
        "--windowed"
    ])
    
    print("Build complete! Executable is in the dist folder.")

if __name__ == "__main__":
    build_standalone()
