"""
FiveM Cheat Detector v3.0 - Forensic Analyzer Module
Handles advanced forensic analysis for detecting deleted cheats and historical evidence
"""

import os
import re
import winreg
import subprocess
import json
import datetime
import logging
from pathlib import Path
from threading import Thread
import ctypes
import tempfile

class ForensicAnalyzer:
    """Advanced forensic analyzer for detecting deleted cheats and historical evidence"""
    
    def __init__(self, progress_callback=None):
        """Initialize the forensic analyzer"""
        self.callback = progress_callback
        self.results = {
            "dll_injection": [],
            "file_remnants": [],
            "registry_forensics": [],
            "timeline": [],
            "usn_journal": [],  # Add USN journal results category
            "command_line_args": [],  # Add command line arguments results category
            "network_connections": []  # Add network connections results category
        }
        self.severity_count = {"critical": 0, "warning": 0, "info": 0, "high": 0, "error": 0}
        self.setup_logging()
    
    def setup_logging(self):
        """Set up logging for the forensic analyzer"""
        self.logger = logging.getLogger("ForensicAnalyzer")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler("forensic_analysis.log")
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def log_progress(self, message, progress=None):
        """Log progress and call the callback if provided"""
        self.logger.info(message)
        if self.callback and callable(self.callback):
            self.callback(message, progress)
    
    def log(self, message, level="info"):
        """Log a message with the specified level"""
        if level == "info":
            self.logger.info(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "error":
            self.logger.error(message)
        elif level == "critical":
            self.logger.critical(message)
        elif level == "debug":
            self.logger.debug(message)
    
    def run_analysis(self):
        """Run all forensic analysis methods"""
        self.log_progress("Starting forensic analysis...", 0)
        # Reset results
        self.results = {
            "dll_injection": [],
            "file_remnants": [],
            "registry_forensics": [],
            "timeline": [],
            "usn_journal": [],  # Add USN journal results category
            "command_line_args": [],  # Add command line arguments results category
            "network_connections": []  # Add network connections results category
        }
        self.severity_count = {"critical": 0, "warning": 0, "info": 0, "high": 0, "error": 0}
        
        # Check if running with admin privileges
        is_admin = self._check_admin_privileges()
        if not is_admin:
            self.log_progress("Running without administrator privileges. Some forensic checks will be limited.", 5)
            self.results["dll_injection"].append({
                "process": "N/A",
                "dll": "N/A",
                "description": "Limited access to system files. Run as administrator for full forensic analysis.",
                "severity": "info"
            })
            self.severity_count["info"] += 1
        
        # Run analysis methods
        self.analyze_dll_injection_history()
        self.log_progress("DLL injection history analysis complete", 25)
        
        self.analyze_file_remnants()
        self.log_progress("File remnant analysis complete", 50)
        
        self.analyze_registry_forensics()
        self.log_progress("Registry forensics analysis complete", 75)
        
        self.analyze_command_line_arguments()
        self.log_progress("Command line arguments analysis complete", 80)
        
        # Add USN journal analysis
        self.analyze_usn_journal()
        self.log_progress("USN journal analysis complete", 85)
        
        # Add network connections analysis
        self.analyze_network_connections()
        self.log_progress("Network connections analysis complete", 90)
        
        return self.results
    
    def analyze_all(self):
        """Run all forensic analysis methods - alias for run_analysis for compatibility"""
        return self.run_analysis()
    
    def _check_admin_privileges(self):
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def analyze_dll_injection_history(self):
        """Analyze DLL injection history"""
        self.log_progress("Analyzing DLL injection history...", 10)
        
        # Check FiveM directories for suspicious DLLs
        self._check_fivem_directories_for_dlls()
        
        # Check prefetch files for evidence of DLL injection
        self._check_prefetch_files()
        
        self.log_progress("DLL injection history analysis complete", 25)
    
    def _check_fivem_directories_for_dlls(self):
        """Check FiveM directories for suspicious DLLs"""
        try:
            # Known suspicious DLLs - Updated with new cheat signatures
            suspicious_dlls = [
                "d3d10.dll", "USBDeview.dll", "eulen.dll", "redengine.dll", 
                "hxcheats.dll", "cobrafree.dll", "tzx.dll", "skript.dll",
                "hx-cheats.dll", "tdpremium.dll", "tdfree.dll", "testogg.dll",
                "gosth.dll", "susano.dll", "diamond.dll"
            ]
            
            # FiveM directories to check
            fivem_dirs = [
                os.path.expandvars("%LOCALAPPDATA%\\FiveM"),
                os.path.expandvars("%LOCALAPPDATA%\\FiveM\\FiveM Application Data"),
                os.path.expandvars("%LOCALAPPDATA%\\FiveM\\FiveM Application Data\\plugins"),
                os.path.expandvars("%LOCALAPPDATA%\\FiveM\\FiveM Application Data\\cache"),
                os.path.expandvars("%LOCALAPPDATA%\\FiveM\\FiveM Application Data\\data")
            ]
            
            # Special check for d3d10.dll in GTA V directory
            gtav_dirs = [
                os.path.expandvars("%USERPROFILE%\\Documents\\Rockstar Games\\GTA V"),
                os.path.expandvars("%USERPROFILE%\\Documents\\Rockstar Games\\Red Dead Redemption 2")
            ]
            
            # Check FiveM directories
            for directory in fivem_dirs:
                if not os.path.exists(directory):
                    continue
                
                for root, _, files in os.walk(directory):
                    for file in files:
                        if file.lower().endswith(".dll"):
                            file_lower = file.lower()
                            
                            # Check for known cheat DLLs
                            for dll in suspicious_dlls:
                                if dll.lower() in file_lower:
                                    file_path = os.path.join(root, file)
                                    self.results["dll_injection"].append({
                                        "name": "FiveM",
                                        "path": file_path,
                                        "description": f"Suspicious DLL found in FiveM directory: {file}",
                                        "severity": "critical"
                                    })
                                    self.severity_count["critical"] += 1
                                    break
            
            # Check GTA V directory specifically for d3d10.dll
            for directory in gtav_dirs:
                if not os.path.exists(directory):
                    continue
                
                d3d10_path = os.path.join(directory, "d3d10.dll")
                if os.path.exists(d3d10_path):
                    self.results["dll_injection"].append({
                        "name": "GTA V",
                        "path": d3d10_path,
                        "description": "d3d10.dll found in game directory - commonly used by cheats",
                        "severity": "critical"
                    })
                    self.severity_count["critical"] += 1
                
                # Check for imgui.ini in GTA V folder (Red Engine indicator)
                imgui_path = os.path.join(directory, "imgui.ini")
                if os.path.exists(imgui_path):
                    self.results["dll_injection"].append({
                        "name": "GTA V",
                        "path": imgui_path,
                        "description": "imgui.ini found in game directory - commonly used by Red Engine cheat",
                        "severity": "critical"
                    })
                    self.severity_count["critical"] += 1
                
                # Check for settings.cock in GTA V folder (Red Engine indicator)
                settings_path = os.path.join(directory, "settings.cock")
                if os.path.exists(settings_path):
                    self.results["dll_injection"].append({
                        "name": "GTA V",
                        "path": settings_path,
                        "description": "settings.cock found in game directory - Red Engine cheat configuration",
                        "severity": "critical"
                    })
                    self.severity_count["critical"] += 1
                    
        except Exception as e:
            self.log(f"Error checking FiveM directories for DLLs: {str(e)}", "error")
    
    def _check_prefetch_files(self):
        """Check Windows Prefetch files for evidence of cheat execution"""
        try:
            prefetch_dir = os.path.expandvars("%SystemRoot%\\Prefetch")
            if not os.path.exists(prefetch_dir):
                self.log.warning(f"Prefetch directory not found: {prefetch_dir}")
                return
            
            # Common cheat executables to look for in prefetch
            cheat_executables = [
                "USBDeview", "loader", "loader_prod", "TDLoader", 
                "fontdrvhost", "svhost", "BetterDiscord-Windows", 
                "launcher", "diamond", "Impaciente", "hwid_get", 
                "free cobra loader", "eulen", "redengine", "skript"
            ]
            
            # FiveM bypasser and HWID spoofer executables
            bypasser_executables = [
                "fivembypass", "bypass_fivem", "hwid_spoof", "hwid_bypass", 
                "fivem_unban", "cfx_bypass", "citizenfx_bypass", "spoofer", 
                "hwid_reset", "hwid_clean", "hwid_changer", "serial_changer", 
                "mac_changer", "ban_evade", "ban_bypass", "cfx_unban", 
                "fivem_cleaner", "trace_cleaner"
            ]
            
            # Combine all patterns
            all_executables = cheat_executables + bypasser_executables
            
            try:
                for file in os.listdir(prefetch_dir):
                    file_lower = file.lower()
                    if file_lower.endswith(".pf"):
                        for exe in all_executables:
                            if exe.lower() in file_lower:
                                # Determine severity based on executable type
                                severity = "critical" if exe in bypasser_executables else "high"
                                
                                self.results["registry_forensics"].append({
                                    "key": "Prefetch",
                                    "value": file,
                                    "description": f"Evidence of {exe} execution found in Prefetch",
                                    "severity": severity
                                })
                                self.severity_count[severity] += 1
            except PermissionError:
                self.log.warning("Access denied to Prefetch directory. Run as administrator for complete analysis.")
                self.results["registry_forensics"].append({
                    "key": "Prefetch",
                    "value": "Access Denied",
                    "description": "Cannot access Prefetch directory. Run as administrator for complete analysis.",
                    "severity": "info"
                })
                self.severity_count["info"] += 1
        except Exception as e:
            self.log(f"Error checking prefetch files: {str(e)}", "error")
    
    def analyze_file_remnants(self):
        """Analyze file remnants from deleted cheats"""
        self.log_progress("Analyzing file remnants...", 40)
        
        # Check common locations for cheat remnants
        self._check_common_locations_for_remnants()
        
        # Check temp directories
        self._check_temp_directories()
        
        self.log_progress("File remnant analysis complete", 50)
    
    def _check_common_locations_for_remnants(self):
        """Check common locations for file remnants"""
        try:
            # Common locations to check
            common_locations = [
                os.path.expandvars("%TEMP%"),
                os.path.expandvars("%APPDATA%"),
                os.path.expandvars("%LOCALAPPDATA%"),
                os.path.expandvars("%USERPROFILE%\\Downloads"),
                os.path.expandvars("%USERPROFILE%\\Desktop")
            ]
            
            # Suspicious patterns to look for
            suspicious_patterns = [
                "eulen", "redengine", "skript", "desudo", "hammafia", "lynx", "hydro", 
                "dopamine", "absolute", "maestro", "reaper", "fallout", "brutan", "lumia", 
                "surge", "impulse", "paragon", "phantom", "ozark", "cherax", "2take1", 
                "stand", "midnight", "robust", "disturbed", "loader", "injector", "hack", 
                "cheat", "USBDeview", "BetterDiscord", "fontdrvhost", "svhost"
            ]
            
            # FiveM bypasser specific patterns
            bypasser_patterns = [
                "fivembypass", "bypass_fivem", "hwid_spoof", "hwid_bypass", "fivem_unban",
                "cfx_bypass", "citizenfx_bypass", "spoofer", "hwid_reset", "hwid_clean",
                "hwid_changer", "serial_changer", "mac_changer", "ban_evade", "ban_bypass",
                "cfx_unban", "fivem_cleaner", "trace_cleaner"
            ]
            
            # List of legitimate applications to exclude (to avoid false positives)
            legitimate_apps = [
                "beatsabermodmanager",
                "easyanticheat",
                "voicemod",
                "voicemeeter",
                "gmod",
                "garry's mod",
                "microsoft asp .net core module"
            ]
            
            for location in common_locations:
                self.log_progress(f"Checking {location} for remnants...", 35)
                
                # Only scan top-level directories to avoid deep scanning
                for item in os.listdir(location):
                    item_lower = item.lower()
                    
                    # Skip legitimate applications
                    if any(app in item_lower for app in legitimate_apps):
                        continue
                    
                    item_path = os.path.join(location, item)
                    
                    # Check for bypasser patterns first (higher severity)
                    for pattern in bypasser_patterns:
                        if pattern in item_lower:
                            is_dir = os.path.isdir(item_path)
                            self.results["file_remnants"].append({
                                "name": item,
                                "path": item_path,
                                "description": f"Possible FiveM bypasser/HWID spoofer remnant found: {pattern}",
                                "severity": "critical"
                            })
                            self.severity_count["critical"] += 1
                            break
                    else:
                        # If not a bypasser, check for other suspicious patterns
                        for pattern in suspicious_patterns:
                            if pattern in item_lower:
                                is_dir = os.path.isdir(item_path)
                                self.results["file_remnants"].append({
                                    "name": item,
                                    "path": item_path,
                                    "description": f"Suspicious {'folder' if is_dir else 'file'} found: {pattern}",
                                    "severity": "high"
                                })
                                self.severity_count["high"] += 1
                                break
        except Exception as e:
            self.log(f"Error checking common locations for remnants: {str(e)}", "error")
    
    def _check_temp_directories(self):
        """Check temp directories for cheat remnants"""
        try:
            # Temp directories to check
            temp_dirs = [
                os.path.expandvars("%TEMP%"),
                os.path.expandvars("%TMP%")
            ]
            
            # Suspicious file patterns
            suspicious_patterns = [
                "eulen", "redengine", "cheat", "hack", "injector", 
                "loader", "hwid", "spoofer", "cobra", "skript", "hxcheats", 
                "tdloader", "tzx", "testogg", "gosth", "susano", "impaciente"
            ]
            
            # Legitimate applications that should be excluded (to avoid false positives)
            legitimate_apps = [
                "BeatSaberModManager", "EasyAntiCheat", "Voicemod", "Voicemod.exe", 
                "VoicemodV3", "Garry's Mod", "Microsoft ASP .NET Core Module",
                "Microsoft ASP .NET Core Module V2"
            ]
            
            for temp_dir in temp_dirs:
                if not os.path.exists(temp_dir):
                    continue
                
                # Only scan top-level directories to avoid deep scanning
                for item in os.listdir(temp_dir):
                    item_path = os.path.join(temp_dir, item)
                    item_lower = item.lower()
                    
                    # Check if the file/folder name contains suspicious patterns
                    for pattern in suspicious_patterns:
                        if pattern in item_lower:
                            # Skip if it's a legitimate application
                            if any(legitimate_app.lower() in item_lower for legitimate_app in legitimate_apps):
                                continue
                                
                            is_dir = os.path.isdir(item_path)
                            self.results["file_remnants"].append({
                                "name": item,
                                "path": item_path,
                                "description": f"Suspicious {'folder' if is_dir else 'file'} found in temp directory: {item}",
                                "severity": "warning"
                            })
                            self.severity_count["warning"] += 1
                            break
        except Exception as e:
            self.log(f"Error checking temp directories: {str(e)}", "error")
    
    def analyze_registry_forensics(self):
        """Analyze registry for forensic evidence of cheats"""
        self.log_progress("Analyzing registry for forensic evidence...", 70)
        
        # Check UserAssist registry for evidence of cheat execution
        self._check_userassist_registry()
        
        # Check for known cheat registry keys
        self._check_known_cheat_registry_keys()
        
        # Check for suspicious uninstall entries
        self._check_uninstall_entries()
        
        # Check registry for cheat traces
        self._check_registry_for_cheat_traces()
        
        self.log_progress("Registry forensics analysis complete", 75)
    
    def _check_userassist_registry(self):
        """Check UserAssist registry for evidence of cheat execution"""
        try:
            # Known cheat executables
            cheat_exes = [
                "eulen.exe", "redengine.exe", "loader_prod.exe", "TDLoader.exe", 
                "fontdrvhost.exe", "svhost.exe", "BetterDiscord-Windows.exe", 
                "launcher.exe", "diamond.exe", "Impaciente.exe", "hwid_get.exe", 
                "free cobra loader.exe", "USBDeview.exe"
            ]
            
            # Legitimate applications that should be excluded (to avoid false positives)
            legitimate_apps = [
                "BeatSaberModManager", "EasyAntiCheat", "Voicemod", "Voicemod.exe", 
                "VoicemodV3", "Garry's Mod", "Microsoft ASP .NET Core Module",
                "Microsoft ASP .NET Core Module V2"
            ]
            
            # UserAssist registry key
            userassist_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, userassist_key) as key:
                    # In a real implementation, we would decode and analyze the UserAssist entries
                    # to find specific cheat executables. For now, we'll just check if the key exists
                    # and only report it if we find specific evidence of cheats.
                    
                    # Check if any of the known cheat executables are in the registry
                    found_cheat = False
                    
                    # This is a placeholder for actual UserAssist decoding and analysis
                    # In a real implementation, we would iterate through the UserAssist entries,
                    # decode them, and check for specific cheat executables
                    
                    # For now, we'll skip adding a generic "UserAssist contains evidence" entry
                    # to avoid false positives
                    
                    if found_cheat:
                        self.results["registry_forensics"].append({
                            "key": userassist_key,
                            "value": "UserAssist",
                            "description": "UserAssist registry contains evidence of cheat program execution",
                            "severity": "warning"
                        })
                        self.severity_count["warning"] += 1
            except Exception as e:
                self.log(f"Error accessing UserAssist registry: {str(e)}", "error")
        except Exception as e:
            self.log(f"Error checking UserAssist registry: {str(e)}", "error")
    
    def _check_known_cheat_registry_keys(self):
        """Check for known cheat registry keys"""
        try:
            # Known cheat registry keys
            cheat_registry_keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Eulen"),
                (winreg.HKEY_CURRENT_USER, r"Software\RedEngine"),
                (winreg.HKEY_CURRENT_USER, r"Software\TDLOADER"),
                (winreg.HKEY_CURRENT_USER, r"Software\HXCheats"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Eulen"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RedEngine")
            ]
            
            for hkey, key_path in cheat_registry_keys:
                try:
                    with winreg.OpenKey(hkey, key_path) as key:
                        # Key exists, add to results
                        hkey_name = "HKCU" if hkey == winreg.HKEY_CURRENT_USER else "HKLM"
                        self.results["registry_forensics"].append({
                            "key": f"{hkey_name}\\{key_path}",
                            "value": "",
                            "description": f"Known cheat registry key found: {key_path}",
                            "severity": "critical"
                        })
                        self.severity_count["critical"] += 1
                except FileNotFoundError:
                    # Key doesn't exist, which is expected
                    pass
                except Exception as e:
                    self.log(f"Error checking registry key {key_path}: {str(e)}", "error")
        except Exception as e:
            self.log(f"Error checking known cheat registry keys: {str(e)}", "error")
    
    def _check_uninstall_entries(self):
        """Check for suspicious uninstall entries"""
        try:
            # Uninstall registry key
            uninstall_key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
            
            # Suspicious uninstall entry names
            suspicious_names = [
                "eulen", "redengine", "cheat", "hack", "injector", 
                "loader", "hwid", "spoofer", "cobra", "skript", "hxcheats", 
                "tdloader", "tzx", "testogg", "gosth", "susano", "impaciente"
            ]
            
            # Legitimate applications that should be excluded (to avoid false positives)
            legitimate_apps = [
                "BeatSaberModManager", "EasyAntiCheat", "Voicemod", "Voicemod.exe", 
                "VoicemodV3", "Garry's Mod", "Microsoft ASP .NET Core Module",
                "Microsoft ASP .NET Core Module V2"
            ]
            
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key) as key:
                    # Count subkeys
                    subkey_count = winreg.QueryInfoKey(key)[0]
                    
                    # Check each subkey
                    for i in range(subkey_count):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                    
                                    # Check if display name contains suspicious patterns
                                    display_name_lower = display_name.lower()
                                    for pattern in suspicious_names:
                                        if pattern in display_name_lower:
                                            # Skip if it's a legitimate application
                                            if any(legitimate_app.lower() in display_name_lower for legitimate_app in legitimate_apps):
                                                break
                                                
                                            self.results["registry_forensics"].append({
                                                "key": f"HKLM\\{uninstall_key}\\{subkey_name}",
                                                "value": "DisplayName",
                                                "description": f"Suspicious uninstall entry found: {display_name}",
                                                "severity": "warning"
                                            })
                                            self.severity_count["warning"] += 1
                                            break
                                except (FileNotFoundError, OSError):
                                    # DisplayName value doesn't exist
                                    pass
                        except (FileNotFoundError, OSError):
                            # Error accessing subkey
                            pass
            except Exception as e:
                self.log(f"Error accessing uninstall registry key: {str(e)}", "error")
        except Exception as e:
            self.log(f"Error checking uninstall entries: {str(e)}", "error")
    
    def _check_registry_for_cheat_traces(self):
        """Check registry for traces of cheats"""
        try:
            # Check run keys for autostart entries
            run_keys = [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
            ]
            
            # Common cheat patterns
            cheat_patterns = [
                "eulen", "redengine", "skript", "desudo", "hammafia", "lynx", "hydro", 
                "dopamine", "absolute", "maestro", "reaper", "fallout", "brutan", "lumia", 
                "surge", "impulse", "paragon", "phantom", "ozark", "cherax", "2take1", 
                "stand", "midnight", "robust", "disturbed", "loader", "injector", "hack", 
                "cheat", "USBDeview", "BetterDiscord-Windows", "TDLoader", "diamond",
                "Impaciente", "hwid_get", "cobra"
            ]
            
            # FiveM bypasser and HWID spoofer specific patterns
            bypasser_patterns = [
                "fivembypass", "bypass_fivem", "hwid_spoof", "hwid_bypass", "fivem_unban",
                "cfx_bypass", "citizenfx_bypass", "spoofer", "hwid_reset", "hwid_clean",
                "hwid_changer", "serial_changer", "mac_changer", "ban_evade", "ban_bypass",
                "cfx_unban", "fivem_cleaner", "trace_cleaner"
            ]
            
            # Specific registry keys that might contain bypasser traces
            bypasser_registry_keys = [
                r"Software\FiveM\Bypass",
                r"Software\FiveMBypass",
                r"Software\HWID\Spoofer",
                r"Software\HWIDSpoofer",
                r"Software\CFXBypass",
                r"Software\CitizenFX\Bypass",
                r"SYSTEM\CurrentControlSet\Control\IDConfig\Spoofed",
                r"SYSTEM\CurrentControlSet\Services\HWIDSpoof"
            ]
            
            # Check run keys for cheat autostart entries
            for key_path in run_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                name_lower = name.lower()
                                value_lower = value.lower()
                                
                                # Check for bypasser patterns first (higher severity)
                                for pattern in bypasser_patterns:
                                    if pattern in name_lower or pattern in value_lower:
                                        self.results["registry_forensics"].append({
                                            "key": key_path,
                                            "value": f"{name}: {value}",
                                            "description": f"FiveM bypasser/HWID spoofer autostart entry found: {pattern}",
                                            "severity": "critical"
                                        })
                                        self.severity_count["critical"] += 1
                                        break
                                else:
                                    # If not a bypasser, check for other cheat patterns
                                    for pattern in cheat_patterns:
                                        if pattern in name_lower or pattern in value_lower:
                                            self.results["registry_forensics"].append({
                                                "key": key_path,
                                                "value": f"{name}: {value}",
                                                "description": f"Cheat autostart entry found: {pattern}",
                                                "severity": "high"
                                            })
                                            self.severity_count["high"] += 1
                                            break
                                
                                i += 1
                            except WindowsError:
                                break
                except Exception as e:
                    self.log(f"Error checking registry key {key_path}: {str(e)}", "error")
            
            # Check for specific bypasser registry keys
            for key_path in bypasser_registry_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                        # Just the existence of these keys is suspicious
                        self.results["registry_forensics"].append({
                            "key": key_path,
                            "value": "Key exists",
                            "description": f"FiveM bypasser/HWID spoofer registry key found",
                            "severity": "critical"
                        })
                        self.severity_count["critical"] += 1
                except FileNotFoundError:
                    # Key doesn't exist, which is normal
                    pass
                except Exception as e:
                    self.log(f"Error checking registry key {key_path}: {str(e)}", "error")
            
            # Check for specific bypasser registry keys in HKLM
            for key_path in bypasser_registry_keys:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                        # Just the existence of these keys is suspicious
                        self.results["registry_forensics"].append({
                            "key": key_path,
                            "value": "Key exists",
                            "description": f"FiveM bypasser/HWID spoofer registry key found in HKLM",
                            "severity": "critical"
                        })
                        self.severity_count["critical"] += 1
                except FileNotFoundError:
                    # Key doesn't exist, which is normal
                    pass
                except Exception as e:
                    self.log(f"Error checking registry key {key_path}: {str(e)}", "error")
                    
        except Exception as e:
            self.log(f"Error checking registry for cheat traces: {str(e)}", "error")
    
    def analyze_command_line_arguments(self):
        """Analyze command line arguments for suspicious patterns"""
        self.log_progress("Analyzing command line arguments...", 60)
        
        # Check for suspicious command line arguments in running processes
        self._check_command_line_arguments()
        
        self.log_progress("Command line arguments analysis complete", 65)
    
    def _check_command_line_arguments(self):
        """Check for suspicious command line arguments in running processes"""
        try:
            # Get all running processes with their command line arguments
            command = 'wmic process get caption,commandline /format:csv'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.log.warning(f"Error running WMIC command: {result.stderr}")
                return
            
            # Parse the CSV output
            lines = result.stdout.strip().split('\n')
            
            # Common cheat-related command line arguments
            suspicious_args = [
                "-inject", "/inject", "-hook", "/hook", "-dll", "/dll", 
                "-load", "/load", "-cheat", "/cheat", "-hack", "/hack"
            ]
            
            # FiveM bypasser and HWID spoofer specific command line arguments
            bypasser_args = [
                "-bypass", "/bypass", "-fivembypass", "/fivembypass",
                "-bypassfivem", "/bypassfivem", "-cfxbypass", "/cfxbypass",
                "-bypasscfx", "/bypasscfx", "-unban", "/unban",
                "-spoof", "/spoof", "-hwid", "/hwid", "-resetid", "/resetid",
                "-cleantrace", "/cleantrace", "-cleanfivem", "/cleanfivem",
                "-spoofhwid", "/spoofhwid", "-hwid_spoof", "/hwid_spoof",
                "-hwid_reset", "/hwid_reset", "-hwid_clean", "/hwid_clean",
                "-serial_spoof", "/serial_spoof", "-mac_spoof", "/mac_spoof",
                "-ban_evade", "/ban_evade", "-ban_bypass", "/ban_bypass",
                "-fivem_unban", "/fivem_unban", "-cfx_unban", "/cfx_unban",
                "-trace_clean", "/trace_clean", "-log_wipe", "/log_wipe"
            ]
            
            # Skip these legitimate processes
            legitimate_processes = [
                "svchost.exe", "explorer.exe", "wininit.exe", "services.exe", 
                "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", 
                "spoolsv.exe", "dwm.exe", "taskhostw.exe", "sihost.exe",
                "ctfmon.exe", "searchindexer.exe", "shellexperiencehost.exe",
                "runtimebroker.exe", "backgroundtaskhost.exe", "wmic.exe"
            ]
            
            for line in lines:
                if not line or "CommandLine" not in line:
                    continue
                
                parts = line.split(',')
                if len(parts) < 3:
                    continue
                
                process_name = parts[1].strip().lower()
                command_line = parts[2].strip().lower() if len(parts) > 2 else ""
                
                # Skip legitimate Windows processes
                if any(process_name == legit.lower() for legit in legitimate_processes):
                    continue
                
                # Check for bypasser arguments first (higher severity)
                for arg in bypasser_args:
                    if arg.lower() in command_line:
                        self.results["command_line_args"].append({
                            "process": process_name,
                            "command_line": command_line,
                            "description": f"Process using FiveM bypasser/HWID spoofer command line argument: {arg}",
                            "severity": "critical"
                        })
                        self.severity_count["critical"] += 1
                        break
                else:
                    # If not a bypasser argument, check for other suspicious arguments
                    for arg in suspicious_args:
                        if arg.lower() in command_line:
                            self.results["command_line_args"].append({
                                "process": process_name,
                                "command_line": command_line,
                                "description": f"Process using suspicious command line argument: {arg}",
                                "severity": "high"
                            })
                            self.severity_count["high"] += 1
                            break
                
        except Exception as e:
            self.log(f"Error checking command line arguments: {str(e)}", "error")
    
    def analyze_usn_journal(self):
        """Analyze USN journal for deleted cheat files"""
        self.log_progress("Analyzing USN journal for deleted files...", 60)
        
        # Check for common cheat-related deleted files
        suspicious_patterns = [
            "eulen", "redengine", "skript", "desudo", "hammafia", "lynx", "hydro", 
            "dopamine", "absolute", "maestro", "reaper", "fallout", "brutan", "lumia", 
            "surge", "impulse", "paragon", "phantom", "ozark", "cherax", "2take1", 
            "stand", "midnight", "robust", "disturbed", "loader", "injector", "hack", 
            "cheat", "USBDeview", "BetterDiscord-Windows", "TDLoader", "diamond",
            "Impaciente", "hwid_get", "cobra"
        ]
        
        # FiveM bypasser and HWID spoofer specific patterns
        bypasser_patterns = [
            "fivembypass", "bypass_fivem", "hwid_spoof", "hwid_bypass", "fivem_unban",
            "cfx_bypass", "citizenfx_bypass", "spoofer", "hwid_reset", "hwid_clean",
            "hwid_changer", "serial_changer", "mac_changer", "ban_evade", "ban_bypass",
            "cfx_unban", "fivem_cleaner", "trace_cleaner"
        ]
        
        # Combine all patterns for searching
        all_patterns = suspicious_patterns + bypasser_patterns
        
        # Run the USN journal query for deleted EXEs
        try:
            # Create a temporary file to store the output
            temp_file = os.path.join(tempfile.gettempdir(), "DeletedExes.txt")
            
            # Run the fsutil command to get deleted EXEs from USN journal
            command = f'fsutil usn readjournal c: csv | findstr /i /c:.exe | findstr /i /c:0x80000200 > "{temp_file}"'
            subprocess.run(command, shell=True, check=False)
            
            # Also check for deleted DLLs
            dll_temp_file = os.path.join(tempfile.gettempdir(), "DeletedDlls.txt")
            dll_command = f'fsutil usn readjournal c: csv | findstr /i /c:.dll | findstr /i /c:0x80000200 > "{dll_temp_file}"'
            subprocess.run(dll_command, shell=True, check=False)
            
            # Also check for deleted SYS files (potential drivers for HWID spoofers)
            sys_temp_file = os.path.join(tempfile.gettempdir(), "DeletedSys.txt")
            sys_command = f'fsutil usn readjournal c: csv | findstr /i /c:.sys | findstr /i /c:0x80000200 > "{sys_temp_file}"'
            subprocess.run(sys_command, shell=True, check=False)
            
            # Process the results
            deleted_files = []
            
            # Process EXE files
            if os.path.exists(temp_file):
                with open(temp_file, 'r') as f:
                    for line in f:
                        for pattern in all_patterns:
                            if pattern.lower() in line.lower():
                                # Determine severity based on pattern type
                                severity = "critical" if pattern in bypasser_patterns else "high"
                                
                                # Add to results
                                deleted_files.append({
                                    "file": line.strip(),
                                    "description": f"Deleted file matching {'FiveM bypasser/HWID spoofer' if pattern in bypasser_patterns else 'cheat'} pattern: {pattern}",
                                    "severity": severity
                                })
                                self.severity_count[severity] += 1
                                break
                
                # Clean up
                os.remove(temp_file)
            
            # Process DLL files
            if os.path.exists(dll_temp_file):
                with open(dll_temp_file, 'r') as f:
                    for line in f:
                        for pattern in all_patterns:
                            if pattern.lower() in line.lower():
                                # Determine severity based on pattern type
                                severity = "critical" if pattern in bypasser_patterns else "high"
                                
                                # Add to results
                                deleted_files.append({
                                    "file": line.strip(),
                                    "description": f"Deleted DLL matching {'FiveM bypasser/HWID spoofer' if pattern in bypasser_patterns else 'cheat'} pattern: {pattern}",
                                    "severity": severity
                                })
                                self.severity_count[severity] += 1
                                break
                
                # Clean up
                os.remove(dll_temp_file)
            
            # Process SYS files
            if os.path.exists(sys_temp_file):
                with open(sys_temp_file, 'r') as f:
                    for line in f:
                        for pattern in all_patterns:
                            if pattern.lower() in line.lower():
                                # SYS files related to bypasser patterns are especially suspicious (likely drivers)
                                severity = "critical" if pattern in bypasser_patterns else "high"
                                
                                # Add to results
                                deleted_files.append({
                                    "file": line.strip(),
                                    "description": f"Deleted driver file matching {'FiveM bypasser/HWID spoofer' if pattern in bypasser_patterns else 'cheat'} pattern: {pattern}",
                                    "severity": severity
                                })
                                self.severity_count[severity] += 1
                                break
                
                # Clean up
                os.remove(sys_temp_file)
            
            # Add results to the main results dictionary
            self.results["usn_journal"] = deleted_files
            
        except Exception as e:
            self.log(f"Error analyzing USN journal: {str(e)}", "error")
            self.results["usn_journal"] = [{
                "file": "Error",
                "description": f"Error analyzing USN journal: {str(e)}",
                "severity": "error"
            }]
            self.severity_count["error"] += 1
        
        self.log_progress("USN journal analysis complete", 65)
    
    def _get_file_timestamp(self, file_path):
        """Get the timestamp of a file"""
        try:
            if os.path.exists(file_path):
                timestamp = os.path.getmtime(file_path)
                dt = datetime.datetime.fromtimestamp(timestamp)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            self.log(f"Error getting file timestamp: {str(e)}", "error")
        return "Unknown"
    
    def analyze_network_connections(self):
        """Analyze network connections for suspicious patterns"""
        self.log_progress("Analyzing network connections...", 85)
        
        # Check for suspicious network connections
        self._check_network_connections()
        
        self.log_progress("Network connections analysis complete", 90)
    
    def _check_network_connections(self):
        """Check for suspicious network connections"""
        try:
            # Get all active network connections
            command = 'netstat -ano'
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.log.warning(f"Error running netstat command: {result.stderr}")
                return
            
            # Parse the output
            lines = result.stdout.strip().split('\n')
            
            # Known cheat server domains and IPs
            suspicious_domains = [
                "eulen.cc", "eulencheats", "redengine", "skript.gg", "desudo", 
                "hammafia", "lynxmenu", "hydromenu", "dopamine", "absolute", 
                "maestro", "reaper", "fallout", "brutan", "lumia", "surge", 
                "impulse", "paragon", "phantom", "ozark", "cherax", "2take1", 
                "stand", "midnight", "robust", "disturbed"
            ]
            
            # FiveM bypasser and HWID spoofer specific domains
            bypasser_domains = [
                "bypass.server", "fivembypass.com", "cfxbypass.net", 
                "hwid-spoofer.com", "spoofer-service.net", "hwid-reset.com",
                "hwid-spoof.com", "serial-spoof.net", "mac-changer.com", 
                "hwid-reset.net", "hardware-spoof.com",
                "fivem-unban.com", "cfx-unban.net", "ban-bypass.com", 
                "ban-evade.net", "fivem-cleaner.com"
            ]
            
            # Suspicious IP ranges
            suspicious_ips = [
                "185.193.36.", "194.87.138.", "194.87.139.", "45.131.208.", "45.131.209.",
                "193.84.64.", "185.137.234.", "185.223.28.", "185.223.29."
            ]
            
            # Suspicious ports
            suspicious_ports = ["1337", "6666", "7777", "8989", "9999"]
            
            # Get process information for correlation
            process_info = {}
            try:
                proc_command = 'tasklist /fo csv'
                proc_result = subprocess.run(proc_command, shell=True, capture_output=True, text=True)
                if proc_result.returncode == 0:
                    proc_lines = proc_result.stdout.strip().split('\n')
                    for proc_line in proc_lines[1:]:  # Skip header
                        parts = proc_line.strip('"').split('","')
                        if len(parts) >= 2:
                            process_name = parts[0]
                            pid = parts[1]
                            process_info[pid] = process_name
            except Exception as e:
                self.log(f"Error getting process information: {str(e)}", "error")
            
            # Initialize results list
            network_results = []
            
            for line in lines[4:]:  # Skip header lines
                parts = line.strip().split()
                if len(parts) < 5:
                    continue
                
                protocol = parts[0]
                local_address = parts[1]
                remote_address = parts[2]
                state = parts[3] if protocol.lower() == "tcp" else "N/A"
                pid = parts[4] if protocol.lower() == "tcp" else parts[3]
                
                # Skip localhost connections
                if "127.0.0.1" in remote_address or "::1" in remote_address:
                    continue
                
                # Get process name
                process_name = process_info.get(pid, "Unknown")
                
                # Check for bypasser domains first (higher severity)
                for domain in bypasser_domains:
                    if domain in remote_address:
                        network_results.append({
                            "protocol": protocol,
                            "local_address": local_address,
                            "remote_address": remote_address,
                            "state": state,
                            "process": f"{process_name} (PID: {pid})",
                            "description": f"Connection to known FiveM bypasser/HWID spoofer domain: {domain}",
                            "severity": "critical"
                        })
                        self.severity_count["critical"] += 1
                        break
                else:
                    # Check for suspicious domains
                    for domain in suspicious_domains:
                        if domain in remote_address:
                            network_results.append({
                                "protocol": protocol,
                                "local_address": local_address,
                                "remote_address": remote_address,
                                "state": state,
                                "process": f"{process_name} (PID: {pid})",
                                "description": f"Connection to known cheat domain: {domain}",
                                "severity": "high"
                            })
                            self.severity_count["high"] += 1
                            break
                    
                    # Check for suspicious IP ranges
                    for ip_range in suspicious_ips:
                        if ip_range in remote_address:
                            network_results.append({
                                "protocol": protocol,
                                "local_address": local_address,
                                "remote_address": remote_address,
                                "state": state,
                                "process": f"{process_name} (PID: {pid})",
                                "description": f"Connection to suspicious IP range: {ip_range}",
                                "severity": "high"
                            })
                            self.severity_count["high"] += 1
                            break
                    
                    # Check for suspicious ports
                    remote_port = remote_address.split(':')[-1]
                    for port in suspicious_ports:
                        if port == remote_port:
                            network_results.append({
                                "protocol": protocol,
                                "local_address": local_address,
                                "remote_address": remote_address,
                                "state": state,
                                "process": f"{process_name} (PID: {pid})",
                                "description": f"Connection to suspicious port: {port}",
                                "severity": "warning"
                            })
                            self.severity_count["warning"] += 1
                            break
            
            # Add results to the main results dictionary
            self.results["network_connections"] = network_results
            
        except Exception as e:
            self.log(f"Error checking network connections: {str(e)}", "error")
    
# Example usage
if __name__ == "__main__":
    def progress_callback(message, progress):
        print(f"{progress}% - {message}")
    
    analyzer = ForensicAnalyzer(callback=progress_callback)
    results = analyzer.run_analysis()
    
    print("\nForensic Analysis Results:")
    print(f"DLL Injection Issues: {len(results['dll_injection'])}")
    print(f"File Remnant Issues: {len(results['file_remnants'])}")
    print(f"Registry Issues: {len(results['registry_forensics'])}")
    print(f"USN Journal Issues: {len(results['usn_journal'])}")
    print(f"Command Line Argument Issues: {len(results['command_line_args'])}")
    print(f"Network Connection Issues: {len(results['network_connections'])}")
    
    print("\nSeverity Counts:")
    print(f"Critical: {analyzer.severity_count['critical']}")
    print(f"Warning: {analyzer.severity_count['warning']}")
    print(f"Info: {analyzer.severity_count['info']}")
    print(f"High: {analyzer.severity_count['high']}")
    print(f"Error: {analyzer.severity_count['error']}")
