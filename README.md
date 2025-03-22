# FiveM Cheat Detector

A specialized tool for detecting potential cheating software in FiveM game installations.

## New in Version 3.0

- **Network Analysis**: Detects suspicious network connections, DNS modifications, and firewall tampering
- **Update System**: Automatic checks for application updates and cheat definition updates
- **Enhanced Forensic Analysis**: Improved detection of historical cheat installations
- **Improved Process Monitoring**: Better detection of suspicious processes and DLL injections
- **Comprehensive Reporting**: Enhanced reporting with additional details and recommendations

## Features

- **Service Check**: Detects if critical Windows services have been disabled (a common technique used by cheat software)
- **Event Viewer Analysis**: Scans Windows Event Logs for suspicious events like journal deletions and crashes
- **File Scanning**: Scans directories for known cheat signatures, suspicious file patterns, and recently modified files
- **Registry Check**: Examines Windows Registry for suspicious modifications related to FiveM cheats
- **Process Monitoring**: Identifies suspicious processes that may be associated with cheating
- **Forensic Analysis**: Uses Process Hacker-like features to detect if FiveM cheats were ever installed on the system, even if they've been removed
- **Network Analysis**: Checks for suspicious network connections, DNS modifications, and firewall tampering
- **Update System**: Keeps the application and cheat definitions up-to-date
- **Comprehensive Reporting**: Generates detailed reports with findings and recommendations

## Requirements

- Windows 10/11
- Python 3.7+
- pywin32 library

## Installation

1. Clone or download this repository
2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Building Standalone Executable

To build a standalone executable that can be run on any Windows system without requiring Python installation:

1. Make sure you have PyInstaller installed:
   ```
   pip install pyinstaller
   ```

2. Run the build script:
   ```
   python build_exe.py
   ```
   
   Alternatively, you can simply double-click the `build_exe.bat` file.

3. Once completed, the executable will be available in the `dist` folder as `FiveM_Cheat_Detector.exe`

## Installation

There are two ways to use the application:

### Method 1: Direct Execution
Simply run the executable from the `dist` folder. A desktop shortcut will be created automatically.

### Method 2: Full Installation
Run the `install.bat` script to:
- Copy the executable to Program Files
- Create desktop shortcut
- Create Start Menu entry

## Usage

Run the application directly with Python:
```
python fivem_cheat_detector2.1.py
```

## How to Use
1. Make sure you have python installed. (There is also a .exe version.)
2. Launch the application
3. Use the tabs to navigate between different detection methods
4. Run checks individually or use the "Run All Checks" button in the Report tab
5. Review the results and save the report if suspicious activity is detected

### Tabs and Functions

1. **Services Tab**: Check critical Windows services that are often disabled by cheat software
2. **Event Viewer Tab**: Query Windows Event Logs for suspicious events
3. **File Scan Tab**: Scan directories for suspicious files related to FiveM cheats
4. **Registry Tab**: Check Windows Registry for suspicious modifications
5. **Processes Tab**: Check running processes for suspicious activity
6. **Forensic Analysis Tab**: Detect evidence of past cheat usage, even if the cheats have been uninstalled
7. **Network Analysis Tab**: Check for suspicious network connections and DNS modifications
8. **Updates Tab**: Check for application updates and cheat definition updates
9. **Report Tab**: Generate a comprehensive report of all findings

### Running a Full Scan

1. Click the "Run All Checks" button on the Report tab
2. Wait for all scans to complete
3. Review the results in each tab
4. Generate a report by clicking "Generate Report"
5. Save the report using the "Save Report" button

## Forensic Analysis Features

The Forensic Analysis tab uses Process Hacker-like features to detect if FiveM cheats were ever installed on the system, even if they've been removed. It checks:

1. **Registry Forensic Evidence**: Examines registry keys that might contain references to cheat software
2. **Prefetch Files**: Checks Windows Prefetch files for evidence of cheat executable execution
3. **File Remnants**: Searches for remnants of cheat files in common locations
4. **Event Log History**: Analyzes Windows Event Logs for historical evidence of cheat usage

This deep forensic analysis can detect cheats that have been uninstalled or hidden, providing a comprehensive view of the system's history.

## Network Analysis Features

The Network Analysis tab examines network connections and configurations that might indicate cheat software:

1. **Active Connections**: Checks for connections to known cheat servers or suspicious domains
2. **DNS Modifications**: Examines the hosts file for suspicious redirections of FiveM-related domains
3. **Firewall Status**: Checks if the Windows Firewall has been disabled (common with cheats)
4. **Non-Standard Connections**: Identifies if FiveM is connecting to non-standard servers

## Update System

The Updates tab provides functionality to keep the application up-to-date:

1. **Application Updates**: Checks for newer versions of the FiveM Cheat Detector
2. **Definition Updates**: Updates the cheat definitions database with the latest known cheats
3. **Automatic Download**: Downloads updates and guides you through the installation process

## Disclaimer

This tool is for educational and informational purposes only. It is designed to help server administrators identify potential cheating software. False positives may occur, and the absence of detections does not guarantee the absence of cheats.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
