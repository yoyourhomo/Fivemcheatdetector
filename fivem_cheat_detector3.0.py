#!/usr/bin/env python
"""
FiveM Cheat Detector v3.0
Advanced Forensic Analysis Edition

This application detects FiveM cheats and provides forensic analysis
to identify historical cheat usage.
"""

import os
import sys
import time
import datetime
import subprocess
import threading
from threading import Thread
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import re
import winreg
import socket
import ctypes
from ctypes import windll
import win32api
import win32con
import win32service
import win32security
import win32process
import win32file
import win32gui
import win32com.client
import pywintypes
import codecs
import psutil
import random
from deleted_cheat_detector import DeletedCheatDetector
import requests
import tempfile
import logging
import traceback
from PIL import Image, ImageTk
from io import BytesIO

# Function to check if running as administrator
def is_admin():
    """Check if the application is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# Function to restart the application with admin rights
def run_as_admin():
    """Restart the application with administrator privileges"""
    # Show a message explaining why admin rights are needed
    ctypes.windll.user32.MessageBoxW(
        0,
        "FiveM Cheat Detector requires administrator privileges to access protected system files like Prefetch data.\n\n"
        "This is necessary for comprehensive forensic analysis and to detect deleted cheat files.\n\n"
        "Click OK to restart with administrator privileges.",
        "Administrator Rights Required",
        0x40 | 0x1  # MB_ICONINFORMATION | MB_OKCANCEL
    )
    
    # Restart with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

# Define theme constants
DARK_THEME = {
    "bg": "#1E1E1E",
    "fg": "#FFFFFF",
    "accent": "#0078D7",
    "accent_fg": "#FFFFFF",
    "error": "#FF5252",
    "warning": "#FFC107",
    "info": "#03A9F4",
    "success": "#4CAF50",
    "card_bg": "#252525",
    "card_border": "#333333",
    "nav_bg": "#333333",
    "nav_fg": "#CCCCCC",
    "nav_active_bg": "#0078D7",  # Added missing key
    "nav_active_fg": "#FFFFFF",  # Added missing key
    "button_bg": "#444444",
    "button_fg": "#FFFFFF",
    "text_bg": "#2D2D2D",
    "text_fg": "#FFFFFF"
}

# Define font constants
FONT_FAMILY = "Segoe UI"
HEADING_FONT = (FONT_FAMILY, 18, "bold")
SUBHEADING_FONT = (FONT_FAMILY, 14, "bold")
NORMAL_FONT = (FONT_FAMILY, 10)
SMALL_FONT = (FONT_FAMILY, 9)
MONOSPACE_FONT = ("Consolas", 10)
BUTTON_FONT = (FONT_FAMILY, 10)

class ModernButton(tk.Button):
    """Custom button with modern styling"""
    def __init__(self, master=None, **kwargs):
        self.theme = kwargs.pop('theme', DARK_THEME)
        self.is_accent = kwargs.pop('is_accent', True)
        
        # Set default styling
        kwargs['relief'] = tk.FLAT
        kwargs['borderwidth'] = 0
        kwargs['font'] = kwargs.get('font', NORMAL_FONT)
        
        # Set colors based on theme and type
        if self.is_accent:
            kwargs['bg'] = self.theme['button_bg']
            kwargs['fg'] = self.theme['button_fg']
            kwargs['activebackground'] = self.theme['accent']
            kwargs['activeforeground'] = self.theme['button_fg']
        else:
            kwargs['bg'] = self.theme['bg']
            kwargs['fg'] = self.theme['fg']
            kwargs['activebackground'] = self.theme['card_border']
            kwargs['activeforeground'] = self.theme['fg']
        
        # Create the button
        super().__init__(master, **kwargs)
        
        # Add padding
        self['padx'] = 15
        self['pady'] = 5
        
        # Bind hover events
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
    
    def on_enter(self, event):
        """Mouse hover effect"""
        if self.is_accent:
            self['bg'] = self.theme['accent']
        else:
            self['bg'] = self.theme['card_border']
    
    def on_leave(self, event):
        """Mouse leave effect"""
        if self.is_accent:
            self['bg'] = self.theme['button_bg']
        else:
            self['bg'] = self.theme['bg']
    
    def update_theme(self, theme):
        """Update button theme"""
        self.theme = theme
        if self.is_accent:
            self['bg'] = self.theme['button_bg']
            self['fg'] = self.theme['button_fg']
            self['activebackground'] = self.theme['accent']
            self['activeforeground'] = self.theme['button_fg']
        else:
            self['bg'] = self.theme['bg']
            self['fg'] = self.theme['fg']
            self['activebackground'] = self.theme['card_border']
            self['activeforeground'] = self.theme['fg']

class ModernCard(tk.Frame):
    """Custom card widget with modern styling"""
    def __init__(self, master=None, **kwargs):
        self.theme = kwargs.pop('theme', DARK_THEME)
        self.title_text = kwargs.pop('title', None)
        
        # Set frame styling
        kwargs['bg'] = self.theme['card_bg']
        kwargs['highlightbackground'] = self.theme['card_border']
        kwargs['highlightthickness'] = 1
        
        # Create the frame
        super().__init__(master, **kwargs)
        
        # Add title if provided
        if self.title_text:
            self.title = tk.Label(
                self, 
                text=self.title_text,
                font=SUBHEADING_FONT,
                bg=self.theme['card_bg'],
                fg=self.theme['fg']
            )
            self.title.pack(anchor='w', padx=15, pady=(15, 5))
            
            # Add separator
            self.separator = ttk.Separator(self, orient='horizontal')
            self.separator.pack(fill='x', padx=15, pady=5)
        
        # Create content frame
        self.content_frame = tk.Frame(
            self,
            bg=self.theme['card_bg']
        )
        self.content_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
    
    def update_theme(self, theme):
        """Update card theme"""
        self.theme = theme
        self['bg'] = self.theme['card_bg']
        self['highlightbackground'] = self.theme['card_border']
        
        if self.title_text:
            self.title['bg'] = self.theme['card_bg']
            self.title['fg'] = self.theme['fg']
        
        self.content_frame['bg'] = self.theme['card_bg']
        
        # Update all children
        for child in self.content_frame.winfo_children():
            if hasattr(child, 'update_theme'):
                child.update_theme(self.theme)
            elif isinstance(child, tk.Label):
                child['bg'] = self.theme['card_bg']
                child['fg'] = self.theme['fg']
            elif isinstance(child, tk.Frame):
                child['bg'] = self.theme['card_bg']

class FiveMCheatDetector:
    """Main application class for FiveM Cheat Detector v3.0"""
    def __init__(self, root):
        """Initialize the application"""
        self.root = root
        self.root.title("FiveM Cheat Detector")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Set version
        self.version = "3.0.0"
        
        # Set icon
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass  # Icon not found, use default
        
        # Always use dark mode
        self.is_dark_mode = True
        self.theme = DARK_THEME
        
        # Apply theme to root
        self.root.configure(bg=self.theme["bg"])
        
        # Initialize variables
        self.frames = {}
        self.current_frame = None
        self.sidebar_buttons = {}  # Initialize sidebar_buttons dictionary
        self.current_sidebar_btn = None
        self.nav_buttons = {}
        
        # Status variables
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.IntVar(value=0)
        
        # Statistics variables
        self.total_issues_var = tk.StringVar(value="0")
        self.critical_issues_var = tk.StringVar(value="0")
        self.warning_issues_var = tk.StringVar(value="0")
        self.info_issues_var = tk.StringVar(value="0")
        
        # Initialize report data
        self.report_data = {
            "process_issues": [],
            "service_issues": [],
            "file_issues": [],
            "registry_issues": [],
            "network_issues": [],
            "forensic_issues": []
        }
        
        # Define critical services
        self.critical_services = [
            "BFE", "mpssvc", "SharedAccess", "WinDefend"
        ]
        
        # Initialize known cheats database
        self.initialize_cheat_database()
        
        # Configure ttk styles
        self.configure_styles()
        
        # Create UI layout
        self.create_layout()
        
        # Log startup
        self.log_activity("Application started")
        self.status_var.set("Ready")
    
    def initialize_cheat_database(self):
        """Initialize the database of known cheats"""
        self.log_activity("Initializing cheat database")
        
        # This would normally load from a file, but for simplicity we'll define it here
        self.cheat_database = {
            "version": "1.0.0",
            "last_updated": "2025-03-22",
            "processes": [
                {"name": "eulen.exe", "description": "Eulen Cheat", "severity": "critical"},
                {"name": "redengine.exe", "description": "Red Engine Cheat", "severity": "critical"},
                {"name": "loader_prod.exe", "description": "Eulen Loader", "severity": "critical"},
                {"name": "TDLoader.exe", "description": "TD Free Cheat", "severity": "critical"},
                {"name": "fontdrvhost.exe", "description": "TD Premium Cheat", "severity": "critical"},
                {"name": "svhost.exe", "description": "TZX Cheat", "severity": "critical"},
                {"name": "BetterDiscord-Windows.exe", "description": "TestOgg Cheat", "severity": "critical"},
                {"name": "launcher.exe", "description": "Gosth Cheat", "severity": "critical"},
                {"name": "diamond.exe", "description": "Susano Cheat", "severity": "critical"},
                {"name": "Impaciente.exe", "description": "Red Engine Cheat", "severity": "critical"},
                {"name": "hwid_get.exe", "description": "HX Softwares Cheat", "severity": "critical"},
                {"name": "free cobra loader.exe", "description": "Cobra Free Cheat", "severity": "critical"},
                {"name": "USBDeview.exe", "description": "Skript.gg Cheat", "severity": "critical"}
            ],
            "files": [
                {"path": "*\\d3d10.dll", "description": "D3D10 Cheat", "severity": "critical"},
                {"path": "*\\USBDeview.dll", "description": "Skript.gg Cheat", "severity": "critical"},
                {"path": "*\\settings.cock", "description": "Red Engine Cheat", "severity": "critical"},
                {"path": "*\\gtav\\imgui.ini", "description": "Red Engine Cheat", "severity": "critical"}
            ],
            "registry": [
                {"path": "HKCU\\Software\\Eulen", "description": "Eulen Cheat", "severity": "critical"},
                {"path": "HKCU\\Software\\RedEngine", "description": "Red Engine Cheat", "severity": "critical"}
            ]
        }
        
        self.log_activity(f"Cheat database initialized (version {self.cheat_database['version']})")
    
    def configure_styles(self):
        """Configure ttk styles for the application"""
        style = ttk.Style()
        
        # Configure TNotebook style (for tabs)
        style.configure("TNotebook", background=self.theme["bg"])
        style.configure("TNotebook.Tab", background="#1E1E1E", foreground=self.theme["fg"], padding=[10, 2])
        style.map("TNotebook.Tab", background=[("selected", self.theme["accent"])], foreground=[("selected", self.theme["accent_fg"])])
        
        # Configure Treeview style (for lists)
        style.configure("Treeview", background=self.theme["card_bg"], foreground=self.theme["fg"], fieldbackground=self.theme["card_bg"])
        style.map("Treeview", background=[("selected", self.theme["accent"])], foreground=[("selected", self.theme["accent_fg"])])
        
        # Configure other ttk widgets
        style.configure("TButton", background=self.theme["button_bg"], foreground=self.theme["button_fg"])
        style.configure("TLabel", background=self.theme["bg"], foreground=self.theme["fg"])
        style.configure("TFrame", background=self.theme["bg"])
    
    def create_layout(self):
        """Create the main application layout"""
        # Create main container
        self.main_container = tk.Frame(self.root, bg=self.theme["bg"])
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create sidebar
        self.sidebar = tk.Frame(self.main_container, bg=self.theme["nav_bg"], width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)  # Prevent sidebar from shrinking
        
        # Create logo
        logo_frame = tk.Frame(self.sidebar, bg=self.theme["nav_bg"], height=100)
        logo_frame.pack(fill=tk.X)
        
        logo_text = tk.Label(logo_frame, text="FiveM\nCheat Detector", 
                           font=(FONT_FAMILY, 16, "bold"), 
                           bg=self.theme["nav_bg"], fg=self.theme["accent"])
        logo_text.pack(pady=20)
        
        # Create content area
        self.content_area = tk.Frame(self.main_container, bg=self.theme["bg"])
        self.content_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Create status bar
        self.create_status_bar()
        
        # Initialize frames dictionary
        self.frames = {}
        
        # Create all frames
        self.frames["dashboard"] = self.create_dashboard_frame()
        self.frames["deleted_cheat"] = self.create_deleted_cheat_frame()
        self.frames["registry"] = self.create_registry_frame()
        self.frames["services"] = self.create_services_frame()
        self.frames["network"] = self.create_network_frame()
        self.frames["forensic"] = self.create_forensic_frame()
        self.frames["updates"] = self.create_updates_frame()
        
        # Show the dashboard frame by default
        self.show_frame("dashboard")
        
        # Create sidebar buttons
        self.create_sidebar_button("Dashboard", "dashboard", 0)
        self.create_sidebar_button("Deleted Cheat Detection", "deleted_cheat", 1)
        self.create_sidebar_button("Registry Analysis", "registry", 2)
        self.create_sidebar_button("Services Analysis", "services", 3)
        self.create_sidebar_button("Network Analysis", "network", 4)
        self.create_sidebar_button("Forensic Analysis", "forensic", 5)
        self.create_sidebar_button("Updates", "updates", 6)
    
    def create_dashboard_frame(self):
        """Create the dashboard frame with one-click scan button"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Create header
        header = tk.Frame(frame, bg=self.theme["bg"], height=100)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        title = tk.Label(header, text="FiveM Cheat Detector v3.0", font=HEADING_FONT, bg=self.theme["bg"], fg=self.theme["fg"])
        title.pack(anchor="w")
        
        subtitle = tk.Label(header, text="Advanced Forensic Analysis Edition", font=SUBHEADING_FONT, bg=self.theme["bg"], fg=self.theme["accent"])
        subtitle.pack(anchor="w")
        
        # Create main content
        content = tk.Frame(frame, bg=self.theme["bg"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create one-click scan card
        scan_card = tk.Frame(content, bg=self.theme["card_bg"], padx=20, pady=20, highlightbackground=self.theme["card_border"], highlightthickness=1)
        scan_card.pack(fill=tk.X, pady=10)
        
        scan_title = tk.Label(scan_card, text="One-Click Comprehensive Scan", font=SUBHEADING_FONT, bg=self.theme["card_bg"], fg=self.theme["fg"])
        scan_title.pack(anchor="w", pady=(0, 10))
        
        scan_desc = tk.Label(scan_card, text="Detect active cheats and historical cheat usage with a single click. This scan will check for all known FiveM cheats and analyze your system for evidence of deleted cheats.", 
                           font=NORMAL_FONT, bg=self.theme["card_bg"], fg=self.theme["fg"], justify=tk.LEFT, wraplength=800)
        scan_desc.pack(anchor="w", pady=(0, 20))
        
        scan_button = tk.Button(scan_card, text="Start Comprehensive Scan", font=NORMAL_FONT, bg=self.theme["accent"], fg=self.theme["accent_fg"],
                              padx=20, pady=10, relief=tk.FLAT, command=self.run_all_checks)
        scan_button.pack(anchor="w")
        
        # Create statistics cards
        stats_frame = tk.Frame(content, bg=self.theme["bg"])
        stats_frame.pack(fill=tk.X, pady=20)
        
        # Create 4 statistic cards in a row
        for i, (title, var, color) in enumerate([
            ("Total Issues", self.total_issues_var, self.theme["accent"]),
            ("Critical Issues", self.critical_issues_var, self.theme["error"]),
            ("Warnings", self.warning_issues_var, self.theme["warning"]),
            ("Info", self.info_issues_var, self.theme["info"])
        ]):
            stat_card = tk.Frame(stats_frame, bg=self.theme["card_bg"], padx=15, pady=15, highlightbackground=self.theme["card_border"], highlightthickness=1)
            stat_card.grid(row=0, column=i, padx=5, sticky="nsew")
            
            stat_title = tk.Label(stat_card, text=title, font=NORMAL_FONT, bg=self.theme["card_bg"], fg=self.theme["fg"])
            stat_title.pack(anchor="w")
            
            stat_value = tk.Label(stat_card, textvariable=var, font=HEADING_FONT, bg=self.theme["card_bg"], fg=color)
            stat_value.pack(anchor="w", pady=5)
        
        # Configure grid columns to be equal width
        for i in range(4):
            stats_frame.grid_columnconfigure(i, weight=1)
        
        return frame
    
    def create_deleted_cheat_frame(self):
        """Create the deleted cheat detection frame"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Create the deleted cheat detector
        self.deleted_cheat_detector = DeletedCheatDetector(frame, self.theme)
        self.deleted_cheat_detector.pack(fill=tk.BOTH, expand=True)
        
        # Connect the callback for results
        self.deleted_cheat_detector.set_results_callback(self.handle_deleted_cheat_results)
        
        return frame
    
    def handle_deleted_cheat_results(self, results):
        """Handle results from the deleted cheat detector"""
        # Update statistics
        total_issues = len(results.get("issues", []))
        critical_issues = len([i for i in results.get("issues", []) if i.get("severity") == "critical"])
        warning_issues = len([i for i in results.get("issues", []) if i.get("severity") == "warning"])
        info_issues = len([i for i in results.get("issues", []) if i.get("severity") == "info"])
        
        self.total_issues_var.set(str(total_issues))
        self.critical_issues_var.set(str(critical_issues))
        self.warning_issues_var.set(str(warning_issues))
        self.info_issues_var.set(str(info_issues))
        
        # Update report data
        self.report_data["forensic_issues"] = results.get("issues", [])
        
        # Log completion
        self.log_activity(f"Deleted cheat detection completed: {total_issues} issues found")
    
    def create_status_bar(self):
        """Create the status bar at the bottom of the application"""
        self.status_bar = tk.Frame(self.root, bg=self.theme["card_bg"], height=30)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Status label
        self.status_label = tk.Label(self.status_bar, textvariable=self.status_var, bg=self.theme["card_bg"], fg=self.theme["fg"], font=SMALL_FONT)
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Version label
        version_label = tk.Label(self.status_bar, text=f"v{self.version}", bg=self.theme["card_bg"], fg=self.theme["fg"], font=SMALL_FONT)
        version_label.pack(side=tk.RIGHT, padx=10)
    
    def log_activity(self, message):
        """Log activity to console and potentially a log file"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        print(log_message)
        
        # Update status bar
        self.status_var.set(message)
        
        # In a real application, you might want to write to a log file as well
    
    def run_all_checks(self):
        """Run all checks"""
        self.log_activity("Starting comprehensive scan...")
        
        # Reset statistics
        self.total_issues_var.set("0")
        self.critical_issues_var.set("0")
        self.warning_issues_var.set("0")
        self.info_issues_var.set("0")
        
        # Start the scan in a separate thread to keep UI responsive
        threading.Thread(target=self._run_all_checks_thread, daemon=True).start()
    
    def _run_all_checks_thread(self):
        """Run all checks in a separate thread"""
        # First, switch to the deleted cheat frame to show progress
        self.root.after(0, lambda: self.show_frame("deleted_cheat"))
        
        # Start the deleted cheat detection
        self.root.after(100, self.run_deleted_cheat_detection)
    
    def run_deleted_cheat_detection(self):
        """Run deleted cheat detection"""
        self.log_activity("Running deleted cheat detection...")
        
        # Start the scan using the deleted cheat detector
        self.deleted_cheat_detector.start_scan()
    
    def show_frame(self, frame_name):
        """Show the specified frame and update sidebar button states"""
        # Hide current frame if exists
        if self.current_frame:
            self.frames[self.current_frame].pack_forget()
        
        # Show new frame
        self.frames[frame_name].pack(fill=tk.BOTH, expand=True)
        self.current_frame = frame_name
        
        # Update sidebar button states
        for name, button in self.sidebar_buttons.items():
            if name == frame_name:
                button.configure(bg=self.theme["accent"], fg=self.theme["accent_fg"])
                self.current_sidebar_btn = button
            else:
                button.configure(bg=self.theme["nav_bg"], fg=self.theme["nav_fg"])
    
    def create_sidebar_button(self, text, frame_name, index):
        """Create a sidebar button for navigation"""
        # Get theme colors with fallbacks
        nav_bg = self.theme.get("nav_bg", "#333333")
        nav_fg = self.theme.get("nav_fg", "#CCCCCC")
        nav_active_bg = self.theme.get("nav_active_bg", "#0078D7")
        nav_active_fg = self.theme.get("nav_active_fg", "#FFFFFF")
        
        button = tk.Button(
            self.sidebar,
            text=text,
            font=BUTTON_FONT,
            bg=nav_bg,
            fg=nav_fg,
            activebackground=nav_active_bg,
            activeforeground=nav_active_fg,
            bd=0,
            relief=tk.FLAT,
            padx=10,
            pady=5,
            anchor=tk.W,
            justify=tk.LEFT,
            command=lambda f=frame_name: self.show_frame(f)
        )
        button.pack(fill=tk.X, padx=5, pady=2)
        
        # Store the button for later reference
        self.sidebar_buttons[frame_name] = button
        
        # Highlight the active button
        if frame_name == "dashboard":
            button.configure(bg=nav_active_bg, fg=nav_active_fg)
    
    def update_ui_with_results(self, results):
        """Update the UI with the results of the cheat detection"""
        # Clear previous results
        self.result_text.delete(1.0, tk.END)
        
        # Add a header
        self.result_text.insert(tk.END, "=== FiveM Cheat Detector Results ===\n\n", "header")
        
        # Process summary
        if "processes" in results:
            self.result_text.insert(tk.END, "PROCESS CHECKS:\n", "section")
            if results["processes"]:
                for process in results["processes"]:
                    severity = process.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- {process['name']}: ", "bold")
                    self.result_text.insert(tk.END, f"{process['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No suspicious processes detected.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # File summary
        if "files" in results:
            self.result_text.insert(tk.END, "FILE CHECKS:\n", "section")
            if results["files"]:
                for file in results["files"]:
                    severity = file.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- {file['path']}: ", "bold")
                    self.result_text.insert(tk.END, f"{file['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No suspicious files detected.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # DLL injection summary
        if "dll_injection" in results:
            self.result_text.insert(tk.END, "DLL INJECTION CHECKS:\n", "section")
            if results["dll_injection"]:
                for dll in results["dll_injection"]:
                    severity = dll.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- Process: {dll['process']}, DLL: {dll['dll']}: ", "bold")
                    self.result_text.insert(tk.END, f"{dll['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No DLL injection detected.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # File remnants summary
        if "file_remnants" in results:
            self.result_text.insert(tk.END, "FILE REMNANT CHECKS:\n", "section")
            if results["file_remnants"]:
                for remnant in results["file_remnants"]:
                    severity = remnant.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- {remnant['name']} ({remnant['path']}): ", "bold")
                    self.result_text.insert(tk.END, f"{remnant['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No suspicious file remnants detected.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # Registry forensics summary
        if "registry_forensics" in results:
            self.result_text.insert(tk.END, "REGISTRY FORENSICS:\n", "section")
            if results["registry_forensics"]:
                for reg in results["registry_forensics"]:
                    severity = reg.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- {reg['key']}: {reg['value']}: ", "bold")
                    self.result_text.insert(tk.END, f"{reg['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No suspicious registry entries detected.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # USN journal summary
        if "usn_journal" in results:
            self.result_text.insert(tk.END, "USN JOURNAL ANALYSIS:\n", "section")
            if results["usn_journal"]:
                for usn in results["usn_journal"]:
                    severity = usn.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- {usn['file']}: ", "bold")
                    self.result_text.insert(tk.END, f"{usn['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No suspicious deleted files detected in USN journal.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # Command line arguments summary
        if "command_line_args" in results:
            self.result_text.insert(tk.END, "COMMAND LINE ARGUMENT ANALYSIS:\n", "section")
            if results["command_line_args"]:
                for cmd in results["command_line_args"]:
                    severity = cmd.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- Process: {cmd['process']}: ", "bold")
                    self.result_text.insert(tk.END, f"{cmd['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No suspicious command line arguments detected.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # Network connections summary
        if "network_connections" in results:
            self.result_text.insert(tk.END, "NETWORK CONNECTION ANALYSIS:\n", "section")
            if results["network_connections"]:
                for conn in results["network_connections"]:
                    severity = conn.get("severity", "warning")
                    self.result_text.insert(tk.END, f"- {conn['protocol']} {conn['local_address']} -> {conn['remote_address']} ({conn['process']}): ", "bold")
                    self.result_text.insert(tk.END, f"{conn['description']}\n", severity)
            else:
                self.result_text.insert(tk.END, "No suspicious network connections detected.\n", "good")
            self.result_text.insert(tk.END, "\n")
        
        # Add a summary section
        self.result_text.insert(tk.END, "DETECTION SUMMARY:\n", "section")
        critical_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "critical")
        high_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "high")
        warning_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "warning")
        
        if critical_count > 0:
            self.result_text.insert(tk.END, f"CRITICAL ISSUES: {critical_count}\n", "critical")
        if high_count > 0:
            self.result_text.insert(tk.END, f"HIGH SEVERITY ISSUES: {high_count}\n", "high")
        if warning_count > 0:
            self.result_text.insert(tk.END, f"WARNING ISSUES: {warning_count}\n", "warning")
        
        if critical_count == 0 and high_count == 0 and warning_count == 0:
            self.result_text.insert(tk.END, "No issues detected. System appears clean.\n", "good")
        else:
            # Add special note for FiveM bypasser and HWID spoofer detection
            bypasser_detected = any(
                item.get("description", "").lower().find("fivem bypasser") != -1 or 
                item.get("description", "").lower().find("hwid spoofer") != -1
                for category in results.values() 
                for item in category 
                if isinstance(item, dict)
            )
            
            if bypasser_detected:
                self.result_text.insert(tk.END, "\nWARNING: FiveM bypasser or HWID spoofer detected!\n", "critical")
                self.result_text.insert(tk.END, "These tools are used to evade FiveM bans and are strictly prohibited.\n", "critical")
                self.result_text.insert(tk.END, "Using these tools can result in permanent bans from FiveM and associated servers.\n", "critical")
        
        # Scroll to the top
        self.result_text.see("1.0")

    def run_checks(self):
        """Run all cheat detection checks"""
        self.progress_var.set(0)
        self.progress_label.config(text="Starting checks...")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "Running checks...\n")
        
        # Create a thread for running the checks
        threading.Thread(target=self._run_checks_thread, daemon=True).start()
    
    def _run_checks_thread(self):
        """Thread function for running checks"""
        try:
            # Initialize the forensic analyzer
            analyzer = ForensicAnalyzer(progress_callback=self.update_progress)
            
            # Run the analysis
            results = analyzer.analyze_all()
            
            # Update the UI with the results
            self.update_ui_with_results(results)
            
            # Save the results to a file
            self.save_results_to_file(results)
            
            # Show a message box with the summary
            critical_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "critical")
            high_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "high")
            warning_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "warning")
            
            # Check specifically for bypasser/spoofer detection
            bypasser_detected = any(
                item.get("description", "").lower().find("fivem bypasser") != -1 or 
                item.get("description", "").lower().find("hwid spoofer") != -1
                for category in results.values() 
                for item in category 
                if isinstance(item, dict)
            )
            
            if critical_count > 0 or high_count > 0:
                message = f"Detection complete. Found {critical_count} critical and {high_count} high severity issues."
                if bypasser_detected:
                    message += "\n\nWARNING: FiveM bypasser or HWID spoofer detected! These tools are strictly prohibited."
                messagebox.showwarning("FiveM Cheat Detector", message)
            elif warning_count > 0:
                messagebox.showinfo("FiveM Cheat Detector", f"Detection complete. Found {warning_count} potential issues.")
            else:
                messagebox.showinfo("FiveM Cheat Detector", "No issues detected. System appears clean.")
            
        except Exception as e:
            self.update_progress(f"Error: {str(e)}", 0)
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def save_results_to_file(self, results):
        """Save the results to a file"""
        try:
            # Create a directory for the results if it doesn't exist
            results_dir = os.path.join(os.path.expanduser("~"), "FiveM_Cheat_Detector_Results")
            os.makedirs(results_dir, exist_ok=True)
            
            # Create a filename with the current date and time
            filename = f"fivem_cheat_detector_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.join(results_dir, filename)
            
            with open(filepath, "w") as f:
                f.write("=== FiveM Cheat Detector Results ===\n\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Process summary
                if "processes" in results:
                    f.write("PROCESS CHECKS:\n")
                    if results["processes"]:
                        for process in results["processes"]:
                            f.write(f"- {process['name']}: {process['description']} (Severity: {process.get('severity', 'warning')})\n")
                    else:
                        f.write("No suspicious processes detected.\n")
                    f.write("\n")
                
                # File summary
                if "files" in results:
                    f.write("FILE CHECKS:\n")
                    if results["files"]:
                        for file in results["files"]:
                            f.write(f"- {file['path']}: {file['description']} (Severity: {file.get('severity', 'warning')})\n")
                    else:
                        f.write("No suspicious files detected.\n")
                    f.write("\n")
                
                # DLL injection summary
                if "dll_injection" in results:
                    f.write("DLL INJECTION CHECKS:\n")
                    if results["dll_injection"]:
                        for dll in results["dll_injection"]:
                            f.write(f"- Process: {dll['process']}, DLL: {dll['dll']}: {dll['description']} (Severity: {dll.get('severity', 'warning')})\n")
                    else:
                        f.write("No DLL injection detected.\n")
                    f.write("\n")
                
                # File remnants summary
                if "file_remnants" in results:
                    f.write("FILE REMNANT CHECKS:\n")
                    if results["file_remnants"]:
                        for remnant in results["file_remnants"]:
                            f.write(f"- {remnant['name']} ({remnant['path']}): {remnant['description']} (Severity: {remnant.get('severity', 'warning')})\n")
                    else:
                        f.write("No suspicious file remnants detected.\n")
                    f.write("\n")
                
                # Registry forensics summary
                if "registry_forensics" in results:
                    f.write("REGISTRY FORENSICS:\n")
                    if results["registry_forensics"]:
                        for reg in results["registry_forensics"]:
                            f.write(f"- {reg['key']}: {reg['value']}: {reg['description']} (Severity: {reg.get('severity', 'warning')})\n")
                    else:
                        f.write("No suspicious registry entries detected.\n")
                    f.write("\n")
                
                # USN journal summary
                if "usn_journal" in results:
                    f.write("USN JOURNAL ANALYSIS:\n")
                    if results["usn_journal"]:
                        for usn in results["usn_journal"]:
                            f.write(f"- {usn['file']}: {usn['description']} (Severity: {usn.get('severity', 'warning')})\n")
                    else:
                        f.write("No suspicious deleted files detected in USN journal.\n")
                    f.write("\n")
                
                # Command line arguments summary
                if "command_line_args" in results:
                    f.write("COMMAND LINE ARGUMENT ANALYSIS:\n")
                    if results["command_line_args"]:
                        for cmd in results["command_line_args"]:
                            f.write(f"- Process: {cmd['process']}: {cmd['description']} (Severity: {cmd.get('severity', 'warning')})\n")
                    else:
                        f.write("No suspicious command line arguments detected.\n")
                    f.write("\n")
                
                # Network connections summary
                if "network_connections" in results:
                    f.write("NETWORK CONNECTION ANALYSIS:\n")
                    if results["network_connections"]:
                        for conn in results["network_connections"]:
                            f.write(f"- {conn['protocol']} {conn['local_address']} -> {conn['remote_address']} ({conn['process']}): {conn['description']} (Severity: {conn.get('severity', 'warning')})\n")
                    else:
                        f.write("No suspicious network connections detected.\n")
                    f.write("\n")
                
                # Add a summary section
                f.write("DETECTION SUMMARY:\n")
                critical_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "critical")
                high_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "high")
                warning_count = sum(1 for category in results.values() for item in category if isinstance(item, dict) and item.get("severity") == "warning")
                
                if critical_count > 0:
                    f.write(f"CRITICAL ISSUES: {critical_count}\n")
                if high_count > 0:
                    f.write(f"HIGH SEVERITY ISSUES: {high_count}\n")
                if warning_count > 0:
                    f.write(f"WARNING ISSUES: {warning_count}\n")
                
                if critical_count == 0 and high_count == 0 and warning_count == 0:
                    f.write("No issues detected. System appears clean.\n")
                else:
                    # Add special note for FiveM bypasser and HWID spoofer detection
                    bypasser_detected = any(
                        item.get("description", "").lower().find("fivem bypasser") != -1 or 
                        item.get("description", "").lower().find("hwid spoofer") != -1
                        for category in results.values() 
                        for item in category 
                        if isinstance(item, dict)
                    )
                    
                    if bypasser_detected:
                        f.write("\nWARNING: FiveM bypasser or HWID spoofer detected!\n")
                        f.write("These tools are used to evade FiveM bans and are strictly prohibited.\n")
                        f.write("Using these tools can result in permanent bans from FiveM and associated servers.\n")
            
            self.update_progress(f"Results saved to {filepath}", 100)
            
        except Exception as e:
            self.update_progress(f"Error saving results: {str(e)}", 100)
            messagebox.showerror("Error", f"Error saving results: {str(e)}")

    def create_registry_frame(self):
        """Create the registry analysis frame"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Create header
        header = tk.Frame(frame, bg=self.theme["bg"], height=100)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        title = tk.Label(header, text="Registry Analysis", font=HEADING_FONT, bg=self.theme["bg"], fg=self.theme["fg"])
        title.pack(anchor="w")
        
        subtitle = tk.Label(header, text="Scan Windows registry for potential cheat remnants", 
                          font=SUBHEADING_FONT, bg=self.theme["bg"], fg=self.theme["accent"])
        subtitle.pack(anchor="w")
        
        # Create main content
        content = tk.Frame(frame, bg=self.theme["bg"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create registry keys list
        keys_frame = ModernCard(content, title="Registry Keys to Check")
        keys_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 10), pady=10)
        
        # Create a listbox for registry keys
        self.registry_keys_listbox = tk.Listbox(
            keys_frame.content_frame,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"],
            selectbackground=self.theme["accent"],
            selectforeground=self.theme["accent_fg"],
            font=NORMAL_FONT,
            height=15,
            width=40
        )
        self.registry_keys_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add some common registry locations to check
        registry_keys = [
            "HKEY_CURRENT_USER\\Software\\Eulen",
            "HKEY_CURRENT_USER\\Software\\RedEngine",
            "HKEY_CURRENT_USER\\Software\\Skript",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]
        
        for key in registry_keys:
            self.registry_keys_listbox.insert(tk.END, key)
        
        # Create buttons frame
        buttons_frame = tk.Frame(keys_frame.content_frame, bg=self.theme["card_bg"])
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add buttons
        scan_button = ModernButton(
            buttons_frame,
            text="Scan All Keys",
            command=self.run_registry_scan,
            theme=self.theme
        )
        scan_button.pack(side=tk.LEFT, padx=5)
        
        check_button = ModernButton(
            buttons_frame,
            text="Check Selected Key",
            command=self.check_selected_registry_key,
            theme=self.theme
        )
        check_button.pack(side=tk.LEFT, padx=5)
        
        # Create results frame
        results_frame = ModernCard(content, title="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(10, 0), pady=10)
        
        # Create text area for results
        self.registry_results_text = tk.Text(
            results_frame.content_frame,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"],
            font=NORMAL_FONT,
            wrap=tk.WORD,
            height=15,
            width=50
        )
        self.registry_results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        return frame
    
    def run_registry_scan(self):
        """Scan all registry keys for potential cheat remnants"""
        self.status_var.set("Scanning registry keys...")
        self.registry_results_text.delete(1.0, tk.END)
        self.registry_results_text.insert(tk.END, "Starting registry scan...\n\n")
        
        # Get all keys from the listbox
        keys = [self.registry_keys_listbox.get(i) for i in range(self.registry_keys_listbox.size())]
        
        # Run the scan in a separate thread
        threading.Thread(target=self._run_registry_scan_thread, args=(keys,), daemon=True).start()
    
    def _run_registry_scan_thread(self, keys):
        """Thread function for running registry scan"""
        import winreg
        
        issues_found = []
        
        for key_path in keys:
            try:
                # Update status
                self.root.after(0, lambda: self.status_var.set(f"Scanning {key_path}..."))
                self.root.after(0, lambda k=key_path: self.registry_results_text.insert(tk.END, f"Checking {k}...\n"))
                
                # Parse the key path
                if key_path.startswith("HKEY_CURRENT_USER"):
                    hkey = winreg.HKEY_CURRENT_USER
                    subkey = key_path[18:]  # Remove "HKEY_CURRENT_USER\"
                elif key_path.startswith("HKEY_LOCAL_MACHINE"):
                    hkey = winreg.HKEY_LOCAL_MACHINE
                    subkey = key_path[19:]  # Remove "HKEY_LOCAL_MACHINE\"
                elif key_path.startswith("HKEY_USERS"):
                    hkey = winreg.HKEY_USERS
                    subkey = key_path[11:]  # Remove "HKEY_USERS\"
                else:
                    self.root.after(0, lambda k=key_path: self.registry_results_text.insert(tk.END, f"Unsupported key format: {k}\n"))
                    continue
                
                # Try to open the key
                try:
                    key = winreg.OpenKey(hkey, subkey)
                except FileNotFoundError:
                    self.root.after(0, lambda k=key_path: self.registry_results_text.insert(tk.END, f"Key not found: {k}\n"))
                    continue
                
                # Check for suspicious values
                try:
                    i = 0
                    while True:
                        name, value, type_ = winreg.EnumValue(key, i)
                        
                        # Check if the value contains suspicious strings
                        suspicious = False
                        suspicious_terms = ["cheat", "hack", "inject", "eulen", "redengine", "skript", "bypass"]
                        
                        if isinstance(value, str):
                            for term in suspicious_terms:
                                if term.lower() in value.lower():
                                    suspicious = True
                                    break
                        
                        if suspicious:
                            issue = {
                                "path": f"{key_path}\\{name}",
                                "description": f"Suspicious registry value: {value}",
                                "severity": "critical"
                            }
                            issues_found.append(issue)
                            
                            self.root.after(0, lambda i=issue: self.registry_results_text.insert(tk.END, f"[CRITICAL] {i['path']}: {i['description']}\n"))
                        
                        i += 1
                except WindowsError:
                    # No more values
                    pass
                
                # Check for suspicious subkeys
                try:
                    i = 0
                    while True:
                        subkey_name = winreg.EnumKey(key, i)
                        
                        # Check if the subkey name contains suspicious strings
                        suspicious = False
                        for term in suspicious_terms:
                            if term.lower() in subkey_name.lower():
                                suspicious = True
                                break
                        
                        if suspicious:
                            issue = {
                                "path": f"{key_path}\\{subkey_name}",
                                "description": f"Suspicious registry key",
                                "severity": "critical"
                            }
                            issues_found.append(issue)
                            
                            self.root.after(0, lambda i=issue: self.registry_results_text.insert(tk.END, f"[CRITICAL] {i['path']}: {i['description']}\n"))
                        
                        i += 1
                except WindowsError:
                    # No more subkeys
                    pass
                
                winreg.CloseKey(key)
                
            except Exception as e:
                self.root.after(0, lambda k=key_path, err=str(e): self.registry_results_text.insert(tk.END, f"Error scanning {k}: {err}\n"))
        
        # Update report data
        if "registry_issues" not in self.report_data:
            self.report_data["registry_issues"] = []
        self.report_data["registry_issues"].extend(issues_found)
        
        # Update status
        if issues_found:
            self.root.after(0, lambda: self.status_var.set(f"Registry scan complete. Found {len(issues_found)} issues."))
            self.root.after(0, lambda: self.registry_results_text.insert(tk.END, f"\nScan complete. Found {len(issues_found)} issues.\n"))
        else:
            self.root.after(0, lambda: self.status_var.set("Registry scan complete. No issues found."))
            self.root.after(0, lambda: self.registry_results_text.insert(tk.END, "\nScan complete. No issues found.\n"))
    
    def check_selected_registry_key(self):
        """Check the selected registry key for potential cheat remnants"""
        selected = self.registry_keys_listbox.curselection()
        
        if not selected:
            messagebox.showinfo("No Selection", "Please select a registry key to check.")
            return
        
        key_path = self.registry_keys_listbox.get(selected[0])
        self.status_var.set(f"Checking {key_path}...")
        self.registry_results_text.delete(1.0, tk.END)
        self.registry_results_text.insert(tk.END, f"Checking {key_path}...\n\n")
        
        # Run the check in a separate thread
        threading.Thread(target=self._run_registry_scan_thread, args=([key_path],), daemon=True).start()
    
    def create_services_frame(self):
        """Create the services analysis frame"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Create header
        header = tk.Frame(frame, bg=self.theme["bg"], height=100)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        title = tk.Label(header, text="Services Analysis", font=HEADING_FONT, bg=self.theme["bg"], fg=self.theme["fg"])
        title.pack(anchor="w")
        
        subtitle = tk.Label(header, text="Analyze Windows services for potential cheat-related services", 
                          font=SUBHEADING_FONT, bg=self.theme["bg"], fg=self.theme["accent"])
        subtitle.pack(anchor="w")
        
        # Create main content
        content = tk.Frame(frame, bg=self.theme["bg"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create services list frame
        services_frame = ModernCard(content, title="Services")
        services_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 10), pady=10)
        
        # Create a treeview for services
        columns = ("name", "display_name", "status", "start_type", "binary_path")
        self.services_tree = ttk.Treeview(
            services_frame.content_frame,
            columns=columns,
            show="headings",
            height=15
        )
        
        # Define column headings
        self.services_tree.heading("name", text="Service Name")
        self.services_tree.heading("display_name", text="Display Name")
        self.services_tree.heading("status", text="Status")
        self.services_tree.heading("start_type", text="Start Type")
        self.services_tree.heading("binary_path", text="Binary Path")
        
        # Define column widths
        self.services_tree.column("name", width=100)
        self.services_tree.column("display_name", width=150)
        self.services_tree.column("status", width=80)
        self.services_tree.column("start_type", width=100)
        self.services_tree.column("binary_path", width=200)
        
        # Add scrollbar
        services_scrollbar = ttk.Scrollbar(services_frame.content_frame, orient=tk.VERTICAL, command=self.services_tree.yview)
        self.services_tree.configure(yscrollcommand=services_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.services_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        services_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Create buttons frame
        buttons_frame = tk.Frame(services_frame.content_frame, bg=self.theme["card_bg"])
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add buttons
        scan_button = ModernButton(
            buttons_frame,
            text="Scan Services",
            command=self.scan_services,
            theme=self.theme
        )
        scan_button.pack(side=tk.LEFT, padx=5)
        
        check_button = ModernButton(
            buttons_frame,
            text="Check Selected Service",
            command=self.check_selected_service,
            theme=self.theme
        )
        check_button.pack(side=tk.LEFT, padx=5)
        
        # Create details frame
        details_frame = ModernCard(content, title="Service Details")
        details_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(10, 0), pady=10)
        
        # Create text area for details
        self.service_details_text = tk.Text(
            details_frame.content_frame,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"],
            font=NORMAL_FONT,
            wrap=tk.WORD,
            height=15,
            width=50
        )
        self.service_details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        return frame
    
    def scan_services(self):
        """Scan Windows services for potential cheat-related services"""
        self.status_var.set("Scanning Windows services...")
        self.service_details_text.delete(1.0, tk.END)
        self.service_details_text.insert(tk.END, "Starting services scan...\n\n")
        
        # Clear the treeview
        for item in self.services_tree.get_children():
            self.services_tree.delete(item)
        
        # Run the scan in a separate thread
        threading.Thread(target=self._scan_services_thread, daemon=True).start()
    
    def _scan_services_thread(self):
        """Thread function for scanning services"""
        import win32service
        import win32con
        
        issues_found = []
        
        try:
            # Open the Service Control Manager
            sc_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            
            # Get all services
            services = win32service.EnumServicesStatus(sc_handle, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL)
            
            # Suspicious terms to look for in service names and descriptions
            suspicious_terms = ["cheat", "hack", "inject", "eulen", "redengine", "skript", "bypass", "fivem", "gta"]
            
            # Process each service
            for i, service in enumerate(services):
                service_name = service[0]
                display_name = service[1]
                status = service[2]
                
                # Update progress
                progress = int((i + 1) / len(services) * 100)
                self.root.after(0, lambda p=progress: self.progress_var.set(p))
                self.root.after(0, lambda: self.status_var.set(f"Scanning services ({i+1}/{len(services)})..."))
                
                try:
                    # Open the service to get more details
                    service_handle = win32service.OpenService(
                        sc_handle, 
                        service_name, 
                        win32service.SERVICE_QUERY_CONFIG
                    )
                    
                    # Get service configuration
                    config = win32service.QueryServiceConfig(service_handle)
                    
                    # Get binary path and start type
                    binary_path = config[3]
                    start_type = config[2]
                    
                    # Convert start type to string
                    start_type_str = {
                        win32service.SERVICE_AUTO_START: "Auto",
                        win32service.SERVICE_DEMAND_START: "Manual",
                        win32service.SERVICE_DISABLED: "Disabled",
                        win32service.SERVICE_BOOT_START: "Boot",
                        win32service.SERVICE_SYSTEM_START: "System"
                    }.get(start_type, str(start_type))
                    
                    # Convert status to string
                    status_str = {
                        win32service.SERVICE_STOPPED: "Stopped",
                        win32service.SERVICE_START_PENDING: "Starting",
                        win32service.SERVICE_STOP_PENDING: "Stopping",
                        win32service.SERVICE_RUNNING: "Running",
                        win32service.SERVICE_CONTINUE_PENDING: "Continuing",
                        win32service.SERVICE_PAUSE_PENDING: "Pausing",
                        win32service.SERVICE_PAUSED: "Paused"
                    }.get(status[1], str(status[1]))
                    
                    # Convert service type to string
                    service_type_str = {
                        win32service.SERVICE_KERNEL_DRIVER: "Kernel Driver",
                        win32service.SERVICE_FILE_SYSTEM_DRIVER: "File System Driver",
                        win32service.SERVICE_WIN32_OWN_PROCESS: "Own Process",
                        win32service.SERVICE_WIN32_SHARE_PROCESS: "Shared Process",
                        win32service.SERVICE_INTERACTIVE_PROCESS: "Interactive Process"
                    }.get(service_type & ~win32service.SERVICE_INTERACTIVE_PROCESS, str(service_type))
                    
                    if service_type & win32service.SERVICE_INTERACTIVE_PROCESS:
                        service_type_str += " (Interactive)"
                    
                    # Convert error control to string
                    error_control_str = {
                        win32service.SERVICE_ERROR_IGNORE: "Ignore",
                        win32service.SERVICE_ERROR_NORMAL: "Normal",
                        win32service.SERVICE_ERROR_SEVERE: "Severe",
                        win32service.SERVICE_ERROR_CRITICAL: "Critical"
                    }.get(error_control, str(error_control))
                    
                    # Format dependencies
                    dependencies_str = ", ".join(dependencies) if dependencies else "None"
                    
                    # Check if the service is suspicious
                    suspicious = False
                    suspicious_reason = ""
                    
                    # Check service name
                    for term in suspicious_terms:
                        if term.lower() in service_name.lower() or term.lower() in display_name.lower():
                            suspicious = True
                            suspicious_reason = f"Service name contains suspicious term: {term}"
                            break
                    
                    # Check binary path
                    if not suspicious:
                        for term in suspicious_terms:
                            if term.lower() in binary_path.lower():
                                suspicious = True
                                suspicious_reason = f"Binary path contains suspicious term: {term}"
                                break
                    
                    # Check for specific cheat-related services based on the cheat database
                    for cheat_process in self.cheat_database["processes"]:
                        cheat_name = cheat_process["name"].lower()
                        if cheat_name in binary_path.lower():
                            suspicious = True
                            suspicious_reason = f"Binary path contains known cheat process: {cheat_name}"
                            break
                    
                    # Add to treeview
                    item_id = self.root.after(0, lambda sn=service_name, dn=display_name, ss=status_str, st=start_type_str, bp=binary_path: 
                        self.services_tree.insert("", tk.END, values=(sn, dn, ss, st, bp)))
                    
                    # If suspicious, highlight in the treeview and add to issues
                    if suspicious:
                        issue = {
                            "name": service_name,
                            "display_name": display_name,
                            "binary_path": binary_path,
                            "description": suspicious_reason,
                            "severity": "critical"
                        }
                        issues_found.append(issue)
                        
                        # Add to report data
                        self.report_data["service_issues"].append(issue)
                        
                        # Highlight in treeview (need to wait for the item to be inserted)
                        self.root.after(100, lambda i=item_id: self.highlight_tree_item(i))
                
                except Exception as e:
                    # Skip this service if there's an error
                    pass
            
            # Close Service Control Manager handle
            win32service.CloseServiceHandle(sc_handle)
            
            # Update status
            if issues_found:
                self.root.after(0, lambda: self.status_var.set(f"Services scan complete. Found {len(issues_found)} suspicious services."))
                self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Scan complete. Found {len(issues_found)} suspicious services.\n\n"))
                
                # Add details of suspicious services
                for issue in issues_found:
                    self.root.after(0, lambda i=issue: self.service_details_text.insert(tk.END, 
                        f"[CRITICAL] {i['name']} ({i['display_name']})\n"
                        f"Binary Path: {i['binary_path']}\n"
                        f"Reason: {i['description']}\n\n"))
            else:
                self.root.after(0, lambda: self.status_var.set("Services scan complete. No suspicious services found."))
                self.root.after(0, lambda: self.service_details_text.insert(tk.END, "Scan complete. No suspicious services found.\n"))
            
        except Exception as e:
            self.root.after(0, lambda err=str(e): self.service_details_text.insert(tk.END, f"Error scanning services: {err}\n"))
            self.root.after(0, lambda: self.status_var.set("Error scanning services."))
        
        # Reset progress
        self.root.after(0, lambda: self.progress_var.set(0))
    
    def check_selected_service(self):
        """Check details of the selected service"""
        selected = self.services_tree.selection()
        
        if not selected:
            messagebox.showinfo("No Selection", "Please select a service to check.")
            return
        
        # Get service details
        service_name = self.services_tree.item(selected[0], "values")[0]
        
        # Clear details text
        self.service_details_text.delete(1.0, tk.END)
        self.service_details_text.insert(tk.END, f"Checking service: {service_name}...\n\n")
        
        # Run the check in a separate thread
        threading.Thread(target=self._check_service_thread, args=(service_name,), daemon=True).start()
    
    def _check_service_thread(self, service_name):
        """Thread function for checking a specific service"""
        import win32service
        import win32con
        
        try:
            # Open the Service Control Manager
            sc_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            
            # Open the service
            service_handle = win32service.OpenService(
                sc_handle, 
                service_name, 
                win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
            )
            
            # Get service configuration
            config = win32service.QueryServiceConfig(service_handle)
            
            # Get service status
            status = win32service.QueryServiceStatus(service_handle)
            
            # Get binary path and start type
            binary_path = config[3]
            start_type = config[2]
            service_type = config[0]
            error_control = config[1]
            load_order_group = config[4]
            tag_id = config[5]
            dependencies = config[6]
            service_start_name = config[7]
            display_name = config[8]
            
            # Convert start type to string
            start_type_str = {
                win32service.SERVICE_AUTO_START: "Auto",
                win32service.SERVICE_DEMAND_START: "Manual",
                win32service.SERVICE_DISABLED: "Disabled",
                win32service.SERVICE_BOOT_START: "Boot",
                win32service.SERVICE_SYSTEM_START: "System"
            }.get(start_type, str(start_type))
            
            # Convert status to string
            status_str = {
                win32service.SERVICE_STOPPED: "Stopped",
                win32service.SERVICE_START_PENDING: "Starting",
                win32service.SERVICE_STOP_PENDING: "Stopping",
                win32service.SERVICE_RUNNING: "Running",
                win32service.SERVICE_CONTINUE_PENDING: "Continuing",
                win32service.SERVICE_PAUSE_PENDING: "Pausing",
                win32service.SERVICE_PAUSED: "Paused"
            }.get(status[1], str(status[1]))
            
            # Convert service type to string
            service_type_str = {
                win32service.SERVICE_KERNEL_DRIVER: "Kernel Driver",
                win32service.SERVICE_FILE_SYSTEM_DRIVER: "File System Driver",
                win32service.SERVICE_WIN32_OWN_PROCESS: "Own Process",
                win32service.SERVICE_WIN32_SHARE_PROCESS: "Shared Process",
                win32service.SERVICE_INTERACTIVE_PROCESS: "Interactive Process"
            }.get(service_type & ~win32service.SERVICE_INTERACTIVE_PROCESS, str(service_type))
            
            if service_type & win32service.SERVICE_INTERACTIVE_PROCESS:
                service_type_str += " (Interactive)"
            
            # Convert error control to string
            error_control_str = {
                win32service.SERVICE_ERROR_IGNORE: "Ignore",
                win32service.SERVICE_ERROR_NORMAL: "Normal",
                win32service.SERVICE_ERROR_SEVERE: "Severe",
                win32service.SERVICE_ERROR_CRITICAL: "Critical"
            }.get(error_control, str(error_control))
            
            # Format dependencies
            dependencies_str = ", ".join(dependencies) if dependencies else "None"
            
            # Check if the service is suspicious
            suspicious = False
            suspicious_reason = ""
            
            # Suspicious terms to look for
            suspicious_terms = ["cheat", "hack", "inject", "eulen", "redengine", "skript", "bypass", "fivem", "gta"]
            
            # Check service name
            for term in suspicious_terms:
                if term.lower() in service_name.lower() or term.lower() in display_name.lower():
                    suspicious = True
                    suspicious_reason = f"Service name contains suspicious term: {term}"
                    break
            
            # Check binary path
            if not suspicious:
                for term in suspicious_terms:
                    if term.lower() in binary_path.lower():
                        suspicious = True
                        suspicious_reason = f"Binary path contains suspicious term: {term}"
                        break
            
            # Check for specific cheat-related services based on the cheat database
            for cheat_process in self.cheat_database["processes"]:
                cheat_name = cheat_process["name"].lower()
                if cheat_name in binary_path.lower():
                    suspicious = True
                    suspicious_reason = f"Binary path contains known cheat process: {cheat_name}"
                    break
            
            # Update details text
            self.root.after(0, lambda: self.service_details_text.delete(1.0, tk.END))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Service: {service_name}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Display Name: {display_name}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Status: {status_str}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Start Type: {start_type_str}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Service Type: {service_type_str}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Error Control: {error_control_str}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Binary Path: {binary_path}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Service Start Name: {service_start_name}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Load Order Group: {load_order_group or 'None'}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Tag ID: {tag_id or 'None'}\n"))
            self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Dependencies: {dependencies_str}\n"))
            
            if suspicious:
                self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"\n[WARNING] This service is suspicious!\n"))
                self.root.after(0, lambda: self.service_details_text.insert(tk.END, f"Reason: {suspicious_reason}\n"))
            
            # Close handles
            win32service.CloseServiceHandle(service_handle)
            win32service.CloseServiceHandle(sc_handle)
            
        except Exception as e:
            self.root.after(0, lambda err=str(e): self.service_details_text.insert(tk.END, f"Error checking service: {err}\n"))
    
    def create_network_frame(self):
        """Create the network analysis frame"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Create header
        header = tk.Frame(frame, bg=self.theme["bg"], height=100)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        title = tk.Label(header, text="Network Analysis", font=HEADING_FONT, bg=self.theme["bg"], fg=self.theme["fg"])
        title.pack(anchor="w")
        
        subtitle = tk.Label(header, text="Scan network connections for potential FiveM cheat communication", 
                          font=SUBHEADING_FONT, bg=self.theme["bg"], fg=self.theme["accent"])
        subtitle.pack(anchor="w")
        
        # Create main content
        content = tk.Frame(frame, bg=self.theme["bg"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create connections list frame
        connections_frame = ModernCard(content, title="Network Connections")
        connections_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 10), pady=10)
        
        # Create a treeview for connections
        columns = ("pid", "process", "local_addr", "remote_addr", "status")
        self.network_tree = ttk.Treeview(
            connections_frame.content_frame,
            columns=columns,
            show="headings",
            height=15
        )
        
        # Define column headings
        self.network_tree.heading("pid", text="PID")
        self.network_tree.heading("process", text="Process")
        self.network_tree.heading("local_addr", text="Local Address")
        self.network_tree.heading("remote_addr", text="Remote Address")
        self.network_tree.heading("status", text="Status")
        
        # Define column widths
        self.network_tree.column("pid", width=50)
        self.network_tree.column("process", width=100)
        self.network_tree.column("local_addr", width=150)
        self.network_tree.column("remote_addr", width=150)
        self.network_tree.column("status", width=80)
        
        # Add scrollbar
        connections_scrollbar = ttk.Scrollbar(connections_frame.content_frame, orient=tk.VERTICAL, command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=connections_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.network_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        connections_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Create buttons frame
        buttons_frame = tk.Frame(connections_frame.content_frame, bg=self.theme["card_bg"])
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add buttons
        scan_button = ModernButton(
            buttons_frame,
            text="Scan Connections",
            command=self.scan_network_connections,
            theme=self.theme
        )
        scan_button.pack(side=tk.LEFT, padx=5)
        
        check_button = ModernButton(
            buttons_frame,
            text="Check Selected Connection",
            command=self.check_selected_connection,
            theme=self.theme
        )
        check_button.pack(side=tk.LEFT, padx=5)
        
        # Create details frame
        details_frame = ModernCard(content, title="Connection Details")
        details_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(10, 0), pady=10)
        
        # Create text area for details
        self.network_details_text = tk.Text(
            details_frame.content_frame,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"],
            font=NORMAL_FONT,
            wrap=tk.WORD,
            height=15,
            width=50
        )
        self.network_details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        return frame
    
    def scan_network_connections(self):
        """Scan network connections for potential cheat-related traffic"""
        self.status_var.set("Scanning network connections...")
        self.network_details_text.delete(1.0, tk.END)
        self.network_details_text.insert(tk.END, "Starting network scan...\n\n")
        
        # Clear the treeview
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)
        
        # Run the scan in a separate thread
        threading.Thread(target=self._scan_network_thread, daemon=True).start()
    
    def _scan_network_thread(self):
        """Thread function for scanning network connections"""
        import psutil
        
        issues_found = []
        
        try:
            # Get all network connections
            connections = psutil.net_connections(kind='all')
            
            # Get all processes
            processes = {p.pid: p for p in psutil.process_iter(['name', 'exe', 'cmdline'])}
            
            # Known cheat-related domains and IPs
            suspicious_domains = [
                "eulen", "skript", "redengine", "hxcheats", "testogg", "gosth", "susano", 
                "cobra", "hxsoftwares", "d3d10", "cheat", "hack", "inject"
            ]
            
            # Process each connection
            for i, conn in enumerate(connections):
                try:
                    # Extract connection details
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    status = conn.status
                    pid = conn.pid
                    
                    # Get process info
                    process_name = "N/A"
                    process_exe = "N/A"
                    
                    if pid and pid in processes:
                        process = processes[pid]
                        process_name = process.info['name'] if 'name' in process.info else "N/A"
                        process_exe = process.info['exe'] if 'exe' in process.info else "N/A"
                    
                    # Check if the connection is suspicious
                    suspicious = False
                    suspicious_reason = ""
                    
                    # Check remote address for suspicious domains/IPs
                    if conn.raddr:
                        for domain in suspicious_domains:
                            if domain.lower() in conn.raddr.ip.lower():
                                suspicious = True
                                suspicious_reason = f"Remote IP contains suspicious domain: {domain}"
                                break
                    
                    # Check if the process is a known cheat process
                    if not suspicious and pid:
                        for cheat_process in self.cheat_database["processes"]:
                            if process_name.lower() == cheat_process["name"].lower():
                                suspicious = True
                                suspicious_reason = f"Process is a known cheat process: {process_name}"
                                break
                    
                    # Add to treeview
                    item_id = self.root.after(0, lambda ln=process_name, la=laddr, ra=raddr, st=status, pe=process_exe: 
                        self.network_tree.insert("", tk.END, values=(ln, la, ra, st, pe)))
                    
                    # If suspicious, highlight in the treeview and add to issues
                    if suspicious:
                        issue = {
                            "process_name": process_name,
                            "local_address": laddr,
                            "remote_address": raddr,
                            "status": status,
                            "process_path": process_exe,
                            "description": suspicious_reason,
                            "severity": "critical"
                        }
                        issues_found.append(issue)
                        
                        # Add to report data
                        self.report_data["network_issues"].append(issue)
                        
                        # Highlight in treeview (need to wait for the item to be inserted)
                        self.root.after(100, lambda i=item_id: self.highlight_tree_item(i))
                
                except Exception as e:
                    # Skip this connection if there's an error
                    pass
                
                # Update progress
                progress = int((i + 1) / len(connections) * 100)
                self.root.after(0, lambda p=progress: self.progress_var.set(p))
                self.root.after(0, lambda: self.status_var.set(f"Scanning connections ({i+1}/{len(connections)})..."))
            
            # Update status
            if issues_found:
                self.root.after(0, lambda: self.status_var.set(f"Network scan complete. Found {len(issues_found)} suspicious connections."))
                self.root.after(0, lambda: self.network_details_text.insert(tk.END, f"Scan complete. Found {len(issues_found)} suspicious connections.\n\n"))
                
                # Add details of suspicious connections
                for issue in issues_found:
                    self.root.after(0, lambda i=issue: self.network_details_text.insert(tk.END, 
                        f"[CRITICAL] {i['process_name']} ({i['process_path']})\n"
                        f"Local Address: {i['local_address']}\n"
                        f"Remote Address: {i['remote_address']}\n"
                        f"Status: {i['status']}\n"
                        f"Reason: {i['description']}\n\n"))
            else:
                self.root.after(0, lambda: self.status_var.set("Network scan complete. No suspicious connections found."))
                self.root.after(0, lambda: self.network_details_text.insert(tk.END, "Scan complete. No suspicious connections found.\n"))
            
        except Exception as e:
            self.root.after(0, lambda err=str(e): self.network_details_text.insert(tk.END, f"Error scanning network connections: {err}\n"))
            self.root.after(0, lambda: self.status_var.set("Error scanning network connections."))
        
        # Reset progress
        self.root.after(0, lambda: self.progress_var.set(0))
    
    def check_selected_connection(self):
        """Check details of the selected network connection"""
        selected = self.network_tree.selection()
        
        if not selected:
            messagebox.showinfo("No Selection", "Please select a connection to check.")
            return
        
        # Get connection details
        values = self.network_tree.item(selected[0], "values")
        process_name = values[0]
        local_address = values[1]
        remote_address = values[2]
        status = values[3]
        process_path = values[4]
        
        # Clear details text
        self.network_details_text.delete(1.0, tk.END)
        
        # Display connection details
        self.network_details_text.insert(tk.END, f"Process: {process_name}\n")
        self.network_details_text.insert(tk.END, f"Local Address: {local_address}\n")
        self.network_details_text.insert(tk.END, f"Remote Address: {remote_address}\n")
        self.network_details_text.insert(tk.END, f"Status: {status}\n")
        self.network_details_text.insert(tk.END, f"Process Path: {process_path}\n\n")
        
        # Check if the connection is suspicious
        suspicious = False
        suspicious_reason = ""
        
        # Known cheat-related domains and IPs
        suspicious_domains = [
            "eulen", "skript", "redengine", "hxcheats", "testogg", "gosth", "susano", 
            "cobra", "hxsoftwares", "d3d10", "cheat", "hack", "inject"
        ]
        
        # Check remote address for suspicious domains/IPs
        if remote_address != "N/A":
            for domain in suspicious_domains:
                if domain.lower() in remote_address.lower():
                    suspicious = True
                    suspicious_reason = f"Remote address contains suspicious domain: {domain}"
                    break
        
        # Check if the process is a known cheat process
        if not suspicious:
            for cheat_process in self.cheat_database["processes"]:
                if process_name.lower() == cheat_process["name"].lower():
                    suspicious = True
                    suspicious_reason = f"Process is a known cheat process: {process_name}"
                    break
        
        # Display suspicious warning if applicable
        if suspicious:
            self.network_details_text.insert(tk.END, f"[WARNING] This connection is suspicious!\n")
            self.network_details_text.insert(tk.END, f"Reason: {suspicious_reason}\n")
        
        # Try to get more details about the process
        try:
            import psutil
            
            # Find the process by name and path
            for proc in psutil.process_iter(['name', 'exe', 'cmdline', 'username', 'create_time']):
                if proc.info['name'] == process_name and (process_path == "N/A" or proc.info['exe'] == process_path):
                    # Get process details
                    self.network_details_text.insert(tk.END, f"\nAdditional Process Details:\n")
                    self.network_details_text.insert(tk.END, f"PID: {proc.pid}\n")
                    self.network_details_text.insert(tk.END, f"Username: {proc.info['username']}\n")
                    
                    # Format creation time
                    import datetime
                    create_time = datetime.datetime.fromtimestamp(proc.info['create_time']).strftime('%Y-%m-%d %H:%M:%S')
                    self.network_details_text.insert(tk.END, f"Created: {create_time}\n")
                    
                    # Get command line
                    cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else "N/A"
                    self.network_details_text.insert(tk.END, f"Command Line: {cmdline}\n")
                    
                    # Check if the process is related to FiveM
                    if "fivem" in process_name.lower() or "gta" in process_name.lower():
                        self.network_details_text.insert(tk.END, f"\n[INFO] This process appears to be related to FiveM or GTA V.\n")
                    
                    break
        
        except Exception as e:
            self.network_details_text.insert(tk.END, f"\nError getting additional process details: {str(e)}\n")
    
    def create_forensic_frame(self):
        """Create the forensic analysis frame"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Create header
        header = tk.Frame(frame, bg=self.theme["bg"], height=100)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        title = tk.Label(header, text="Forensic Analysis", font=HEADING_FONT, bg=self.theme["bg"], fg=self.theme["fg"])
        title.pack(anchor="w")
        
        subtitle = tk.Label(header, text="Advanced forensic analysis for detecting traces of deleted cheats", 
                          font=SUBHEADING_FONT, bg=self.theme["bg"], fg=self.theme["accent"])
        subtitle.pack(anchor="w")
        
        # Create main content
        content = tk.Frame(frame, bg=self.theme["bg"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create analysis options frame
        options_frame = ModernCard(content, title="Analysis Options")
        options_frame.pack(fill=tk.BOTH, expand=False, side=tk.TOP, pady=(0, 10))
        
        # Create checkboxes for analysis options
        options_content = tk.Frame(options_frame.content_frame, bg=self.theme["card_bg"])
        options_content.pack(fill=tk.X, padx=10, pady=10)
        
        # Create variables for checkboxes
        self.check_dll_var = tk.BooleanVar(value=True)
        self.check_files_var = tk.BooleanVar(value=True)
        self.check_registry_var = tk.BooleanVar(value=True)
        self.check_prefetch_var = tk.BooleanVar(value=True)
        self.check_usn_journal_var = tk.BooleanVar(value=True)
        
        # Create checkboxes
        check_dll = ttk.Checkbutton(
            options_content,
            text="Check for DLL injection evidence",
            variable=self.check_dll_var,
            style="TCheckbutton"
        )
        check_dll.grid(row=0, column=0, sticky="w", padx=10, pady=2)
        
        check_files = ttk.Checkbutton(
            options_content,
            text="Check for file remnants",
            variable=self.check_files_var,
            style="TCheckbutton"
        )
        check_files.grid(row=0, column=1, sticky="w", padx=10, pady=2)
        
        check_registry = ttk.Checkbutton(
            options_content,
            text="Check registry for forensic evidence",
            variable=self.check_registry_var,
            style="TCheckbutton"
        )
        check_registry.grid(row=1, column=0, sticky="w", padx=10, pady=2)
        
        check_prefetch = ttk.Checkbutton(
            options_content,
            text="Analyze prefetch files",
            variable=self.check_prefetch_var,
            style="TCheckbutton"
        )
        check_prefetch.grid(row=1, column=1, sticky="w", padx=10, pady=2)
        
        check_usn = ttk.Checkbutton(
            options_content,
            text="Scan USN journal for deleted cheat files",
            variable=self.check_usn_journal_var,
            style="TCheckbutton"
        )
        check_usn.grid(row=2, column=0, sticky="w", padx=10, pady=2)
        
        # Create buttons frame
        buttons_frame = tk.Frame(options_frame.content_frame, bg=self.theme["card_bg"])
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Add buttons
        scan_button = ModernButton(
            buttons_frame,
            text="Run Forensic Analysis",
            command=self.run_forensic_analysis,
            theme=self.theme
        )
        scan_button.pack(side=tk.LEFT, padx=5)
        
        # Create results frame
        results_frame = ModernCard(content, title="Analysis Results")
        results_frame.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM, pady=(10, 0))
        
        # Create text area for results
        self.forensic_results_text = tk.Text(
            results_frame.content_frame,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"],
            font=NORMAL_FONT,
            wrap=tk.WORD,
            height=15
        )
        self.forensic_results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        return frame
    
    def run_forensic_analysis(self):
        """Run forensic analysis to detect traces of deleted cheats"""
        self.status_var.set("Running forensic analysis...")
        self.forensic_results_text.delete(1.0, tk.END)
        self.forensic_results_text.insert(tk.END, "Starting forensic analysis...\n\n")
        
        # Get selected analysis types
        analysis_types = []
        if self.check_dll_var.get():
            analysis_types.append("dll_injection")
        if self.check_files_var.get():
            analysis_types.append("file_remnants")
        if self.check_registry_var.get():
            analysis_types.append("registry_forensics")
        if self.check_prefetch_var.get():
            analysis_types.append("prefetch")
        if self.check_usn_journal_var.get():
            analysis_types.append("usn_journal")
        
        if not analysis_types:
            messagebox.showinfo("No Selection", "Please select at least one analysis type.")
            self.status_var.set("Ready")
            return
        
        # Run the analysis in a separate thread
        threading.Thread(target=self._run_forensic_analysis_thread, args=(analysis_types,), daemon=True).start()
    
    def _run_forensic_analysis_thread(self, analysis_types):
        """Thread function for running forensic analysis"""
        import winreg
        import os
        
        issues_found = []
        
        for analysis_type in analysis_types:
            if analysis_type == "dll_injection":
                # Check for DLL injection evidence
                try:
                    # Get all running processes
                    processes = [p.info for p in psutil.process_iter(['pid', 'name'])]
                    
                    # Check each process for DLL injection
                    for process in processes:
                        pid = process['pid']
                        name = process['name']
                        
                        # Update status
                        self.root.after(0, lambda p=name: self.status_var.set(f"Checking {p} for DLL injection..."))
                        self.root.after(0, lambda p=name: self.forensic_results_text.insert(tk.END, f"Checking {p} for DLL injection...\n"))
                        
                        try:
                            # Get the process handle
                            process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
                            
                            # Get the DLLs loaded by the process
                            dlls = win32process.EnumProcessModules(process_handle)
                            
                            # Check each DLL for suspicious names
                            for dll in dlls:
                                dll_name = win32process.GetModuleFileNameEx(process_handle, dll)
                                dll_name = os.path.basename(dll_name)
                                
                                # Check if the DLL name contains suspicious terms
                                suspicious_terms = ["cheat", "hack", "inject", "eulen", "redengine", "skript", "bypass"]
                                for term in suspicious_terms:
                                    if term.lower() in dll_name.lower():
                                        issue = {
                                            "process": name,
                                            "dll": dll_name,
                                            "description": f"Suspicious DLL loaded: {dll_name}",
                                            "severity": "critical"
                                        }
                                        issues_found.append(issue)
                                        
                                        self.root.after(0, lambda i=issue: self.forensic_results_text.insert(tk.END, f"[CRITICAL] {i['process']}: {i['dll']}: {i['description']}\n"))
                                        break
                            
                            # Close the process handle
                            win32api.CloseHandle(process_handle)
                        
                        except Exception as e:
                            # Skip this process if there's an error
                            self.root.after(0, lambda p=name, err=str(e): self.forensic_results_text.insert(tk.END, f"Error checking {p}: {err}\n"))
                
                except Exception as e:
                    self.root.after(0, lambda err=str(e): self.forensic_results_text.insert(tk.END, f"Error checking for DLL injection: {err}\n"))
            
            elif analysis_type == "file_remnants":
                # Check for file remnants
                try:
                    # Get all files in the temp directory
                    temp_dir = os.environ['TEMP']
                    files = [f for f in os.listdir(temp_dir) if os.path.isfile(os.path.join(temp_dir, f))]
                    
                    # Check each file for suspicious names
                    for file in files:
                        # Check if the file name contains suspicious terms
                        suspicious_terms = ["cheat", "hack", "inject", "eulen", "redengine", "skript", "bypass"]
                        for term in suspicious_terms:
                            if term.lower() in file.lower():
                                issue = {
                                    "name": file,
                                    "path": os.path.join(temp_dir, file),
                                    "description": f"Suspicious file found: {file}",
                                    "severity": "critical"
                                }
                                issues_found.append(issue)
                                
                                self.root.after(0, lambda i=issue: self.forensic_results_text.insert(tk.END, f"[CRITICAL] {i['name']} ({i['path']}): {i['description']}\n"))
                                break
                
                except Exception as e:
                    self.root.after(0, lambda err=str(e): self.forensic_results_text.insert(tk.END, f"Error checking for file remnants: {err}\n"))
            
            elif analysis_type == "registry_forensics":
                # Check registry for forensic evidence
                try:
                    # Define registry keys to check
                    reg_paths = [
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel"
                    ]
                    
                    for reg_path in reg_paths:
                        try:
                            # Open the key
                            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
                            
                            # Enumerate values
                            i = 0
                            while True:
                                try:
                                    name, value, type_ = winreg.EnumValue(key, i)
                                    
                                    # Check if value contains suspicious terms
                                    suspicious_terms = ["cheat", "hack", "inject", "eulen", "redengine", "skript", "bypass"]
                                    for term in suspicious_terms:
                                        if isinstance(value, str) and term.lower() in value.lower():
                                            issue = {
                                                "key": reg_path,
                                                "value": name,
                                                "data": value,
                                                "description": f"Suspicious registry value: {value}",
                                                "severity": "critical"
                                            }
                                            issues_found.append(issue)
                                            
                                            self.root.after(0, lambda i=issue: self.forensic_results_text.insert(tk.END, 
                                                f"[CRITICAL] {i['key']}\\{i['value']}: {i['description']}\n"))
                                            break
                                    
                                    i += 1
                                except WindowsError:
                                    # No more values
                                    break
                            
                            # Close the key
                            winreg.CloseKey(key)
                        
                        except Exception as e:
                            # Skip this key if there's an error
                            self.root.after(0, lambda k=reg_path, err=str(e): 
                                self.forensic_results_text.insert(tk.END, f"Error checking {k}: {err}\n"))
                
                except Exception as e:
                    self.root.after(0, lambda err=str(e): 
                        self.forensic_results_text.insert(tk.END, f"Error checking registry for forensic evidence: {err}\n"))
            
            elif analysis_type == "prefetch":
                # Analyze prefetch files
                try:
                    # Get all prefetch files
                    prefetch_dir = os.environ['WINDIR'] + "\\Prefetch"
                    files = [f for f in os.listdir(prefetch_dir) if os.path.isfile(os.path.join(prefetch_dir, f))]
                    
                    # Check each file for suspicious names
                    for file in files:
                        # Check if the file name contains suspicious terms
                        suspicious_terms = ["cheat", "hack", "inject", "eulen", "redengine", "skript", "bypass"]
                        for term in suspicious_terms:
                            if term.lower() in file.lower():
                                issue = {
                                    "name": file,
                                    "path": os.path.join(prefetch_dir, file),
                                    "description": f"Suspicious prefetch file: {file}",
                                    "severity": "critical"
                                }
                                issues_found.append(issue)
                                
                                self.root.after(0, lambda i=issue: self.forensic_results_text.insert(tk.END, f"[CRITICAL] {i['name']} ({i['path']}): {i['description']}\n"))
                                break
                
                except Exception as e:
                    self.root.after(0, lambda err=str(e): self.forensic_results_text.insert(tk.END, f"Error analyzing prefetch files: {err}\n"))
            
            elif analysis_type == "usn_journal":
                # Analyze USN journal for deleted cheat files
                try:
                    # Known cheat file patterns to look for
                    cheat_patterns = [
                        "USBDeview.exe", "USBDeview.dll",  # Skript.gg
                        "loader.exe",  # hx-cheats
                        "loader_prod.exe",  # eulen
                        "TDLoader.exe",  # tdfree
                        "fontdrvhost.exe", "discord.exe",  # tdpremium
                        "svhost.exe", "svchost.exe",  # tzx (fake system processes)
                        "BetterDiscord-Windows.exe",  # testogg
                        "launcher.exe",  # gosth
                        "diamond.exe",  # susano
                        "Impaciente.exe", "settings.cock",  # red engine
                        "hwid_get.exe", "d3d10.dll",  # hxsoftwares
                        "free cobra loader.exe",  # cobrafree
                        "imgui.ini"  # red engine in gtav folder
                    ]
                    
                    # Common file extensions used by cheats
                    cheat_extensions = [".exe", ".dll", ".rpf", ".meta", ".pf"]
                    
                    # Create a temporary file to store the USN journal output
                    import tempfile
                    import os
                    
                    temp_dir = tempfile.gettempdir()
                    usn_output_file = os.path.join(temp_dir, "usn_journal_output.csv")
                    
                    # Run the fsutil command to get USN journal entries
                    import subprocess
                    
                    self.root.after(0, lambda: self.forensic_results_text.insert(tk.END, 
                        "Scanning USN journal for deleted cheat files. This may take a few moments...\n"))
                    
                    # Run the command for each extension
                    for ext in cheat_extensions:
                        cmd = f'fsutil usn readjournal c: csv | findstr /i /c:{ext} | findstr /i /c:0x80000200'
                        
                        try:
                            # Run the command and capture the output
                            process = subprocess.Popen(
                                cmd, 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                shell=True,
                                text=True
                            )
                            
                            stdout, stderr = process.communicate(timeout=30)
                            
                            if stderr:
                                self.root.after(0, lambda e=stderr: self.forensic_results_text.insert(tk.END, 
                                    f"Error scanning USN journal for {ext} files: {e}\n"))
                                continue
                            
                            # Process the output
                            if stdout:
                                # Parse the CSV output
                                lines = stdout.strip().split('\n')
                                
                                for line in lines:
                                    parts = line.split(',')
                                    
                                    if len(parts) >= 6:  # Ensure we have enough parts
                                        filename = parts[5].strip('"')
                                        
                                        # Check if the filename matches any known cheat pattern
                                        for pattern in cheat_patterns:
                                            if pattern.lower() in filename.lower():
                                                issue = {
                                                    "filename": filename,
                                                    "description": f"Deleted cheat file found in USN journal: {filename}",
                                                    "severity": "critical"
                                                }
                                                issues_found.append(issue)
                                                
                                                self.root.after(0, lambda i=issue: self.forensic_results_text.insert(tk.END, 
                                                    f"[CRITICAL] {i['description']}\n"))
                                                break
                        
                        except subprocess.TimeoutExpired:
                            self.root.after(0, lambda e=ext: self.forensic_results_text.insert(tk.END, 
                                f"Timeout scanning USN journal for {e} files\n"))
                        
                        except Exception as e:
                            self.root.after(0, lambda e=str(e): self.forensic_results_text.insert(tk.END, 
                                f"Error processing USN journal for {e} files: {e}\n"))
                    
                    # Check for specific file sizes that are known to be associated with cheats
                    known_cheat_sizes = [
                        23478784, 7518736, 3398656, 2422272, 18708496, 12920336, 17542244, 
                        15958528, 5815296, 17041920, 1270784, 8132066, 27732992, 6827008, 
                        1269880, 7598592, 6543872, 5841408, 30743040, 1601536, 4270592, 
                        6224896, 7590450
                    ]
                    
                    # Run a second pass to check for file sizes
                    cmd = 'fsutil usn readjournal c: csv | findstr /i /c:.exe | findstr /i /c:0x80000200'
                    
                    try:
                        process = subprocess.Popen(
                            cmd, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            shell=True,
                            text=True
                        )
                        
                        stdout, stderr = process.communicate(timeout=30)
                        
                        if stdout:
                            # Parse the CSV output
                            lines = stdout.strip().split('\n')
                            
                            for line in lines:
                                parts = line.split(',')
                                
                                if len(parts) >= 7:  # Ensure we have enough parts
                                    try:
                                        filename = parts[5].strip('"')
                                        file_size = int(parts[6].strip('"'))
                                        
                                        # Check if the file size matches a known cheat size
                                        if file_size in known_cheat_sizes:
                                            issue = {
                                                "filename": filename,
                                                "size": file_size,
                                                "description": f"Deleted file with known cheat size found: {filename} ({file_size} bytes)",
                                                "severity": "high"
                                            }
                                            issues_found.append(issue)
                                            
                                            self.root.after(0, lambda i=issue: self.forensic_results_text.insert(tk.END, 
                                                f"[HIGH] {i['description']}\n"))
                                    except (ValueError, IndexError):
                                        # Skip entries with invalid format
                                        pass
                    
                    except Exception as e:
                        self.root.after(0, lambda e=str(e): self.forensic_results_text.insert(tk.END, 
                            f"Error checking for known cheat file sizes: {e}\n"))
                    
                    if not issues_found:
                        self.root.after(0, lambda: self.forensic_results_text.insert(tk.END, 
                            "No suspicious deleted files found in USN journal.\n"))
                
                except Exception as e:
                    self.root.after(0, lambda err=str(e): self.forensic_results_text.insert(tk.END, 
                        f"Error analyzing USN journal: {err}\n"))
        
        # Update report data
        self.report_data["forensic_issues"].extend(issues_found)
        
        # Update status
        if issues_found:
            self.root.after(0, lambda: self.status_var.set(f"Forensic analysis complete. Found {len(issues_found)} issues."))
            self.root.after(0, lambda: self.forensic_results_text.insert(tk.END, f"\nAnalysis complete. Found {len(issues_found)} issues.\n"))
        else:
            self.root.after(0, lambda: self.status_var.set("Forensic analysis complete. No issues found."))
            self.root.after(0, lambda: self.forensic_results_text.insert(tk.END, "\nAnalysis complete. No issues found.\n"))
    
    def create_updates_frame(self):
        """Create the updates frame"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Create header
        header_frame = tk.Frame(frame, bg=self.theme["bg"])
        header_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        header_label = tk.Label(
            header_frame,
            text="Updates",
            font=HEADING_FONT,
            bg=self.theme["bg"],
            fg=self.theme["fg"]
        )
        header_label.pack(anchor=tk.W)
        
        # Create content
        content = tk.Frame(frame, bg=self.theme["bg"])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create updates text area for displaying update information
        updates_text_frame = tk.Frame(content, bg=self.theme["bg"])
        updates_text_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=(0, 10))
        
        self.updates_text = scrolledtext.ScrolledText(
            updates_text_frame,
            wrap=tk.WORD,
            font=NORMAL_FONT,
            bg=self.theme["text_bg"],
            fg=self.theme["text_fg"],
            height=15
        )
        self.updates_text.pack(fill=tk.BOTH, expand=True)
        self.updates_text.insert(tk.END, "Welcome to the Updates section.\n\n"
                              "Here you can check for updates to the application and the cheat database.\n\n"
                              "Click the buttons below to check for updates.")
        
        # Create app updates frame
        app_updates_frame = ModernCard(content, title="Application Updates")
        app_updates_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0, 10), pady=10)
        
        # Create app update content
        app_update_content = tk.Frame(app_updates_frame.content_frame, bg=self.theme["card_bg"])
        app_update_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Current version label
        current_version_label = tk.Label(
            app_update_content,
            text=f"Current Version: {self.version}",
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"]
        )
        current_version_label.pack(anchor="w", pady=5)
        
        # Latest version label
        self.latest_version_var = tk.StringVar(value="Unknown")
        latest_version_label = tk.Label(
            app_update_content,
            textvariable=self.latest_version_var,
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"]
        )
        latest_version_label.pack(anchor="w", pady=5)
        
        # Update status label
        self.update_status_var = tk.StringVar(value="")
        update_status_label = tk.Label(
            app_update_content,
            textvariable=self.update_status_var,
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["accent"]
        )
        update_status_label.pack(anchor="w", pady=5)
        
        # Add buttons
        check_updates_button = ModernButton(
            app_update_content,
            text="Check for Updates",
            command=self.check_for_updates,
            theme=self.theme
        )
        check_updates_button.pack(anchor="w", pady=10)
        
        # Create database updates frame
        db_updates_frame = ModernCard(content, title="Cheat Database Updates")
        db_updates_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT, padx=(10, 0), pady=10)
        
        # Create database update content
        db_update_content = tk.Frame(db_updates_frame.content_frame, bg=self.theme["card_bg"])
        db_update_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Current DB version label
        current_db_version_label = tk.Label(
            db_update_content,
            text=f"Current Database Version: {self.cheat_database['version']}",
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"]
        )
        current_db_version_label.pack(anchor="w", pady=5)
        
        # Latest DB version label
        self.latest_db_version_var = tk.StringVar(value="Unknown")
        latest_db_version_label = tk.Label(
            db_update_content,
            textvariable=self.latest_db_version_var,
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"]
        )
        latest_db_version_label.pack(anchor="w", pady=5)
        
        # DB Update status label
        self.db_update_status_var = tk.StringVar(value="")
        db_update_status_label = tk.Label(
            db_update_content,
            textvariable=self.db_update_status_var,
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["accent"]
        )
        db_update_status_label.pack(anchor="w", pady=5)
        
        # Add buttons
        check_db_updates_button = ModernButton(
            db_update_content,
            text="Check for Database Updates",
            command=self.check_for_db_updates,
            theme=self.theme
        )
        check_db_updates_button.pack(anchor="w", pady=10)
        
        update_db_button = ModernButton(
            db_update_content,
            text="Update Database",
            command=self.update_cheat_database,
            theme=self.theme
        )
        update_db_button.pack(anchor="w", pady=10)
        
        # Add force update button for administrators
        force_update_frame = ModernCard(content, title="Administrator Controls")
        force_update_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=(10, 0))
        
        force_update_content = tk.Frame(force_update_frame.content_frame, bg=self.theme["card_bg"])
        force_update_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        force_update_label = tk.Label(
            force_update_content,
            text="Force update on remote computers running this application:",
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"]
        )
        force_update_label.pack(anchor="w", pady=5)
        
        # Server settings
        server_frame = tk.Frame(force_update_content, bg=self.theme["card_bg"])
        server_frame.pack(fill=tk.X, pady=5)
        
        server_label = tk.Label(
            server_frame,
            text="Update Server URL:",
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"],
            width=20,
            anchor="w"
        )
        server_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.server_url_var = tk.StringVar(value="https://your-update-server.com/api/updates")
        server_entry = tk.Entry(
            server_frame,
            textvariable=self.server_url_var,
            font=NORMAL_FONT,
            bg=self.theme["text_bg"],
            fg=self.theme["text_fg"],
            width=40
        )
        server_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # API Key
        api_frame = tk.Frame(force_update_content, bg=self.theme["card_bg"])
        api_frame.pack(fill=tk.X, pady=5)
        
        api_label = tk.Label(
            api_frame,
            text="API Key:",
            font=NORMAL_FONT,
            bg=self.theme["card_bg"],
            fg=self.theme["fg"],
            width=20,
            anchor="w"
        )
        api_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.api_key_var = tk.StringVar()
        api_entry = tk.Entry(
            api_frame,
            textvariable=self.api_key_var,
            font=NORMAL_FONT,
            bg=self.theme["text_bg"],
            fg=self.theme["text_fg"],
            width=40,
            show="*"
        )
        api_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Force update button
        force_update_button = ModernButton(
            force_update_content,
            text="Force Update All Clients",
            command=self.force_update_clients,
            theme=self.theme
        )
        force_update_button.pack(anchor="w", pady=10)
        
        return frame
    
    def save_forensic_report(self):
        """Save the forensic analysis results to a file"""
        # Get the current content of the results text
        report_content = self.forensic_results_text.get(1.0, tk.END)
        
        if not report_content.strip():
            messagebox.showinfo("No Report", "No forensic analysis results to save.")
            return
        
        # Ask for a file to save to
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Forensic Report"
        )
        
        if not file_path:
            return  # User cancelled
        
        try:
            # Add header to the report
            import datetime
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            header = f"FiveM Cheat Detector - Forensic Analysis Report\n"
            header += f"Generated: {now}\n"
            header += f"{'=' * 50}\n\n"
            
            # Write the report to the file
            with open(file_path, "w") as f:
                f.write(header + report_content)
            
            messagebox.showinfo("Report Saved", f"Forensic report saved to:\n{file_path}")
            self.log_activity(f"Saved forensic report to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error saving report: {str(e)}")
    
    def check_for_updates(self):
        """Check for updates to the application"""
        self.status_var.set("Checking for updates...")
        
        # Make sure updates_text exists before trying to use it
        if hasattr(self, 'updates_text'):
            self.updates_text.delete(1.0, tk.END)
            self.updates_text.insert(tk.END, "Checking for updates...\n\n")
        
        # Run the check in a separate thread
        threading.Thread(target=self._check_for_updates_thread, daemon=True).start()
    
    def _check_for_updates_thread(self):
        """Thread function for checking for updates"""
        import requests
        import json
        
        try:
            # Get the current version
            current_version = self.version
            
            # URL for checking updates (this would be replaced with a real URL in production)
            update_url = "https://api.github.com/repos/yourusername/fivem-cheat-detector/releases/latest"
            
            # Make the request
            response = requests.get(update_url, timeout=10)
            
            if response.status_code == 200:
                # Parse the response
                data = response.json()
                latest_version = data.get("tag_name", "v0.0.0")
                
                # Remove 'v' prefix if present
                if latest_version.startswith("v"):
                    latest_version = latest_version[1:]
                
                # Compare versions
                if self._compare_versions(latest_version, current_version) > 0:
                    # Update available
                    self.root.after(0, lambda: self.status_var.set(f"Update available: {latest_version}"))
                    self.root.after(0, lambda v=latest_version: self.updates_text.insert(tk.END, 
                        f"Update available!\n\n"
                        f"Current version: {current_version}\n"
                        f"Latest version: {v}\n\n"
                        f"Release notes:\n{data.get('body', 'No release notes available.')}\n\n"
                        f"Download URL: {data.get('html_url', 'N/A')}\n\n"
                        f"Please download the latest version to get the newest features and bug fixes."
                    ))
                else:
                    # No update available
                    self.root.after(0, lambda: self.status_var.set("No updates available."))
                    self.root.after(0, lambda: self.updates_text.insert(tk.END, 
                        f"You are running the latest version: {current_version}\n\n"
                        f"No updates available at this time."
                    ))
            else:
                # Error checking for updates
                self.root.after(0, lambda: self.status_var.set("Error checking for updates."))
                self.root.after(0, lambda: self.updates_text.insert(tk.END, 
                    f"Error checking for updates: HTTP {response.status_code}\n\n"
                    f"Please try again later or check manually at the project repository."
                ))
        
        except Exception as e:
            # Error checking for updates
            self.root.after(0, lambda err=str(e): self.status_var.set(f"Error checking for updates: {err}"))
            self.root.after(0, lambda err=str(e): self.updates_text.insert(tk.END, 
                f"Error checking for updates: {err}\n\n"
                f"Please check your internet connection and try again."
            ))
    
    def _compare_versions(self, version1, version2):
        """Compare two version strings
        
        Returns:
            int: 1 if version1 > version2, -1 if version1 < version2, 0 if equal
        """
        v1_parts = [int(x) for x in version1.split('.')]
        v2_parts = [int(x) for x in version2.split('.')]
        
        # Pad with zeros if necessary
        while len(v1_parts) < len(v2_parts):
            v1_parts.append(0)
        while len(v2_parts) < len(v1_parts):
            v2_parts.append(0)
        
        # Compare parts
        for i in range(len(v1_parts)):
            if v1_parts[i] > v2_parts[i]:
                return 1
            elif v1_parts[i] < v2_parts[i]:
                return -1
        
        return 0
    
    def update_cheat_database(self):
        """Update the cheat database"""
        self.status_var.set("Updating cheat database...")
        
        # Make sure updates_text exists before trying to use it
        if hasattr(self, 'updates_text'):
            self.updates_text.delete(1.0, tk.END)
            self.updates_text.insert(tk.END, "Updating cheat database...\n\n")
        
        # Run the update in a separate thread
        threading.Thread(target=self._update_cheat_database_thread, daemon=True).start()
    
    def _update_cheat_database_thread(self):
        """Thread function for updating the cheat database"""
        import requests
        import json
        
        try:
            # URL for updating the cheat database (this would be replaced with a real URL in production)
            database_url = "https://api.github.com/repos/yourusername/fivem-cheat-detector/contents/cheat_database.json"
            
            # Make the request
            response = requests.get(database_url, timeout=10)
            
            if response.status_code == 200:
                # Parse the response
                data = response.json()
                
                # Get the content (base64 encoded)
                import base64
                content = base64.b64decode(data.get("content", "")).decode("utf-8")
                
                # Parse the JSON content
                new_database = json.loads(content)
                
                # Update the database
                self.cheat_database = new_database
                
                # Save the database to disk
                with open("cheat_database.json", "w") as f:
                    json.dump(self.cheat_database, f, indent=4)
                
                # Update status
                self.root.after(0, lambda: self.status_var.set("Cheat database updated successfully."))
                self.root.after(0, lambda: self.updates_text.insert(tk.END, 
                    f"Cheat database updated successfully.\n\n"
                    f"New database contains:\n"
                    f"- {len(self.cheat_database.get('processes', []))} known cheat processes\n"
                    f"- {len(self.cheat_database.get('files', []))} known cheat files\n"
                    f"- {len(self.cheat_database.get('registry', []))} known registry entries\n\n"
                    f"The updated database will be used for all future scans."
                ))
                
                # Log the update
                self.log_activity("Updated cheat database")
            else:
                # Error updating database
                self.root.after(0, lambda: self.status_var.set("Error updating cheat database."))
                self.root.after(0, lambda: self.updates_text.insert(tk.END, 
                    f"Error updating cheat database: HTTP {response.status_code}\n\n"
                    f"Please try again later or check manually at the project repository."
                ))
        
        except Exception as e:
            # Error updating database
            self.root.after(0, lambda err=str(e): self.status_var.set(f"Error updating cheat database: {err}"))
            self.root.after(0, lambda err=str(e): self.updates_text.insert(tk.END, 
                f"Error updating cheat database: {err}\n\n"
                f"Please check your internet connection and try again."
            ))

    def check_for_db_updates(self):
        """Check for updates to the cheat database"""
        self.status_var.set("Checking for database updates...")
        
        # Make sure updates_text exists before trying to use it
        if hasattr(self, 'updates_text'):
            self.updates_text.delete(1.0, tk.END)
            self.updates_text.insert(tk.END, "Checking for cheat database updates...\n\n")
        
        # Run the check in a separate thread
        threading.Thread(target=self._check_for_db_updates_thread, daemon=True).start()
    
    def _check_for_db_updates_thread(self):
        """Thread function for checking for database updates"""
        import requests
        import json
        
        try:
            # URL for checking database updates (this would be replaced with a real URL in production)
            db_update_url = "https://api.github.com/repos/yourusername/fivem-cheat-detector/contents/cheat_database.json"
            
            # Make the request
            response = requests.get(db_update_url, timeout=10)
            
            if response.status_code == 200:
                # Parse the response
                data = response.json()
                
                # Get the database version from the metadata
                import base64
                content = base64.b64decode(data.get("content", "")).decode("utf-8")
                db_data = json.loads(content)
                
                # Get the database version
                db_version = db_data.get("version", "0.0.0")
                
                # Get the current database version
                current_db_version = "0.0.0"  # Default if not found
                try:
                    if os.path.exists("cheat_database.json"):
                        with open("cheat_database.json", "r") as f:
                            current_db = json.load(f)
                            current_db_version = current_db.get("version", "0.0.0")
                except Exception as e:
                    self.root.after(0, lambda err=str(e): self.updates_text.insert(tk.END, 
                        f"Error reading current database version: {err}\n\n"))
                
                # Update the UI with the latest version
                self.root.after(0, lambda v=db_version: self.latest_db_version_var.set(f"Latest Database Version: {v}"))
                
                # Compare versions
                if self._compare_versions(db_version, current_db_version) > 0:
                    # Update available
                    self.root.after(0, lambda: self.db_update_status_var.set("Database update available!"))
                    self.root.after(0, lambda v=db_version, c=current_db_version: self.updates_text.insert(tk.END, 
                        f"Database update available!\n\n"
                        f"Current version: {c}\n"
                        f"Latest version: {v}\n\n"
                        f"The new database contains updated cheat signatures and detection rules.\n"
                        f"Click 'Update Database' to download and install the latest version."
                    ))
                else:
                    # No update available
                    self.root.after(0, lambda: self.db_update_status_var.set("Database is up to date."))
                    self.root.after(0, lambda v=current_db_version: self.updates_text.insert(tk.END, 
                        f"Your cheat database is up to date (version {v}).\n\n"
                        f"No updates available at this time."
                    ))
            else:
                # Error checking for updates
                self.root.after(0, lambda: self.db_update_status_var.set("Error checking for database updates."))
                self.root.after(0, lambda: self.updates_text.insert(tk.END, 
                    f"Error checking for database updates: HTTP {response.status_code}\n\n"
                    f"Please try again later or check manually at the project repository."
                ))
        
        except Exception as e:
            # Error checking for updates
            self.root.after(0, lambda err=str(e): self.db_update_status_var.set(f"Error: {err}"))
            self.root.after(0, lambda err=str(e): self.updates_text.insert(tk.END, 
                f"Error checking for database updates: {err}\n\n"
                f"Please check your internet connection and try again."
            ))

    def highlight_tree_item(self, item_id):
        """Safely highlight an item in a treeview"""
        try:
            if self.services_tree.exists(item_id):
                self.services_tree.item(item_id, tags=("suspicious",))
        except Exception as e:
            self.log_activity(f"Error highlighting tree item: {str(e)}")

    def force_update_clients(self):
        """Force update on all clients"""
        # Check if API key is provided
        if not self.api_key_var.get():
            messagebox.showerror("Error", "API Key is required to force updates.")
            return
        
        # Confirm action
        if not messagebox.askyesno("Confirm Force Update", 
                                 "This will force all clients to update to the latest version.\n\n"
                                 "Are you sure you want to continue?"):
            return
        
        self.status_var.set("Forcing update on all clients...")
        
        # Make sure updates_text exists before trying to use it
        if hasattr(self, 'updates_text'):
            self.updates_text.delete(1.0, tk.END)
            self.updates_text.insert(tk.END, "Forcing update on all clients...\n\n")
        
        # Run the force update in a separate thread
        threading.Thread(target=self._force_update_clients_thread, daemon=True).start()
    
    def _force_update_clients_thread(self):
        """Thread function for forcing updates on all clients"""
        import requests
        import json
        
        try:
            # Get the server URL and API key
            server_url = self.server_url_var.get()
            api_key = self.api_key_var.get()
            
            # Prepare the request data
            data = {
                "action": "force_update",
                "version": self.version,
                "db_version": self.cheat_database["version"],
                "timestamp": datetime.datetime.now().isoformat()
            }
            
            # Make the request
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(server_url, json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Parse the response
                result = response.json()
                
                # Update status
                self.root.after(0, lambda: self.status_var.set("Force update command sent successfully."))
                
                if hasattr(self, 'updates_text'):
                    self.root.after(0, lambda: self.updates_text.insert(tk.END, 
                        f"Force update command sent successfully.\n\n"
                        f"Response from server: {result.get('message', 'No message')}\n\n"
                        f"Clients affected: {result.get('clients_affected', 'Unknown')}\n\n"
                        f"All clients will be updated to version {self.version} with database version {self.cheat_database['version']}."
                    ))
                
                # Log the action
                self.log_activity(f"Forced update on all clients. Clients affected: {result.get('clients_affected', 'Unknown')}")
            else:
                # Error sending force update command
                self.root.after(0, lambda: self.status_var.set("Error sending force update command."))
                
                if hasattr(self, 'updates_text'):
                    self.root.after(0, lambda: self.updates_text.insert(tk.END, 
                        f"Error sending force update command: HTTP {response.status_code}\n\n"
                        f"Response: {response.text}\n\n"
                        f"Please check your API key and server URL."
                    ))
        
        except Exception as e:
            # Error sending force update command
            self.root.after(0, lambda err=str(e): self.status_var.set(f"Error: {err}"))
            
            if hasattr(self, 'updates_text'):
                self.root.after(0, lambda err=str(e): self.updates_text.insert(tk.END, 
                    f"Error sending force update command: {err}\n\n"
                    f"Please check your internet connection, API key, and server URL."
                ))

if __name__ == "__main__":
    try:
        # Set up logging
        import logging
        import os
        import tempfile
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(tempfile.gettempdir(), "FiveM_Cheat_Detector_Logs")
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up logging to file
        log_file = os.path.join(log_dir, "fivem_cheat_detector.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        logging.info("Starting FiveM Cheat Detector")
        
        # Check if running as admin
        if not is_admin():
            logging.info("Not running as admin, restarting with admin privileges")
            run_as_admin()
        else:
            # Create the main window
            logging.info("Creating main window")
            root = tk.Tk()
            app = FiveMCheatDetector(root)
            logging.info("Starting main loop")
            root.mainloop()
    except Exception as e:
        import traceback
        error_msg = f"Critical error: {str(e)}\n{traceback.format_exc()}"
        
        # Log the error
        logging.critical(error_msg)
        
        # Create a simple error window
        try:
            error_window = tk.Tk()
            error_window.title("FiveM Cheat Detector - Error")
            error_window.geometry("600x400")
            
            # Add error message
            tk.Label(error_window, text="An error occurred while starting the application:", font=("Segoe UI", 12, "bold")).pack(pady=10)
            
            # Add scrollable text area for the error
            error_frame = tk.Frame(error_window)
            error_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            scrollbar = tk.Scrollbar(error_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            error_text = tk.Text(error_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
            error_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            error_text.insert(tk.END, error_msg)
            error_text.config(state=tk.DISABLED)
            
            scrollbar.config(command=error_text.yview)
            
            # Add log file location
            tk.Label(error_window, text=f"Error details have been logged to: {log_file}").pack(pady=10)
            
            # Add close button
            tk.Button(error_window, text="Close", command=error_window.destroy).pack(pady=10)
            
            error_window.mainloop()
        except:
            # If even the error window fails, write to a file
            with open(os.path.join(tempfile.gettempdir(), "fivem_cheat_detector_error.txt"), "w") as f:
                f.write(error_msg)
