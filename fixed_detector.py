#!/usr/bin/env python
import os
import sys
import time
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import json
import re
import socket
import subprocess
import winreg
import psutil
from pathlib import Path

# Constants
FONT_FAMILY = "Segoe UI"
HEADING_FONT = (FONT_FAMILY, 16, "bold")
SUBHEADING_FONT = (FONT_FAMILY, 12, "bold")
NORMAL_FONT = (FONT_FAMILY, 10)
SMALL_FONT = (FONT_FAMILY, 9)
MONOSPACE_FONT = ("Consolas", 10)

# Theme
LIGHT_THEME = {
    "bg": "#f5f5f5",
    "fg": "#333333",
    "text_bg": "#ffffff",
    "text_fg": "#333333",
    "button_bg": "#4a86e8",
    "button_fg": "#ffffff",
    "card_bg": "#ffffff",
    "card_border": "#e0e0e0",
    "accent": "#4a86e8",
    "accent_fg": "#ffffff",
    "nav_bg": "#f5f5f5",
    "nav_fg": "#333333",
    "warning": "#ff9800",
    "error": "#f44336",
    "success": "#4caf50",
    "info": "#2196f3"
}

DARK_THEME = {
    "bg": "#121212",
    "fg": "#e0e0e0",
    "text_bg": "#1e1e1e",
    "text_fg": "#e0e0e0",
    "button_bg": "#4a86e8",
    "button_fg": "#ffffff",
    "card_bg": "#1e1e1e",
    "card_border": "#333333",
    "accent": "#4a86e8",
    "accent_fg": "#ffffff",
    "nav_bg": "#121212",
    "nav_fg": "#e0e0e0",
    "warning": "#ff9800",
    "error": "#f44336",
    "success": "#4caf50",
    "info": "#2196f3"
}

# Default theme
APP_THEME = LIGHT_THEME

class ModernButton(tk.Button):
    """Custom button with modern styling"""
    def __init__(self, master=None, **kwargs):
        self.theme = kwargs.pop('theme', APP_THEME)
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
            self.config(bg=self.theme['accent'])
        else:
            self.config(bg=self.theme['card_border'])
    
    def on_leave(self, event):
        """Mouse leave effect"""
        if self.is_accent:
            self.config(bg=self.theme['button_bg'])
        else:
            self.config(bg=self.theme['bg'])
    
    def update_theme(self, theme):
        """Update button theme"""
        self.theme = theme
        if self.is_accent:
            self.config(bg=theme['button_bg'], fg=theme['button_fg'],
                      activebackground=theme['accent'], activeforeground=theme['button_fg'])
        else:
            self.config(bg=theme['bg'], fg=theme['fg'],
                      activebackground=theme['card_border'], activeforeground=theme['fg'])

class ModernCard(tk.Frame):
    """Custom card widget with modern styling"""
    def __init__(self, master=None, **kwargs):
        self.theme = kwargs.pop('theme', APP_THEME)
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
        self.config(bg=theme['card_bg'], highlightbackground=theme['card_border'])
        self.content_frame.config(bg=theme['card_bg'])
        
        if hasattr(self, 'title'):
            self.title.config(bg=theme['card_bg'], fg=theme['fg'])

class FiveMCheatDetector:
    """Main application class for FiveM Cheat Detector v2.0"""
    def __init__(self, root):
        """Initialize the application"""
        self.root = root
        self.root.title("FiveM Cheat Detector")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Set icon
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass  # Icon not found, use default
        
        # Detect system theme
        self.is_dark_mode = self.detect_system_theme()
        self.theme = DARK_THEME if self.is_dark_mode else LIGHT_THEME
        
        # Apply theme to root
        self.root.configure(bg=self.theme["bg"])
        
        # Initialize variables
        self.frames = {}
        self.current_frame = None
        self.sidebar_buttons = {}
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
            "forensic_issues": [],
            "update_status": {"app_update": False, "definitions_update": False}
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
    
    def detect_system_theme(self):
        """Detect if system is using dark mode"""
        return False  # Always use light theme
    
    def initialize_cheat_database(self):
        """Initialize the known cheats database"""
        self.known_cheats = {
            "process_artifacts": [
                "eulen", "cobra", "tzproject", "hx-cheats", "cheat", "hack", 
                "injector", "executor", "mod menu", "redengine"
            ],
            "file_artifacts": [
                "eulen", "cobra", "tzproject", "hx-cheats", "cheat", "hack", 
                "injector", "executor", "mod menu", "redengine"
            ],
            "registry_artifacts": [
                "eulen", "cobra", "tzproject", "hx-cheats", "cheat", "hack", 
                "injector", "executor", "mod menu", "redengine"
            ],
            "network_artifacts": [
                "eulen.xyz", "cobra.gg", "tzproject.com", "hx-cheats.com", 
                "redengine.dev", "skript.gg"
            ],
            "command_line_args": [
                "eulen", "cobra", "tzproject", "hx-cheats", "cheat", "hack", 
                "injector", "executor", "mod menu", "redengine"
            ],
            "services": [
                "eulen", "cobra", "tzproject", "hx-cheats", "cheat", "hack", 
                "injector", "executor", "mod menu", "redengine"
            ],
            "processes": [
                "eulen", "cobra", "tzproject", "hx-cheats", "cheat", "hack", 
                "injector", "executor", "mod menu", "redengine"
            ],
            "server_ips": [
                "127.0.0.1", "192.168.1.100", "192.168.1.101"
            ],
            "suspicious_ports": [
                8080, 8081, 8082
            ],
            "registry_keywords": [
                "eulen", "cobra", "tzproject", "hx-cheats", "cheat", "hack", 
                "injector", "executor", "mod menu", "redengine"
            ]
        }
    
    def configure_styles(self):
        """Configure ttk styles for the application"""
        self.style = ttk.Style()
        
        # Configure basic styles
        self.style.configure("TFrame", background=self.theme["bg"])
        self.style.configure("TLabel", background=self.theme["bg"], foreground=self.theme["fg"], font=NORMAL_FONT)
        self.style.configure("TButton", background=self.theme["button_bg"], foreground=self.theme["button_fg"], font=NORMAL_FONT)
        self.style.configure("TCheckbutton", background=self.theme["bg"], foreground=self.theme["fg"], font=NORMAL_FONT)
        self.style.configure("TRadiobutton", background=self.theme["bg"], foreground=self.theme["fg"], font=NORMAL_FONT)
        
        # Configure notebook styles
        self.style.configure("TNotebook", background=self.theme["bg"], borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.theme["bg"], foreground=self.theme["fg"], 
                            padding=[10, 5], font=NORMAL_FONT)
        self.style.map("TNotebook.Tab", background=[("selected", self.theme["button_bg"])], 
                      foreground=[("selected", self.theme["button_fg"])])
        
        # Configure progressbar
        self.style.configure("TProgressbar", background=self.theme["accent"], troughcolor=self.theme["bg"],
                           borderwidth=0, thickness=10)
