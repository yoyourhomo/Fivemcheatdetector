"""
FiveM Cheat Detector v3.0 - Deleted Cheat Detector Module
Handles detection of deleted cheats using advanced forensic techniques
"""

import os
import sys
import json
import datetime
import logging
import tkinter as tk
from tkinter import ttk
from threading import Thread
from pathlib import Path

from forensic_analyzer import ForensicAnalyzer
from ui_components import NotificationBanner

class DeletedCheatDetector(tk.Frame):
    """Detector for finding evidence of deleted cheats"""
    
    def __init__(self, parent_frame, theme):
        """Initialize the deleted cheat detector"""
        super().__init__(parent_frame, bg=theme["bg"])
        self.parent_frame = parent_frame
        self.theme = theme
        self.results_callback = None
        self.forensic_analyzer = ForensicAnalyzer(progress_callback=self.update_progress)
        self.setup_logging()
        self.configure_styles()  # Configure ttk styles before creating UI
        self.create_ui()
        
        # Results storage
        self.scan_results = None
        self.is_scanning = False
    
    def setup_logging(self):
        """Set up logging for the deleted cheat detector"""
        self.logger = logging.getLogger("DeletedCheatDetector")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler("deleted_cheat_detector.log")
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def configure_styles(self):
        """Configure ttk styles for the UI components"""
        style = ttk.Style()
        
        # Configure the notebook tabs with proper colors
        style.configure("TNotebook", background=self.theme["bg"])
        style.configure("TNotebook.Tab", 
                        background="#ffa07a",  
                        foreground="#000000",  
                        padding=[10, 2])
        
        # Configure selected tab style
        style.map("TNotebook.Tab", 
                  background=[("selected", self.theme["accent"])],
                  foreground=[("selected", "#000000")])
        
        # Configure the progressbar
        style.configure("TProgressbar", 
                        background=self.theme["accent"],
                        troughcolor=self.theme["card_bg"])

    def create_ui(self):
        """Create the user interface"""
        # Main frame
        self.main_frame = tk.Frame(self, bg=self.theme["bg"], padx=15, pady=15)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = tk.Frame(self.main_frame, bg=self.theme["bg"])
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.title_label = tk.Label(
            header_frame, 
            text="Comprehensive Cheat Scanner", 
            font=("Segoe UI", 16, "bold"),
            fg=self.theme["fg"],
            bg=self.theme["bg"]
        )
        self.title_label.pack(side=tk.LEFT)
        
        # Scan button
        self.scan_button = tk.Button(
            header_frame,
            text="Start Scan",
            font=("Segoe UI", 10),
            bg=self.theme["accent"],
            fg=self.theme["accent_fg"],
            padx=15,
            pady=5,
            relief=tk.FLAT,
            command=self.start_scan
        )
        self.scan_button.pack(side=tk.RIGHT)
        
        # Progress frame
        self.progress_frame = tk.Frame(self.main_frame, bg=self.theme["bg"])
        self.progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            orient=tk.HORIZONTAL,
            length=400,
            mode='determinate'
        )
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.progress_label = tk.Label(
            self.progress_frame,
            text="Ready to scan",
            font=("Segoe UI", 10),
            fg=self.theme["fg"],
            bg=self.theme["bg"]
        )
        self.progress_label.pack(side=tk.RIGHT)
        
        # Results frame
        self.results_frame = tk.Frame(self.main_frame, bg=self.theme["card_bg"], padx=15, pady=15)
        self.results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for different result categories
        self.results_notebook = ttk.Notebook(self.results_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        self.summary_frame = tk.Frame(self.results_notebook, bg=self.theme["card_bg"])
        self.results_notebook.add(self.summary_frame, text="Summary")
        
        
        # DLL Injection tab
        self.dll_frame = tk.Frame(self.results_notebook, bg=self.theme["card_bg"])
        self.results_notebook.add(self.dll_frame, text="DLL Injection")
        
        
        # File Remnants tab
        self.file_frame = tk.Frame(self.results_notebook, bg=self.theme["card_bg"])
        self.results_notebook.add(self.file_frame, text="File Remnants")
        
        
        # Registry tab
        self.registry_frame = tk.Frame(self.results_notebook, bg=self.theme["card_bg"])
        self.results_notebook.add(self.registry_frame, text="Registry") 
        
        # USN Journal tab
        self.usn_journal_frame = tk.Frame(self.results_notebook, bg=self.theme["card_bg"])
        self.results_notebook.add(self.usn_journal_frame, text="Deleted Files") 
        
        # Initialize results display
        self.initialize_results_display()
    
    def initialize_results_display(self):
        """Initialize the results display"""
        # Summary frame content
        self.summary_content = tk.Frame(self.summary_frame, bg=self.theme["card_bg"], padx=10, pady=10)
        self.summary_content.pack(fill=tk.BOTH, expand=True)
        
        self.summary_label = tk.Label(
            self.summary_content,
            text="Run a scan to detect active and deleted cheats",
            font=("Segoe UI", 12),
            fg=self.theme["fg"],
            bg=self.theme["card_bg"],
            justify=tk.LEFT
        )
        self.summary_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Severity counters
        severity_frame = tk.Frame(self.summary_content, bg=self.theme["card_bg"])
        severity_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Critical severity
        critical_frame = tk.Frame(severity_frame, bg=self.theme["card_bg"], padx=5, pady=5, 
                              highlightbackground=self.theme["error"], highlightthickness=1)
        critical_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        tk.Label(
            critical_frame,
            text="Critical",
            font=("Segoe UI", 10, "bold"),
            fg=self.theme["fg"],
            bg=self.theme["card_bg"]
        ).pack(anchor=tk.W)
        
        self.critical_count = tk.Label(
            critical_frame,
            text="0",
            font=("Segoe UI", 18, "bold"),
            fg=self.theme["error"],
            bg=self.theme["card_bg"]
        )
        self.critical_count.pack(anchor=tk.W)
        
        # Warning severity
        warning_frame = tk.Frame(severity_frame, bg=self.theme["card_bg"], padx=5, pady=5,
                             highlightbackground=self.theme["warning"], highlightthickness=1)
        warning_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        tk.Label(
            warning_frame,
            text="Warning",
            font=("Segoe UI", 10, "bold"),
            fg=self.theme["fg"],
            bg=self.theme["card_bg"]
        ).pack(anchor=tk.W)
        
        self.warning_count = tk.Label(
            warning_frame,
            text="0",
            font=("Segoe UI", 18, "bold"),
            fg=self.theme["warning"],
            bg=self.theme["card_bg"]
        )
        self.warning_count.pack(anchor=tk.W)
        
        # Info severity
        info_frame = tk.Frame(severity_frame, bg=self.theme["card_bg"], padx=5, pady=5,
                           highlightbackground=self.theme["info"], highlightthickness=1)
        info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        
        tk.Label(
            info_frame,
            text="Info",
            font=("Segoe UI", 10, "bold"),
            fg=self.theme["fg"],
            bg=self.theme["card_bg"]
        ).pack(anchor=tk.W)
        
        self.info_count = tk.Label(
            info_frame,
            text="0",
            font=("Segoe UI", 18, "bold"),
            fg=self.theme["info"],
            bg=self.theme["card_bg"]
        )
        self.info_count.pack(anchor=tk.W)
        
        # Results list
        self.results_list_frame = tk.Frame(self.summary_content, bg=self.theme["card_bg"])
        self.results_list_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create treeview for results
        self.results_tree = ttk.Treeview(
            self.results_list_frame,
            columns=("Type", "Description", "Severity"),
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.results_tree.heading("Type", text="Type")
        self.results_tree.heading("Description", text="Description")
        self.results_tree.heading("Severity", text="Severity")
        
        self.results_tree.column("Type", width=100)
        self.results_tree.column("Description", width=300)
        self.results_tree.column("Severity", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.results_list_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initialize other tabs
        self.initialize_dll_tab()
        self.initialize_file_tab()
        self.initialize_registry_tab()
        self.initialize_usn_journal_tab()
    
    def initialize_dll_tab(self):
        """Initialize the DLL injection tab"""
        # Create treeview for DLL injection results
        self.dll_tree = ttk.Treeview(
            self.dll_frame,
            columns=("Process", "DLL", "Path", "Severity"),
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.dll_tree.heading("Process", text="Process")
        self.dll_tree.heading("DLL", text="DLL")
        self.dll_tree.heading("Path", text="Path")
        self.dll_tree.heading("Severity", text="Severity")
        
        self.dll_tree.column("Process", width=100)
        self.dll_tree.column("DLL", width=150)
        self.dll_tree.column("Path", width=250)
        self.dll_tree.column("Severity", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.dll_frame, orient="vertical", command=self.dll_tree.yview)
        self.dll_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.dll_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def initialize_file_tab(self):
        """Initialize the file remnants tab"""
        # Create treeview for file remnant results
        self.file_tree = ttk.Treeview(
            self.file_frame,
            columns=("Name", "Path", "Type", "Severity"),
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.file_tree.heading("Name", text="Name")
        self.file_tree.heading("Path", text="Path")
        self.file_tree.heading("Type", text="Type")
        self.file_tree.heading("Severity", text="Severity")
        
        self.file_tree.column("Name", width=150)
        self.file_tree.column("Path", width=250)
        self.file_tree.column("Type", width=100)
        self.file_tree.column("Severity", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.file_frame, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def initialize_registry_tab(self):
        """Initialize the registry tab"""
        # Create treeview for registry results
        self.registry_tree = ttk.Treeview(
            self.registry_frame,
            columns=("Key", "Value", "Data", "Severity"),
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.registry_tree.heading("Key", text="Key")
        self.registry_tree.heading("Value", text="Value")
        self.registry_tree.heading("Data", text="Data")
        self.registry_tree.heading("Severity", text="Severity")
        
        self.registry_tree.column("Key", width=200)
        self.registry_tree.column("Value", width=150)
        self.registry_tree.column("Data", width=150)
        self.registry_tree.column("Severity", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.registry_frame, orient="vertical", command=self.registry_tree.yview)
        self.registry_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.registry_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def initialize_usn_journal_tab(self):
        """Initialize the USN journal tab"""
        # Create treeview for USN journal results
        self.usn_journal_tree = ttk.Treeview(
            self.usn_journal_frame,
            columns=("File", "Path", "Reason", "Severity"),
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.usn_journal_tree.heading("File", text="File")
        self.usn_journal_tree.heading("Path", text="Path")
        self.usn_journal_tree.heading("Reason", text="Reason")
        self.usn_journal_tree.heading("Severity", text="Severity")
        
        self.usn_journal_tree.column("File", width=150)
        self.usn_journal_tree.column("Path", width=250)
        self.usn_journal_tree.column("Reason", width=150)
        self.usn_journal_tree.column("Severity", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.usn_journal_frame, orient="vertical", command=self.usn_journal_tree.yview)
        self.usn_journal_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack treeview and scrollbar
        self.usn_journal_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def start_scan(self):
        """Start the deleted cheat scan"""
        if self.is_scanning:
            return
        
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.progress_bar["value"] = 0
        self.progress_label.config(text="Starting scan...")
        
        # Clear previous results
        self.clear_results()
        
        # Start scan in a separate thread
        Thread(target=self._run_scan, daemon=True).start()
    
    def _run_scan(self):
        """Run the scan in a separate thread"""
        try:
            self.update_progress("Initializing forensic analysis...", 5)
            
            # Run forensic analysis
            results = self.forensic_analyzer.run_analysis()
            
            # Process results
            self.update_progress("Processing results...", 90)
            self.scan_results = self.process_results(results)
            
            # Update UI with results
            self.update_ui_with_results()
            
            # Call the callback if set
            if self.results_callback:
                self.results_callback(self.scan_results)
            
            self.update_progress("Scan completed", 100)
            
            # Show notification
            self.show_notification("Scan completed", "success")
            
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            self.update_progress(f"Error: {str(e)}", 0)
            self.show_notification(f"Error during scan: {str(e)}", "error")
        
        finally:
            self.is_scanning = False
            self.scan_button.config(state=tk.NORMAL)
    
    def process_results(self, results):
        """Process the forensic analysis results"""
        processed_results = {
            "issues": [],
            "severity_count": {
                "critical": 0,
                "warning": 0,
                "info": 0
            }
        }
        
        # Process DLL injection results
        for issue in results.get("dll_injection", []):
            severity = issue.get("severity", "warning")
            processed_results["issues"].append({
                "type": "dll_injection",
                "name": issue.get("name", "Unknown"),
                "description": issue.get("description", ""),
                "path": issue.get("path", ""),
                "severity": severity
            })
            processed_results["severity_count"][severity] = processed_results["severity_count"].get(severity, 0) + 1
        
        # Process file remnant results
        for issue in results.get("file_remnants", []):
            severity = issue.get("severity", "warning")
            processed_results["issues"].append({
                "type": "file_remnant",
                "name": issue.get("name", "Unknown"),
                "description": issue.get("description", ""),
                "path": issue.get("path", ""),
                "severity": severity
            })
            processed_results["severity_count"][severity] = processed_results["severity_count"].get(severity, 0) + 1
        
        # Process registry results
        for issue in results.get("registry_forensics", []):
            severity = issue.get("severity", "warning")
            processed_results["issues"].append({
                "type": "registry_forensic",
                "name": issue.get("name", "Unknown"),
                "description": issue.get("description", ""),
                "key": issue.get("key", ""),
                "value": issue.get("value", ""),
                "severity": severity
            })
            processed_results["severity_count"][severity] = processed_results["severity_count"].get(severity, 0) + 1
        
        # Process USN journal results
        for issue in results.get("usn_journal", []):
            severity = issue.get("severity", "warning")
            processed_results["issues"].append({
                "type": "usn_journal",
                "file": issue.get("file", "Unknown"),
                "path": issue.get("path", ""),
                "reason": issue.get("reason", ""),
                "severity": severity
            })
            processed_results["severity_count"][severity] = processed_results["severity_count"].get(severity, 0) + 1
        
        return processed_results
    
    def update_ui_with_results(self):
        """Update the UI with scan results"""
        if not self.scan_results:
            return
        
        # Update severity counts
        self.critical_count.config(text=str(self.scan_results["severity_count"].get("critical", 0)))
        self.warning_count.config(text=str(self.scan_results["severity_count"].get("warning", 0)))
        self.info_count.config(text=str(self.scan_results["severity_count"].get("info", 0)))
        
        # Update summary label
        total_issues = len(self.scan_results["issues"])
        if total_issues > 0:
            self.summary_label.config(
                text=f"Found {total_issues} potential issues related to cheats",
                fg=self.theme["error"] if self.scan_results["severity_count"].get("critical", 0) > 0 else self.theme["warning"]
            )
        else:
            self.summary_label.config(
                text="No cheat-related issues found",
                fg=self.theme["success"]
            )
        
        # Update results tree
        for issue in self.scan_results["issues"]:
            issue_type = issue.get("type", "Unknown")
            description = issue.get("description", "")
            severity = issue.get("severity", "info")
            
            # Add to summary tree
            self.results_tree.insert("", "end", values=(issue_type, description, severity))
            
            # Add to specific tab based on type
            if issue_type == "dll_injection":
                self.dll_tree.insert("", "end", values=(
                    issue.get("name", ""),
                    os.path.basename(issue.get("path", "")),
                    issue.get("path", ""),
                    severity
                ))
            elif issue_type == "file_remnant":
                self.file_tree.insert("", "end", values=(
                    issue.get("name", ""),
                    issue.get("path", ""),
                    "Remnant",
                    severity
                ))
            elif issue_type == "registry_forensic":
                self.registry_tree.insert("", "end", values=(
                    issue.get("key", ""),
                    issue.get("value", ""),
                    issue.get("data", ""),
                    severity
                ))
            elif issue_type == "usn_journal":
                self.usn_journal_tree.insert("", "end", values=(
                    issue.get("file", ""),
                    issue.get("path", ""),
                    issue.get("reason", ""),
                    severity
                ))
    
    def clear_results(self):
        """Clear all results"""
        # Clear summary
        self.summary_label.config(text="Scanning for cheats...", fg=self.theme["fg"])
        self.critical_count.config(text="0")
        self.warning_count.config(text="0")
        self.info_count.config(text="0")
        
        # Clear trees
        for tree in [self.results_tree, self.dll_tree, self.file_tree, self.registry_tree, self.usn_journal_tree]:
            for item in tree.get_children():
                tree.delete(item)
    
    def update_progress(self, message, progress=None):
        """Update the progress bar and label"""
        def _update():
            if progress is not None:
                self.progress_bar["value"] = progress
            self.progress_label.config(text=message)
        
        # Update UI from main thread
        if self.winfo_exists():
            self.after(0, _update)
    
    def show_notification(self, message, type_="info"):
        """Show a notification banner"""
        try:
            notification = NotificationBanner(
                self.parent_frame,
                text=message,
                type=type_  
            )
            notification.pack(fill=tk.X, expand=False)
            
            # Schedule notification to be hidden after 5 seconds
            self.after(5000, notification.hide)
        except Exception as e:
            # Fallback to logging if notification fails
            self.logger.error(f"Failed to show notification: {str(e)}")
    
    def set_results_callback(self, callback):
        """Set the callback function for results"""
        self.results_callback = callback

# Example usage
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Deleted Cheat Detector")
    root.geometry("1000x700")
    root.configure(bg="#1E1E1E")
    
    # Define a simple theme
    theme = {
        "bg": "#1E1E1E",
        "fg": "#FFFFFF",
        "accent": "#0078D7",
        "accent_fg": "#FFFFFF",
        "error": "#FF5252",
        "warning": "#FFC107",
        "info": "#03A9F4",
        "success": "#4CAF50",
        "card_bg": "#252525",
        "card_border": "#333333"
    }
    
    def callback(results):
        print(f"Found {len(results.get('issues', []))} issues")
    
    detector = DeletedCheatDetector(root, theme)
    detector.set_results_callback(callback)
    detector.pack(fill=tk.BOTH, expand=True)
    
    root.mainloop()
