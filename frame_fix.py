import tkinter as tk
from tkinter import ttk, scrolledtext

# Constants
FONT_FAMILY = "Segoe UI"
HEADING_FONT = (FONT_FAMILY, 16, "bold")
SUBHEADING_FONT = (FONT_FAMILY, 12, "bold")
NORMAL_FONT = (FONT_FAMILY, 10)

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

class FrameFixApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Frame Navigation Fix Demo")
        self.root.geometry("800x600")
        self.theme = LIGHT_THEME
        
        # Apply theme to root
        self.root.configure(bg=self.theme["bg"])
        
        # Status variable
        self.status_var = tk.StringVar(value="Ready")
        
        # Create layout
        self.create_layout()
    
    def create_layout(self):
        """Create the main application layout"""
        # Create main container
        self.main_container = tk.Frame(self.root, bg=self.theme["bg"])
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create sidebar
        self.sidebar = tk.Frame(self.main_container, bg=self.theme["bg"], width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)  # Prevent sidebar from shrinking
        
        # Create logo
        logo_frame = tk.Frame(self.sidebar, bg=self.theme["bg"], height=100)
        logo_frame.pack(fill=tk.X)
        
        logo_text = tk.Label(logo_frame, text="Frame\nNavigation Fix", 
                           font=(FONT_FAMILY, 16, "bold"), 
                           bg=self.theme["bg"], fg=self.theme["accent"])
        logo_text.pack(pady=20)
        
        # Create content area
        self.content_area = tk.Frame(self.main_container, bg=self.theme["bg"])
        self.content_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Create status bar
        self.status_bar = tk.Frame(self.root, bg=self.theme["bg"], height=30)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        status_label = tk.Label(self.status_bar, textvariable=self.status_var,
                              bg=self.theme["bg"], fg=self.theme["fg"],
                              font=NORMAL_FONT)
        status_label.pack(side=tk.LEFT, padx=10)
        
        # Initialize frames dictionary
        self.frames = {}
        self.current_frame = None
        self.sidebar_buttons = {}
        
        # Create sidebar buttons
        self.create_sidebar_button("dashboard", "Dashboard")
        self.create_sidebar_button("scan", "File Scan")
        self.create_sidebar_button("process", "Processes")
        self.create_sidebar_button("services", "Services")
        
        # Create frames
        self.frames["dashboard"] = self.create_frame("dashboard", "Dashboard")
        self.frames["scan"] = self.create_frame("scan", "File Scan")
        self.frames["process"] = self.create_frame("process", "Processes")
        self.frames["services"] = self.create_frame("services", "Services")
        
        # Show dashboard by default
        self.show_frame("dashboard")
    
    def create_sidebar_button(self, frame_name, text):
        """Create a sidebar button that shows a specific frame when clicked"""
        button = tk.Button(self.sidebar, text=text, 
                         font=NORMAL_FONT, 
                         bg=self.theme["bg"], 
                         fg=self.theme["fg"],
                         bd=0, 
                         padx=20, 
                         pady=10,
                         anchor="w",
                         width=15,
                         command=lambda: self.show_frame(frame_name))
        button.pack(fill=tk.X, pady=2)
        
        # Store button reference
        self.sidebar_buttons[frame_name] = button
    
    def create_frame(self, frame_name, title):
        """Create a generic frame with a title and text area"""
        frame = tk.Frame(self.content_area, bg=self.theme["bg"])
        
        # Header
        header = tk.Label(frame, text=title, font=HEADING_FONT, 
                        bg=self.theme["bg"], fg=self.theme["fg"])
        header.pack(anchor=tk.W, pady=(20, 20), padx=20)
        
        # Text area
        text_area = scrolledtext.ScrolledText(frame, 
                                           height=20, 
                                           bg=self.theme["text_bg"], 
                                           fg=self.theme["text_fg"],
                                           font=NORMAL_FONT)
        text_area.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        text_area.insert(tk.END, f"This is the {title} frame.\n")
        text_area.insert(tk.END, f"Frame name: {frame_name}\n")
        
        return frame
    
    def show_frame(self, frame_name):
        """Show the specified frame and update sidebar button states"""
        print(f"Showing frame: {frame_name}")
        print(f"Available frames: {list(self.frames.keys())}")
        
        # Hide current frame if exists
        if self.current_frame:
            self.current_frame.pack_forget()
        
        # Reset all sidebar button styles
        for button in self.sidebar_buttons.values():
            button.config(bg=self.theme["bg"], fg=self.theme["fg"])
        
        # Show the requested frame if it exists
        if frame_name in self.frames:
            self.frames[frame_name].pack(fill=tk.BOTH, expand=True)
            self.current_frame = self.frames[frame_name]
            
            # Highlight the active sidebar button
            if frame_name in self.sidebar_buttons:
                self.sidebar_buttons[frame_name].config(
                    bg=self.theme["accent"],
                    fg=self.theme["accent_fg"]
                )
            
            self.status_var.set(f"Viewing {frame_name}")
        else:
            print(f"Error: Frame '{frame_name}' not found")
            self.status_var.set(f"Error: Frame '{frame_name}' not found")

if __name__ == "__main__":
    root = tk.Tk()
    app = FrameFixApp(root)
    root.mainloop()
