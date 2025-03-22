"""
FiveM Cheat Detector v3.0 - Cheat Database
Contains definitions of known FiveM cheats and their signatures
"""

class CheatDatabase:
    """Database of known FiveM cheats and their detection signatures"""
    
    def __init__(self):
        """Initialize the cheat database"""
        self.version = "3.0.0"
        self.last_updated = "2025-03-21"
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize the database with known cheats"""
        self.known_cheats = {
            # Process names and executables
            "processes": [
                # Common FiveM cheats
                {"name": "Eulen", "patterns": ["eulen", "eulen.exe", "eulenclient", "loader_prod.exe"], "severity": "high"},
                {"name": "Redengine", "patterns": ["redengine", "re.exe", "redengine.exe", "Impaciente.exe"], "severity": "high"},
                {"name": "Skript", "patterns": ["skript", "skript.exe", "skriptclient", "USBDeview.exe"], "severity": "high"},
                {"name": "Desudo", "patterns": ["desudo", "desudo.exe", "desudoclient"], "severity": "high"},
                {"name": "Hammafia", "patterns": ["hammafia", "hammafia.exe", "hammafiaclient"], "severity": "high"},
                {"name": "Lynx", "patterns": ["lynx", "lynx.exe", "lynxmenu"], "severity": "high"},
                {"name": "Hydro", "patterns": ["hydro", "hydro.exe", "hydromenu"], "severity": "high"},
                {"name": "Dopamine", "patterns": ["dopamine", "dopamine.exe", "dopaminemenu"], "severity": "high"},
                {"name": "Absolute", "patterns": ["absolute", "absolute.exe", "absolutemenu"], "severity": "high"},
                {"name": "Maestro", "patterns": ["maestro", "maestro.exe", "maestromenu"], "severity": "high"},
                {"name": "Reaper", "patterns": ["reaper", "reaper.exe", "reapermenu"], "severity": "high"},
                {"name": "Fallout", "patterns": ["fallout", "fallout.exe", "falloutmenu"], "severity": "high"},
                {"name": "Brutan", "patterns": ["brutan", "brutan.exe", "brutanmenu"], "severity": "high"},
                {"name": "Lumia", "patterns": ["lumia", "lumia.exe", "lumiamenu"], "severity": "high"},
                {"name": "Surge", "patterns": ["surge", "surge.exe", "surgemenu"], "severity": "high"},
                {"name": "Impulse", "patterns": ["impulse", "impulse.exe", "impulsemenu"], "severity": "high"},
                {"name": "Paragon", "patterns": ["paragon", "paragon.exe", "paragonmenu"], "severity": "high"},
                {"name": "Phantom-X", "patterns": ["phantom", "phantomx", "phantom-x.exe"], "severity": "high"},
                {"name": "Ozark", "patterns": ["ozark", "ozark.exe", "ozarkmenu"], "severity": "high"},
                {"name": "Cherax", "patterns": ["cherax", "cherax.exe", "cheraxmenu"], "severity": "high"},
                {"name": "2Take1", "patterns": ["2take1", "2take1.exe", "2take1menu"], "severity": "high"},
                {"name": "Stand", "patterns": ["stand", "stand.exe", "standmenu"], "severity": "high"},
                {"name": "Midnight", "patterns": ["midnight", "midnight.exe", "midnightmenu"], "severity": "high"},
                {"name": "Robust", "patterns": ["robust", "robust.exe", "robustmenu"], "severity": "high"},
                {"name": "Disturbed", "patterns": ["disturbed", "disturbed.exe", "disturbedmenu"], "severity": "high"},
                
                # User-provided specific cheat processes
                {"name": "Skript.gg", "patterns": ["USBDeview.exe"], "severity": "high"},
                {"name": "HX-Cheats", "patterns": ["loader.exe", "chrome_loader.exe", "firefox_loader.exe", "edge_loader.exe", "browser_loader.exe"], "severity": "high"},
                {"name": "TDFree", "patterns": ["TDLoader.exe"], "severity": "high"},
                {"name": "TDPremium", "patterns": ["fontdrvhost.exe", "discord.exe"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True},
                
                # FiveM Bypasser detection
                {"name": "FiveM Bypasser", "patterns": ["fivembypass", "bypass.exe", "hwid_spoof", "hwid_bypass", "fivem_unban", "cfx_bypass", "citizenfx_bypass"], "severity": "critical"},
                {"name": "HWID Spoofer", "patterns": ["spoofer", "hwid_reset", "hwid_clean", "hwid_changer", "serial_changer", "mac_changer"], "severity": "critical"},
                {"name": "Ban Evasion Tool", "patterns": ["unban", "ban_evade", "ban_bypass", "cfx_unban", "fivem_cleaner", "trace_cleaner"], "severity": "critical"},
                {"name": "TZX", "patterns": ["svhost.exe", "svchost.exe"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True},
                {"name": "TestOgg", "patterns": ["BetterDiscord-Windows.exe"], "severity": "high"},
                {"name": "Gosth", "patterns": ["launcher.exe"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True},
                {"name": "Susano", "patterns": ["diamond.exe"], "severity": "high"},
                {"name": "HXSoftwares", "patterns": ["hwid_get.exe"], "severity": "high"},
                {"name": "CobraFree", "patterns": ["free cobra loader.exe", "cobra loader.exe", "cobraloader.exe"], "severity": "high"},
                
                # Generic cheat-related processes
                {"name": "Cheat Engine", "patterns": ["cheatengine", "cheat engine", "cheatengine-x86_64.exe"], "severity": "medium"},
                {"name": "Process Hacker", "patterns": ["processhacker", "processhacker.exe"], "severity": "low"},
                {"name": "Extreme Injector", "patterns": ["extremeinjector", "extreme injector", "extremeinjector.exe"], "severity": "high"},
                {"name": "Xenos Injector", "patterns": ["xenos", "xenos64", "xenos.exe", "xenos64.exe"], "severity": "high"},
                {"name": "GH Injector", "patterns": ["ghinjector", "gh injector", "ghinjector.exe"], "severity": "high"},
                {"name": "Process Explorer", "patterns": ["procexp", "procexp64", "procexp.exe", "procexp64.exe"], "severity": "low"},
                {"name": "Memory Hacker", "patterns": ["memoryhacker", "memory hacker", "memoryhacker.exe"], "severity": "high"},
                {"name": "Hex Editor", "patterns": ["hexeditor", "hex editor", "hexeditor.exe"], "severity": "low"},
                
                # Suspicious generic names often used by cheats
                {"name": "Suspicious Process", "patterns": ["injector", "executor", "mod menu", "hack", "cheat", "bypass"], "severity": "medium"},
                {"name": "Suspicious Process", "patterns": ["trainer", "menu", "unlocker", "unlock", "aimbot", "wallhack"], "severity": "medium"}
            ],
            
            # Services
            "services": [
                # Common cheat registry keys
                {"name": "Eulen Service", "patterns": ["Software\\Eulen"], "value_patterns": [], "severity": "high"},
                {"name": "Redengine Service", "patterns": ["Software\\RedEngine"], "value_patterns": [], "severity": "high"},
                {"name": "Skript Service", "patterns": ["Software\\Skript"], "value_patterns": [], "severity": "high"},
                {"name": "Desudo Service", "patterns": ["Software\\Desudo"], "value_patterns": [], "severity": "high"},
                {"name": "Hammafia Service", "patterns": ["Software\\Hammafia"], "value_patterns": [], "severity": "high"},
                {"name": "Cheat Service", "patterns": ["Software\\Cheat"], "value_patterns": [], "severity": "high"},
                {"name": "TDPremium Service", "patterns": ["Software\\TDPremium"], "value_patterns": [], "severity": "high"},
                {"name": "Suspicious Service", "patterns": ["injector", "executor", "mod", "hack", "cheat", "bypass"], "value_patterns": [], "severity": "medium"},
                
                # FiveM Bypasser and HWID Spoofer services
                {"name": "FiveM Bypasser Service", "patterns": ["Software\\FiveM\\Bypass"], "value_patterns": [], "severity": "critical"},
                {"name": "HWID Spoofer Service", "patterns": ["Software\\HWID\\Spoofer"], "value_patterns": [], "severity": "critical"},
                {"name": "CFX Bypass Service", "patterns": ["Software\\CFX\\Bypass"], "value_patterns": [], "severity": "critical"},
                {"name": "Ban Evader Service", "patterns": ["Software\\BanEvade"], "value_patterns": [], "severity": "critical"}
            ],
            
            # DLL files
            "dlls": [
                # Common cheat DLLs
                {"name": "Eulen DLL", "patterns": ["eulen.dll", "eulenclient.dll"], "severity": "high"},
                {"name": "Redengine DLL", "patterns": ["redengine.dll", "re.dll"], "severity": "high"},
                {"name": "Skript DLL", "patterns": ["skript.dll", "skriptclient.dll", "USBDeview.dll"], "severity": "high"},
                {"name": "Desudo DLL", "patterns": ["desudo.dll", "desudoclient.dll"], "severity": "high"},
                {"name": "Hammafia DLL", "patterns": ["hammafia.dll", "hammafiaclient.dll"], "severity": "high"},
                {"name": "Lynx DLL", "patterns": ["lynx.dll", "lynxmenu.dll"], "severity": "high"},
                {"name": "Hydro DLL", "patterns": ["hydro.dll", "hydromenu.dll"], "severity": "high"},
                {"name": "Dopamine DLL", "patterns": ["dopamine.dll", "dopaminemenu.dll"], "severity": "high"},
                {"name": "Absolute DLL", "patterns": ["absolute.dll", "absolutemenu.dll"], "severity": "high"},
                {"name": "Maestro DLL", "patterns": ["maestro.dll", "maestromenu.dll"], "severity": "high"},
                {"name": "Reaper DLL", "patterns": ["reaper.dll", "reapermenu.dll"], "severity": "high"},
                {"name": "Fallout DLL", "patterns": ["fallout.dll", "falloutmenu.dll"], "severity": "high"},
                {"name": "Brutan DLL", "patterns": ["brutan.dll", "brutanmenu.dll"], "severity": "high"},
                {"name": "Lumia DLL", "patterns": ["lumia.dll", "lumiamenu.dll"], "severity": "high"},
                {"name": "Surge DLL", "patterns": ["surge.dll", "surgemenu.dll"], "severity": "high"},
                {"name": "Impulse DLL", "patterns": ["impulse.dll", "impulsemenu.dll"], "severity": "high"},
                {"name": "Paragon DLL", "patterns": ["paragon.dll", "paragonmenu.dll"], "severity": "high"},
                {"name": "Phantom-X DLL", "patterns": ["phantom.dll", "phantomx.dll"], "severity": "high"},
                {"name": "Ozark DLL", "patterns": ["ozark.dll", "ozarkmenu.dll"], "severity": "high"},
                {"name": "Cherax DLL", "patterns": ["cherax.dll", "cheraxmenu.dll"], "severity": "high"},
                {"name": "2Take1 DLL", "patterns": ["2take1.dll", "2take1menu.dll"], "severity": "high"},
                {"name": "Stand DLL", "patterns": ["stand.dll", "standmenu.dll"], "severity": "high"},
                {"name": "Midnight DLL", "patterns": ["midnight.dll", "midnightmenu.dll"], "severity": "high"},
                {"name": "Robust DLL", "patterns": ["robust.dll", "robustmenu.dll"], "severity": "high"},
                {"name": "Disturbed DLL", "patterns": ["disturbed.dll", "disturbedmenu.dll"], "severity": "high"},
                
                # User-provided specific cheat DLLs
                {"name": "Skript.gg DLL", "patterns": ["USBDeview.dll"], "severity": "high"},
                {"name": "D3D10 Cheat", "patterns": ["d3d10.dll"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True, 
                 "locations": ["%WINDIR%\\System32", "%WINDIR%\\SysWOW64"]},
                {"name": "HXSoftwares DLL", "patterns": ["d3d10.dll"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True,
                 "locations": ["%WINDIR%\\System32", "%WINDIR%\\SysWOW64"]},
                
                # FiveM Bypasser and HWID Spoofer DLLs
                {"name": "FiveM Bypasser DLL", "patterns": ["fivembypass.dll", "bypass.dll", "bypass_fivem.dll", "fivem_bypass.sys"], "severity": "critical"},
                {"name": "HWID Spoofer DLL", "patterns": ["hwid_spoof.dll", "spoofer.dll", "hwid_changer.dll", "hwid_spoof.sys", "spoofer.sys"], "severity": "critical"},
                {"name": "CFX Bypass DLL", "patterns": ["cfx_bypass.dll", "citizenfx_bypass.dll", "cfx_hook.dll"], "severity": "critical"},
                {"name": "Ban Evader DLL", "patterns": ["ban_evade.dll", "ban_bypass.dll", "fivem_unban.dll", "cfx_unban.dll"], "severity": "critical"},
                {"name": "Hardware Changer DLL", "patterns": ["serial_changer.dll", "mac_changer.dll", "hwid_reset.dll", "hwid_clean.dll"], "severity": "critical"},
                {"name": "Trace Cleaner DLL", "patterns": ["fivem_cleaner.dll", "trace_cleaner.dll", "log_wiper.dll"], "severity": "critical"}
            ],
            
            # Files (non-DLL)
            "files": [
                # Common FiveM cheat files
                {"name": "Eulen Files", "patterns": ["eulen.dll", "eulenclient.dll", "loader_prod.exe"], "severity": "high"},
                {"name": "Redengine Files", "patterns": ["redengine.dll", "re.dll", "settings.cock", "imgui.ini"], "severity": "high"},
                {"name": "Skript Files", "patterns": ["skript.dll", "skriptclient.dll", "USBDeview.dll"], "severity": "high"},
                {"name": "Desudo Files", "patterns": ["desudo.dll", "desudoclient.dll"], "severity": "high"},
                {"name": "Hammafia Files", "patterns": ["hammafia.dll", "hammafiaclient.dll"], "severity": "high"},
                {"name": "Lynx Files", "patterns": ["lynx.dll", "lynxmenu.dll"], "severity": "high"},
                {"name": "Hydro Files", "patterns": ["hydro.dll", "hydromenu.dll"], "severity": "high"},
                {"name": "Dopamine Files", "patterns": ["dopamine.dll", "dopaminemenu.dll"], "severity": "high"},
                {"name": "Absolute Files", "patterns": ["absolute.dll", "absolutemenu.dll"], "severity": "high"},
                {"name": "Maestro Files", "patterns": ["maestro.dll", "maestromenu.dll"], "severity": "high"},
                {"name": "Reaper Files", "patterns": ["reaper.dll", "reapermenu.dll"], "severity": "high"},
                {"name": "Fallout Files", "patterns": ["fallout.dll", "falloutmenu.dll"], "severity": "high"},
                {"name": "Brutan Files", "patterns": ["brutan.dll", "brutanmenu.dll"], "severity": "high"},
                {"name": "Lumia Files", "patterns": ["lumia.dll", "lumiamenu.dll"], "severity": "high"},
                {"name": "Surge Files", "patterns": ["surge.dll", "surgemenu.dll"], "severity": "high"},
                {"name": "Impulse Files", "patterns": ["impulse.dll", "impulsemenu.dll"], "severity": "high"},
                {"name": "Paragon Files", "patterns": ["paragon.dll", "paragonmenu.dll"], "severity": "high"},
                {"name": "Phantom-X Files", "patterns": ["phantom.dll", "phantomx.dll"], "severity": "high"},
                {"name": "Ozark Files", "patterns": ["ozark.dll", "ozarkmenu.dll"], "severity": "high"},
                {"name": "Cherax Files", "patterns": ["cherax.dll", "cheraxmenu.dll"], "severity": "high"},
                {"name": "2Take1 Files", "patterns": ["2take1.dll", "2take1menu.dll"], "severity": "high"},
                {"name": "Stand Files", "patterns": ["stand.dll", "standmenu.dll"], "severity": "high"},
                {"name": "Midnight Files", "patterns": ["midnight.dll", "midnightmenu.dll"], "severity": "high"},
                {"name": "Robust Files", "patterns": ["robust.dll", "robustmenu.dll"], "severity": "high"},
                {"name": "Disturbed Files", "patterns": ["disturbed.dll", "disturbedmenu.dll"], "severity": "high"},
                
                # User-provided specific cheat files
                {"name": "Skript.gg Files", "patterns": ["USBDeview.exe", "USBDeview.dll"], "severity": "high"},
                {"name": "HX-Cheats Files", "patterns": ["loader.exe", "chrome_loader.exe", "firefox_loader.exe", "edge_loader.exe", "browser_loader.exe", "hwid_get.exe"], "severity": "high"},
                {"name": "Eulen Files", "patterns": ["loader_prod.exe"], "severity": "high"},
                {"name": "TDFree Files", "patterns": ["TDLoader.exe"], "severity": "high"},
                {"name": "TDPremium Files", "patterns": ["fontdrvhost.exe", "discord.exe"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True},
                {"name": "TZX Files", "patterns": ["svhost.exe", "svchost.exe"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True},
                {"name": "TestOgg Files", "patterns": ["BetterDiscord-Windows.exe"], "severity": "high"},
                {"name": "Gosth Files", "patterns": ["launcher.exe"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True},
                {"name": "Susano Files", "patterns": ["diamond.exe"], "severity": "high"},
                {"name": "Red Engine Files", "patterns": ["Impaciente.exe", "settings.cock", "imgui.ini"], "severity": "high"},
                {"name": "HXSoftwares Files", "patterns": ["hwid_get.exe", "d3d10.dll"], "severity": "high"},
                {"name": "CobraFree Files", "patterns": ["free cobra loader.exe", "cobra loader.exe", "cobraloader.exe"], "severity": "high"},
                {"name": "D3D10 Files", "patterns": ["d3d10.dll"], "severity": "high", "legitimate_match": True, "needs_extra_verification": True},
                
                # FiveM Bypasser files
                {"name": "FiveM Bypasser Files", "patterns": [
                    "fivembypass.exe", "fivembypass.dll", "bypass_fivem.exe", "bypass_fivem.dll",
                    "hwid_spoof.exe", "hwid_spoof.dll", "hwid_reset.exe", "hwid_reset.dll",
                    "fivem_unban.exe", "fivem_unban.dll", "cfx_bypass.exe", "cfx_bypass.dll",
                    "citizenfx_bypass.exe", "citizenfx_bypass.dll", "fivem_cleaner.exe",
                    "trace_cleaner.exe", "hwid_clean.exe", "hwid_changer.exe", "serial_changer.exe",
                    "mac_changer.exe", "spoofer.exe", "spoofer.dll"
                ], "severity": "critical"},
                
                # Generic cheat-related files
                {"name": "Cheat Executable", "patterns": [".exe"], "locations": [
                    "%TEMP%", 
                    "%LOCALAPPDATA%\\Temp", 
                    "%APPDATA%\\Roaming"
                ], "severity": "medium"},
                {"name": "Cheat Log", "patterns": [".log"], "content_patterns": [
                    "eulen", "redengine", "skript", "desudo", "hammafia", 
                    "cheat", "hack", "inject", "bypass"
                ], "severity": "medium"},
                {"name": "Suspicious File", "patterns": ["injector", "executor", "mod menu", "hack", "cheat", "bypass"], "severity": "medium"}
            ],
            
            # Registry keys and values
            "registry": [
                # Common cheat registry keys
                {"name": "Eulen Registry", "key_patterns": ["Software\\Eulen"], "value_patterns": [], "severity": "high"},
                {"name": "Redengine Registry", "key_patterns": ["Software\\RedEngine"], "value_patterns": [], "severity": "high"},
                
                # FiveM Bypasser registry entries
                {"name": "FiveM Bypasser Registry", "key_patterns": [
                    "Software\\FiveM\\Bypass", 
                    "Software\\FiveMBypass",
                    "Software\\HWID\\Spoofer",
                    "Software\\HWIDSpoofer",
                    "Software\\CFXBypass",
                    "Software\\CitizenFX\\Bypass"
                ], "value_patterns": [], "severity": "critical"},
                
                # HWID Spoofer registry traces
                {"name": "HWID Spoofer Registry", "key_patterns": [
                    "SYSTEM\\CurrentControlSet\\Control\\IDConfig\\Spoofed",
                    "SYSTEM\\CurrentControlSet\\Services\\HWIDSpoof",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\HWIDSpoofer",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\FiveMBypass",
                    "Software\\Classes\\CLSID\\{SPOOFED-GUID}"
                ], "value_patterns": [], "severity": "critical"},
                
                # Common autostart registry keys
                {"name": "Run Keys", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["eulen", "redengine", "skript", "desudo", "hammafia", "lynx", "hydro", "dopamine", "absolute", "maestro", "reaper", "fallout", "brutan", "lumia", "surge", "impulse", "paragon", "phantom", "ozark", "cherax", "2take1", "stand", "midnight", "robust", "disturbed", "loader", "injector", "hack", "cheat", "mod menu", "bypass", "spoofer", "hwid", "fivembypass"], "severity": "high"},
                
                # UserAssist entries (ROT-13 encoded)
                {"name": "UserAssist Entries", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"], "value_patterns": ["rhyra", "erqratvar", "fxevcg", "qrfhqb", "unzznsvn", "ylak", "ulqeb", "qbcnzvar", "nofbyhgr", "znrfgeb", "erncre", "snyybhg", "oehgna", "yhzvn", "fhetr", "vzchyfr", "cnentra", "cunagbz", "bmnex", "purenk", "2gnxr1", "fgnaq", "zvqavtug", "ebohfg", "qvfgheorq", "ybnqre", "vavrpgbe", "unpx", "purng", "zbq zrah", "olcnff", "fcbbsre", "ujvq", "svizrolcnff"], "severity": "high"},
                
                # Uninstall keys
                {"name": "Uninstall Keys", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"], "value_patterns": ["eulen", "redengine", "skript", "desudo", "hammafia", "lynx", "hydro", "dopamine", "absolute", "maestro", "reaper", "fallout", "brutan", "lumia", "surge", "impulse", "paragon", "phantom", "ozark", "cherax", "2take1", "stand", "midnight", "robust", "disturbed", "bypass", "spoofer", "hwid", "fivembypass"], "severity": "high"},
                
                # User-provided specific cheat registry entries
                {"name": "Skript.gg Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["USBDeview", "skript.gg"], "severity": "high"},
                {"name": "HX-Cheats Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["loader", "hx-cheats", "hxcheats"], "severity": "high"},
                {"name": "Eulen Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["loader_prod", "eulen"], "severity": "high"},
                {"name": "TDFree Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["TDLoader", "tdfree"], "severity": "high"},
                {"name": "TDPremium Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["fontdrvhost", "tdpremium"], "severity": "high"},
                {"name": "TZX Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["svhost", "svchost", "tzx"], "severity": "high"},
                {"name": "TestOgg Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["BetterDiscord-Windows", "testogg"], "severity": "high"},
                {"name": "Gosth Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["launcher", "gosth"], "severity": "high"},
                {"name": "Susano Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["diamond", "susano"], "severity": "high"},
                {"name": "Red Engine Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["Impaciente", "redengine"], "severity": "high"},
                {"name": "HXSoftwares Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["hwid_get", "hxsoftwares"], "severity": "high"},
                {"name": "CobraFree Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["cobra loader", "cobrafree"], "severity": "high"},
                
                # Bypasser-specific registry entries
                {"name": "FiveM Bypasser Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["fivembypass", "bypass", "hwid_spoof", "hwid_bypass", "fivem_unban", "cfx_bypass", "citizenfx_bypass"], "severity": "critical"},
                {"name": "HWID Spoofer Registry", "key_patterns": ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"], "value_patterns": ["spoofer", "hwid_reset", "hwid_clean", "hwid_changer", "serial_changer", "mac_changer"], "severity": "critical"},
            ],
            
            # Network connections
            "network": [
                # Known cheat network connections
                {"name": "Cheat Domains", "patterns": [
                    "eulen.cc", "eulencheats", "redengine", "skript.gg", "desudo", 
                    "hammafia", "lynxmenu", "hydromenu", "dopamine", "absolute", 
                    "maestro", "reaper", "fallout", "brutan", "lumia", "surge", 
                    "impulse", "paragon", "phantom", "ozark", "cherax", "2take1", 
                    "stand", "midnight", "robust", "disturbed"
                ], "severity": "high"},
                
                # FiveM Bypasser and HWID Spoofer network connections
                {"name": "FiveM Bypasser Servers", "patterns": [
                    "bypass.server", "fivembypass.com", "cfxbypass.net", 
                    "hwid-spoofer.com", "spoofer-service.net", "hwid-reset.com"
                ], "severity": "critical"},
                {"name": "HWID Spoofer Services", "patterns": [
                    "hwid-spoof.com", "serial-spoof.net", "mac-changer.com", 
                    "hwid-reset.net", "hardware-spoof.com"
                ], "severity": "critical"},
                {"name": "Ban Evasion Services", "patterns": [
                    "fivem-unban.com", "cfx-unban.net", "ban-bypass.com", 
                    "ban-evade.net", "fivem-cleaner.com"
                ], "severity": "critical"},
                
                # Suspicious Port
                {"name": "Suspicious Port", "patterns": ["1337", "6666", "7777", "8989", "9999"], "severity": "low"}
            ],
            
            # Command line arguments
            "command_line": [
                # Known cheat command line arguments
                {"name": "Injection Arguments", "patterns": [
                    "-inject", "/inject", "-i ", "/i ", 
                    "-hook", "/hook", 
                    "-dll", "/dll"
                ], "severity": "high"},
                
                # FiveM Bypasser and HWID Spoofer command line arguments
                {"name": "FiveM Bypasser Arguments", "patterns": [
                    "-bypass", "/bypass", 
                    "-noanticheat", "/noanticheat", 
                    "-noeac", "/noeac",
                    "-nobe", "/nobe",
                    "-nocheat", "/nocheat"
                ], "severity": "high"},
                {"name": "HWID Spoofer Arguments", "patterns": [
                    "-spoof", "/spoof",
                    "-spoofhwid", "/spoofhwid",
                    "-hwid", "/hwid",
                    "-resethwid", "/resethwid",
                    "-cleanhwid", "/cleanhwid",
                    "-changemac", "/changemac",
                    "-changeserial", "/changeserial",
                    "-resetdiskid", "/resetdiskid",
                    "-resetmac", "/resetmac",
                    "-resetall", "/resetall"
                ], "severity": "critical"},
                
                # Debug Arguments
                {"name": "Debug Arguments", "patterns": [
                    "-debug", "/debug", 
                    "-console", "/console"
                ], "severity": "medium"}
            ],
            
            # Prefetch files
            "prefetch": [
                {"name": "Eulen Prefetch", "patterns": ["EULEN.EXE", "EULENCLIENT.EXE", "LOADER_PROD.EXE"], "severity": "high"},
                {"name": "Redengine Prefetch", "patterns": ["REDENGINE.EXE", "RE.EXE", "IMPACIENTE.EXE"], "severity": "high"},
                {"name": "Skript Prefetch", "patterns": ["SKRIPT.EXE", "SKRIPTCLIENT.EXE", "USBDEVIEW.EXE"], "severity": "high"},
                {"name": "Desudo Prefetch", "patterns": ["DESUDO.EXE", "DESUDOCLIENT.EXE"], "severity": "high"},
                {"name": "Hammafia Prefetch", "patterns": ["HAMMAFIA.EXE", "HAMMAFIACLIENT.EXE"], "severity": "high"},
                {"name": "TDFree/TDPremium Prefetch", "patterns": ["TDLOADER.EXE", "FONTDRVHOST.EXE"], "severity": "high"},
                {"name": "TestOgg Prefetch", "patterns": ["BETTERDISCORD-WINDOWS.EXE"], "severity": "high"},
                {"name": "Gosth Prefetch", "patterns": ["LAUNCHER.EXE"], "severity": "high"},
                {"name": "Susano Prefetch", "patterns": ["DIAMOND.EXE"], "severity": "high"},
                {"name": "HXSoftwares Prefetch", "patterns": ["HWID_GET.EXE"], "severity": "high"},
                {"name": "CobraFree Prefetch", "patterns": ["FREE COBRA LOADER.EXE", "COBRA LOADER.EXE", "COBRALOADER.EXE"], "severity": "high"},
                {"name": "Injector Prefetch", "patterns": [
                    "EXTREMEINJECTOR.EXE", "XENOS.EXE", "XENOS64.EXE", 
                    "GHINJECTOR.EXE", "INJECTOR.EXE"
                ], "severity": "high"}
            ],
            
            # Event log patterns
            "event_logs": [
                {"name": "Crash Events", "patterns": [
                    "FiveM.exe", "Cfx.re", "CitizenFX.exe"
                ], "severity": "medium"},
                {"name": "Service Installation", "patterns": [
                    "service installed", "service created", "new service"
                ], "value_patterns": [
                    "eulen", "redengine", "skript", "desudo", "hammafia",
                    "td", "tdpremium", "tdfree", "hx", "hx-cheats"
                ], "severity": "high"},
                {"name": "Suspicious Driver", "patterns": [
                    "driver installed", "driver loaded", "new driver"
                ], "severity": "high"}
            ],
            
            # Common deletion patterns
            "deletion_patterns": [
                {"name": "Temp Cleanup", "patterns": [
                    "%TEMP%", 
                    "%LOCALAPPDATA%\\Temp"
                ], "severity": "medium"},
                {"name": "Recycle Bin", "patterns": [
                    "$Recycle.Bin"
                ], "file_patterns": [
                    "eulen", "redengine", "skript", "desudo", "hammafia",
                    "cheat", "hack", "injector", "executor", "mod menu",
                    "USBDeview", "loader_prod", "TDLoader", "BetterDiscord-Windows",
                    "diamond", "Impaciente", "hwid_get", "cobra loader",
                    "d3d10.dll", "settings.cock"
                ], "severity": "high"},
                {"name": "USN Journal", "patterns": [
                    "eulen", "redengine", "skript", "desudo", "hammafia",
                    "cheat", "hack", "injector", "executor", "mod menu",
                    "USBDeview", "loader_prod", "TDLoader", "BetterDiscord-Windows",
                    "diamond", "Impaciente", "hwid_get", "cobra loader",
                    "d3d10.dll", "settings.cock"
                ], "severity": "high"}
            ],
            
            # Common directories to check
            "directories": [
                {"name": "AppData", "path": "%LOCALAPPDATA%", "severity": "medium"},
                {"name": "Roaming", "path": "%APPDATA%", "severity": "medium"},
                {"name": "Temp", "path": "%TEMP%", "severity": "medium"},
                {"name": "Program Files", "path": "%PROGRAMFILES%", "severity": "low"},
                {"name": "Program Files (x86)", "path": "%PROGRAMFILES(X86)%", "severity": "low"},
                {"name": "Documents", "path": "%USERPROFILE%\\Documents", "severity": "medium"},
                {"name": "Downloads", "path": "%USERPROFILE%\\Downloads", "severity": "medium"},
                {"name": "Desktop", "path": "%USERPROFILE%\\Desktop", "severity": "medium"},
                {"name": "FiveM Application Data", "path": "%LOCALAPPDATA%\\FiveM", "severity": "high"},
                {"name": "CitizenFX", "path": "%LOCALAPPDATA%\\CitizenFX", "severity": "high"},
                {"name": "GTA V", "path": "%USERPROFILE%\\Documents\\Rockstar Games\\GTA V", "severity": "high"}
            ]
        }
        
        # Add common cheat file hashes (MD5)
        self.known_hashes = {
            # These would be actual MD5 hashes of known cheat files
            "eulen_client": [
                "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"
            ],
            "redengine_client": [
                "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
                "2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q"
            ],
            "skript_client": [
                "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
                "3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r"
            ],
            "desudo_client": [
                "d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9",
                "4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s"
            ],
            "hammafia_client": [
                "e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
                "5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t"
            ]
        }
    
    def get_all_cheats(self):
        """Get all known cheats"""
        return self.known_cheats
    
    def get_cheats_by_category(self, category):
        """Get cheats by category"""
        return self.known_cheats.get(category, [])
    
    def get_known_hashes(self):
        """Get all known file hashes"""
        return self.known_hashes
    
    def get_database_info(self):
        """Get database version information"""
        return {
            "version": self.version,
            "last_updated": self.last_updated,
            "total_signatures": sum(len(self.known_cheats.get(category, [])) for category in self.known_cheats)
        }

# Example usage
if __name__ == "__main__":
    db = CheatDatabase()
    info = db.get_database_info()
    print(f"Cheat Database v{info['version']}")
    print(f"Last Updated: {info['last_updated']}")
    print(f"Total Signatures: {info['total_signatures']}")
    
    # Print some example entries
    processes = db.get_cheats_by_category("processes")
    print(f"\nProcess Signatures ({len(processes)}):")
    for i, process in enumerate(processes[:5], 1):
        print(f"{i}. {process['name']} - Severity: {process['severity']}")
