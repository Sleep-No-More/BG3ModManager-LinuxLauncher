#!/usr/bin/env python3
# BG3 Mod Manager Linux Setup Script
# Requires: pip install vdf pefile
#
# Recent fixes:
# - Updated to use 32-bit Wine prefix (WINEARCH=win32) for better .NET compatibility
# - Added proper error handling for failed winetricks installations
# - Fixed file encoding issues (added UTF-8 encoding to all file operations)
# - Improved exception handling with specific exception types instead of broad catches
# - Auto-creates Data directory and shortcuts.vdf if they don't exist
# - Added wineboot initialization step for more stable Wine prefix setup

import argparse
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys

try:
    import pefile
    import vdf
except ImportError:
    print("Please `pip install vdf pefile` for adding to Steam")

user = getpass.getuser()  # getlogin()
script_path = os.path.abspath(__file__)
prefix_location = os.path.join(os.path.expanduser("~"), ".local/share/wineprefixes/BG3MM/")


class DbgOutput:
    def __init__(self):
        self.data = []

    def write(self, s):
        self.data.append(s)

    def flush(self):
        pass

    def get_contents(self):
        return "".join(self.data)


debug = False
dbgoutput = DbgOutput()


def clean_dbgOut(dbgOut):
    lines = dbgOut.split("\n")
    if not lines:
        return ""

    processed = []
    prev_line = lines[0]
    count = 1

    for current_line in lines[1:]:
        if current_line == prev_line:
            count += 1
        else:
            if count > 1:
                processed.append(f"{prev_line}    [x{count}]")
            else:
                processed.append(prev_line)
            count = 1
        prev_line = current_line

    # Handle the last line(s)
    if count > 1:
        processed.append(f"{prev_line}    [x{count}]")
    else:
        processed.append(prev_line)

    return "\n".join(processed)


def termbin():
    # Uses module-level 'debug' variable (read-only, no global declaration needed)
    if not debug:
        return
    notify("Uploading debug output to termbin.com...")
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    upload = clean_dbgOut(dbgoutput.get_contents())
    host = "termbin.com"
    port = 9999
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(upload.encode())
    response = s.recv(1024).decode().strip()
    s.close()
    print(f"{upload}\n\n")
    notify(f"Debug output uploaded to: {response}")
    return response


def run_command(cmd):
    """Run a command safely with shell=False.
    
    Args:
        cmd: Either a string (will be split) or a list of command arguments
    """
    if isinstance(cmd, str):
        cmd_list = cmd.split()
        print(f"Running {cmd}")
    else:
        cmd_list = cmd
        print(f"Running {' '.join(cmd)}")
    
    result = subprocess.run(
        cmd_list, shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    output = result.stdout.decode("utf-8")
    print(output)


def run_wine_command(wine_cmd, *args):
    """Run a Wine command with the configured prefix and architecture.
    
    Args:
        wine_cmd: The wine command to run (e.g., 'wine', 'winecfg', 'wineboot')
        *args: Additional arguments for the command
    """
    env = os.environ.copy()
    env['WINEARCH'] = 'win32'
    env['WINEPREFIX'] = prefix_location
    
    cmd = [wine_cmd] + list(args)
    print(f"Running Wine command: {' '.join(cmd)}")
    print(f"  WINEARCH=win32 WINEPREFIX={prefix_location}")
    
    result = subprocess.run(
        cmd, env=env, shell=False, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    output = result.stdout.decode("utf-8")
    print(output)


def notify(message):
    """Send desktop notification and print to console.

    Fixed: Added check=False to subprocess.run to avoid warnings.
    Fixed: Changed from broad Exception to specific FileNotFoundError/OSError.
    Note: notify-send is optional, script continues if not installed.
    """
    print(message)
    try:
        subprocess.run(["notify-send", "BG3MM Linux Setup", message], check=False)
    except OSError as e:
        print(e)


def get_wine_prefix_arch(prefix_path):
    """Detect Wine prefix architecture (win32 or win64).
    
    Args:
        prefix_path: Path to the Wine prefix directory
    
    Returns:
        'win32', 'win64', or None if unable to determine
    """
    system_reg_path = os.path.join(prefix_path, "system.reg")
    if not os.path.exists(system_reg_path):
        return None
    
    try:
        with open(system_reg_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "WINEARCH" in line:
                    if "win32" in line:
                        return "win32"
                    elif "win64" in line:
                        return "win64"
        
        # Fallback: check for presence of syswow64 (64-bit) or system32 (32-bit only)
        syswow64_path = os.path.join(prefix_path, "drive_c", "windows", "syswow64")
        if os.path.exists(syswow64_path):
            return "win64"
        else:
            system32_path = os.path.join(prefix_path, "drive_c", "windows", "system32")
            if os.path.exists(system32_path):
                return "win32"
    except OSError:
        return None
    
    return None


def install_wine_component(component_name, component_description):
    """Install a Wine component using winetricks.
    
    Args:
        component_name: The winetricks package name
        component_description: Human-readable description for messages
    """
    print(f"Installing {component_description} if necessary...")
    try:
        env = os.environ.copy()
        env['WINEARCH'] = 'win32'
        env['WINEPREFIX'] = prefix_location
        
        cmd = ['winetricks', '-q', component_name]
        print(f"Running: {' '.join(cmd)}")
        print(f"  WINEARCH=win32 WINEPREFIX={prefix_location}")
        
        subprocess.run(
            cmd, env=env, shell=False, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        print(f"Warning: {component_description} installation failed with exit code {e.returncode}")
        print("Continuing anyway - BG3MM may still work without it...")


def setup_wineprefix():
    """Setup Wine prefix and install required components.

    Changed: Now uses 32-bit Wine prefix (WINEARCH=win32) instead of 64-bit.
    Reason: Better compatibility with .NET Framework and winetricks.
    Added: wineboot -u step to properly initialize the Wine environment.
    Added: Architecture checking to prevent 32-bit/64-bit conflicts.
    """
    # Create WINEPREFIX if it doesn't exist
    print("Checking if WINEPREFIX exists...")
    if not os.path.exists(prefix_location):
        print("Creating WINEPREFIX...")
        os.makedirs(prefix_location)
        print(f"{prefix_location} created, running winecfg.")
        notify(
            "Click 'OK' on the 'Wine configuration' window when it appears to continue..."
        )
        # Using 32-bit Wine prefix for better .NET Framework compatibility
        run_wine_command("winecfg")
        print("Initializing Wine prefix with wineboot...")
        # wineboot ensures the Wine environment is fully initialized before installing packages
        run_wine_command("wineboot", "-u")
    else:
        # Check if existing prefix is 32-bit
        prefix_arch = get_wine_prefix_arch(prefix_location)
        if prefix_arch and prefix_arch != "win32":
            notify(
                f"WARNING: Existing Wine prefix at {prefix_location} is {prefix_arch}, "
                "but win32 is required for BG3 Mod Manager. "
                "Please use --clean flag to remove the existing prefix and create a new 32-bit one."
            )
            print(
                f"ERROR: Wine prefix architecture mismatch. Found {prefix_arch}, required win32."
            )
            print("Skipping component installation due to architecture mismatch.")
            return
    
    # Try to install .NET Framework 4.7.2 (required for BG3 Mod Manager)
    # Note: This can take 10-20 minutes and may fail on older Wine versions
    install_wine_component("dotnet472", ".NET Framework 4.7.2")
    
    # Try to install DirectX shader compiler (recommended for better graphics compatibility)
    install_wine_component("d3dcompiler_47", "DirectX shader compiler (d3dcompiler_47)")


def update_settings():
    """Create or update settings.json with Steam game paths.

    Fixed: Now auto-creates Data directory if it doesn't exist.
    Fixed: Added UTF-8 encoding to all file operations.
    Fixed: Use os.path.expanduser instead of hardcoded /home/{user}.
    """
    print("Updating settings.json...")

    # Wine path format: Z: drive maps to Linux root /
    # Convert Unix paths to Windows paths for Wine
    home_path = os.path.expanduser("~")
    steam_path = os.path.join(home_path, ".steam/steam")
    
    settings_data = {
        "GameDataPath": f"Z:{steam_path.replace('/', chr(92))}\\steamapps\\common\\Baldurs Gate 3\\Data",
        "GameExecutablePath": f"Z:{steam_path.replace('/', chr(92))}\\steamapps\\common\\Baldurs Gate 3\\bin\\bg3.exe",
        "DocumentsFolderPathOverride": f"Z:{steam_path.replace('/', chr(92))}\\steamapps\\compatdata\\1086940\\pfx\\drive_c\\users\\steamuser\\AppData\\Local\\Larian Studios\\Baldur's Gate 3\\",
    }

    settings_path = "Data/settings.json"

    # Fixed: Auto-create Data directory (was causing FileNotFoundError)
    os.makedirs("Data", exist_ok=True)

    # If settings.json doesn't exist, create it
    print("Checking if settings.json exists...")
    if not os.path.exists(settings_path):
        print("Creating settings.json...")
        # Fixed: Added encoding='utf-8' to prevent encoding issues
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings_data, f, indent=2)
    else:
        # If it exists, update the required fields (preserves other settings)
        print("Updating settings.json...")
        # Fixed: Added encoding='utf-8' here too
        with open(settings_path, "r", encoding="utf-8") as f:
            existing_data = json.load(f)

        for key, value in settings_data.items():
            existing_data[key] = value

        # Fixed: Added encoding='utf-8' for write operation
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2)


def load_vdf_or_init(path):
    """Load a Steam VDF file or return empty shortcuts structure if missing.
    
    Args:
        path: Path to the shortcuts.vdf file
    
    Returns:
        Dictionary with VDF contents or {'shortcuts': {}} if file doesn't exist
    
    Raises:
        ValueError, KeyError, AttributeError: If VDF parsing fails
    """
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return {"shortcuts": {}}
    
    with open(path, "rb") as f:
        return vdf.binary_loads(f.read())


def save_vdf_with_backup(path, data):
    """Backup existing VDF file and write new data.
    
    Args:
        path: Path to the shortcuts.vdf file
        data: Dictionary to save as VDF
    """
    # Backup BEFORE opening file for writing to prevent data loss
    if os.path.exists(path):
        backup_path = f"{path}.bkup"
        print(f"Backing up {path} to {backup_path}...")
        shutil.copy(path, backup_path)
    
    with open(path, "wb") as f:
        f.write(vdf.binary_dumps(data))


def extract_icon(exe_path, resource_type_id, resource_id_value, output_path):
    """Extract icon from Windows executable for Steam library.

    Fixed: Changed from broad Exception to specific exception types.
    """
    try:
        pe = pefile.PE(exe_path)
    except (OSError, pefile.PEFormatError) as e:
        notify(
            f"Couldn't read {exe_path}. `pip install vdf pefile` if you have't already!"
        )
        print(e)
        print("Icon extraction failed.")
        return

    # Check if DIRECTORY_ENTRY_RESOURCE is present
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        notify("No resources found!")
        return

    # Go through resources and find the desired one
    # Note: Linter doesn't recognize pefile's dynamic attributes (they exist at runtime)
    for (
        resource_type
    ) in pe.DIRECTORY_ENTRY_RESOURCE.entries:  # pylint: disable=no-member
        if resource_type.id == resource_type_id:  # Check the resource type ID
            for resource_id in resource_type.directory.entries:
                if resource_id.id == resource_id_value:  # Check the resource ID
                    data = pe.get_data(
                        resource_id.directory.entries[0].data.struct.OffsetToData,
                        resource_id.directory.entries[0].data.struct.Size,
                    )
                    with open(output_path, "wb") as out_file:
                        out_file.write(data)
                    return
    notify(
        f"Resource with type ID {resource_type_id} and ID {resource_id_value} not found!"
    )


def add_to_steam():
    """Add BG3 Mod Manager to Steam as a non-Steam game.

    Fixed: Now creates shortcuts.vdf if it doesn't exist.
    Fixed: Improved exception handling with specific exception types.
    Fixed: Backup happens before file write to prevent data loss.
    Refactored: Uses helper functions for VDF loading and saving.
    """
    # Extract icon from the Windows .exe to use in Steam library
    extract_icon("BG3ModManager.exe", 3, 1, "bg3mm.png")
    icon_path = os.path.join(os.path.dirname(script_path), "bg3mm.png")
    steam_dir = os.path.expanduser("~/.steam/steam/userdata/")

    # Find the appropriate user directory (assuming only one user)
    user_dirs = [d for d in os.listdir(steam_dir) if d.isdigit()]
    if not user_dirs:
        notify("Couldn't find the Steam user directory.")
        return
    
    shortcuts_file = os.path.join(steam_dir, user_dirs[0], "config/shortcuts.vdf")

    # Load existing shortcuts or create new structure
    try:
        shortcuts = load_vdf_or_init(shortcuts_file)
    except (ValueError, KeyError, AttributeError) as e:
        notify(
            f"Couldn't read {shortcuts_file}. `pip install vdf pefile` if you haven't already!"
        )
        print(e)
        print("Add to Steam failed.")
        return

    # Create new entry for BG3 Mod Manager
    new_entry = {
        "appname": "BG3 Mod Manager - Linux",
        "Exe": script_path,
        "StartDir": os.path.dirname(script_path),
        "icon": icon_path,
        "ShortcutPath": "",
        "LaunchOptions": "",
        "IsHidden": False,
        "AllowDesktopConfig": True,
        "AllowOverlay": True,
        "openvr": False,
        "Devkit": False,
        "DevkitGameID": "",
        "LastPlayTime": 0,
        "tags": {"0": "BG3"},
    }

    # Add BG3MM to the shortcuts dictionary
    try:
        idx = str(len(shortcuts["shortcuts"]))
        shortcuts["shortcuts"][idx] = new_entry
    except (KeyError, TypeError, AttributeError) as e:
        notify(
            f"Couldn't add {script_path} as 'BG3 Mod Manager - Linux' to Steam."
        )
        print(e)
        print("Add to Steam failed.")
        return

    # Save the shortcuts file (Steam will reload it next time it starts)
    try:
        save_vdf_with_backup(shortcuts_file, shortcuts)
        notify(
            f"Added {script_path} as 'BG3 Mod Manager - Linux' to Steam as a non-Steam game."
        )
    except OSError as e:
        notify(f"Couldn't save {shortcuts_file}.")
        print(e)
        print("Add to Steam failed.")
        return


def main():
    parser = argparse.ArgumentParser(description="Setup and launch BG3 Mod Manager.")
    parser.add_argument(
        "--setup", action="store_true", help="Setup the WINEPREFIX and settings.json."
    )
    parser.add_argument(
        "--steam", action="store_true", help="Add to Steam as a non-Steam game."
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help=f"Removes the WINEPREFIX '{prefix_location}'. Can be used with --setup for a fresh install.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Uploads all output to an unlisted paste on termbin.com with a 1 month expiration date. Provides the URL to the user.",
    )
    args = parser.parse_args()
    if args.debug:
        notify("BG3 Mod Manager linux.py running! - DEBUG mode enabled.")
        print(
            "Output is now being captured and will upload to termbin and print to stdout when the script exits."
        )
        global debug  # pylint: disable=global-statement
        debug = True
        sys.stdout = dbgoutput
        sys.stderr = dbgoutput
    if args.clean:
        # Remove existing Wine prefix for a fresh install
        try:
            shutil.rmtree(prefix_location)
            notify(f"Removed WINEPREFIX '{prefix_location}'.")
        except OSError as e:
            # FileNotFoundError is a subclass of OSError
            notify(f"Couldn't remove WINEPREFIX '{prefix_location}'.")
            print(e)
    if args.setup:
        setup_wineprefix()
        update_settings()
    if args.steam:
        add_to_steam()
    if not args.setup and not args.steam:
        # If no flags provided, just launch the mod manager
        print("Checking if WINEPREFIX exists...")
        if not os.path.exists(prefix_location):
            notify(
                "WINEPREFIX doesn't exist. Please run with --setup flag to create it."
            )
            termbin()
            return
        # Launch BG3 Mod Manager using the 32-bit Wine prefix
        run_wine_command("wine", "BG3ModManager.exe")
    termbin()


if __name__ == "__main__":
    os.chdir(os.path.dirname(script_path))
    main()
