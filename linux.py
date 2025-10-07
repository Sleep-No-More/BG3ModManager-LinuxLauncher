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
prefix_location = f"/home/{user}/.local/share/wineprefixes/BG3MM/"


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
    print(f"Running {cmd}")
    result = subprocess.run(
        cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
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
    except (FileNotFoundError, OSError) as e:
        print(e)


def setup_wineprefix():
    """Setup Wine prefix and install required components.

    Changed: Now uses 32-bit Wine prefix (WINEARCH=win32) instead of 64-bit.
    Reason: Better compatibility with .NET Framework and winetricks.
    Added: wineboot -u step to properly initialize the Wine environment.
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
        run_command(f"WINEARCH=win32 WINEPREFIX={prefix_location} winecfg")
        print("Initializing Wine prefix with wineboot...")
        # wineboot ensures the Wine environment is fully initialized before installing packages
        run_command(f"WINEARCH=win32 WINEPREFIX={prefix_location} wineboot -u")
    # Try to install .NET Framework 4.7.2 (required for BG3 Mod Manager)
    # Note: This can take 10-20 minutes and may fail on older Wine versions
    print("Installing dotnet472 if necessary...")
    try:
        run_command(
            f"WINEARCH=win32 WINEPREFIX={prefix_location} winetricks -q dotnet472"
        )
    except subprocess.CalledProcessError as e:
        # Changed: Don't fail the whole setup if dotnet installation fails
        # The mod manager might still work, or user can install dotnet manually later
        print(f"Warning: dotnet472 installation failed with exit code {e.returncode}")
        print("Continuing anyway - BG3MM may still work without it...")
    # Try to install DirectX shader compiler (recommended for better graphics compatibility)
    print("Installing d3dcompiler_47 if necessary...")
    try:
        run_command(
            f"WINEARCH=win32 WINEPREFIX={prefix_location} winetricks -q d3dcompiler_47"
        )
    except subprocess.CalledProcessError as e:
        # Changed: Also don't fail on d3dcompiler errors
        print(
            f"Warning: d3dcompiler_47 installation failed with exit code {e.returncode}"
        )
        print("Continuing anyway...")


def update_settings():
    """Create or update settings.json with Steam game paths.

    Fixed: Now auto-creates Data directory if it doesn't exist.
    Fixed: Added UTF-8 encoding to all file operations.
    """
    print("Updating settings.json...")

    # Wine path format: Z: drive maps to Linux root /
    settings_data = {
        "GameDataPath": f"Z:\\home\\{user}\\.steam\\steam\\steamapps\\common\\Baldurs Gate 3\\Data",
        "GameExecutablePath": f"Z:\\home\\{user}\\.steam\\steam\\steamapps\\common\\Baldurs Gate 3\\bin\\bg3.exe",
        "DocumentsFolderPathOverride": f"Z:\\home\\{user}\\.steam\\steam\\steamapps\\compatdata\\1086940\\pfx\\drive_c\\users\\steamuser\\AppData\\Local\\Larian Studios\\Baldur's Gate 3\\",
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


def extract_icon(exe_path, resource_type_id, resource_id_value, output_path):
    """Extract icon from Windows executable for Steam library.

    Fixed: Changed from broad Exception to specific exception types.
    """
    try:
        pe = pefile.PE(exe_path)
    except (FileNotFoundError, OSError, pefile.PEFormatError) as e:
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

    Fixed: Now creates shortcuts.vdf if it doesn't exist (was causing FileNotFoundError).
    Fixed: Improved exception handling with specific exception types.
    """
    # Extract icon from the Windows .exe to use in Steam library
    extract_icon("BG3ModManager.exe", 3, 1, "bg3mm.png")
    icon_path = os.path.join(os.path.dirname(script_path), "bg3mm.png")
    steam_dir = os.path.expanduser("~/.steam/steam/userdata/")

    # Find the appropriate user directory (assuming only one user)
    user_dirs = [d for d in os.listdir(steam_dir) if d.isdigit()]
    if not user_dirs:
        notify("Couldn't find the Steam user directory. Exiting.")
        return
    shortcuts_file = os.path.join(steam_dir, user_dirs[0], "config/shortcuts.vdf")

    # Fixed: Auto-create shortcuts.vdf if it doesn't exist (new Steam installs may not have this)
    if not os.path.exists(shortcuts_file):
        print(f"Creating new shortcuts.vdf at {shortcuts_file}")
        os.makedirs(os.path.dirname(shortcuts_file), exist_ok=True)
        shortcuts = {"shortcuts": {}}
    else:
        with open(shortcuts_file, "rb") as f:
            try:
                shortcuts = vdf.binary_loads(f.read())
            except (ValueError, KeyError, AttributeError) as e:
                # Fixed: Specific exceptions for VDF parsing errors instead of broad Exception
                notify(
                    f"Couldn't read {shortcuts_file}. `pip install vdf pefile` if you have't already!"
                )
                print(e)
                print("Add to Steam failed.")
                return

    new_entry = {
        "appname": "BG3 Mod Manager - Linux",
        "Exe": f"{script_path}",
        "StartDir": f"{os.path.dirname(script_path)}",
        "icon": f"{icon_path}",
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
    # The key is the next available index as a string
    try:
        shortcuts["shortcuts"][str(len(shortcuts["shortcuts"]))] = new_entry
    except (KeyError, TypeError, AttributeError) as e:
        # Fixed: Specific exceptions for dictionary manipulation errors
        notify(
            f"Couldn't add {script_path} as 'BG3 Mod Manager - Linux' to Steam as a non-Steam game."
        )
        print(e)
        print("Add to Steam failed.")
        return

    # Save the shortcuts file (Steam will reload it next time it starts)
    try:
        with open(shortcuts_file, "wb") as f:
            print(f"Backing up {shortcuts_file} to {shortcuts_file}.bkup...")
            shutil.copy(shortcuts_file, f"{shortcuts_file}.bkup")
            f.write(vdf.binary_dumps(shortcuts))
            notify(
                f"Added {script_path} as 'BG3 Mod Manager - Linux' to Steam as a non-Steam game."
            )
    except (OSError, IOError) as e:
        # Fixed: Specific exceptions for file I/O errors
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
        except (FileNotFoundError, OSError) as e:
            # Fixed: Specific exceptions instead of broad Exception
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
        if not os.path.exists(f"{prefix_location}"):
            notify(
                "WINEPREFIX doesn't exist. Please run with --setup flag to create it."
            )
            termbin()
            return
        # Launch BG3 Mod Manager using the 32-bit Wine prefix
        run_command(
            f"WINEARCH=win32 WINEPREFIX={prefix_location} wine BG3ModManager.exe"
        )
    termbin()


if __name__ == "__main__":
    os.chdir(os.path.dirname(script_path))
    main()
