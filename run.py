#!/usr/bin/env python3
"""
UnEarth Forensic Recovery Tool - Main Launcher
Interactive launcher that lets users choose between CLI and GUI

Usage:
    python run.py           # Interactive mode (asks for preference)
    python run.py --cli     # Launch CLI directly
    python run.py --gui     # Launch GUI directly
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def print_banner():
    """Print Unearth banner"""
    banner = r"""
╔════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║  ██    ██ ███    ██ ███████ ███████  █████  ██████╗ ████████╗ ██   ██          ║
║  ██    ██ ████   ██ ██      ██      ██   ██ ██   ██ ╚══██╔══╝ ██   ██          ║
║  ██    ██ ██ ██  ██ █████   █████   ███████ ██████╔╝   ██║    ███████          ║
║  ██    ██ ██  ██ ██ ██      ██      ██   ██ ██   ██    ██║    ██   ██          ║
║   ██████  ██   ████ ███████ ███████ ██   ██ ██   ██    ██║    ██   ██          ║
║                                                                                ║
║               Forensic Data Recovery & Analysis Tool                           ║
║                               Version 1.0.0                                    ║
║                                                                                ║
╚════════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)



def check_dependencies():
    """Check if required dependencies are installed"""
    missing = []
    
    # Check CLI dependencies
    try:
        import click
        import rich
    except ImportError as e:
        missing.append(f"CLI: {str(e).split()[-1]}")
    
    # Check GUI dependencies
    try:
        import PyQt6
        import qtawesome
    except ImportError as e:
        missing.append(f"GUI: {str(e).split()[-1]}")
    
    return missing


def launch_cli():
    """Launch CLI interface"""
    try:
        from ui.cli import main as cli_main
        print("\n🖥️  Launching CLI Interface...\n")
        cli_main()
    except ImportError as e:
        print(f"❌ Error: Failed to launch CLI")
        print(f"   {str(e)}")
        print("\n💡 Install CLI dependencies:")
        print("   pip install click rich")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)


def launch_gui():
    """Launch GUI interface"""
    try:
        from ui.gui import main as gui_main
        print("\n🖼️  Launching GUI Interface...\n")
        gui_main()
    except ImportError as e:
        print(f"❌ Error: Failed to launch GUI")
        print(f"   {str(e)}")
        print("\n💡 Install GUI dependencies:")
        print("   pip install PyQt6 qtawesome")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)


def interactive_mode():
    """Interactive mode - ask user preference"""
    print_banner()
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print("⚠️  Warning: Some dependencies are missing:")
        for dep in missing:
            print(f"   • {dep}")
        print("\n💡 Install all dependencies:")
        print("   pip install -r requirements.txt\n")
    
    print("📋 Choose Interface Mode:\n")
    print("   [1] 🖼️  GUI - Graphical User Interface (Recommended)")
    print("   [2] 🖥️  CLI - Command-Line Interface")
    print("   [3] ❌ Exit\n")
    
    while True:
        try:
            choice = input("Enter your choice (1-3): ").strip()
            
            if choice == '1':
                launch_gui()
                break
            elif choice == '2':
                launch_cli()
                break
            elif choice == '3':
                print("\n👋 Goodbye!")
                sys.exit(0)
            else:
                print("❌ Invalid choice. Please enter 1, 2, or 3.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            sys.exit(0)
        except EOFError:
            print("\n\n👋 Goodbye!")
            sys.exit(0)


def main():
    """Main launcher entry point"""
    parser = argparse.ArgumentParser(
        description='UnEarth Forensic Recovery Tool',
        epilog='For detailed help, run: unearth --help (CLI) or use GUI help menu'
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--cli',
        action='store_true',
        help='Launch CLI directly'
    )
    group.add_argument(
        '--gui',
        action='store_true',
        help='Launch GUI directly'
    )
    
    args = parser.parse_args()
    
    # Decide execution mode
    if args.cli:
        print_banner()
        launch_cli()
    elif args.gui:
        print_banner()
        launch_gui()
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
