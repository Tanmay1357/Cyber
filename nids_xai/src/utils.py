"""
Utility functions for NIDS with XAI.

Author: Final Year CS Project
"""

import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import COLORS, TERMINAL_WIDTH, TESTABLE_ATTACKS

# Ensure stdout can handle Unicode on Windows (CP1252 can't encode ✓ ✗ ⚠ etc.)
try:
    if sys.stdout is not None and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


def clear_screen():
    """Clear terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_colored(text: str, color: str) -> None:
    """Print colored text, with safe fallback for terminals that can't handle Unicode."""
    try:
        print(f"{COLORS.get(color, '')}{text}{COLORS['END']}")
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, 'encoding', 'ascii') or 'ascii'
        safe = text.encode(enc, errors='replace').decode(enc)
        print(f"{COLORS.get(color, '')}{safe}{COLORS['END']}")


def print_header(text: str) -> None:
    """Print a header."""
    print()
    print("=" * TERMINAL_WIDTH)
    print_colored(f"  {text}", "CYAN")
    print("=" * TERMINAL_WIDTH)


def print_subheader(text: str) -> None:
    """Print a subheader."""
    print()
    print_colored(f">> {text}", "BLUE")
    print("-" * 40)


def print_success(text: str) -> None:
    """Print success message."""
    print_colored(f"✓ {text}", "GREEN")


def print_error(text: str) -> None:
    """Print error message."""
    print_colored(f"✗ {text}", "RED")


def print_warning(text: str) -> None:
    """Print warning message."""
    print_colored(f"⚠ {text}", "YELLOW")


def print_info(text: str) -> None:
    """Print info message."""
    print(f"  {text}")


def print_metric(name: str, value: float) -> None:
    """Print a metric."""
    print_colored(f"  {name}: {value:.4f}", "GREEN")


def format_number(n: int) -> str:
    """Format number with commas."""
    return f"{n:,}"


def format_percent(value: float) -> str:
    """Format as percentage."""
    return f"{value * 100:.1f}%"


def get_timestamp() -> str:
    """Get current timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def confirm_action(prompt: str) -> bool:
    """Ask user for confirmation."""
    response = input(f"{prompt} (y/n): ").strip().lower()
    return response in ['y', 'yes']


def get_menu_choice(max_choice: int) -> int:
    """Get menu choice from user."""
    while True:
        try:
            choice = input(f"\nEnter choice (1-{max_choice}): ").strip()
            choice_int = int(choice)
            if 1 <= choice_int <= max_choice:
                return choice_int
            print_error(f"Please enter 1-{max_choice}")
        except ValueError:
            print_error("Enter a valid number")
        except KeyboardInterrupt:
            return max_choice


def display_menu(options: List[str]) -> None:
    """Display a menu."""
    print()
    print("╔" + "═" * (TERMINAL_WIDTH - 2) + "╗")
    print("║" + " MAIN MENU ".center(TERMINAL_WIDTH - 2) + "║")
    print("╠" + "═" * (TERMINAL_WIDTH - 2) + "╣")
    
    for i, option in enumerate(options, 1):
        line = f"  {i}. {option}"
        padding = TERMINAL_WIDTH - 3 - len(line)
        print("║" + line + " " * padding + "║")
    
    print("╚" + "═" * (TERMINAL_WIDTH - 2) + "╝")


def display_banner() -> None:
    """Display application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║     ███╗   ██╗██╗██████╗ ███████╗    ██╗  ██╗ █████╗ ██╗         ║
    ║     ████╗  ██║██║██╔══██╗██╔════╝    ╚██╗██╔╝██╔══██╗██║         ║
    ║     ██╔██╗ ██║██║██║  ██║███████╗     ╚███╔╝ ███████║██║         ║
    ║     ██║╚██╗██║██║██║  ██║╚════██║     ██╔██╗ ██╔══██║██║         ║
    ║     ██║ ╚████║██║██████╔╝███████║    ██╔╝ ██╗██║  ██║██║         ║
    ║     ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ║
    ║                                                                   ║
    ║        Network Intrusion Detection with Explainable AI            ║
    ║                      Final Year Project                           ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print_colored(banner, "CYAN")


def display_attack_info() -> None:
    """Display testable attacks information."""
    print_header("Testable Attack Types")
    
    print_info("\nAttacks you can simulate for testing:\n")
    
    categories = {}
    for attack, info in TESTABLE_ATTACKS.items():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((attack, info))
    
    for category, attacks in categories.items():
        print_colored(f"\n  {category}:", "YELLOW")
        for attack, info in attacks:
            print(f"    • {attack}")
            print(f"      Tool: {info['tool']} | Difficulty: {info['difficulty']}")


class Timer:
    """Context manager for timing operations."""
    
    def __init__(self, description: str = "Operation"):
        self.description = description
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, *args):
        elapsed = time.time() - self.start_time
        if elapsed < 60:
            time_str = f"{elapsed:.1f}s"
        else:
            mins = int(elapsed // 60)
            secs = elapsed % 60
            time_str = f"{mins}m {secs:.0f}s"
        print_info(f"{self.description}: {time_str}")
