"""Original entry point, kept so that existing habits and links keep working.

    python fangy.py            asks for a value, as before
    python fangy.py ARGS...    same as the defanger command (see: python fangy.py --help)
"""

import sys

from defanger.cli import main
from defanger.core import defang_text, is_defanged, refang_text


def interactive() -> int:
    value = input("Enter an IP address, DNS name, URL or email address: ").strip()
    if is_defanged(value):
        print("Reverted input:", refang_text(value))
    else:
        print("Defanged input:", defang_text(value))
    return 0


if __name__ == "__main__":
    sys.exit(interactive() if len(sys.argv) == 1 and sys.stdin.isatty() else main())
