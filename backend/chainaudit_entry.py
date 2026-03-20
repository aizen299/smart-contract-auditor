import sys
from pathlib import Path

# Always resolves to the backend/ directory where this file lives
# Works for any user on any machine
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.cli import main

if __name__ == "__main__":
    main()