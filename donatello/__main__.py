"""Main entry point for the `donatello` command-line functionality."""

import sys

from .cli import main as cli_main


def main():
    """The function pointed to by `donatello` in console_scripts."""
    sys.exit(cli_main())


if __name__ == '__main__':
    main()
