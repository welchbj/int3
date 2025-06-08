#!/usr/bin/env python3

import os
import subprocess
from argparse import ArgumentParser, Namespace
from contextlib import contextmanager
from pathlib import Path

from livereload import Server

SCRIPTS_DIR = Path(__file__).resolve().parent
INT3_ROOT_DIR = SCRIPTS_DIR.parent
DOCS_DIR = INT3_ROOT_DIR / "docs"


@contextmanager
def _cwd(new_cwd: Path):
    """Context manager for temporarily changing the cwd."""
    old_cwd = os.getcwd()

    try:
        os.chdir(new_cwd)
        yield
    finally:
        os.chdir(old_cwd)


def parse_args() -> Namespace:
    parser = ArgumentParser(description="Make and serve the documentation site")
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Live reload serve the documentation site",
        default=False,
    )
    return parser.parse_args()


def build_docs():
    """Build the documentation from source into HTML."""
    with _cwd(DOCS_DIR):
        subprocess.check_output(["make", "html"])


def serve_docs():
    server = Server()

    watch_patterns = [
        "docs/*.rst",
        "docs/**/*.rst",
        "docs/conf.py",
        "README.rst",
        "int3/**/*.py",
    ]
    for pattern in watch_patterns:
        server.watch(pattern, build_docs)

    server.serve(root="docs/_build/html", host="127.0.0.1", port=5000)


def main():
    args = parse_args()
    if args.serve:
        serve_docs()
    else:
        build_docs()


if __name__ == "__main__":
    main()
