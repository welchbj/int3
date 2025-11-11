import sys
from datetime import datetime
from pathlib import Path

# Configuration file for the Sphinx documentation builder.
#
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

DOCS_DIR = Path(__file__).resolve().parent
INT3_ROOT_DIR = DOCS_DIR.parent
INT3_MODULE_DIR = INT3_ROOT_DIR / "int3"
VERSION_FILE = INT3_MODULE_DIR / "version.py"

# Ensure the int3 module is findable during Sphinx autodoc generation.
sys.path.insert(0, str(INT3_ROOT_DIR))

# Expose __version__ and __version_info__
exec(VERSION_FILE.read_text())
int3_version: str = __version__  # noqa

project = "int3"
author = "Brian Welch"
year = datetime.now().year
copyright = f"{year}, {author}"
release = int3_version

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx_rtd_theme",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "alabaster"

html_theme = "sphinx_rtd_theme"
html_theme_options = {"logo_only": True}
html_baseurl = "https://int3.brianwel.ch"
html_title = f"int3 ({int3_version})"
html_static_path = ["_static"]
# XXX: Make logo
# html_logo = "_static/logo-white.png"
# XXX: Add favicon (html_favicon)
# html_favicon = "_static/favicon.ico"
