#!/usr/bin/env python3
"""Setup script for soroauth Python bindings.

This is a minimal setup.py that works with the pyproject.toml configuration
and ensures the CFFI module is built.
"""

from setuptools import setup

# The cffi_modules directive in pyproject.toml handles the CFFI module generation
# This setup.py just ensures the package is properly configured for setuptools

setup()