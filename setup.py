#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
setup.py for anonip
"""

from io import open
from os import path

from setuptools import setup

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="anonip",
    version="1.0.0",
    description="Anonip is a tool to anonymize IP-addresses in log-files.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DigitaleGesellschaft/Anonip",
    author="Digitale Gesellschaft",
    license="BSD",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
    ],
    install_requires=['ipaddress; python_version<"3.3"'],
    py_modules=["anonip"],
    entry_points={"console_scripts": ["anonip = anonip:main"]},
)
