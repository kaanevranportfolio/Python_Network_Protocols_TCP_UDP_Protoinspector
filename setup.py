# setup.py

from setuptools import setup, find_packages

setup(
    name="protoinspector",
    version="0.1.0",
    description="A tool for analyzing and injecting custom network packets",
    author="kemechial",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "bitstring>=4.1.0",
        "typer[all]>=0.12.0",
        "rich>=13.7.0",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "protoinspector=protoinspector.main:app",
        ],
    },

)
