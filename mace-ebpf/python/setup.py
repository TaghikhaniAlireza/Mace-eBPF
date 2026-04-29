"""Installable package for local development."""

from setuptools import find_packages, setup

setup(
    name="mace-ebpf",
    version="0.1.0",
    packages=find_packages(),
    package_data={"mace": ["py.typed"], "mace.proto": ["*.py"]},
    install_requires=[
        "protobuf>=4.21.0",
    ],
    python_requires=">=3.8",
)
