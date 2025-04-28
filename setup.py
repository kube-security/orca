from setuptools import setup,find_packages
from setuptools.command.install import install
import subprocess
import os

def read_requirements(filename="requirements.txt"):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line and not line.startswith("#")]

setup(
    name='orca',
    version='0.1.20',
    packages=find_packages(),
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'orca=orca.main:main',
        ],
    },
    include_package_data=True,
)
