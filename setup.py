from setuptools import setup,find_packages
from setuptools.command.install import install
import subprocess
import os

def read_requirements(filename="requirements.txt"):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line and not line.startswith("#")]

class GoBuildCommand(install):
    def run(self):
        print("Installing go package")
        # Run the Go build process
        if subprocess.call(['go', 'version']) != 0:
            raise RuntimeError("Go is not installed or not found in the PATH")
        
        result = subprocess.run(
            ['go', 'build', '-o', 'rpm_checker', 'main.go'],
            cwd=os.getcwd() + "/orca/rpm_checker",
            capture_output=True,  
            text=True            
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Could not install rpm_checker. Current path: {os.getcwd()} - {os.listdir()}\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            )
        else:
            print(f"rpm_checker installed at {os.getcwd()}")
        print("Complete installation")
        super().run()
setup(
    name='orca',
    version='0.1.14',
    packages=find_packages(),
    install_requires=read_requirements(),
    cmdclass={
       'install': GoBuildCommand,
    },
    entry_points={
        'console_scripts': [
            'orca=orca.main:main',
        ],
    },
    include_package_data=True,
)
