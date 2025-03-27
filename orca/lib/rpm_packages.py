
import json
import os
import re
import subprocess
from typing import Dict, List

from . import logger
from .types import PackageInfo, PackageInfoType

installed_bins = {"coreutils": 
                  ["arch","base64","basename","cat","chcon","chgrp","chmod","chown","chroot","cksum","comm","cp","csplit","cut","date","dd","df","dir","dircolors","dirname","du","echo","env","expand","expr","factor","false","flock","fmt","fold","groups","head","hostid","id","install","join","link","ln","logname","ls","md5sum","mkdir","mkfifo","mknod","mktemp","mv","nice","nl","nohup","nproc","numfmt","od","paste","pathchk","pinky","pr","printenv","printf","ptx","pwd","readlink","realpath","rm","rmdir","runcon","sha1sum","shasum","sha256sum","sha384sum","sha224sum","sha512sum","seq","shred","sleep","sort","split","stat","stty","sum","sync","tac","tail","tee","test","timeout","touch","tr","true","truncate","tsort","tty","uname","unexpand","uniq","unlink","users","vdir","wc","who","whoami","yes"],

                  "findutils": ["find","xargs"],

                  "procps": ["ee","kill","pkill","pgrep","pmap","ps","pwdx","skill","slabtop","snice","sysctl","tload","top","uptime","vmstat","w","watch"],
                  "bsdutils": ["logger", "renice", "script", "scriptlive", "scriptreplay","wall"],
                  "debianutils": ["add-shell", "installkernel", "ischroot", "remove-shell", "run-parts", "savelog","update-shells", "which"],
                  "libc-bin": ["getconf","getent","iconv","ldd","lddconfig","locale","localedef","tzselect","zdump","zic"]
                  }

additional_files = [".preinst",".prerm",".postrm",".postinst",".list",".md5sums",".shlibs",".symbols",".triggers",".conffiles",".templates",".config"]

def get_author(author):
    if "Red" in author:
        return "redhat"
    elif "Amazon" in author:
        return "amazonlinux"
    elif "suse" in author.lower():
        return "suse"
    else:
        return author.lower()


def read_rpm_db(directory,path)->Dict[PackageInfo,List[str]]:
    packages_dict = {}
    try:
        # Run the rpm command with --dbpath to list installed packages from the specified database
        result = subprocess.run(['rpm_checker', '--dbpath', os.path.join(directory,path),], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check for errors
        if result.returncode != 0:
            print(f"Error reading RPM database: {result.stderr} - {path}")
            return
        
        # Print the list of installed packages
        packages_raw = result.stdout.splitlines()[0]
        json_data = json.loads(packages_raw)
    
        for item in json_data:
            author =  get_author(item['author'])



            package = PackageInfo(item["package"],item["version"],author,PackageInfoType.RPM)
            packages_dict[package] = [*item["files"],path]
            if author == "amazonlinux":
                pattern = re.compile(r"^([a-zA-Z0-9\-_]+)-(\d+\.\d+(?:\.\d+)?)-")
                # Process each package
                match = pattern.match(item['rpm'])
                if match:
                    name, version = match.groups()
                    package = PackageInfo(name,version,author,PackageInfoType.RPM)
                    if name.startswith("python-") or name.startswith("python3-"):
                        split= version.split("-")
                        if len(split) <=1:
                            continue
                        pythonp = split[1]
                        ppkg = PackageInfo(pythonp,version,None,PackageInfoType.PYPI)
                        packages_dict[ppkg] = [*item["files"],path]
                    packages_dict[package] = [*item["files"],path]

        return packages_dict
    
    except Exception as e:
        print(f"An error occurred: {e.with_traceback()}")


def get_rpm(paths: List[str],directory: str)-> Dict[PackageInfo,List[str]]:
    additional_files = [file for file in paths if "var/lib/yum" in file or "var/cache/yum/" in file or "etc/yum.repos.d/" in file or "var/log/yum" in file]
    total_packages = {}
    for path in paths:
        if "rpm/Packages" in path or path.endswith( "rpmdb.sqlite"):
            packages = read_rpm_db(directory,path)
            if packages and len(packages.keys()):
                logger.logger.info(f"RPMs: {len(packages.keys())}")
                if len(additional_files):
                    for package in packages.keys():
                        packages[package].extend(additional_files)
                total_packages.update(packages)
            
  


    return total_packages