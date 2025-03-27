
from typing import Dict, List
import debian.deb822
from .logger import logger
import os
from .types import PackageInfo, PackageInfoType

def parse_dpkg_status(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        status_file = debian.deb822.Deb822.iter_paragraphs(file)
        packages = [dict(pkg) for pkg in status_file]
        pp = []
        for package in packages:
            version = package["Version"]
            epoch = None
                
            if len(version.split(":")) > 1:
                epoch = version.split(":")[0] 
                version = version.split(":")[1] 
            pp.append(PackageInfo(package["Package"],version,None,PackageInfoType.DEBIAN,package["Architecture"],epoch))
            if "python-" in package["Package"]:
                pp.append(PackageInfo(package["Package"].replace("python-",""),version,None,PackageInfoType.PYPI,package["Architecture"],epoch))
            elif "python3-" in package["Package"]:
                pp.append(PackageInfo(package["Package"].replace("python3-",""),version,None,PackageInfoType.PYPI,package["Architecture"],epoch))
            if "Source" in package:
                pp.append(PackageInfo(package["Source"].split(" ")[0],version,None,PackageInfoType.DEBIAN,package["Architecture"],epoch))
    return pp

installed_bins = {"coreutils": 
                  ["arch","base64","basename","cat","chcon","chgrp","chmod","chown","chroot","cksum","comm","cp","csplit","cut","date","dd","df","dir","dircolors","dirname","du","echo","env","expand","expr","factor","false","flock","fmt","fold","groups","head","hostid","id","install","join","link","ln","logname","ls","md5sum","mkdir","mkfifo","mknod","mktemp","mv","nice","nl","nohup","nproc","numfmt","od","paste","pathchk","pinky","pr","printenv","printf","ptx","pwd","readlink","realpath","rm","rmdir","runcon","sha1sum","shasum","sha256sum","sha384sum","sha224sum","sha512sum","seq","shred","sleep","sort","split","stat","stty","sum","sync","tac","tail","tee","test","timeout","touch","tr","true","truncate","tsort","tty","uname","unexpand","uniq","unlink","users","vdir","wc","who","whoami","yes"],

                  "findutils": ["find","xargs"],

                  "procps": ["ee","kill","pkill","pgrep","pmap","ps","pwdx","skill","slabtop","snice","sysctl","tload","top","uptime","vmstat","w","watch"],
                  "bsdutils": ["logger", "renice", "script", "scriptlive", "scriptreplay","wall"],
                  "debianutils": ["add-shell", "installkernel", "ischroot", "remove-shell", "run-parts", "savelog","update-shells", "which"],
                  "libc-bin": ["getconf","getent","iconv","ldd","lddconfig","locale","localedef","tzselect","zdump","zic"]
                  }

additional_files = [".preinst",".prerm",".postrm",".postinst",".list",".md5sums",".shlibs",".symbols",".triggers",".conffiles",".templates",".config"]


def find_individual_packages(paths: List[str],directory: str)-> Dict[PackageInfo,List[str]]:
    packagesMap = {}
    for path in paths:
        if "var/lib/dpkg/status.d/" in path and "." not in path.split("/")[-1]:
            packages = parse_dpkg_status(directory + "/" +path)
            for package in packages:
                packagesMap[package] = [path]
        elif "var/lib/dpkg/status.d/" in path and os.path.isfile(path):
           for package in packages:
               packagesMap[package].add(path)
    return packagesMap

def parse_dpkg_from_status(paths,directory,status) -> Dict[PackageInfo,List[str]]:
    package_dict = dict()
    os_pkgs = parse_dpkg_status(directory + "/" + status)
    for package in os_pkgs:
        files_checked = []
        target_file = "var/lib/dpkg/info/" + package.name + ".list"
        if target_file in paths:
            content = open(directory + "/" + target_file).readlines()
            content = [ c.replace("\n","")[1:] if c[0] == "/" else c.replace("\n","") for c in content]
            files_checked.extend(content)
            for f in additional_files:
                fname = "var/lib/dpkg/info/" + package.name + f
                if fname in paths:
                    files_checked.append(fname)
        else:
            target_file = "var/lib/dpkg/info/" + package.name + ":amd64.list"
            try:
                content = open(directory + "/" + target_file).readlines()
                content = [ c.replace("\n","")[1:] if c[0] == "/" else c.replace("\n","") for c in content]
                files_checked.extend(content)
                for f in additional_files:
                    fname = "var/lib/dpkg/info/" + package.name + ":amd64" + f
                    if fname in paths:
                        files_checked.append(fname)
            except Exception:
                logger.debug(f"DPKG indexed file not found: {target_file}")
                pass
        # Check binaries
        if package.name in installed_bins:
            for f in installed_bins[package.name]:
                files_checked.append("bin/"+f)

        files_checked.append("var/lib/dpkg/status")
        if package in package_dict:
            package_dict[package] = list(set([*package_dict[package],*files_checked]))
        else:
            package_dict[package] = files_checked
    return package_dict

def get_dpkg(paths: List[str],directory: str)-> Dict[PackageInfo,List[str]]:
    status = [path for path in paths if path.endswith("dpkg/status")]
    others = [path for path in paths if "var/lib/dpkg" in path]
   
    assert len(status) < 2
    packages = {}
   
    if len(status) == 1:
        packages.update(parse_dpkg_from_status(paths, directory, status[0]))
        if len(packages.keys()):
            logger.info(f"DPKGS: {len(packages.keys())}")
            for package in packages.keys():
                packages[package].extend(others)
 
    packages.update(find_individual_packages(paths,directory))
    if len(packages.keys()):
        logger.info(f"DPKGS: {len(packages.keys())}")
        for package in packages.keys():
            packages[package].extend(others)

    return packages

       


    