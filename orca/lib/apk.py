
import os
from typing import Dict, List

from . import logger
from .types import PackageInfo,PackageInfoType



def read_apk_db(db_path,path) -> Dict[PackageInfo,List[str]]:
    fs = open(db_path).read()
    cpeMap = {}
    for entry in fs.split("\n\n"):
        print(entry)
        package = ""
        version = ""
        last_folder = ""
        files = set()
        for line in entry.split():
            if line.startswith("P:"):
                package = line[2:]
            elif line.startswith("V:"):
                version = line[2:]
            elif line.startswith("F:"):
                last_folder = line[2:]
            elif line.startswith("R:"):
                files.add(last_folder + "/"+ line[2:])
        if package == "":
            continue
        files.add(path)
        package = PackageInfo(package,version,None,PackageInfoType.APK)
        cpeMap[package] = files
    return cpeMap

def read_world_file(db_path,path) -> Dict[PackageInfo,List[str]]:
    lines = open(db_path).readlines()
    cpeMap = {}
    files = set()
    files.add(path)
    for entry in lines:
        package = PackageInfo(entry.strip(),None,None,PackageInfoType.APK)
        cpeMap[package] = files
    return cpeMap

# 1549 65
def get_apk(paths: List[str],directory: str)-> Dict[PackageInfo,List[str]]:
    apks = [p for p in paths if "apk/db/installed" in p or "apk/world" in p]# or "apk/db/names" in p ]
    total_pkgs = {}
    for path in apks:
        if "installed" in path:
            packages = read_apk_db(os.path.join(directory,path),path)
            total_pkgs.update(packages)
        elif "world" in path:
            packages = read_world_file(os.path.join(directory,path),path)
            total_pkgs.update(packages)

 
    if len(total_pkgs.keys()):
        logger.logger.info(f"APKs: {len(total_pkgs.keys())}")
    return total_pkgs