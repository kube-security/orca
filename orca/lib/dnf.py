
import os
from typing import Dict, List

from . import logger
from .types import PackageInfo, PackageInfoType
import sqlite3


def read_dnf_db(db_path,path) -> Dict[PackageInfo,List[str]]:
    c = sqlite3.connect(db_path)
    cur = c.cursor()
    res = cur.execute("SELECT name,version from rpm")
    packagesMap = {}
    for entry in res.fetchall():
        package = PackageInfo(entry[0],entry[1],None,PackageInfoType.RPM)
        packagesMap[package] = [path]
    return packagesMap


def get_dnf(paths: List[str],directory: str)-> Dict[PackageInfo,List[str]]:
    if "var/lib/dnf/history.sqlite" in paths:
            packages = read_dnf_db(os.path.join(directory,"var/lib/dnf/history.sqlite"),"var/lib/dnf/history.sqlite")

            if len(packages.keys()):
                logger.logger.info(f"DNFs: {len(packages.keys())}")
            return packages

    return {}