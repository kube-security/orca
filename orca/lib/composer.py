
import os
from typing import List
import json

from . import logger
from .types import PackageInfo, PackageInfoType


def parse_composer_lock(paths,directory,filename):
    composer_lock = json.load(open(directory +"/" + filename))
    packages = []
    accessed_paths = []
    files = [filename]
    for package in composer_lock["packages"]:
            name = package["name"]
            version = package["version"]
            pkg = PackageInfo(name.split("/")[1],version,name.split("/")[0],PackageInfoType.COMPOSER)
 
            basepath = os.path.dirname(filename)
            packages.append(pkg)
    
    if "autoload" in composer_lock:
        for key,value in composer_lock["autoload"].items():
            if "psr" in key:
                v = list(value.values())
                if type(v[0]) is list:
                    accessed_paths.extend(v[0])
                else:
                    accessed_paths.extend(v)
    if "autoload-dev" in composer_lock: 
        for key,value in composer_lock["autoload-dev"].items():
            if "psr" in key:
                if type(v[0]) is list:
                    accessed_paths.extend(v[0])
                else:
                    accessed_paths.extend(v)
    for path in accessed_paths:
        baseinfo = os.path.join(basepath,path)
        for imagepath in paths:
            if baseinfo in imagepath:
                files.append(baseinfo)

    return {pkg: files for pkg in packages}

def parse_composer(paths,directory,filename):
    try:
        composer = json.load(open(directory +"/" + filename))
    except Exception as e:
        logger.logger.error(f"[COMPOSER] Could not open file {filename} -- {e}")
        return {}

    if "name" in composer:
        name = composer["name"]
        version = composer["version"] if "version" in composer else None
        pkg = PackageInfo(name.split("/")[1],version,name.split("/")[0],PackageInfoType.COMPOSER)
        accessed_paths = []
        files = [filename]
        basepath = os.path.dirname(filename)
        if "autoload" in composer:
            for key,value in composer["autoload"].items():
                if "psr" in key:
                    values = value.values()
                    for v in values:
                        if type(v) is list:
                            accessed_paths.extend(v)
                        else:
                            accessed_paths.append(v)
        if "autoload-dev" in composer: 
            for key,value in composer["autoload-dev"].items():
                if "psr" in key:
                    values = value.values()
                    for v in values:
                        if type(v) is list:
                            accessed_paths.extend(v)
                        else:
                            accessed_paths.append(v)
        for path in accessed_paths:
            baseinfo = os.path.join(basepath,path)
            for imagepath in paths:
                if baseinfo in imagepath:
                    files.append(baseinfo)

        return {pkg: files}
    return {}


def get_composer(paths: List[str],directory: str): # Assuming only one composer per container
    packages = {}
    files = set()
    composer_lock = sorted([path for path in paths if "composer.lock" in path ],key=len)
    composer_json = sorted([path for path in paths if "composer.json" in path ],key=len)
    if len(composer_lock) == 0:
        return {}
    files.update(composer_json)
    files.update(composer_lock)
    raw_packages = []
    # Start by root composer.lock
    root_composer_lock = json.load(open(directory +"/" + composer_lock[0]))
    #root_composer_json = json.load(open(directory +"/" + composer_json[0]))
    for package in root_composer_lock["packages"]:
                name = package["name"]
                version = package["version"]
                pkg = PackageInfo(name.split("/")[1],version,name.split("/")[0],PackageInfoType.COMPOSER)
                packages[pkg] = []
                raw_packages.append(name)

    basepath = os.path.dirname(composer_json[0])
    for package in raw_packages:
        composer_lock = [x for x in composer_lock if package not in x]
        composer_json = [x for x in composer_json if package not in x]

    accessed_paths = []
    if "autoload" in root_composer_lock:
        for key,value in root_composer_lock["autoload"].items():
            if "psr" in key:
                v = list(value.values())
                if type(v[0]) is list:
                    accessed_paths.extend(v[0])
                else:
                    accessed_paths.extend(v)
    if "autoload-dev" in root_composer_lock: 
        for key,value in root_composer_lock["autoload-dev"].items():
            if "psr" in key:
                if type(v[0]) is list:
                    accessed_paths.extend(v[0])
                else:
                    accessed_paths.extend(v)
    for path in paths:
        for accessed_path in accessed_paths:
            if f"{basepath}/{accessed_path}" in path:
                files.add(path)
        if "vendor" in path:
            upath = path.replace(f"{basepath}/vendor/","")
            try:
                upathsplit = upath.split("/")
                final_package = f"{upathsplit[0]}/{upathsplit[1]}"
                if final_package in raw_packages:
                    files.add(path)
                else:
                    pass
                    #print(path)
            except Exception:
                 pass # probably a folder


             
    for package in packages:
        packages[package] = files

    for composer in composer_json:
        packages.update(parse_composer(paths,directory,composer))
    if len(packages):
        logger.logger.info(f"PHP composer: {len(packages)}")
    return packages