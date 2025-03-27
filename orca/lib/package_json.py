
import os
from typing import Dict, List
import json

from.logger import logger
from.types import PackageInfo, PackageInfoType
#import rpm


def parse_package_json(paths,enclosing_dir,file: str):
    try:
        content = json.load(open(file))
    except Exception:
        logger.error(f"[JS] Could not parse {file}")
        return {}
    if "name" not in content:
        return {}
    name = content["name"]
    files = set([path for path in paths if enclosing_dir in path])
    main_package = PackageInfo(name,"","npm")
    packages = {}
    if "version" in content:
        main_package = PackageInfo(name,content["version"],None,PackageInfoType.NPM)
    else:
        logger.info(f"Could not parse version from package.json at {file}")
    
    if "dependencies" not in content:
        return {main_package: list(files)}
    else:
        # TODO: Maybe we should also add dev-packages
        for dependency,version in content["dependencies"].items():
            if type(version) is dict:
                version = version['version']
            package = PackageInfo(dependency,version.split(" ")[0].replace("<","").replace(">","").replace("=",""),None,PackageInfoType.NPM)
            files_to_add = set([path for path in paths if os.path.join(enclosing_dir,"node_modules","package") in path])
            packages[package] = list(files_to_add)
            files.difference_update(files_to_add)
        packages[main_package] = list(files)

    return packages


def parse_package_lock(paths,enclosing_dir,file: str):
    packages = {}
    content = json.load(open(file))
    name_author = content["name"].split("/")
    author = "npm"
    name = ""
    if len(name_author) > 1:
        author = name_author[0].replace("@","")
        name = name_author[1]
    else:
        name = name_author[0]
        if "version" in content:
            packages[PackageInfo(name,content["version"],author)] = [path for path in paths if enclosing_dir in path]
    key = "packages" if "packages" in content else "dependencies"
    for pkgname,package in content[key].items():
        if pkgname == "":
            continue
        if "node_modules" in pkgname:
            pkg = pkgname.split("node_modules/")[-1]
            if "version" not in package:
                continue
            if "/" in pkg:
                pkg_split = pkg.replace("@","").split("/")
                packages[PackageInfo(pkg_split[1],package["version"],pkg_split[0],PackageInfoType.NPM)] = [enclosing_dir + "/package_lock.json",enclosing_dir + "/package.json"]
            else:
                packages[PackageInfo(pkg,package["version"],"npm",PackageInfoType.NPM)] = [path for path in paths if enclosing_dir in path]
        else:
            if "/" in pkgname:
                pkg_split = pkgname.replace("@","").split("/")
                packages[PackageInfo(pkg_split[1],package["version"],pkg_split[0])] = [enclosing_dir + "/package_lock.json",enclosing_dir + "/package.json"]
            else:
                packages[PackageInfo(pkgname,package["version"],"npm",PackageInfoType.NPM)] = [enclosing_dir + "/package_lock.json",enclosing_dir + "/package.json"]
                
    return packages

def parse_library_packages(directory,paths,package_jsons)-> Dict[PackageInfo,List[str]]:
    packageMap = {}
    for file in package_jsons:
        pmap = parse_package_json(paths,os.path.dirname(file),os.path.join(directory,file))
        packageMap.update(pmap)
    return packageMap


def get_package_json(paths: List[str],directory: str):
    total_packages = {}

    package_json_node_modules = [path for path in paths if path.endswith("package.json") or path.endswith("package-lock.json")]
    package_lock = sorted([path for path in package_json_node_modules if "node_modules" not in path ],key=len)
    
    package_json = sorted([path for path in paths if path.endswith("package.json") and "node_modules" not in path ],key=len)
    
    if len(package_json_node_modules) > 200: # Number can be changes
        logger.warning(f"Discovered {len(package_json_node_modules)} package modules. Analyzing all of these files will take time")
    
    total_packages = parse_library_packages(directory,paths,package_json_node_modules)

    if len(package_lock) == 0 and len(package_json) == 0:
        if len(package_json_node_modules) == 0:
            return {}
        else: 
            if len(total_packages.keys()):
                logger.info(f"JS packages: {len(total_packages.keys())}")
            return total_packages
    else:
        biggest = max(package_json,package_lock,key=len)
        for item in biggest:
            basepath = os.path.dirname(item)
            if basepath + "/package.json" in package_json and basepath + "/package-lock.json" in package_lock:
                total_packages.update(parse_package_lock(paths,basepath,os.path.join(directory,basepath,"package-lock.json")))

            elif basepath + "/package.json" in package_json and basepath + "/package-lock.json" not in package_lock:
                pmap = parse_package_json(paths,basepath,os.path.join(directory,basepath,"package.json"))
                total_packages.update(pmap)
             
            else:
                continue
    #files.update(package_json)
    #files.update(package_lock)


    if len(total_packages.keys()):
        logger.info(f"JS packages: {len(total_packages.keys())}")
    return total_packages