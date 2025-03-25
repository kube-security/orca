import os
from typing import List
from .types import PackageInfo, PackageInfoType
from .logger import logger
from email.parser import Parser
from packaging.requirements import Requirement

import re
python_dist_regex = re.compile(
    r'.*python(\d\.\d+)\/(?:site|dist)-packages\/(([a-zA-Z0-9_\-]+)\/)?([a-zA-Z0-9]+)-(\d+\.\d+\.?\d*)\.dist-info'
)

def check_python_from_path_once(paths,filename: str,directory: str):
    filenamenopath = [split for split in filename.split("/") if "-info" in split]
    if len(filenamenopath) == 0:
        return {}
    filenamenopath = filenamenopath[0]
    basename = os.path.dirname(filename)
    files = list(filter(lambda x: basename in x,paths))
    if filenamenopath.endswith(".dist-info") or  filenamenopath.endswith(".egg-info"):
        file = filenamenopath.replace(".dist-info","").replace(".egg-info","")
        splits = file.split("-")
        package = "-".join(splits[:-1]).replace(".wh.","")
        version = splits[-1].replace(".dist","")
        if package is None or package== "":
            return {}
        pkg = PackageInfo(package,version,None,PackageInfoType.PYPI)
        if filename.endswith("RECORD"):
            record = open(os.path.join(directory,filename)).readlines()
            basepath = "/".join(filename.split("/")[:-2])
            files.extend([basepath + "/" + line.split(",")[0] for line in record])

        return {pkg: files}
    return {}


def check_python_from_path(paths: List[str],directory: str):
    packages = {}
    all_dist_info_records = [p for p in paths if ".dist-info" in p or "egg" in p]

    for path in all_dist_info_records:
        for k,v in check_python_from_path_once(paths,path,directory).items():
            if k in packages:
                packages[k] = list(set([*packages[k],*v]))
            else:
                packages[k] = v
    return packages

def extract_egg_dependencies(depfile):
    packages = []
    pkg_info_content = open(depfile, 'r').read()

    pkg_info = Parser().parsestr(pkg_info_content)

    # Access general metadata fields
    package_name = pkg_info.get('Name')
    package_version = pkg_info.get('Version').replace(".dist","")
    author = pkg_info.get('Author')
    packages.append(PackageInfo(package_name,package_version,author,PackageInfoType.PYPI))
    requires_dist = pkg_info.get_all('Requires-Dist')
    if requires_dist:
        for requirement in requires_dist:
            req = Requirement(requirement)
            name = req.name.replace(".wh.","")
            version = req.specifier.__str__().replace("!","").replace(">","").replace("<","").replace("=","").split(",")[0].replace(".dist","")
            if req.marker and "runtime" not in req.marker.__str__():
                continue
            packages.append(PackageInfo(name,version,None,PackageInfoType.PYPI))
    return packages

def get_egg_files(file:str,sources: str):
    basepath = "/".join(file.split("/")[:-2])
    if not os.path.exists(sources):
        return []
    lines = open(sources).readlines()
    return [basepath + "/"+line.replace("\n","") for line in lines]

def get_record_files(file:str,sources: str):
    basepath = "/".join(file.split("/")[:-2])
    lines = open(sources).readlines()
    return [basepath + "/"+line.replace("\n","").split(",")[0] for line in lines]

def parse_egg_info(paths,file,dirpath: str):
    packagesMap = {}
    packages = extract_egg_dependencies(os.path.join(dirpath,"PKG-INFO"))
    basename = os.path.dirname(file)
    for package in packages:
        packagesMap[package] = [*get_egg_files(file,dirpath + "SOURCES.txt"),*list(filter(lambda x: basename in x, paths))]
    return packagesMap

def parse_metadata(paths,file,dirpath: str):
    packagesMap = {}
    packages = extract_egg_dependencies(dirpath + "METADATA")
    basename = os.path.dirname(file)
    for package in packages:
        packagesMap[package] = [*get_record_files(file,dirpath + "RECORD"),*list(filter(lambda x: basename in x, paths))]
    return packagesMap

def extract_python_dependencies(paths,directory: str):
    interesting_paths = [p for p in paths if "dist-info" in p or "site-packages" in p or "dist-packages" in p]
    total_packages = {}
    total_packages.update(check_python_from_path(interesting_paths,directory))

    for path in interesting_paths:
        if path.endswith(".egg-info") or path.endswith(".dist-info"):
            # pygpgme-0.3-py2.7.egg-info
            path.replace(".egg-info","").replace(".dist-info","")
            stuff = path.split("/")[-1]
            tokens = stuff.split("-")
            version = tokens[1].replace(".egg","").replace(".dist","")
            pkg = PackageInfo(tokens[0].replace(".wh.",""),version,None,PackageInfoType.PYPI)
            if pkg in total_packages:
                total_packages[pkg] = [*total_packages[pkg],path]
            else:
                total_packages[pkg] = [path]

    pkginfo = [path for path in interesting_paths if ".egg-info/PKG-INFO" in path]
    records = [path for path in interesting_paths if ".dist-info/RECORD" in path]


    for eggpkg in pkginfo:
        pakagesegg = parse_egg_info(interesting_paths,eggpkg,os.path.join(directory,eggpkg).replace("PKG-INFO",""))
        for k,v in  pakagesegg.items():
            if k in total_packages:
                total_packages[k].extend(v)
            else:
                total_packages[k] = v
        total_packages.update(pakagesegg)
    for record in records:
        pakagesegg = parse_metadata(interesting_paths,record,os.path.join(directory,record).replace("RECORD",""))
        for k,v in  pakagesegg.items():
            if k in total_packages:
                total_packages[k].extend(v)
            else:
                total_packages[k] = v
    if len(total_packages):
         logger.info(f"Python: {len(total_packages)}")
    return total_packages

