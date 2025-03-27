
from typing import Dict, List
import pykg_config
import pykg_config.pcfile

from . import logger
from .types import PackageInfo

def get_pkgconfig(paths: List[str],directory: str) -> Dict[PackageInfo,List[str]]:
    pkgs = filter(lambda path: "pkgconfig" in path and path.endswith(".pc"), paths)
    pkgmap = {}
    for pkg in pkgs:
        name = pkg.split("/")[-1]
        if name not in pkgmap:
            pkgmap[name] = pkg
    pkg_dir = {}
    for pkg in pkgmap.values():
        directories = []
        pc_file_path = directory + "/" + pkg
        vars = {}
        props = {}
        try:
            _, vars, props = pykg_config.pcfile.read_pc_file(pc_file_path,{})
        except Exception as _:
            logger.logger.warning(f"Could not parse pkgconfig file {pc_file_path}")
            continue
        version = props.get("version")
        if "." not in version:
            version = vars.get("abiver")

        package = PackageInfo(props.get("name"),version,None,None)

        directories.append(pkg)
        if vars.get("exec_prefix") is not None:
            directories.append(vars.get("exec_prefix")[1:])
        if props.get("libdir") is not None:
            directories.append(props.get("libdir")[1:])
        
        if package in pkg_dir:
           pkg_dir[package] = [*pkg_dir[package],*directories] 
        else:
            pkg_dir[package] = directories

    package_files = {}
    for package,dirs in pkg_dir.items():
        for directory in list(set(dirs)):
            files_found = []
            for path in paths:
                if directory in path:
                    files_found.append(path)
        package_files[package] = files_found
    return package_files
