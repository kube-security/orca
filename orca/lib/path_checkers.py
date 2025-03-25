

import os
import re
from typing import List
from .types import PackageInfo

python_dist_regex = re.compile(r'.*python(\d\.\d+)\/site-packages\/(([a-zA-Z0-9_\-]+)\/)?([a-zA-Z0-9]+)-(\d+\.\d+\.?\d*)\.dist-info')
def check_python_from_path_once(filename: str,directory: str):
    result = re.match(python_dist_regex,filename)
    files = [filename]
    if result:
        pkg = [PackageInfo("python", result.group(1),None)]
        if result.group(3) is not None:
            package = f"{result.group(3)}-{result.group(4)}"      
            version = result.group(5)
            pkg.append(PackageInfo(package,version,None))
        else:
            package = result.group(4)
            version = result.group(5)
            pkg.append(PackageInfo(package,version,None))
        if filename.endswith("RECORD"):
            record = open(os.path.join(directory,filename)).readlines()
            basepath = "/".join(filename.split("/")[:-1])
            files = [basepath + "/" + line.split(",")[0] for line in record]
            files.append(filename)

        return pkg,files
    return None,files


def check_python_from_path(paths: List[str],directory: str):
    files = set()
    cpes = []
    for path in [p for p in paths if ".dist-info" in p]:
        res,fn = check_python_from_path_once(path,directory)
        if res:
            cpes.extend(res)
            files.update(fn)
    return cpes,files