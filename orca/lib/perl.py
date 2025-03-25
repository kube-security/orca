
from typing import List
import re
import os

from . import logger
from .types import PackageInfo, PackageInfoType

package_regex = r'package\s+([^\s;]+)'
# Regex for extracting the version
version_regex = r'\$VERSION\s*=\s*\'([^\']+)\''




def parse_module(filepath):
    try:
        content = open(filepath).read()
    except Exception as _:
        return "",""
    # Extract package name
    package_match = re.search(package_regex, content)
    if package_match:
        package_name = package_match.group(1)
        version_match = re.search(version_regex, content)
        if version_match:
            version = version_match.group(1)
            return package_name,version
    return "",""

def get_perl(paths: List[str],directory: str):
    packages = {} 
    perl_modules = [path for path in paths if path.endswith(".pm") and "perl" in path]
    for module in perl_modules:
        package,version = parse_module(os.path.join(directory,module))
        if len(package) > 0 and len(package.split("::")) < 3:
            packages[PackageInfo(package,version,None,PackageInfoType.PERL)] = [module]
    if len(packages):
         logger.logger.info(f"Perl: {len(packages)}")
    return packages
            



