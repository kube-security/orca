import re
import subprocess
import os
from typing import Dict, List
from .types import PackageInfo, PackageInfoType
from .logger import logger
def extract_go_dependencies(go_binary_path,directory: str):
    results = {}
    for path in go_binary_path:
        result = extract_dependency(os.path.join(directory,path))
        for res in result:
            results[res] = [path]
    if len(results):
             logger.info(f"GO executables {len(results)}")
    return results
          
def extract_dependency(go_binary_path):
        packages = []
        # Use go list to get package dependencies
        deps_process = subprocess.Popen(['go', 'version',"-m" ,go_binary_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deps_output, deps_error = deps_process.communicate()
        
        if deps_process.returncode != 0 or len(deps_error) > 1:
            return []
        lines = deps_output.decode('utf-8').splitlines()
        try:
            version = lines[0].split(" ")[1]
        except Exception as e:
             logger.warning(f"Go binary {go_binary_path} is too old to be analyzed {e}")
             return packages
        pkg = PackageInfo("stdlib", version[2:],None,PackageInfoType.GOLANG)
        packages.append(pkg)
        
        dep_lines = [line for line in lines if "dep" in line or "=>" in line or "mod" in line]
        for line in dep_lines:
              dep_split = line.split("\t")
              if len(dep_split) < 4:
                   logger.error(f"[GO] Could not parse: {line}")
                   continue

              packages.append(PackageInfo(dep_split[2], dep_split[3],None,PackageInfoType.GOLANG))
        for build_line in [line for line in lines if "build" in line]:
            last_item = build_line.split("\t")[-1]
   
            if "-X " in last_item in last_item:
                #print(last_item)
                flags = last_item.split("-X ")[1:]
                found = False
                for flag in flags:
                    f = flag.split(" ")[0]
                    if "version.Version" in f:
                        found = True
                        split = flag.split("/version.Version=")
                        if len(split) < 2 :
                            continue
                        p = PackageInfo(split[0], split[1],None,PackageInfoType.GOLANG) 
                        packages.append(p)
                if not found:
                    f = flags[0].split(" ")[0]
                    name = "/".join(f.split("/")[:-1])
                    if name is not None and "/" in name:
                        p = PackageInfo(name, "unknown",None,PackageInfoType.GOLANG) 
                        packages.append(p)

                     
        #imported_symbols = [line.strip() for line in objdump_output.decode('utf-8').splitlines() if 'imported symbol' in line]
        return packages#lines#, imported_symbols

   
go_version_pattern = r'^go\s+(\d+\.\d+)'
require_pattern = r'require\s+\(\s*([^)]*)\s*\)'  # for multiline `require` 
single_require_pattern = r'require\s+([^\s]+)\s+([^\s]+)'  # for single line `require`
    

def get_gomod(paths: List[str],directory: str) -> Dict[PackageInfo,List[str]]:
    gomods = [path for path in paths if path.endswith("/go.mod")]

    packages = {}
    for gomod in gomods:
        file_content = open(os.path.join(directory,gomod)).read()
        
        match = re.search(go_version_pattern, file_content, re.MULTILINE)
        if match:
            go_version = match.group(1)
            p = PackageInfo("go",go_version,None)
            if p in packages:
                packages[p].append(gomod)
            else:
                packages[p] = [gomod]


        require_block = re.search(require_pattern, file_content, re.DOTALL)
        if require_block:
        # Extract dependencies from a multiline require block
            modules = require_block.group(1).strip().splitlines()
            for module in modules:
                module_info = module.strip().split()
                if len(module_info) == 2:
                    name, version = module_info
                    p = PackageInfo(name,version,None)
                    if p in packages:
                         packages[p].append(gomod)
                    else:
                        packages[p] = [gomod]
        # TODO: Add also gofiles here
    
    if len(packages):
         logger.info(f"GoMOD : {len(packages)}")
    return packages

