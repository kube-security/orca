

import os
import re
from typing import Dict, List

from . import logger
from.types import PackageInfo, PackageInfoType

GOSUM = re.compile(r'(\S+)\s+(\S+)\s+h1:(\S+)')

def parse_gemspec(paths: List[str],directory: str) -> Dict[PackageInfo, List[str]]:
   files = [f for f in paths if f.endswith(".gemspec")]

   patterns = {
        'name': r'\.name\s*=\s*["\']([^"\']+)["\']',
        'version': r'\.version\s*=\s*["\']([^"\']+)["\']',
    }
   packages: Dict[PackageInfo, List[str]] = {}
   for filename in files: 
         try:
            file = open(os.path.join(directory,filename), 'r')
         except Exception as e:
             logger.logger.error(f"[GEM] could not open file {filename} - {e}")
             continue
         content = file.read()
      
         spec_blocks = re.findall(r'Gem::Specification\.new do (.+?)end', content, re.DOTALL)
         for block in spec_blocks:
            gemspec_data = {}
            for key, pattern in patterns.items():
                  match = re.search(pattern, block)
                  if match:
                        gemspec_data[key] = match.group(1)
            if "version" not in gemspec_data:
                #gemspec_data['version'] = ""
                continue
            if "name" not in gemspec_data:
                continue 
            p = PackageInfo(gemspec_data['name'],gemspec_data['version'],None,PackageInfoType.GEM)

            if p in packages:
                packages[p].append(filename)
            else:
               packages[p] = [filename]
   if len(packages.keys()):
      logger.logger.info(f"Gemspec : {len(packages)}")
   return packages


def parse_gosum(filepath):
   cpes = []
   with open(filepath, 'r') as file:
        lines = file.readlines()
        for line in lines:
           match = GOSUM.match(line)
           if match:
            module_path = match.group(1)
            version = match.group(2)[1:]
            org = module_path.split("/")[-2]
            module = module_path.split("/")[-1]
            version = version if "/go.mod" not in version else version.split("/")[0]
            cpes.append(f"cpe:2.3:a:{org}:{module}:{version}:*:*:*:*:*:*:*")
   return list(set(cpes))
            
              