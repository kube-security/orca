

import os
import re
from typing import List

from . import logger
from.types import PackageInfo

zlib = re.compile(r'inflate\s\(.*\)\s([0-9]+\.[0-9]+\.[0-9]+)')
GCC_re = re.compile(r'GCC:\s\(.*\)\s([0-9]+\.[0-9]+\.[0-9]+)')
GCC2_re = re.compile(r'gcc\s([0-9]+\.[0-9]+\.[0-9]+)')
openssl_re = re.compile(r'.*OpenSSL\s([0-9]+\.[0-9]+\.[0-9]+)')
pg_re = re.compile(r'.*\(PostgreSQL\)\s([0-9]+\.[0-9]+\.[0-9]+)')

def check_gcc(strings: List[str]):
   
   for string in strings:
      match = GCC_re.search(string)
      if match:
         version = match.group(1)
         return PackageInfo("gcc",version,"gnu",None)
   return None

def check_gcc2(strings: List[str]):
   for string in strings:
      match = GCC2_re.search(string)
      if match:
         version = match.group(1)
         return PackageInfo("gcc",version,"gnu",None)
   return None

def check_openssl(strings: List[str]):
   for string in strings:
      match = openssl_re.search(string)
      if match:
         version = match.group(1)
         return  PackageInfo("openssl",version,"openssl",None)
   return None

def check_postgres(strings: List[str]):
   for string in strings:
      match = pg_re.search(string)
      if match:
         version = match.group(1)
         return PackageInfo("postgresql",version,"postgresql",None) 
   return None

def check_zlib(strings: List[str]):
   
   for string in strings:
      match = zlib.search(string)
      if match:
         version = match.group(1)
         return PackageInfo("zlib",version,"zlib",None) 
   return None

def check_self(strings: List[str],binary_name):
   if len(binary_name) == 1:
      return None
   pattern = r'{binary_name}\s(v?[0-9]+\.[0-9]+\.[0-9]+)'.format(binary_name=binary_name)
   try:
      selfbin = re.compile(pattern)
   except Exception as e :
      logger.logger.info(f"Could not compile regex for {binary_name} {e}")
      return None,None
   for string in strings:
      match = selfbin.search(string)
      if match:
         version = match.group(1)
         return PackageInfo(binary_name,version,None,None)
   return None


def extract_strings(filename, min_length=4):
   thestrings = []
   with open(filename, 'rb') as file:
        data = file.read()
    
   # Use a regex to find sequences of printable characters of at least `min_length`
   pattern = re.compile(b'[\x20-\x7E]{' + str(min_length).encode() + b',}')
   strings = pattern.findall(data)
    
   for s in strings:
        thestrings.append(s.decode('ascii')) 
   return thestrings

def check_binaries(directory,executables):
   results = {}
   for exec_file in executables:
        cpes = static_check_cpes(os.path.join(directory,exec_file))
        if len(cpes):
           for cpe in cpes:
              if cpe in results:
                 results[cpe].append(exec_file)
              else:
                 results[cpe] = [exec_file]
   if len(results):
      logger.logger.info(f"Binaries {len(results)}")
   return results 

def static_check_cpes(filepath):
   """
   This function extracts strings from a file and
   applies regex to fing known applications and versions
   
   ---
   Returns: List of CPEs 
   """
   strings = set(extract_strings(filepath,4))
   cpes = []
   gcc_ver = check_gcc(strings)
   if gcc_ver is not None:
      cpes.append(gcc_ver)
   gcc_ver2 = check_gcc2(strings)
   if gcc_ver2 is not None:
      cpes.append(gcc_ver2)
   ssl_ver = check_openssl(strings)
   if ssl_ver is not None:
      cpes.append(ssl_ver)
   zlib_ver = check_zlib(strings)
   if zlib_ver is not None:
      cpes.append(zlib_ver)
   pg = check_postgres(strings)
   if pg is not None:
      cpes.append(pg)
   self_ver = check_self(strings,filepath.split("/")[-1].strip())
   if self_ver is not None:
      cpes.append(self_ver)
   return cpes
 