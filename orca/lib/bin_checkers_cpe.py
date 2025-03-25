

import re
from typing import List

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
         return f"cpe:2.3:a:gnu:gcc:{version}:*:*:*:*:*:*:*",string
   return None,None

def check_gcc2(strings: List[str]):
   for string in strings:
      match = GCC2_re.search(string)
      if match:
         version = match.group(1)
         return f"cpe:2.3:a:gnu:gcc:{version}:*:*:*:*:*:*:*",string
   return None,None

def check_openssl(strings: List[str]):
   for string in strings:
      match = openssl_re.search(string)
      if match:
         version = match.group(1)
         return f"cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*",string
   return None,None

def check_postgres(strings: List[str]):
   for string in strings:
      match = pg_re.search(string)
      if match:
         version = match.group(1)
         return f"cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*",string
   return None,None

def check_zlib(strings: List[str]):
   
   for string in strings:
      match = zlib.search(string)
      if match:
         version = match.group(1)
         return f"cpe:2.3:a:zlib:zlib:{version}:*:*:*:*:*:*:*",string
   return None,None 

def check_self(strings: List[str],binary_name):
   pattern = r'{binary_name}\s(v?[0-9]+\.[0-9]+\.[0-9]+)'.format(binary_name=binary_name)
   selfbin = re.compile(pattern)
   for string in strings:
      match = selfbin.search(string)
      if match:
         version = match.group(1)
         return f"cpe:2.3:a:*:{binary_name}:{version}:*:*:*:*:*:*:*",string
   return None,None 


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

def static_check_cpes(filepath):
   """
   This function extracts strings from a file and
   applies regex to fing known applications and versions
   
   ---
   Returns: List of CPEs 
   """
   strings = set(extract_strings(filepath,4))
   cpes = []
   gcc_ver,gcc_str = check_gcc(strings)
   if gcc_ver is not None:
      strings.remove(gcc_str)
      cpes.append(gcc_ver)

   gcc_ver2,gcc_str2 = check_gcc2(strings)
   if gcc_ver2 is not None:
      strings.remove(gcc_str2)
      cpes.append(gcc_ver2)
      
   ssl_ver,ssl_str = check_openssl(strings)
   if ssl_ver is not None:
      strings.remove(ssl_str)
      cpes.append(ssl_ver)
      
   zlib_ver,zlib_str = check_zlib(strings)
   if zlib_ver is not None:
      strings.remove(zlib_str)
      cpes.append(zlib_ver)

   pg,pg_str = check_postgres(strings)
   if pg is not None:
      strings.remove(pg_str)
      cpes.append(pg)
           
   self_ver,self_str = check_self(strings,filepath.split("/")[-1].strip())
   if self_ver is not None:
      strings.remove(self_str)
      cpes.append(self_ver)
         
   return list(set(cpes))
 