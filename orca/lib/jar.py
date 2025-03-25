
import os
import re
from typing import List
import zipfile
from . import logger
from.types import PackageInfo, PackageInfoType

# TODO: fix this
TMP_DIR = f"{os.getcwd()}/tmpdir"


def parse_pom_properties(jar: zipfile.ZipFile,content: str):
    packages = []
    package_info = {}
    data = jar.open(content).readlines()
    for line in data:
        sline = line.decode()
        if "=" in sline:
            kv = sline.replace("\n","").replace("\r","").split("=")
            package_info[kv[0]] = kv[1]
    try:
        packages.append(PackageInfo(package_info["artifactId"],package_info["version"],package_info["groupId"],PackageInfoType.MAVEN))
    except Exception as e :
        logger.logger.warn(f"{jar.filename} - {package_info.keys()} - {data} - {e}")
        pass    
    return packages


def list_jar_props(jar_path,directory):
    packages = []
    try:
        with zipfile.ZipFile(os.path.join(directory,jar_path), 'r') as jar:
            contents = jar.namelist()
            real_contents =  [content for content in contents if content.endswith("pom.properties") ]
            nested_jars = [content for content in contents if content.endswith(".jar")]

            for nested_jar in nested_jars:
                jar.extract(nested_jar,os.path.join(TMP_DIR,nested_jar[:-4]))
                packages.extend(list_jar_props(nested_jar[:-4],TMP_DIR))
            
            
            for content in real_contents:
                packages.extend(parse_pom_properties(jar,content))
        return packages
    except Exception as _:
       return packages

def extract_jar(input_string: str):
    dots = input_string.split(".")

    for idx, dot in enumerate(dots):
        if len(dot) > 2 and dot[-2] == "-" and dot[-1].isdigit():
            author = ".".join(dots[:idx])
            name = dot[:-2]
            version =dot[-1] + "." + ".".join(dots[idx+1:])
            return {"author": author,"name": name, "version": version}
        elif len(dot) > 2 and dot[-3] == "-" and dot[-2].isdigit() and dot[-1].isdigit():
            author = ".".join(dots[:idx])
            name = dot[:-3]
            version =dot[-2] + dot[-1] +"." + ".".join(dots[idx+1:])
            return {"author": author,"name": name, "version": version}
    return None

def get_jar(paths: List[str],directory: str):
    jars = [path for path in paths if path.endswith(".jar") ]
    packages = {}
    for jar in jars:
        basename = os.path.basename(jar).split(".jar")[0]
        tokens = basename.split("-")
        dots = basename.split(".")
        #print(basename)
        # AwsJavaSdk-CognitoIdentityProvider-2.0.jar
        if len(tokens) > 2 and len(dots) < 4:
            #print("first")
            version = tokens[-1]
            pattern = re.compile(r"^([a-zA-Z0-9\-_]+?)-(\d+\.\d+(?:\.\d+)?)(?:[-_][a-zA-Z0-9\-._]+)?$")
            match = pattern.match(basename)
            if match:
                name, version = match.groups()
                package = PackageInfo(name,version,name,PackageInfoType.MAVEN)
                packages[package] = [basename]
        else:
            result = extract_jar(basename)
            if result is None:
                continue
            name = result["name"]
            version = result["version"]
            author = result["author"]
            package = PackageInfo(name,version,author,PackageInfoType.MAVEN)
            packages[package] = [basename]



    for jar in jars:
        pkgs = list_jar_props(jar,directory)
        basepath = os.path.dirname(jar) 
        files = list(filter(lambda x: basepath in x, paths))
        for pkg in pkgs:
            packages[pkg] = files
    if len(packages):
         logger.logger.info(f"JARs: {len(packages)}")

    return packages

