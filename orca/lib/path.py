import glob
from typing import Set

def remove_folders(paths):
    dir_set = set()
    result = []

    for path in paths:
        parts = path.split("/")
        for i in range(1, len(parts)):
            dir_set.add("/".join(parts[:i]))

    for path in paths:
        if path not in dir_set and len(path) > 2:
            result.append(path)

    return result

def get_filepaths(directory:str) -> Set[str]:
    paths = filter(lambda path: len(path) > 2 
                   and "etc/ssl/certs/" not in path
                   and "usr/share/zoneinfo" not in path
                   and "etc/nginx/" not in path,
                    glob.glob(directory + "/**", recursive=True,include_hidden=True))
    mapped_paths = map(lambda path: path.replace(directory + "/",""),paths)
    return set(mapped_paths)#set(remove_folders(paths))