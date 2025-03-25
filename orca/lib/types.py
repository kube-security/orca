from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum

class LayerAction(Enum):
    ADDED = "added"
    REPLACED = "replaced"
    DELETED = "deleted"

@dataclass
class PackageRecord:
    path: str
    hashtype: Optional[str]
    hash: Optional[str]
    nlines: Optional[int]


def to_record(record_item: str) -> PackageRecord:
    split = record_item.split(',')
    if len(split) < 2:
        return PackageRecord(split[0],None,None,None)
    if len(split[1]) < 5:
        htype = None
        hash = None
        nlines = None
    else:
        htype = split[1].split("=")[0]
        hash = split[1].split("=")[1]
        nlines = int(split[2])
    return PackageRecord(split[0],htype,hash,nlines)

@dataclass
class LayerChangeRecord:
    action: LayerAction
    layer: str

class PackageInfoType(Enum):
    DEBIAN = "debian",
    PYPI = "pypi",
    NPM = "npm",
    MAVEN = "maven",
    GOLANG = "golang",
    APK = "apk",
    COMPOSER = "composer",
    RPM = "rpm",
    GEM = "gem",
    PERL = "perl",
    GITHUB = "github",
    BITNAMI = "bitnami",
    RUST="rust",
    GRADLE="gradle",



@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    author: Optional[str]
    type: Optional[PackageInfoType] = None
    arch: Optional[str] = None
    epoch: Optional[str] = None

    def to_cpe(self):
        return f"cpe:2.3:a:{self.author if self.author is not None and "Amazon" not in self.author else "*"}:{self.name}:{self.version}:*:*:*:*:*:*:*"

    def to_csv_entry(self):
        author = "unknown" if self.author is None else self.author
        author = author if "Amazon" not in author else "unknown"

        return f"{self.name},{self.version},{author}"

class VulnerabilityReport:
    def __init__(self,paths: Set[str]):
        self.initial_files = paths
        self.remaining_files = paths
        self.packages: List[PackageInfo] = []
        self.package_files: Dict[PackageInfo,List[str]] = {}
        self.analyzed_files: Set[str] = set()
        self.os = None

    def add_package_files(self,package_files: Dict[PackageInfo,List[str]]):
        self.packages.extend(package_files.keys())
        self.package_files.update(package_files)
        fs = [file for file_list in package_files.values() for file in file_list ]
        self.analyzed_files.update(fs)
        self.remaining_files = self.remaining_files.difference(fs)
    
    def to_json(self):
        json_dict = {}
        for k,v in self.package_files.items():
            json_dict[f"{k.name}_{k.version}_{k.author}"] = list(v)
        return json_dict

    def to_json_all(self):
        json_dict = {'package_files': {}, 'analyzed_files': [], 'remaining_files': []}
        for k, v in self.package_files.items():
            if isinstance(k, PackageInfo):
                json_dict['package_files'][f"{k.name}_{k.version}_{k.author}"] = {
                    "type": self.package_types[k],
                    "list_files": list(v)
                }
        json_dict['analyzed_files'] = list(set(self.analyzed_files))
        json_dict['remaining_files'] = list(set(self.remaining_files))
        return json_dict
    
    def summary(self) -> str:
        return f"Found {len(self.packages)} packages. Indexed {len(self.analyzed_files)} filed over a total of {len(self.initial_files)} - Remaining files {len(self.initial_files) - len(self.analyzed_files)}"

