import hashlib
from datetime import datetime
from typing import Dict, List
from spdx_tools.spdx.model import (Document,CreationInfo,Package,SpdxNone,Actor,ActorType,ExternalPackageRef,ExternalPackageRefCategory,PackagePurpose,Relationship,RelationshipType,File,Checksum,ChecksumAlgorithm)
from spdx_tools.spdx.writer.write_anything import write_file
import base64
from.types import PackageInfo, PackageInfoType, VulnerabilityReport
from packageurl import PackageURL




def getpurl(packageInfo: PackageInfo) -> str:
    if packageInfo.type == "debian":
        return f"pkg:deb/debian/{packageInfo.name.lower()}@{packageInfo.version}"
    elif packageInfo.type == "pypi":
        return f"pkg:pypi/{packageInfo.name.lower()}@{packageInfo.version}"
    else:
        return f"pkg:generic/{packageInfo.name.lower()}@{packageInfo.version}"

def create_anchore_purl(osinfo,packageInfo: PackageInfo):

    if packageInfo.type is None:
        purl = PackageURL(type="generic",name=packageInfo.name.lower(),version=packageInfo.version)
    elif packageInfo.type == PackageInfoType.DEBIAN:
        qualifiers = {
            "arch": packageInfo.arch,
            "distro": "debian-"+osinfo["version"],
        }
        if packageInfo.epoch is not None:
            qualifiers["epoch"] = packageInfo.epoch
        
        if "name" in osinfo and osinfo["name"].lower().rstrip() == "ubuntu": 
            purl = PackageURL(type="deb",namespace="ubuntu",name=packageInfo.name.lower(),version=packageInfo.version,qualifiers=qualifiers)
        else:
            purl = PackageURL(type="deb",namespace="debian",name=packageInfo.name.lower(),version=packageInfo.version,qualifiers=qualifiers)
        
    elif packageInfo.type == PackageInfoType.RPM: 
        purl = PackageURL(type="rpm",name=packageInfo.name.lower(),version=packageInfo.version,namespace=packageInfo.author)
    elif packageInfo.type == PackageInfoType.APK: 
        purl = PackageURL(type="apk",name=packageInfo.name.lower(),version=packageInfo.version,namespace="alpine")
    elif packageInfo.type == PackageInfoType.NPM:
        purl = PackageURL(type="npm",name=packageInfo.name.lower(),version=packageInfo.version) 
    elif packageInfo.type == PackageInfoType.PYPI:
        purl = PackageURL(type="pypi",name=packageInfo.name.lower(),version=packageInfo.version) 
    elif packageInfo.type == PackageInfoType.PERL:
        purl = PackageURL(type="perl",name=packageInfo.name.lower(),version=packageInfo.version) 
    elif packageInfo.type == PackageInfoType.MAVEN:
        purl = PackageURL(type="maven",name=packageInfo.name.lower(),version=packageInfo.version,namespace=packageInfo.author)
    elif packageInfo.type == PackageInfoType.GOLANG: # This should probably be edited
        path = packageInfo.name.lower()
        path_split = path.split("/")
        name = path
        other = None
        if len(path_split) > 3:
            name = "/".join(path_split[:3])
            other = "/".join(path_split[3:])
        purl = PackageURL(type="golang",name=name,version=packageInfo.version,namespace=packageInfo.author,subpath=other)
    elif packageInfo.type == PackageInfoType.COMPOSER: 
        purl = PackageURL(type="composer",name=packageInfo.name.lower(),version=packageInfo.version,namespace=packageInfo.author)
    elif packageInfo.type == PackageInfoType.GEM: 
        purl = PackageURL(type="gem",name=packageInfo.name.lower(),version=packageInfo.version)
    elif packageInfo.type == PackageInfoType.GITHUB:
        purl = PackageURL(type="github",name=packageInfo.name.lower(),version=packageInfo.version,namespace=packageInfo.author)
    elif packageInfo.type == PackageInfoType.BITNAMI:
        purl = PackageURL(type="bitnami",name=packageInfo.name.lower(),version=packageInfo.version,qualifiers={"arch":packageInfo.arch})
    elif packageInfo.type == PackageInfoType.RUST:
        purl = PackageURL(type="cargo",name=packageInfo.name.lower(),version=packageInfo.version)
    elif packageInfo.type == PackageInfoType.GRADLE:
        purl = PackageURL(type="gradle",name=packageInfo.name.lower(),version=packageInfo.version)
    else:
        purl = PackageURL(type="generic",name=packageInfo.name.lower(),version=packageInfo.version)
    return purl


def map_package(osinfo,index: int,packageInfo: PackageInfo) -> Package:
    def getid():
        return f"SPDXRef-PACKAGE-{base64.b64encode(bytes(f"{packageInfo.name} {packageInfo.version} {packageInfo.author} {packageInfo.arch}",'utf-8')).decode("utf-8",errors="ignore").replace("=","").replace("+","")}"
    external_refs = []
    anchore_purl  = create_anchore_purl(osinfo,packageInfo)
    external_refs = [
            #ExternalPackageRef(ExternalPackageRefCategory.PACKAGE_MANAGER,reference_type="purl",locator=generic_purl+f"?arch=allu0026distro=debian-{osinfo['version']}"),
            ExternalPackageRef(ExternalPackageRefCategory.PACKAGE_MANAGER,reference_type="purl",locator=anchore_purl.to_string())
            #ExternalPackageRef(ExternalPackageRefCategory.PACKAGE_MANAGER,reference_type="purl",locator=generic_purl+f"?os_distro={osinfo['codename']}&os_name=debian&os_version={osinfo['version']}")
                        ]

    package: Package = Package(
        name=packageInfo.name,
        version=packageInfo.version,
        download_location=SpdxNone(),
        license_concluded=SpdxNone(),
        license_declared=SpdxNone(),
        primary_package_purpose=PackagePurpose.LIBRARY,
        spdx_id=getid(),
        copyright_text=SpdxNone(),
        external_references=external_refs)
    return package


def generateSPDXFromCPE(containerImage: str,inputPackages: List[PackageInfo],output_filename: str):

    containerPackage: Package = Package(name=containerImage, download_location=SpdxNone(),license_concluded=SpdxNone(),license_declared=SpdxNone(),spdx_id="SPDXRef-ContainerImage",copyright_text=SpdxNone(),primary_package_purpose=PackagePurpose.CONTAINER)



    creation_info = CreationInfo(spdx_version="SPDX-2.3",spdx_id="SPDXRef-DOCUMENT",name="CPE Finder",created=datetime.now(),creators=[Actor(ActorType.ORGANIZATION,"CNAM"),Actor(ActorType.TOOL,"CPE finder")],document_namespace="http://example.com")

    packages = [map_package(idx,p) for idx,p in enumerate(inputPackages)]

    relationships = []
    relationships.append(Relationship("SPDXRef-DOCUMENT",RelationshipType.DESCRIBES,"SPDXRef-ContainerImage"))

    packages.append(containerPackage)
    doc = Document(creation_info,packages=packages,relationships=relationships)
    write_file(doc, output_filename,validate=True)


def generateFileMappingReport(reportMap: Dict[str,VulnerabilityReport])-> Dict[str,File]:
    filemap: Dict[str,File] = dict()
    for layer,report in reportMap.items():
        layer_id = layer.split("/")[-1]
        
        for file in report.initial_files:
            fid = file.replace("/","-").replace("_","").replace(" ","")
            sid = f"SPDXRef-File-{layer_id}-{fid}"
            if sid in filemap:
                filemap[sid].comment += f"\n Layer: {layer_id}"
            else:
                checksum = Checksum(ChecksumAlgorithm.SHA1,hashlib.sha1("testme".encode()).hexdigest())
               
                filemap[sid] = File(name=file,spdx_id=sid,comment=f"Layer: {layer}",checksums=[checksum])
    return filemap
    

def getOsInfo(reportMap: Dict[str,VulnerabilityReport]) -> Dict[str,str]:
    osinfo = None
    for layer,report in reportMap.items():
        if report.os is not None:
            if osinfo is not None:
                print(f"Received multiple entries of os. The latest one is: {report.os} \nOld one was: {osinfo} \n Merging them")
                for k,v in report.os.items():
                    osinfo[k] = v
            else:
                osinfo = report.os
    return osinfo

def getTotalCPE(reportMap: Dict[str,VulnerabilityReport]) -> List[PackageInfo]:
    total_cpe = set()
    for layer,report in reportMap.items():
        if len(report.packages) == 1 and report.packages[0] == (None,None):
            continue
        total_cpe.update(report.packages)
    return list(total_cpe)

def generateRelationships(reportMap: Dict[str,VulnerabilityReport],filemap: Dict[str,File],packagesmap: Dict[str,Package],osinfo: Dict[str,str]) -> List[Relationship]:
    relmap = {}
    
    for layer,report in reportMap.items():
        layer_id = layer.split("/")[-1]

        for package,files in report.package_files.items():
            for file in files:
                fid = file.replace("/","-").replace("_","").replace(" ","")
                sid = f"SPDXRef-File-{layer_id}-{fid}"
                filemapid = filemap.get(sid).spdx_id if sid in filemap else None
                if filemapid is None:
                    # TODO: this is the case where a file is recorded by ORCA but does not exist in the layer (e.g., updates to a dpkg/status).
                    continue
                customid = f"{packagesmap.get(package).spdx_id}{filemapid}"
                if customid in relmap:
                    continue
                relmap[customid] = Relationship(packagesmap.get(package).spdx_id,RelationshipType.CONTAINS,filemap.get(sid).spdx_id)
        relmap["root"] = Relationship("SPDXRef-DOCUMENT",RelationshipType.DESCRIBES,"SPDXRef-ContainerImage")
    return relmap



def generateSPDXFromReportMap(containerImage: str,reportMap: Dict[str,VulnerabilityReport],output_filename: str,complete_report: bool):

    osinfo = getOsInfo(reportMap)
    if osinfo is not None and "version" not in osinfo:
        osinfo = None

    total_cpe = getTotalCPE(reportMap)
    filemap = generateFileMappingReport(reportMap)
    packagesmap = {p:map_package(osinfo,idx,p) for idx,p in enumerate(list(total_cpe))}
    
    containerPackage: Package = Package(name=containerImage, download_location=SpdxNone(),license_concluded=SpdxNone(),license_declared=SpdxNone(),spdx_id="SPDXRef-ContainerImage",copyright_text=SpdxNone(),primary_package_purpose=PackagePurpose.CONTAINER)
    creation_info = CreationInfo(spdx_version="SPDX-2.3",spdx_id="SPDXRef-DOCUMENT",name="CPE Finder",created=datetime.now(),creators=[Actor(ActorType.ORGANIZATION,"CNAM"),Actor(ActorType.TOOL,"CPE finder")],document_namespace="http://example.com")


   
   

    
     
    packages = list(packagesmap.values())

    packages.append(containerPackage)
    if osinfo is not None:
        osPackage: Package = Package(name=osinfo["name"].split(" ")[0].lower(),
                                 version=osinfo["version"],
                                 download_location=SpdxNone(),license_concluded=SpdxNone(),license_declared=SpdxNone(),spdx_id="SPDXRef-OperatingSystem",copyright_text=SpdxNone(),primary_package_purpose=PackagePurpose.OPERATING_SYSTEM)
        packages.append(osPackage)

    files = list(filemap.values())
    
    doc = None
    if complete_report:
        relmap = generateRelationships(reportMap,filemap,packagesmap,osinfo)  
        relationships = list(relmap.values())
        doc = Document(creation_info,packages=packages,relationships=relationships,files=files)
    else:
        doc = Document(creation_info,packages=packages,files=files)
    
    write_file(doc, output_filename,validate=False)
    #write_file(doc, output_filename,validate=True)
