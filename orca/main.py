import argparse
import datetime
import json
import shutil
from typing import Dict, List
import docker
import docker.errors
from orca.find_cpes import scan_filesystem
from orca.lib.dockerfile import extract_cpes_from_dockerfile_with_validation
from orca.lib.logger import logger
import tarfile
import os

from orca.lib.spdx import generateSPDXFromReportMap
from orca.lib.types import VulnerabilityReport
from orca.lib.utils import map_container_id

TMP_DIR = f"{os.getcwd()}/tmpdir"



def tar_remove_links(file: tarfile.TarInfo,path):
    if not file.islnk() and not file.issym() and not file.isdev() and not file.isdir():
        return file
    return None


def save_image(client:docker.DockerClient,container:str,filepath:str):
    try:
        image = client.images.get(container)
    except docker.errors.ImageNotFound as _:
        logger.info(f"Image {container} not found")
        logger.info(f"Pulling image {container}")
        image = client.images.pull(container)
    except Exception as e:
        print(e)
    
    
    shutil.rmtree(TMP_DIR,ignore_errors=True)
    
    os.mkdir(TMP_DIR,mode=0o755)


    logger.info(f"Saving image {container} to {filepath}")
    f = open(filepath, 'wb')
    for chunk in image.save(named=False):
        f.write(chunk)
    f.close()
    return


def extract_config(config_path: str):
    config_file = json.load(open(config_path))
    data = config_file['history']
    if len(data) > 1:
        return config_file
    # Compressed images with crane
    for item in config_file['history']:
        if "comment" in item:
            try:
                x = json.loads(item["comment"])
                item["comment"] = x
            except json.JSONDecodeError:
                break
                #print(f"Error parsing nested JSON - {item}")
                #exit()
    if 'comment' not in data[0]:
        return config_file
    config_file['history'] = data[0]['comment']
    return config_file



def extract_with_config_and_layers(image_location:str):
    tarf = tarfile.open(image_location)
    manifests = [x for x in tarf.getmembers() if x.name == "manifest.json"]
    assert len(manifests) == 1
    manifest = manifests[0]
    tarf.extract(manifest,path=f"{TMP_DIR}",set_attrs=False,filter=tar_remove_links)
    manifestFile = json.load(open(f"{TMP_DIR}/manifest.json"))
    layers = manifestFile[0]['Layers']
    config_path = manifestFile[0]['Config']
    tarf.extract(config_path,path=f"{TMP_DIR}",set_attrs=False,filter=tar_remove_links)
    config = extract_config(f"{TMP_DIR}/{config_path}")
    return tarf,config,layers

def scan_tar(image_tar:str,client:docker.DockerClient,binary_analysis:bool):
    layers_archive,config,layers = extract_with_config_and_layers(image_tar)

    report_by_layer: Dict[str,VulnerabilityReport] = {}
    for layer in layers:
        logger.info(f"Analyzing layer {layer}")
        layers_archive.extract(layer,f"{TMP_DIR}",set_attrs=False,filter=tar_remove_links)
        if not os.path.exists(f"{TMP_DIR}/{layer}"):
            logger.error(f"Layer {layer} does not exist on container {image_tar}")
            continue
        image_layer = tarfile.open(f"{TMP_DIR}/{layer}")
        image_layer.extractall(f"{TMP_DIR}/{layer}_layer",filter=tar_remove_links,numeric_owner=True)
        report = scan_filesystem(f"{TMP_DIR}/{layer}_layer",binary_analysis,False)
        report_by_layer[layer] = report
        # Add dockerfile:
        logger.info(report.summary())

    cpes = extract_cpes_from_dockerfile_with_validation(config)
    report_by_layer["Dockerfile"] = cpes

    # Cleanup: TODO: probably should be done in a separate function
    shutil.rmtree(TMP_DIR,ignore_errors=True)
    return report_by_layer

def scan_image(container:str,client:docker.DockerClient,binary_analysis:bool):
    image_tar = f'{TMP_DIR}/container.tar'
    save_image(client,container,image_tar)
    layers_archive,config,layers = extract_with_config_and_layers(image_tar)

    report_by_layer: Dict[str,VulnerabilityReport] = {}
    for layer in layers:
        logger.info(f"Analyzing layer {layer}")
        layers_archive.extract(layer,f"{TMP_DIR}",set_attrs=False,filter=tar_remove_links)
        if not os.path.exists(f"{TMP_DIR}/{layer}"):
            logger.error(f"Layer {layer} does not exist on container {container}")
            continue
        image_layer = tarfile.open(f"{TMP_DIR}/{layer}")
        image_layer.extractall(f"{TMP_DIR}/{layer}_layer",filter=tar_remove_links)
        report = scan_filesystem(f"{TMP_DIR}/{layer}_layer",binary_analysis,False)
        report_by_layer[layer] = report

        logger.info(report.summary())

    cpes = extract_cpes_from_dockerfile_with_validation(config)
    report_by_layer["Dockerfile"] = cpes
    # Cleanup: TODO: probably should be done in a separate function
    shutil.rmtree(TMP_DIR,ignore_errors=True)
    return report_by_layer

def write_logfile(report_by_layer: dict[str, VulnerabilityReport],container:str,container_name:str,elapsed:int)->None:
    total_files = set()
    total_files_duplicates = []
    analyzed_files = set()
    analyzed_files_duplicates = []
    for _layer,report in report_by_layer.items():
        total_files.update(report.initial_files)
        total_files_duplicates.extend(report.initial_files)
        analyzed_files.update(report.analyzed_files)
        analyzed_files_duplicates.extend(report.analyzed_files)

    loginfo = {
        "analyzed_files":len(analyzed_files),
        "analyzed_files_duplicates":len(analyzed_files_duplicates),
        "container": container,
        "container_usable_name": container_name,
        "total_files": len(total_files),
        "total_files_duplicates": len(total_files_duplicates),
        "elapsed_time":elapsed
    }
    with open(f"logs/orca-{container_name}_logs.json","w") as fp:
            json.dump(loginfo,fp)


def orca(client: docker.DockerClient,output_folder: str,csv:bool,binary_analysis:bool,containers: List[str]):
 
 if not os.path.exists("logs/"):
    os.mkdir("logs",mode=0o755)
 if output_folder == "results" and not os.path.exists("results"):
     os.mkdir("results",mode=0o755)

 for container in containers: 
        start = datetime.datetime.now()
        container_usable_name = map_container_id(container)

        if not container.endswith(".tar"):
            report_by_layer = scan_image(container,client,binary_analysis)
        else:
            report_by_layer = scan_tar(container,client,binary_analysis) 
            
        end = datetime.datetime.now()

        elapsed = (end-start).total_seconds() * 1000
        total_cpe = set()
        for layer,report in report_by_layer.items():
            logger.info(f"{layer} - {report.summary()}")
            if len(report.packages) == 1 and report.packages[0] == (None,None):
                continue
            total_cpe.update(report.packages)

        print(f"[{container}] Total packages identified {len(total_cpe)}")
        logger.info(f"Elapsed time: {elapsed} ms")
        write_logfile(report_by_layer,container,container_usable_name,elapsed)

        if len(total_cpe) == 0:
            continue
        if csv:
            with open(f"{output_folder}/{container_usable_name}_packages.csv","w") as fp:
                   fp.write("product,version,vendor\n")
                   for pkg in total_cpe:
                       fp.write(pkg.to_csv_entry() + "\n")
                   fp.close()
        
        generateSPDXFromReportMap(container,report_by_layer,f"{output_folder}/orca-{container_usable_name}.json")


def main():
    
    parser = argparse.ArgumentParser(
        prog="orca",
        description="""Software composition analysis for containers"""
    )

    parser.add_argument(
        "-d","--dir", type=str, help="Folder where to store results *without ending /*",default="results")
    
    parser.add_argument(
        "--csv", type=bool, help="Store also a csv file with package information",default=False)
    
    parser.add_argument(
       "-b","--with-binaries", action='store_true', help="Analyze every binary file (slower). Go binaries are always analyzed",default=False)

    parser.add_argument(
        "containers", type=str, help="Comma separated list of containers to analyze")

    args = parser.parse_args()
    client = docker.from_env(timeout=900) # TODO: if scanning a tar there is no reason to access the docker engine
    output = args.dir
    csv = args.csv
    with_bin = args.with_binaries
    containers = args.containers.split(",")
    orca(client,output,csv,with_bin,containers)

if __name__ == "__main__":
    main()