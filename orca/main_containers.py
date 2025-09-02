import argparse
import datetime
import json
import subprocess
import shutil
from typing import Dict, List
import docker
import docker.errors
from orca.find_cpes import scan_filesystem
from orca.lib.dockerfile import extract_cpes_from_dockerfile_with_validation
from orca.lib.logger import logger
import tarfile
import re
import os
import sqlite3 as sql3
from pathlib import Path


from orca.lib.spdx import generateSPDXFromReportMap
from orca.lib.types import VulnerabilityReport
from orca.lib.utils import map_container_id

def check_image_dir_and_tar(image_dir: str, tar_file: str) -> bool:
    """
    Verify that the directory exists and the tar file exists and is not empty.
    Returns True if everything is OK, False otherwise.
    """
    if not os.path.exists(image_dir):
        logger.error(f"Directory {image_dir} does not exist. Skipping.")
        return False

    if not os.path.exists(tar_file):
        logger.error(f"Tar file {tar_file} does not exist. Skipping.")
        return False

    if os.path.getsize(tar_file) == 0:
        logger.error(f"Tar file {tar_file} is empty. Skipping.")
        return False

    return True

def run_syft(image_tar: str, output_file: str):
    if os.path.exists(output_file):
        logger.info(f"Syft SBOM already exists at {output_file}, skipping.")
        return
    logger.info(f"Running Syft on {image_tar}")
    subprocess.run([
        "syft", f"docker-archive:{image_tar}", "-o", f"spdx-json={output_file}"
    ], check=True)

def run_trivy(image_tar: str, output_file: str):
    if os.path.exists(output_file):
        logger.info(f"Trivy SBOM already exists at {output_file}, skipping.")
        return
    logger.info(f"Running Trivy on {image_tar}")
    subprocess.run([
        "trivy", "fs",
        "--format", "spdx-json",
        "--output", output_file,
        image_tar
    ], check=True)


def run_scout(image_tar: str, output_file: str):
    """
    Run Docker Scout to generate an SPDX SBOM from a tarball archive.
    """
    if os.path.exists(output_file):
        logger.info(f"Scout SBOM already exists at {output_file}, skipping.")
        return
    logger.info(f"Running Docker Scout on {image_tar}")
    try:
        subprocess.run([
            "docker", "scout", "sbom",
            "--output", output_file,
            f"archive://{image_tar}"
        ], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Docker Scout failed on {image_tar}: {e}")
        raise

def tar_remove_links(file: tarfile.TarInfo,path):
    if not file.islnk() and not file.issym() and not file.isdev() and not file.isdir():
        return file
    return None

def save_image(client: docker.DockerClient, container: str, filepath: str, IMAGE_DIR: str):
    if os.path.exists(filepath):
        logger.info(f"Image archive already exists at {filepath}, skipping save.")
    else:
        try:
            image = client.images.get(container)
        except docker.errors.ImageNotFound:
            logger.info(f"Image {container} not found locally. Attempting to pull.")
            try:
                image = client.images.pull(container)
            except docker.errors.ImageNotFound:
                logger.error(f"Image {container} not found in registry. Skipping.")
                return None
            except Exception as e:
                logger.error(f"Unexpected error pulling image {container}: {e}")
                return None
            try:
                image = client.images.get(container)  # re-get after pull
            except Exception as e:
                logger.error(f"Error getting image {container} after pull: {e}")
                return None

        logger.info(f"Saving image {container} to {filepath}")
        with open(filepath, 'wb') as f:
            for chunk in image.save(named=False):
                f.write(chunk)

    # Skip extraction if manifest.json already exists
    if os.path.exists(os.path.join(IMAGE_DIR, "manifest.json")):
        logger.info(f"Image already extracted at {IMAGE_DIR}, skipping extraction.")
        return

    logger.info(f"Extracting image {container} archive to {IMAGE_DIR}")
    try:
        with tarfile.open(filepath, 'r') as tar:
            tar.extractall(path=IMAGE_DIR)
    except Exception as e:
        logger.error(f"Failed to extract image {container}: {e}")
        return

    logger.info(f"Image {container} extracted to {IMAGE_DIR}")


def update_index(container_name: str, output_folder: str):
    """
    Update (or create) an index file mapping each container
    to its SBOMs from Orca, Syft, Trivy, Scout.
    """
    index_file = os.path.join(output_folder, "sbom-index.json")
    if os.path.exists(index_file):
        with open(index_file, "r") as f:
            index = json.load(f)
    else:
        index = {}

    index[container_name] = {
        "orca": os.path.join(output_folder, f"orca-{container_name}.json"),
        "syft": os.path.join(output_folder, f"syft-{container_name}.json"),
        "trivy": os.path.join(output_folder, f"trivy-{container_name}.json"),
        "scout": os.path.join(output_folder, f"scout-{container_name}.json"),
    }

    with open(index_file, "w") as f:
        json.dump(index, f, indent=2)
    logger.info(f"Updated SBOM index at {index_file}")


def run_all_tools(source: str, container_name: str, output_folder: str):
    """
    Run SBOM tools (Syft, Trivy, Scout) on either a tarball path or an image reference.
    """
    syft_out = Path(output_folder) / f"syft-{container_name}.json"
    trivy_out = Path(output_folder) / f"trivy-{container_name}.json"
    scout_out = Path(output_folder) / f"scout-{container_name}.json"

    try:
        run_syft(source, syft_out)
    except subprocess.CalledProcessError as e:
        logger.error(f"Syft failed on {source}: {e}")

    try:
        run_trivy(source, trivy_out)
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy failed on {source}: {e}")

    try:
        run_scout(source, scout_out)
    except subprocess.CalledProcessError as e:
        logger.error(f"Scout failed on {source}: {e}")


def extract_config(config_path: str, image_name: str = "image"):
    config_file = json.load(open(config_path))
    data = config_file['history']
    if len(data) > 1:
        return config_file
    # Compressed images with crane
    for item in config_file['history']:
        print('item',item)
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

def extract_with_config_and_layers(image_location:str, image_name: str, IMAGE_DIR: str):
    tarf = tarfile.open(image_location)
    manifests = [x for x in tarf.getmembers() if x.name == "manifest.json"]
    assert len(manifests) == 1
    manifest = manifests[0]
    tarf.extract(manifest,path=f"{IMAGE_DIR}",set_attrs=False,filter=tar_remove_links)
    manifestFile = json.load(open(f"{IMAGE_DIR}/manifest.json"))
    layers = manifestFile[0]['Layers']
    config_path = manifestFile[0]['Config']
    tarf.extract(config_path,path=f"{IMAGE_DIR}",set_attrs=False,filter=tar_remove_links)
    config = extract_config(f"{IMAGE_DIR}/{config_path}", image_name=image_name)
    return tarf,config,layers

def scan_tar(image_tar:str,client:docker.DockerClient,binary_analysis:bool, image_name:str, IMAGE_DIR: str):
    layers_archive, config,layers = extract_with_config_and_layers(image_tar, image_name, IMAGE_DIR)

    report_by_layer: Dict[str,VulnerabilityReport] = {}
    for layer in layers:
        logger.info(f"Analyzing layer {layer}")
        layers_archive.extract(layer,f"{IMAGE_DIR}",set_attrs=False,filter=tar_remove_links)
        if not os.path.exists(f"{IMAGE_DIR}/{layer}"):
            logger.error(f"Layer {layer} does not exist on container {image_tar}")
            continue
        image_layer = tarfile.open(f"{IMAGE_DIR}/{layer}")
        image_layer.extractall(f"{IMAGE_DIR}/{layer}_layer",filter=tar_remove_links,numeric_owner=True)
        image_files = image_layer.getnames()
        report = scan_filesystem(f"{IMAGE_DIR}/{layer}_layer",image_files,binary_analysis,False)
        report_by_layer[layer] = report
        # Add dockerfile:
        logger.info(report.summary())

    cpes = extract_cpes_from_dockerfile_with_validation(config)
    # FIXME: this is a hack to make the report work with the dockerfile. Obfiously Dockerfile commands are not files. 
    cpes.remaining_files = set()
    cpes.initial_files = set()
    cpes.original_files = set()
    report_by_layer["Dockerfile"] = cpes
    report_by_layer["Dockerfile"] = cpes

    # Cleanup: TODO: probably should be done in a separate function
    # shutil.rmtree(TMP_DIR,ignore_errors=True)
    return report_by_layer

def scan_image(container:str,client:docker.DockerClient,binary_analysis:bool, IMAGE_DIR:str):
    image_tar = f'{IMAGE_DIR}/container.tar'
    if not check_image_dir_and_tar(IMAGE_DIR, image_tar):
        return {}
    save_image(client, container, image_tar, IMAGE_DIR)
    container_usable_name = map_container_id(container)
    layers_archive, config, layers = extract_with_config_and_layers(image_tar, container_usable_name, IMAGE_DIR)

    report_by_layer: Dict[str,VulnerabilityReport] = {}
    for layer in layers:
        logger.info(f"Analyzing layer {layer}")
        layers_archive.extract(layer,f"{IMAGE_DIR}",set_attrs=False,filter=tar_remove_links)
        if not os.path.exists(f"{IMAGE_DIR}/{layer}"):
            logger.error(f"Layer {layer} does not exist on container {container}")
            continue
        image_layer = tarfile.open(f"{IMAGE_DIR}/{layer}")
        image_layer.extractall(f"{IMAGE_DIR}/{layer}_layer",filter=tar_remove_links)
        image_files = image_layer.getnames()
        report = scan_filesystem(f"{IMAGE_DIR}/{layer}_layer",image_files, binary_analysis,False)
        report_by_layer[layer] = report

        logger.info(report.summary())

    cpes = extract_cpes_from_dockerfile_with_validation(config)
    report_by_layer["Dockerfile"] = cpes
    # FIXME: this is a hack to make the report work with the dockerfile. Obfiously Dockerfile commands are not files. 
    cpes.remaining_files = set()
    cpes.initial_files = set()
    cpes.original_files = set()
    report_by_layer["Dockerfile"] = cpes
    # Cleanup: TODO: probably should be done in a separate function
    # shutil.rmtree(IMAGE_DIR,ignore_errors=True)

    # try:
    #     os.remove(image_tar)
    #     logger.info(f"Deleted archive: {image_tar}")
    # except Exception as e:
    #     logger.warning(f"Failed to delete {image_tar}: {e}")

    return report_by_layer


def is_file(base: str, rel_path: str) -> bool:
    full_path = Path(base) / rel_path
    return full_path.is_file()


def write_logfile(report_by_layer: dict[str, VulnerabilityReport], container:str, container_name:str, elapsed:int, base_dir: str)->None:
    total_files = set()
    total_files_duplicates = []
    analyzed_files = set()
    analyzed_files_duplicates = []

    layer_files = {}

    for layer, report in report_by_layer.items():
        base_path = os.path.join(base_dir, f"{layer}_layer")

        filtered_initial = [f for f in report.initial_files if is_file(base_path, f)]
        filtered_analyzed = [f for f in report.analyzed_files if is_file(base_path, f)]

        total_files.update(filtered_initial)
        total_files_duplicates.extend(filtered_initial)
        analyzed_files.update(filtered_analyzed)
        analyzed_files_duplicates.extend(filtered_analyzed)

        layer_files[layer] = {
            "initial_files": sorted(filtered_initial),
            "analyzed_files": sorted(filtered_analyzed)
        }

    loginfo = {
        "analyzed_files": len(analyzed_files),
        "analyzed_files_duplicates": len(analyzed_files_duplicates),
        "container": container,
        "container_usable_name": container_name,
        "total_files": len(total_files),
        "total_files_duplicates": len(total_files_duplicates),
        "elapsed_time": elapsed,
        "analyzed_files_list": sorted(list(analyzed_files)),
        "total_files_list": sorted(list(total_files)),
        "layer_files": layer_files
    }

    with open(f"logs/orca-{container_name}_logs.json", "w") as fp:
        json.dump(loginfo, fp, indent=2)


def orca(client: docker.DockerClient, output_folder: str, csv: bool,
         binary_analysis: bool, with_complete_report: bool, containers: List[str]):
 
    if not os.path.exists("logs/"):
        os.mkdir("logs", mode=0o755)
    if output_folder == "results" and not os.path.exists("results"):
        os.mkdir("results", mode=0o755)

    for container in containers: 
        start = datetime.datetime.now()
        container_usable_name = map_container_id(container)
        IMAGE_DIR = os.path.join('/Volumes/LaCie/', container_usable_name)
        if not os.path.exists(IMAGE_DIR):
            os.mkdir(IMAGE_DIR, mode=0o755)

        image_tar = f"{IMAGE_DIR}/container.tar"

        # ORCA SBOM path
        orca_sbom = os.path.join(output_folder, f"orca-{container_usable_name}.json")

        # If ORCA SBOM already exists, skip ORCA analysis
        if os.path.exists(orca_sbom):
            logger.info(f"Orca SBOM already exists at {orca_sbom}, skipping Orca analysis.")
        else:
            if not container.endswith(".tar"):
                report_by_layer = scan_image(container, client, binary_analysis, IMAGE_DIR)
            else:
                report_by_layer = scan_tar(container, client, binary_analysis, IMAGE_DIR)

            end = datetime.datetime.now()
            elapsed = (end - start).total_seconds() * 1000

            total_cpe = set()
            for layer, report in report_by_layer.items():
                logger.info(f"{layer} - {report.summary()}")
                if len(report.packages) == 1 and report.packages[0] == (None, None):
                    continue
                total_cpe.update(report.packages)

            print(f"[{container}] Total packages identified {len(total_cpe)}")
            logger.info(f"Elapsed time: {elapsed} ms")
            write_logfile(report_by_layer, container, container_usable_name, elapsed, IMAGE_DIR)

            if csv and total_cpe:
                with open(f"{output_folder}/{container_usable_name}_packages.csv", "w") as fp:
                    fp.write("product,version,vendor\n")
                    for pkg in total_cpe:
                        fp.write(pkg.to_csv_entry() + "\n")

            if total_cpe:
                generateSPDXFromReportMap(container, report_by_layer, orca_sbom, with_complete_report)

        image_tar = f"{IMAGE_DIR}/container.tar"

        if os.path.exists(image_tar):
            source = f"docker-archive:{image_tar}"
        else:
            source = container  # nom de l'image ou ref
        run_all_tools(image_tar, container_usable_name, output_folder)

        update_index(container_usable_name, output_folder)
    

def main():
    
    parser = argparse.ArgumentParser(
        prog="orca",
        description="""Software composition analysis for containers"""
    )

    parser.add_argument(
        "-d","--dir", type=str, help="Folder where to store results *without ending /*",default="results")
    
    parser.add_argument(
        "--csv", action='store_true', help="Store also a csv file with package information",default=False)
    
    parser.add_argument(
       "-b","--with-binaries", action='store_true', help="Analyze every binary file (slower). Go binaries are always analyzed",default=False)
    
    parser.add_argument(
        "-c","--complete", action='store_true', help="Generate complete SPDX report with relationships (>200MB file is generated)", default=True)
    
    # parser.add_argument(
    #     "containers", type=str, help="Comma separated list of containers to analyze")

    args = parser.parse_args()
    client = docker.from_env(timeout=900) # TODO: if scanning a tar there is no reason to access the docker engine
    output = args.dir
    csv = args.csv
    with_bin = args.with_binaries
    with_complete_report = args.complete
    # containers = args.containers.split(",")

    database = "/Users/agatheblaise/Downloads/containers_21_11_2024.db"
    connection = sql3.connect(database)
    cursor = connection.cursor()

    random_containers = """
    WITH RandomContainers AS (
        -- Step 1: Randomly select N containers
        SELECT DISTINCT container_name
        FROM container_layers
        ORDER BY RANDOM()
    )
    -- Step 2: Output all layers for the selected containers
    SELECT cl.container_name, cl.layer
    FROM container_layers cl
    WHERE cl.container_name IN (SELECT container_name FROM RandomContainers);
    """

    cursor.execute(random_containers)
    result = cursor.fetchall()

    container_layers = {}
    for container_name, layer in result:
        if container_name not in container_layers:
            container_layers[container_name] = []
        container_layers[container_name].append(layer)

    print(result)
    image_names = list(set(row[0] for row in result))
    print(image_names)

    # container_layers = {}
    # for container_name, layer in result:
    #     if container_name not in container_layers:
    #         container_layers[container_name] = []
    #     container_layers[container_name].append(layer)

    orca(client, output, csv, with_bin, with_complete_report, image_names)

if __name__ == "__main__":
    main()