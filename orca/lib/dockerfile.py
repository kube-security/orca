import re
from typing import List, Tuple
import validators

from orca.lib.types import PackageInfo, PackageInfoType, VulnerabilityReport

def extract_urls(text):
    """
    This function extracts all the http and https urls from the list of commands
    """
    url_pattern = re.compile(r'https?://[^\s";|()\']+(?:\([^)]*\))?')
    return url_pattern.findall(text)


def replace_curly_variables(url, line,env_variables=""):
    """
    This function searches for user-defined variables in the Dockerfile
    TODO: needs to be updated with variables of the Dockerfile. RN is only checking for variables in the same line.
    """
    variables = re.findall(r'\$\{[^}]+\}', url)
    env_var_map = {}
    for var in env_variables.split("\n"):
        if "=" in var:
            key,value = var.split("=",1)
            env_var_map[key] = value
    # Refactor line
    for k, v in env_var_map.items():
        line = line.replace(f"${{{k}}}",v)
    if variables:
        for variable in variables:
            var_name = variable.strip("${}()")
            var_pattern = re.compile(rf'{var_name}=(\S+)')
            match_line = var_pattern.search(line)
            match_env = var_pattern.search(env_variables)
            if match_line:
                url = url.replace(variable, match_line.group(1))
            elif match_env:
                url = url.replace(variable, match_env.group(1)) 

    array_pattern = re.compile(r'for\s+(\w+)\s+in\s+"\${(\w+)\[@\]}"')
    array_match = array_pattern.search(line)
    if array_match:
        urls = []
        component = array_match.group(1)
        array_name = array_match.group(2)
        array_pattern = re.compile(rf'{array_name}\s*=\s*\(([^)]+)\)')
        array_match = array_pattern.search(line)
        if array_match:
            array_values = array_match.group(1).split()
            for value in array_values:
                urls.append(url.replace(f"${{{component}}}", value).replace("\"",""))
        return urls
    
    return [url]   

def replace_dollar_variables(url, line, env_variables=""):
    """
    This function searches for user-defined variables in the Dockerfile
    and replaces them with their values. It checks for variables in the same lin and in the environment variables.
    """
    variables = re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', url)
    if variables:
        for variable in variables:
            var_name = variable.strip("$")
            var_pattern = re.compile(rf'{var_name}=(\S+)')
            match_line = var_pattern.search(line)
            match_env = var_pattern.search(env_variables)

            if match_line:
                url = url.replace(variable, match_line.group(1))
            elif match_env:
                url = url.replace(variable, match_env.group(1))
    return url

def interpolate_variables(dockerfile_config):
    extracted_urls = []
    urls = []
    configurations = [""]

    if 'Env' not in dockerfile_config['config'] or dockerfile_config['config']['Env'] is None :
        pass
    else:
        configurations = '\n'.join(dockerfile_config['config']['Env'])

    if len(dockerfile_config['history']) == 1 and 'created_by' in dockerfile_config['history'][0] and "crane" in dockerfile_config['history'][0]['created_by']:
        item = dockerfile_config['history'][0]
        comments = item["comment"]
        for comment in comments:
            if 'created_by' not in comment:
                continue
            line = comment['created_by']
            if "LABEL" in line or "http" not in line: 
                continue
            else:
                ex_u = extract_urls(line)
                extracted_urls.extend(ex_u)
                for url in ex_u:
                    replaced_url = replace_curly_variables(url, line,configurations) 
                    urls.append(replaced_url)

    else:
        for history_line in dockerfile_config['history']:
            if 'created_by' not in history_line:
                #print("Empty history entry:",history_line)
                continue
            line = history_line['created_by']
            if "LABEL" in line or "http" not in line: 
                continue
            else:
                ex_u = extract_urls(line)
                extracted_urls.extend(ex_u)
            for url in ex_u:       
                replaced_url = replace_curly_variables(url, line,configurations) 
                urls.append(replaced_url)
    return urls


def github_to_cpe(urls)->List[Tuple[PackageInfo,str]]:
        # Now find github stuff
    found_cpes = []
    github_pattern = re.compile(r'https://github\.com/([^/]+)/([^/]+)/releases/download/(v?\d+(\.\d+)*(\+\d+)?)/[^/]+')
    github_urls = [url for url in urls if github_pattern.match(url)]
    for github_url in github_urls:
        match = github_pattern.match(github_url)
        if match:
            author = match.group(1)
            name = match.group(2)
            version = match.group(3)
            found_cpes.append((PackageInfo(name,version,author,PackageInfoType.GITHUB),github_url))
    return found_cpes


def selected_websites_to_cpe(urls)->List[Tuple[PackageInfo,str]]:
    rust_pattern = re.compile(r'https://static\.rust-lang\.org/rustup/archive/(\d+\.\d+\.\d+)/')

    github_content_pattern = re.compile(r'https://raw\.githubusercontent\.com/([^\/]+)\/([^\/]+)\/([^\/]*\d+[^\/]*)')
    
    github_archive_pattern = re.compile(r'https://github\.com/([^\/]+)\/([^\/]+)\/archive\/([^\/]+)\.tar\.gz')
    
    gradle_pattern = re.compile(r'https://services\.gradle\.org/distributions/gradle-(.*)-bin\.zip')

    postgresql_pattern = re.compile(r'https://ftp\.postgresql\.org/pub/source/(v[\d\.]+)')

    bitnami_pattern = re.compile(r'https://downloads\.bitnami\.com/files/stacksmith/([^\/]+)\.tar\.gz')

    generic_compressed_app_pattern = re.compile(r'.*\/(\w+)-([\d\.]+)\.tar\.[a-z]z')
    cpes = []

    for kurl in urls:
        url = kurl.rstrip()
        match_rust = rust_pattern.match(url)
        github_content_pattern_match = github_content_pattern.match(url)
        github_archive_pattern_match = github_archive_pattern.match(url)
        gradle_pattern_match = gradle_pattern.match(url)
        postgresql_pattern_match = postgresql_pattern.match(url)
        bitnami_pattern_match = bitnami_pattern.match(url)
        generic_compressed_app_pattern_match = generic_compressed_app_pattern.match(url)
        if match_rust:
            cpes.append((PackageInfo("rust",match_rust.group(1),"rust",type=PackageInfoType.RUST),url))
        elif github_content_pattern_match:
            cpes.append((PackageInfo(github_content_pattern_match.group(1),github_content_pattern_match.group(3),
            github_content_pattern_match.group(2),type=PackageInfoType.GITHUB),url))
        elif github_archive_pattern_match:
            #print(github_archive_pattern_match.groups())
            cpes.append((PackageInfo(github_archive_pattern_match.group(1),github_archive_pattern_match.group(3),
            github_archive_pattern_match.group(2),type=PackageInfoType.GITHUB),url))
        elif gradle_pattern_match:
            cpes.append((PackageInfo("gradle",gradle_pattern_match.group(1),"gradle",PackageInfoType.GRADLE),url))
        elif postgresql_pattern_match:
            cpes.append((PackageInfo("postgresql",postgresql_pattern_match.group(1),"postgresql"),url))
        elif bitnami_pattern_match:
            regex = r"^([a-zA-Z0-9-]+)-([\d.]+-\d+)-linux-(amd64)-debian-(\d+)"
            match = re.match(regex, bitnami_pattern_match.group(1))
            if match:
                name, version, arch, distro = match.groups()
                pkg = PackageInfo(name,version,"bitnami",arch=arch,type=PackageInfoType.BITNAMI)
                #purl = f"pkg:bitnami/{name}@{version}?arch={arch}&distro=debian-{distro}"
                cpes.append((pkg,url))
        elif generic_compressed_app_pattern_match: # TODO: this should probably be separated into a different function
            pkg = PackageInfo(generic_compressed_app_pattern_match.group(1),generic_compressed_app_pattern_match.group(2),generic_compressed_app_pattern_match.group(1))
            cpes.append((pkg,url))

    return cpes

def extract_cpes_from_dockerfile(dockerfile_config):
    # Those are all the urls  + the ones that have been interpolated with the env variables and other variables in the Dockerfile line.
    urls = [u.rstrip() for theurls in interpolate_variables(dockerfile_config) for u in theurls]

    useful_urls = [u for u in urls if "$(" not in u]# TO be removed.
    found_cpes = github_to_cpe(useful_urls)
    found_cpes.extend(selected_websites_to_cpe(useful_urls))

    files_with_cpe = [cpe[1] for cpe in found_cpes]
    non_cpes = list(set(urls).difference(set(files_with_cpe)))


    return found_cpes,non_cpes

def extract_cpes_from_dockerfile_with_validation(dockerfile_config) -> VulnerabilityReport:
    report = VulnerabilityReport(set("Dockerfile"))
    cpes,non_cpes = extract_cpes_from_dockerfile(dockerfile_config)
    new_cpes = []
    packagefiles = {}
    for cpe in cpes:
        if not validators.url(cpe[1]):
            non_cpes.append(cpe[1])
        else:
            new_cpes.append(cpe[0])
            packagefiles[cpe[0]] = ["Dockerfile"]
    
    report.add_package_files(packagefiles)
    return report