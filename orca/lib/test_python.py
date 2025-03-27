import pytest
from orca.lib.types import PackageInfo, PackageInfoType
import os

from orca.lib.python import (
    check_python_from_path_once,
    check_python_from_path,
    extract_egg_dependencies,
    get_egg_files,
    get_record_files,
    parse_egg_info,
    parse_metadata,
    extract_python_dependencies,
)

def test_check_python_from_path_once_dist_info():
    paths = ["/path/to/package-1.0.dist-info/METADATA", "/path/to/package-1.0.dist-info/RECORD"]
    filename = "/path/to/package-1.0.dist-info"
    directory = "/path/to"
    result = check_python_from_path_once(paths, filename, directory)
    expected_package = PackageInfo("package",'1.0',None,PackageInfoType.PYPI)
    
    assert len(result) == 1
    assert expected_package == list(result.keys())[0]
    assert len(result[expected_package]) == 2

def test_check_python_from_path_once_egg_info():
    paths = ["/path/to/package-1.0.egg-info/PKG-INFO", "/path/to/package-1.0.egg-info/SOURCES.txt"]
    filename = "/path/to/package-1.0.egg-info"
    directory = "/path/to"
    result = check_python_from_path_once(paths, filename, directory)
    expected_package = PackageInfo("package",'1.0',None,PackageInfoType.PYPI)
    
    assert len(result) == 1
    assert expected_package == list(result.keys())[0]
    assert len(result[expected_package]) == 2

def skip_test_check_python_from_path_once_record():
    paths = ["/path/to/package-1.0.dist-info/METADATA", "/path/to/package-1.0.dist-info/RECORD", "/path/to/package/file1.py", "/path/to/package/file2.py"]
    filename = "/path/to/package-1.0.dist-info/RECORD"
    directory = "/path/to"
    result = check_python_from_path_once(paths, filename, directory)
    assert len(result) == 1
    package_info = list(result.keys())[0]
    assert package_info.name == "package"
    assert package_info.version == "1.0"
    assert result[package_info] == ['/path/to/package/file1.py', '/path/to/package/file2.py']

def test_check_python_from_path():
    paths = ["/path/to/package1-1.0.dist-info/METADATA",
             "/path/to/package2-2.0.egg-info/PKG-INFO", "/path/to/package2-2.0.egg-info/SOURCES.txt"]
    directory = "/path/to"
    result = check_python_from_path(paths, directory)
    assert isinstance(result, dict)

def test_extract_egg_dependencies(tmpdir):
    depfile_content = """Name: test_package
Version: 1.2.3
Author: Test Author
Requires-Dist: requests
Requires-Dist: flask"""
    depfile = tmpdir.join("PKG-INFO")
    depfile.write(depfile_content)
    packages = extract_egg_dependencies(str(depfile))
    assert len(packages) == 3
    assert packages[0].name == "test_package"
    assert packages[0].version == "1.2.3"

def skip_test_get_egg_files(tmpdir):
    sources_content = """file1.py
file2.py
"""
    sources = tmpdir.join("SOURCES.txt")
    sources.write(sources_content)
    file = "/path/to/package-1.0.egg-info"
    result = get_egg_files(file, str(sources))
    assert result == ['/path/to/file1.py', '/path/to/file2.py']

def skip_test_get_record_files(tmpdir):
    record_content = """file1.py,sha256=abc,100
file2.py,sha256=def,200
"""
    record = tmpdir.join("RECORD")
    record.write(record_content)
    file = "/path/to/package-1.0.dist-info"
    result = get_record_files(file, str(record))
    assert result == ['/path/to/file1.py', '/path/to/file2.py']

def skip_test_parse_egg_info(tmpdir):
    pkg_info_content = """Metadata-Version: 2.1
Name: test_package
Version: 1.2.3
Author: Test Author
Requires-Dist: requests"""
    sources_content = "file1.py\nfile2.py\n"
    pkg_info = tmpdir.join("PKG-INFO")
    sources = tmpdir.join("SOURCES.txt")
    pkg_info.write(pkg_info_content)
    sources.write(sources_content)
    paths = ["/path/to/file1.py", "/path/to/file2.py", "/path/to/package-1.0.egg-info/PKG-INFO"]
    file = "/path/to/package-1.0.egg-info"
    dirpath = str(tmpdir) + "/"
    result = parse_egg_info(paths, file, dirpath)
    assert len(result) == 2
    package_info = list(result.keys())[0]
    assert package_info.name == "test_package"
    assert package_info.version == "1.2.3"
    assert len(result[package_info]) == 3

def skip_test_parse_metadata(tmpdir):
    metadata_content = """Metadata-Version: 2.1
    Name: test_package
    Version: 1.2.3
    Author: Test Author
    Requires-Dist: requests"""
    record_content = "file1.py,sha256=abc,100\nfile2.py,sha256=def,200\n"
    metadata = tmpdir.join("METADATA")
    record = tmpdir.join("RECORD")
    metadata.write(metadata_content)
    record.write(record_content)
    paths = ["/path/to/file1.py", "/path/to/file2.py", "/path/to/package-1.0.dist-info/METADATA"]
    file = "/path/to/package-1.0.dist-info"
    dirpath = str(tmpdir) + "/"
    result = parse_metadata(paths, file, dirpath)
    assert len(result) == 2
    package_info = list(result.keys())[0]
    assert package_info.name == "test_package"
    assert package_info.version == "1.2.3"
    assert len(result[package_info]) == 3

def skip_test_extract_python_dependencies(tmpdir):
    # Create dummy files and directories
    dist_info_dir = tmpdir.mkdir("test_package-1.0.dist-info")
    dist_info_dir.join("METADATA").write("Metadata-Version: 2.1\nName: test_package\nVersion: 1.0")
    dist_info_dir.join("RECORD").write("file1.py,,\nfile2.py,,\n")

    egg_info_dir = tmpdir.mkdir("another_package-2.0.egg-info")
    egg_info_dir.join("PKG-INFO").write("Metadata-Version: 2.1\nName: another_package\nVersion: 2.0")
    egg_info_dir.join("SOURCES.txt").write("file3.py\nfile4.py\n")

    # Define paths
    paths = [str(dist_info_dir.join("METADATA")), str(dist_info_dir.join("RECORD")),
             str(egg_info_dir.join("PKG-INFO")), str(egg_info_dir.join("SOURCES.txt"))]
    directory = str(tmpdir)

    # Call the function
    dependencies = extract_python_dependencies(paths, directory)

    # Assertions
    assert len(dependencies) == 2
    assert PackageInfo("test_package", "1.0", None, PackageInfoType.PYPI) in dependencies
    assert PackageInfo("another_package", "2.0", None, PackageInfoType.PYPI) in dependencies