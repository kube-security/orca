import pytest
from .pkgconfig import get_pkgconfig
from .types import PackageInfo

def test_get_pkgconfig_empty():
    paths = []
    directory = "/test"
    result = get_pkgconfig(paths, directory)
    assert result == {}

def test_get_pkgconfig_no_pc_files():
    paths = ["/test/lib/file.so", "/test/include/header.h"] 
    directory = "/test"
    result = get_pkgconfig(paths, directory)
    assert result == {}

def test_get_pkgconfig_invalid_pc():
    paths = ["/test/usr/lib/pkgconfig/invalid.pc"]
    directory = "/test"
    
    def mock_read_pc_file(path, vars):
        raise Exception("Invalid PC file")
        
    import pykg_config.pcfile
    pykg_config.pcfile.read_pc_file = mock_read_pc_file
    
    result = get_pkgconfig(paths, directory)
    assert result == {}