import pytest
from orca.lib.path import remove_folders, get_filepaths
import os
import tempfile

def test_remove_folders_empty():
    assert remove_folders([]) == []

def test_remove_folders_single_file():
    assert remove_folders(["file.txt"]) == ["file.txt"]

def test_get_filepaths():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create test directory structure
        os.makedirs(os.path.join(tmp_dir, "a/b"))
        os.makedirs(os.path.join(tmp_dir, "etc/ssl/certs"))
        os.makedirs(os.path.join(tmp_dir, "usr/share/zoneinfo"))
        os.makedirs(os.path.join(tmp_dir, "etc/nginx"))
        
        # Create some test files
        open(os.path.join(tmp_dir, "a/b/test.txt"), "w").close()
        open(os.path.join(tmp_dir, "file.txt"), "w").close()
        open(os.path.join(tmp_dir, "etc/ssl/certs/cert.pem"), "w").close()
        
        paths = get_filepaths(tmp_dir)
        
        assert "a/b/test.txt" in paths
        assert "file.txt" in paths
        assert "etc/ssl/certs/cert.pem" not in paths
