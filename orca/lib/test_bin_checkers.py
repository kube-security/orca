import os
import pytest
from unittest.mock import patch
from orca.lib import bin_checkers
from orca.lib.types import PackageInfo

def test_check_gcc():
    strings = ["GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"]
    expected = PackageInfo("gcc", "9.4.0", "gnu", None)
    assert bin_checkers.check_gcc(strings) == expected

    strings = ["Some other string", "GCC: (GNU) 7.5.0"]
    expected = PackageInfo("gcc", "7.5.0", "gnu", None)
    assert bin_checkers.check_gcc(strings) == expected

    strings = ["No match here"]
    assert bin_checkers.check_gcc(strings) is None

def test_check_gcc2():
    strings = ["gcc 4.8.5"]
    expected = PackageInfo("gcc", "4.8.5", "gnu", None)
    assert bin_checkers.check_gcc2(strings) == expected

    strings = ["Some other string", "gcc 5.4.0"]
    expected = PackageInfo("gcc", "5.4.0", "gnu", None)
    assert bin_checkers.check_gcc2(strings) == expected

    strings = ["No match here"]
    assert bin_checkers.check_gcc2(strings) is None

def test_check_openssl():
    strings = ["OpenSSL 1.1.1f  31 Mar 2020"]
    expected = PackageInfo("openssl", "1.1.1", "openssl", None)
    assert bin_checkers.check_openssl(strings) == expected

    strings = ["Some other string", "* OpenSSL 1.0.2g  1 Mar 2016"]
    expected = PackageInfo("openssl", "1.0.2", "openssl", None)
    assert bin_checkers.check_openssl(strings) == expected

    strings = ["No match here"]
    assert bin_checkers.check_openssl(strings) is None

def test_check_postgres():
    expected = PackageInfo("postgresql", "12.3.4", "postgresql", None)
    assert bin_checkers.check_postgres(["(PostgreSQL) 12.3.4"]) == expected

    expected = PackageInfo("postgresql", "9.6.17", "postgresql", None)
    assert bin_checkers.check_postgres(["Some other string", "(PostgreSQL) 9.6.17"]) == expected

    assert bin_checkers.check_postgres(["No match here"]) is None

def test_check_zlib():
    strings = ["inflate (zlib v1.2.11) 1.2.11"]
    expected = PackageInfo("zlib", "1.2.11", "zlib", None)
    assert bin_checkers.check_zlib(strings) == expected

    strings = ["Some other string", "inflate (zlib v1.2.8) 1.2.8"]
    expected = PackageInfo("zlib", "1.2.8", "zlib", None)
    assert bin_checkers.check_zlib(strings) == expected

    strings = ["No match here"]
    assert bin_checkers.check_zlib(strings) is None

def test_check_self():
    strings = ["mybinary v1.2.3"]
    expected = PackageInfo("mybinary", "v1.2.3", None, None)
    assert bin_checkers.check_self(strings, "mybinary") == expected

    strings = ["Some other string", "anotherbin 2.0.0"]
    expected = PackageInfo("anotherbin", "2.0.0", None, None)
    assert bin_checkers.check_self(strings, "anotherbin") == expected

    strings = ["No match here"]
    assert bin_checkers.check_self(strings, "testbin") is None

    # Test with binary name of length 1
    assert bin_checkers.check_self(strings, "a") is None

@patch('orca.lib.bin_checkers.logger.logger.info')
def test_check_self_regex_error(mock_info):
    strings = ["test v1.2.3"]
    # Force a regex error by using an invalid binary name
    result = bin_checkers.check_self(strings, "*invalid*")
    assert result == (None,None)
    mock_info.assert_called()

def test_extract_strings():
    # Create a dummy file for testing
    with open("test_file.txt", "wb") as f:
        f.write(b"This is a test\n")
        f.write(b"with some strings\n")
        f.write(b"and some non-ascii: \x80\x81\x82\n")  # Include some non-ASCII bytes
        f.write(b"short\n")
        f.write(b"toolongstringgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")

# Test code for the "static_check_cpes" function
    # Test with an empty file
    with open("test_file.txt", "w" ) as f:
        f.write("")
    
    assert bin_checkers.static_check_cpes("test_file.txt") == []

    # Clean up the dummy file
    os.remove("test_file.txt")

# Test for check_binaries
@pytest.mark.skip(reason="no way to test this functionality yet")
def test_check_binaries():
    # Create a dummy directory and files for testing
    os.makedirs("test_dir", exist_ok=True)
    with open("test_dir/file1.txt", "w") as f:
        f.write("gcc 1.2.3")
    with open("test_dir/file2.txt", "w") as f:
        f.write("zlib v1.2.8")

    executables = ["file1.txt", "file2.txt"]
    # Call check_binaries
    results = bin_checkers.check_binaries("test_dir", executables)

    # Assert the expected results
    assert len(results) == 2
    assert "gcc" in results
    assert "zlib" in results

    # Clean up the dummy directory and files
    os.remove("test_dir/file1.txt")
    os.remove("test_dir/file2.txt")
    os.rmdir("test_dir")