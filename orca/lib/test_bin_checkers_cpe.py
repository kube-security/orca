import pytest
from orca.lib import bin_checkers_cpe as bcc
import os
import os
import os

def test_check_gcc():
    strings = ["GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"]
    cpe, string = bcc.check_gcc(strings)
    assert cpe == "cpe:2.3:a:gnu:gcc:9.4.0:*:*:*:*:*:*:*"
    assert string == "GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"

    strings = ["Some other string", "GCC: (GNU) 7.5.0"]
    cpe, string = bcc.check_gcc(strings)
    assert cpe == "cpe:2.3:a:gnu:gcc:7.5.0:*:*:*:*:*:*:*"
    assert string == "GCC: (GNU) 7.5.0"

    strings = ["No match here"]
    cpe, string = bcc.check_gcc(strings)
    assert cpe is None
    assert string is None

def test_check_gcc2():
    strings = ["gcc 5.4.0"]
    cpe, string = bcc.check_gcc2(strings)
    assert cpe == "cpe:2.3:a:gnu:gcc:5.4.0:*:*:*:*:*:*:*"
    assert string == "gcc 5.4.0"

    strings = ["Another string", "gcc 4.9.3"]
    cpe, string = bcc.check_gcc2(strings)
    assert cpe == "cpe:2.3:a:gnu:gcc:4.9.3:*:*:*:*:*:*:*"
    assert string == "gcc 4.9.3"

    strings = ["No match"]
    cpe, string = bcc.check_gcc2(strings)
    assert cpe is None
    assert string is None

def test_check_openssl():
    strings = ["OpenSSL 1.1.1f  31 Mar 2020"]
    cpe, string = bcc.check_openssl(strings)
    assert cpe == "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    assert string == "OpenSSL 1.1.1f  31 Mar 2020"

    strings = ["Some text", "OpenSSL 1.0.2k-fips  26 Jan 2017"]
    cpe, string = bcc.check_openssl(strings)
    assert cpe == "cpe:2.3:a:openssl:openssl:1.0.2:*:*:*:*:*:*:*"
    assert string == "OpenSSL 1.0.2k-fips  26 Jan 2017"

    strings = ["No OpenSSL here"]
    cpe, string = bcc.check_openssl(strings)
    assert cpe is None
    assert string is None

def test_check_postgres():
    strings = ["(PostgreSQL) 12.3.2"]
    cpe, string = bcc.check_postgres(strings)
    assert cpe == "cpe:2.3:a:postgresql:postgresql:12.3.2:*:*:*:*:*:*:*"
    assert string == "(PostgreSQL) 12.3.2"

    strings = ["Other stuff", "(PostgreSQL) 9.6.17"]
    cpe, string = bcc.check_postgres(strings)
    assert cpe == "cpe:2.3:a:postgresql:postgresql:9.6.17:*:*:*:*:*:*:*"
    assert string == "(PostgreSQL) 9.6.17"

    strings = ["No PostgreSQL"]
    cpe, string = bcc.check_postgres(strings)
    assert cpe is None
    assert string is None

def test_check_zlib():
    strings = ["inflate (zlib) 1.2.11"]
    cpe, string = bcc.check_zlib(strings)
    assert cpe == "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"
    assert string == "inflate (zlib) 1.2.11"

    strings = ["Another string", "inflate (zlib) 1.2.8"]
    cpe, string = bcc.check_zlib(strings)
    assert cpe == "cpe:2.3:a:zlib:zlib:1.2.8:*:*:*:*:*:*:*"
    assert string == "inflate (zlib) 1.2.8"

    strings = ["No zlib here"]
    cpe, string = bcc.check_zlib(strings)
    assert cpe is None
    assert string is None

def test_check_self():
    strings = ["mybinary v1.0.0"]
    cpe, string = bcc.check_self(strings, "mybinary")
    assert cpe == "cpe:2.3:a:*:mybinary:v1.0.0:*:*:*:*:*:*:*"
    assert string == "mybinary v1.0.0"

    strings = ["Some other string", "anotherbin 2.5.1"]
    cpe, string = bcc.check_self(strings, "anotherbin")
    assert cpe == "cpe:2.3:a:*:anotherbin:2.5.1:*:*:*:*:*:*:*"
    assert string == "anotherbin 2.5.1"

    strings = ["No match for this binary"]
    cpe, string = bcc.check_self(strings, "nonexistent")
    assert cpe is None
    assert string is None

def test_extract_strings():
    # Create a dummy file for testing
    with open("test_file.txt", "wb") as f:
        f.write(b"This is a test file.\n")
        f.write(b"It contains some strings.\n")
        f.write(b"Short: abc\n")
        f.write(b"Longer: abcdefg\n")
        f.write(b"\x01\x02\x03BinaryData\x04\x05\x06\n")

    strings = bcc.extract_strings("test_file.txt", min_length=4)
    assert "This is a test file." in strings
    assert "abc" not in strings  # Shorter than min_length

    # Clean up the dummy file
    os.remove("test_file.txt")

def test_static_check_cpes():
    # Create a dummy file with strings that match known CPE patterns
    with open("test_binary", "wb") as f:
        f.write(b"GCC: (GNU) 7.5.0\n")
        f.write(b"OpenSSL 1.1.1f  31 Mar 2020\n")
        f.write(b"test_binary v2.0.1\n")

    cpes = bcc.static_check_cpes("test_binary")
    assert "cpe:2.3:a:gnu:gcc:7.5.0:*:*:*:*:*:*:*" in cpes
    assert "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*" in cpes
    assert "cpe:2.3:a:*:test_binary:v2.0.1:*:*:*:*:*:*:*" in cpes

    # Clean up the dummy file
    os.remove("test_binary")

def test_static_check_cpes_empty():
    # Create an empty dummy file
    with open("empty_binary", "wb") as f:
        pass

    cpes = bcc.static_check_cpes("empty_binary")
    assert cpes == []

    # Clean up the dummy file
    os.remove("empty_binary")