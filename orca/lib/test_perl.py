import os
from .perl import parse_module, get_perl
from .types import PackageInfo, PackageInfoType
import pytest

class TestPerl:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.test_dir = os.path.dirname(os.path.abspath(__file__))
        
    def test_parse_module_empty(self):
        result = parse_module("nonexistent_file.pm")
        assert result == ("", "")

    def test_parse_module_valid(self, tmp_path):
        test_content = """
        package Test::Module;
        $VERSION = '1.2.3';
        """
        test_file = tmp_path / "test.pm"
        test_file.write_text(test_content)
        
        package, version = parse_module(str(test_file))
        assert package == "Test::Module"
        assert version == "1.2.3"

    def test_parse_module_no_version(self, tmp_path):
        test_content = """
        package Test::Module;
        """
        test_file = tmp_path / "test.pm"
        test_file.write_text(test_content)
            
        package, version = parse_module(str(test_file))
        assert package == ""
        assert version == ""

    def test_get_perl_empty(self):
        result = get_perl([], "")
        assert result == {}
