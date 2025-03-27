import pytest
from unittest.mock import patch
import os
from orca.lib import ascii_checkers
from orca.lib.types import PackageInfo, PackageInfoType

class TestAsciiCheckers:

    def test_parse_gemspec_empty(self):
        paths = []
        directory = ""
        result = ascii_checkers.parse_gemspec(paths, directory)
        assert result == {}

    def test_parse_gemspec_no_gemspec(self):
        paths = ["test.txt"]
        directory = ""
        result = ascii_checkers.parse_gemspec(paths, directory)
        assert result == {}

    @patch("orca.lib.ascii_checkers.logger.logger")
    def test_parse_gemspec_file_not_found(self, mock_logger):
        paths = ["test.gemspec"]
        directory = ""
        result = ascii_checkers.parse_gemspec(paths, directory)
        mock_logger.error.assert_called()
        assert result == {}

    def test_parse_gemspec_ok(self):
        # Create a dummy gemspec file
        gemspec_content = """
Gem::Specification.new do |s|
  s.name    = 'test_gem'
  s.version = '1.2.3'
end
"""
        with open("test.gemspec", "w") as f:
            f.write(gemspec_content)

        paths = ["test.gemspec"]
        directory = ""
        result = ascii_checkers.parse_gemspec(paths, directory)
        expected_package_info = PackageInfo("test_gem", "1.2.3", None, PackageInfoType.GEM)
        assert list(result.keys())[0] == expected_package_info
        assert result[expected_package_info] == ["test.gemspec"]

        # Clean up the dummy file
        os.remove("test.gemspec")

    def test_parse_gemspec_no_version(self):
        # Create a dummy gemspec file
        gemspec_content = """
Gem::Specification.new do |s|
  s.name    = 'test_gem'
end
"""
        with open("test.gemspec", "w") as f:
            f.write(gemspec_content)

        paths = ["test.gemspec"]
        directory = ""
        result = ascii_checkers.parse_gemspec(paths, directory)
        assert result == {}

        # Clean up the dummy file
        os.remove("test.gemspec")

    def test_parse_gemspec_no_name(self):
        # Create a dummy gemspec file
        gemspec_content = """
Gem::Specification.new do |s|
  s.version = '1.2.3'
end
"""
        with open("test.gemspec", "w") as f:
            f.write(gemspec_content)

        paths = ["test.gemspec"]
        directory = ""
        result = ascii_checkers.parse_gemspec(paths, directory)
        assert result == {}

        # Clean up the dummy file
        os.remove("test.gemspec")

    def test_parse_gosum_empty(self):
        # Create a dummy go.sum file
        gosum_content = ""
        with open("go.sum", "w") as f:
            f.write(gosum_content)

        result = ascii_checkers.parse_gosum("go.sum")
        assert result == []

        # Clean up the dummy file
        os.remove("go.sum")

    def test_parse_gosum_ok(self):
        # Create a dummy go.sum file
        gosum_content = """
github.com/test/module v1.2.3 h1:abcdefg
"""
        with open("go.sum", "w") as f:
            f.write(gosum_content)

        result = ascii_checkers.parse_gosum("go.sum")
        assert result == ['cpe:2.3:a:test:module:1.2.3:*:*:*:*:*:*:*']

        # Clean up the dummy file
        os.remove("go.sum")

    def test_parse_gosum_multiple(self):
        # Create a dummy go.sum file
        gosum_content = """
github.com/test/module v1.2.3 h1:abcdefg
github.com/test/module v1.2.4 h1:abcdefg
"""
        with open("go.sum", "w") as f:
            f.write(gosum_content)

        result = ascii_checkers.parse_gosum("go.sum")
        assert set(result) == {'cpe:2.3:a:test:module:1.2.3:*:*:*:*:*:*:*', 'cpe:2.3:a:test:module:1.2.4:*:*:*:*:*:*:*'}

        # Clean up the dummy file
        os.remove("go.sum")

    def test_parse_gosum_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            ascii_checkers.parse_gosum("nonexistent_file.sum")