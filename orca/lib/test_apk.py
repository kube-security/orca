import os
import pytest
from unittest.mock import patch
from orca.lib.apk import get_apk, read_apk_db, read_world_file
from orca.lib.types import PackageInfo, PackageInfoType


class TestApk:
    @patch("orca.lib.apk.open", create=True)
    def test_read_apk_db(self, mock_open):
        # Mock the file content
        file_content = """P:test_package
V:1.2.3
F:lib
R:test.so

P:another_package
V:4.5.6
F:usr/bin
R:executable
"""
        mock_open.return_value.read.return_value = file_content
        mock_open.return_value.__enter__.return_value = mock_open.return_value

        # Call the function
        db_path = "fake_path"
        path = "actual_path"
        result = read_apk_db(db_path, path)

        # Assert the result
        expected_package1 = PackageInfo(
            "test_package", "1.2.3", None, PackageInfoType.APK
        )
        expected_package2 = PackageInfo(
            "another_package", "4.5.6", None, PackageInfoType.APK
        )
        assert expected_package1 in result
        assert expected_package2 in result
        assert result[expected_package1] == {"lib/test.so", "actual_path"}
        assert result[expected_package2] == {"usr/bin/executable", "actual_path"}

    @patch("orca.lib.apk.open", create=True)
    def test_read_world_file(self, mock_open):
        # Mock the file content
        file_content = "package1\npackage2\n"
        mock_open.return_value.readlines.return_value = file_content.splitlines()
        mock_open.return_value.__enter__.return_value = mock_open.return_value

        # Call the function
        db_path = "fake_path"
        path = "actual_path"
        result = read_world_file(db_path, path)

        # Assert the result
        expected_package1 = PackageInfo("package1", None, None, PackageInfoType.APK)
        expected_package2 = PackageInfo("package2", None, None, PackageInfoType.APK)
        assert expected_package1 in result
        assert expected_package2 in result
        assert result[expected_package1] == {"actual_path"}
        assert result[expected_package2] == {"actual_path"}

    @patch("orca.lib.apk.read_apk_db")
    @patch("orca.lib.apk.read_world_file")
    def test_get_apk(self, mock_read_world_file, mock_read_apk_db):
        # Mock the paths
        paths = ["path/to/apk/db/installed", "path/to/apk/world"]
        directory = "test_dir"

        # Mock the return values of read_apk_db and read_world_file
        mock_read_apk_db.return_value = {
            PackageInfo("package1", "1.0", None, PackageInfoType.APK): {"file1"}
        }
        mock_read_world_file.return_value = {
            PackageInfo("package2", None, None, PackageInfoType.APK): {"file2"}
        }

        # Call the function
        result = get_apk(paths, directory)

        # Assert the calls and the result
        mock_read_apk_db.assert_called_once_with(
            os.path.join(directory, paths[0]), paths[0]
        )
        mock_read_world_file.assert_called_once_with(
            os.path.join(directory, paths[1]), paths[1]
        )
        expected_result = {
            PackageInfo("package1", "1.0", None, PackageInfoType.APK): {"file1"},
            PackageInfo("package2", None, None, PackageInfoType.APK): {"file2"},
        }
        assert result == expected_result

    def test_get_apk_no_apks(self):
        # Test when there are no apk files in the paths
        paths = ["path/to/some/other/file"]
        directory = "test_dir"
        result = get_apk(paths, directory)
        assert result == {}

    @patch("orca.lib.apk.logger")
    @patch("orca.lib.apk.read_apk_db")
    def test_get_apk_logging(self, mock_read_apk_db, mock_logger):
        # Mock the paths
        paths = ["path/to/apk/db/installed"]
        directory = "test_dir"

        # Mock the return values of read_apk_db
        mock_read_apk_db.return_value = {
            PackageInfo("package1", "1.0", None, PackageInfoType.APK): {"file1"}
        }

        # Call the function
        get_apk(paths, directory)

        # Assert that the logger was called
        mock_logger.logger.info.assert_called_with("APKs: 1")
