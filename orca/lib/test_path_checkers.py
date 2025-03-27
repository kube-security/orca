import unittest
from .path_checkers import check_python_from_path_once, check_python_from_path
from .types import PackageInfo
import os

class TestPathCheckers(unittest.TestCase):
    def test_check_python_from_path_once_basic(self):
        filename = "python3.8/site-packages/requests-2.25.1.dist-info"
        result, files = check_python_from_path_once(filename, "")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], PackageInfo("python", "3.8", None))
        self.assertEqual(result[1], PackageInfo("requests", "2.25.1", None))
        self.assertEqual(files, [filename])

    def test_check_python_from_path_once_nested(self):
        filename = "python3.9/site-packages/urllib3/urllib3-1.26.4.dist-info"
        result, files = check_python_from_path_once(filename, "")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], PackageInfo("python", "3.9", None))
        self.assertEqual(result[1], PackageInfo("urllib3-urllib3", "1.26.4", None))
        self.assertEqual(files, [filename])

    def test_check_python_from_path_once_invalid(self):
        filename = "invalid/path/format"
        result, files = check_python_from_path_once(filename, "")
        self.assertIsNone(result)
        self.assertEqual(files, [filename])

    def test_check_python_from_path_multiple(self):
        paths = [
            "python3.8/site-packages/requests-2.25.1.dist-info",
            "python3.8/site-packages/urllib3/urllib3-1.26.4.dist-info",
            "not/a/valid/path"
        ]
        result, files = check_python_from_path(paths, "")
        self.assertEqual(len(result), 4)
        self.assertEqual(len(files), 2)

    def test_check_python_from_path_empty(self):
        paths = ["not/a/valid/path"]
        result, files = check_python_from_path(paths, "")
        self.assertEqual(len(result), 0)
        self.assertEqual(len(files), 0)