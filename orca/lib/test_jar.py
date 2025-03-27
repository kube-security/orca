import unittest
import os
from .jar import extract_jar, list_jar_props, parse_pom_properties, get_jar
from .types import PackageInfo, PackageInfoType
import zipfile

class TestJar(unittest.TestCase):
    def test_extract_jar_simple(self):
        # Test simple version format
        result = extract_jar("org.apache.commons.text-1.9")
        self.assertEqual(result["author"], "org.apache.commons")
        self.assertEqual(result["name"], "text")
        self.assertEqual(result["version"], "1.9")

    def test_extract_jar_complex(self):
        # Test complex version format
        result = extract_jar("com.google.guava-31.jar")
        self.assertEqual(result["author"], "com.google")
        self.assertEqual(result["name"], "guava")
        self.assertEqual(result["version"], "31.jar")

    def test_extract_jar_invalid(self):
        # Test invalid format
        result = extract_jar("invalid_format")
        self.assertIsNone(result)

    def test_get_jar(self):
        test_paths = [
            "test.jar",
            "commons-text-1.9.jar",
            "guava-31.0.jar"
        ]
        packages = get_jar(test_paths, ".")
        self.assertIsInstance(packages, dict)

    def test_list_jar_props_empty(self):
        # Test with non-existent jar
        packages = list_jar_props("nonexistent.jar", ".")
        self.assertEqual(packages, [])

if __name__ == '__main__':
    unittest.main()