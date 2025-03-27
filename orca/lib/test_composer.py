import os
import json
from orca.lib import composer
from orca.lib.types import PackageInfo, PackageInfoType

def test_parse_composer_lock_empty(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "composer.lock"
    p.write_text(json.dumps({"packages": []}))
    
    result = composer.parse_composer_lock([], str(d), "composer.lock")
    assert result == {}

def test_parse_composer_lock_basic(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "composer.lock"
    p.write_text(json.dumps({
        "packages": [
            {"name": "vendor/package1", "version": "1.0.0"},
            {"name": "vendor2/package2", "version": "2.0.0"}
        ]
    }))
    
    result = composer.parse_composer_lock([], str(d), "composer.lock")
    
    assert len(result) == 2
    
    expected_package1 = PackageInfo("package1", "1.0.0", "vendor", PackageInfoType.COMPOSER)
    expected_package2 = PackageInfo("package2", "2.0.0", "vendor2", PackageInfoType.COMPOSER)
    
    assert expected_package1 in result
    assert expected_package2 in result
    
    assert result[expected_package1] == ["composer.lock"]
    assert result[expected_package2] == ["composer.lock"]

def test_parse_composer_empty(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "composer.json"
    p.write_text(json.dumps({}))
    
    result = composer.parse_composer([], str(d), "composer.json")
    assert result == {}

def test_parse_composer_basic(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "composer.json"
    p.write_text(json.dumps({
        "name": "vendor/package1",
        "version": "1.0.0"
    }))
    
    result = composer.parse_composer([], str(d), "composer.json")
    
    assert len(result) == 1
    
    expected_package = PackageInfo("package1", "1.0.0", "vendor", PackageInfoType.COMPOSER)
    
    assert expected_package in result
    assert result[expected_package] == ["composer.json"]

def test_parse_composer_no_version(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "composer.json"
    p.write_text(json.dumps({
        "name": "vendor/package1",
    }))
    
    result = composer.parse_composer([], str(d), "composer.json")
    
    assert len(result) == 1
    
    expected_package = PackageInfo("package1", None, "vendor", PackageInfoType.COMPOSER)
    
    assert expected_package in result
    assert result[expected_package] == ["composer.json"]

def test_get_composer_no_composer_files(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    
    result = composer.get_composer([], str(d))
    assert result == {}

def test_get_composer_only_composer_json(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "composer.json"
    p.write_text(json.dumps({"name": "vendor/package1", "version": "1.0.0"}))
    
    result = composer.get_composer([str(p)], str(d))
    assert result == {} # Because it requires composer.lock

def test_parse_composer_exception(tmp_path, caplog):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "composer.json"
    p.write_text("Invalid JSON")

    result = composer.parse_composer([], str(d), "composer.json")
    assert result == {}
    assert "Could not open file composer.json" in caplog.text