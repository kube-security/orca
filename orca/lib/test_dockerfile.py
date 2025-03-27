import pytest
from orca.lib.types import PackageInfo, PackageInfoType
from orca.lib.dockerfile import (
    extract_urls, 
    replace_curly_variables,
    replace_dollar_variables,
    interpolate_variables,
    github_to_cpe,
    selected_websites_to_cpe,
    extract_cpes_from_dockerfile
)

def test_extract_urls():
    text = "RUN curl https://example.com/file.tar.gz && wget http://test.org/pkg.zip"
    urls = extract_urls(text)
    assert urls == ["https://example.com/file.tar.gz", "http://test.org/pkg.zip"]

def test_replace_curly_variables():
    url = "https://example.com/${VERSION}/file.tar.gz"
    line = "VERSION=1.2.3 curl ${VERSION}"
    result = replace_curly_variables(url, line)
    assert result == ["https://example.com/1.2.3/file.tar.gz"]

def test_replace_dollar_variables():
    url = "https://example.com/$VERSION/file.tar.gz"
    line = "VERSION=1.2.3"
    result = replace_dollar_variables(url, line)
    assert result == "https://example.com/1.2.3/file.tar.gz"

def test_github_to_cpe():
    urls = ["https://github.com/user/repo/releases/download/v1.2.3/file.tar.gz"]
    result = github_to_cpe(urls)
    expected = [(PackageInfo("repo", "v1.2.3", "user", PackageInfoType.GITHUB), urls[0])]
    assert result == expected

def test_selected_websites_to_cpe():
    urls = [
        "https://static.rust-lang.org/rustup/archive/1.2.3/",
        "https://services.gradle.org/distributions/gradle-7.0-bin.zip",
        "https://ftp.postgresql.org/pub/source/v12.0"
    ]
    result = selected_websites_to_cpe(urls)
    expected = [
        (PackageInfo("rust", "1.2.3", "rust", type=PackageInfoType.RUST), urls[0]),
        (PackageInfo("gradle", "7.0", "gradle", PackageInfoType.GRADLE), urls[1]),
        (PackageInfo("postgresql", "v12.0", "postgresql"), urls[2])
    ]
    assert result == expected
