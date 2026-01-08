from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from hermeto import APP_NAME
from hermeto.core.errors import BaseError, FetchError, PackageRejected
from hermeto.core.models.input import GenericPackageInput
from hermeto.core.models.sbom import Component
from hermeto.core.package_managers.generic.main import (
    DEFAULT_DEPS_DIR,
    DEFAULT_LOCKFILE_NAME,
    _load_lockfile,
    _resolve_generic_lockfile,
    _resolve_lockfile_path,
    fetch_generic_source,
    resolve_artifact_auth,
)
from hermeto.core.package_managers.generic.models import AuthHeader
from hermeto.core.rooted_path import PathOutsideRoot, RootedPath

LOCKFILE_WRONG_VERSION = """
metadata:
    version: '0.42'
artifacts:
    - download_url: https://example.com/artifact
      checksum: md5:3a18656e1cea70504b905836dee14db0
"""

LOCKFILE_CHECKSUM_MISSING = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://example.com/artifact
"""

LOCKFILE_WRONG_CHECKSUM_FORMAT = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://example.com/artifact
      filename: archive.zip
      checksum: 32112bed1914cfe3799600f962750b1d
"""

LOCKFILE_VALID = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://example.com/artifact
      filename: archive.zip
      checksum: md5:3a18656e1cea70504b905836dee14db0
    - download_url: https://example.com/more/complex/path/file.tar.gz?foo=bar#fragment
      checksum: md5:32112bed1914cfe3799600f962750b1d
"""

LOCKFILE_VALID_MAVEN = """
metadata:
    version: '1.0'
artifacts:
    - type: "maven"
      attributes:
        repository_url: "https://repo.spring.io/release"
        group_id: "org.springframework.boot"
        artifact_id: "spring-boot-starter"
        version: "3.1.5"
        type: "jar"
        classifier: ""
      checksum: "sha256:c3c5e397008ba2d3d0d6e10f7f343b68d2e16c5a3fbe6a6daa7dd4d6a30197a5"
    - type: "maven"
      attributes:
        repository_url: "https://repo1.maven.org/maven2"
        group_id: "io.netty"
        artifact_id: "netty-transport-native-epoll"
        version: "4.1.100.Final"
        type: "jar"
        classifier: "sources"
      checksum: "sha256:c3c5e397008ba2d3d0d6e10f7f343b68d2e16c5a3fbe6a6daa7dd4d6a30197a5"
"""

LOCKFILE_INVALID_FILENAME = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://example.com/artifact
      filename: ./../../../archive.zip
      checksum: md5:3a18656e1cea70504b905836dee14db0
"""

LOCKFILE_FILENAME_OVERLAP = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://example.com/artifact
      filename: archive.zip
      checksum: md5:3a18656e1cea70504b905836dee14db0
    - download_url: https://example.com/artifact2
      filename: archive.zip
      checksum: md5:3a18656e1cea70504b905836dee14db0
"""

LOCKFILE_URL_OVERLAP = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://example.com/artifact
      checksum: md5:3a18656e1cea70504b905836dee14db0
    - download_url: https://example.com/artifact
      filename: archive.zip
      checksum: md5:3a18656e1cea70504b905836dee14db0
"""

LOCKFILE_WRONG_CHECKSUM = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://example.com/artifact
      filename: archive.zip
      checksum: md5:32112bed1914cfe3799600f962750b1d
"""

LOCKFILE_VALID_WITH_AUTH = """
metadata:
    version: '1.0'
artifacts:
    - download_url: https://gitlab.example.com/api/v4/projects/123/repository/archive.tar.gz
      filename: project.tar.gz
      checksum: sha256:c3c5e397008ba2d3d0d6e10f7f343b68d2e16c5a3fbe6a6daa7dd4d6a30197a5
      auth:
        type: header
        header_name: PRIVATE-TOKEN
        value: "$GITLAB_TOKEN"
    - download_url: https://example.com/public-artifact.tar.gz
      checksum: md5:3a18656e1cea70504b905836dee14db0
"""


class TestResolveArtifactAuth:
    """Tests for resolve_artifact_auth function."""

    def test_none_auth_returns_none(self) -> None:
        """When auth is None, return None."""
        assert resolve_artifact_auth(None) is None

    def test_header_auth_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Header auth resolves correctly when env var is set."""
        monkeypatch.setenv("MY_TOKEN", "secret-token-value")

        auth = AuthHeader(
            header_name="PRIVATE-TOKEN",
            value="$MY_TOKEN",
        )
        result = resolve_artifact_auth(auth)

        assert result == {"PRIVATE-TOKEN": "secret-token-value"}

    def test_header_auth_with_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Header auth includes prefix when specified."""
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_xxxxxxxxxxxx")

        auth = AuthHeader(
            header_name="Authorization",
            value="Bearer $GITHUB_TOKEN",
        )
        result = resolve_artifact_auth(auth)

        assert result == {"Authorization": "Bearer ghp_xxxxxxxxxxxx"}

    def test_header_auth_missing_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Raise FetchError when required env var is not set."""
        monkeypatch.delenv("MISSING_TOKEN", raising=False)

        auth = AuthHeader(
            header_name="PRIVATE-TOKEN",
            value="$MISSING_TOKEN",
        )

        with pytest.raises(FetchError) as exc_info:
            resolve_artifact_auth(auth)

        assert "MISSING_TOKEN" in str(exc_info.value)
        assert "not set" in str(exc_info.value)


@pytest.mark.parametrize(
    ["model_input", "components"],
    [
        pytest.param(GenericPackageInput.model_construct(type="generic"), [], id="single_input"),
    ],
)
@mock.patch("hermeto.core.package_managers.generic.main.RequestOutput.from_obj_list")
@mock.patch("hermeto.core.package_managers.generic.main._resolve_generic_lockfile")
def test_fetch_generic_source(
    mock_resolve_generic_lockfile: mock.Mock,
    mock_from_obj_list: mock.Mock,
    model_input: GenericPackageInput,
    components: list[Component],
) -> None:
    mock_resolve_generic_lockfile.return_value = components

    mock_request = mock.Mock()
    mock_request.generic_packages = [model_input]

    fetch_generic_source(mock_request)

    mock_resolve_generic_lockfile.assert_called()


@pytest.mark.parametrize(
    ("pkg_path", "lockfile_value", "expected_result"),
    [
        pytest.param(Path("."), None, "artifacts.lock.yaml", id="default-lockfile"),
        pytest.param(
            Path("pkg"), Path("relative.yaml"), "pkg/relative.yaml", id="relative-lockfile"
        ),
        pytest.param(
            Path("pkg"),
            Path("/absolute/path/to/lockfile.yaml"),
            "/absolute/path/to/lockfile.yaml",
            id="absolute-lockfile",
        ),
    ],
)
def test_resolve_lockfile_path(
    rooted_tmp_path: RootedPath,
    pkg_path: Path,
    lockfile_value: Path | None,
    expected_result: str,
) -> None:
    if Path(expected_result).is_absolute():
        expected_path = Path(expected_result)
    else:
        expected_path = rooted_tmp_path.join_within_root(expected_result).path

    resolved = _resolve_lockfile_path(rooted_tmp_path, pkg_path, lockfile_value)
    assert resolved == Path(expected_path)


def test_resolve_lockfile_path_fail(rooted_tmp_path: RootedPath) -> None:
    with pytest.raises(PackageRejected) as exc_info:
        _resolve_lockfile_path(rooted_tmp_path, Path("pkg"), Path("../outside.yaml"))

    assert "must be inside the package path" in str(exc_info.value)


@mock.patch("hermeto.core.package_managers.generic.main._load_lockfile")
def test_resolve_generic_no_lockfile(mock_load: mock.Mock, rooted_tmp_path: RootedPath) -> None:
    lockfile_path = rooted_tmp_path.join_within_root(DEFAULT_LOCKFILE_NAME)
    with pytest.raises(PackageRejected) as exc_info:
        _resolve_generic_lockfile(lockfile_path.path, rooted_tmp_path)
    assert (
        f"{APP_NAME} generic lockfile '{lockfile_path}' does not exist, refusing to continue."
        in str(exc_info.value)
    )
    mock_load.assert_not_called()


@pytest.mark.parametrize(
    ["lockfile", "expected_exception", "expected_err"],
    [
        pytest.param("{", PackageRejected, "yaml format is not correct", id="invalid_yaml"),
        pytest.param(
            LOCKFILE_WRONG_VERSION, PackageRejected, "Input should be '1.0'", id="wrong_version"
        ),
        pytest.param(
            LOCKFILE_CHECKSUM_MISSING, PackageRejected, "Field required", id="checksum_missing"
        ),
        pytest.param(
            LOCKFILE_INVALID_FILENAME,
            PathOutsideRoot,
            "",
            id="invalid_filename",
        ),
        pytest.param(
            LOCKFILE_FILENAME_OVERLAP,
            PackageRejected,
            "Duplicate filenames",
            id="conflicting_filenames",
        ),
        pytest.param(
            LOCKFILE_URL_OVERLAP,
            PackageRejected,
            "Duplicate download_urls",
            id="conflicting_urls",
        ),
        pytest.param(
            LOCKFILE_WRONG_CHECKSUM,
            PackageRejected,
            "Failed to verify archive.zip against any of the provided checksums.",
            id="wrong_checksum",
        ),
        pytest.param(
            LOCKFILE_WRONG_CHECKSUM_FORMAT,
            PackageRejected,
            "Checksum must be in the format 'algorithm:hash'",
            id="wrong_checksum",
        ),
    ],
)
@mock.patch("hermeto.core.package_managers.generic.main.asyncio.run")
@mock.patch("hermeto.core.package_managers.generic.main.async_download_files")
def test_resolve_generic_lockfile_invalid(
    mock_download: mock.Mock,
    mock_asyncio_run: mock.Mock,
    lockfile: str,
    expected_exception: type[BaseError],
    expected_err: str,
    rooted_tmp_path: RootedPath,
) -> None:
    # setup lockfile
    lockfile_path = rooted_tmp_path.join_within_root(DEFAULT_LOCKFILE_NAME)
    with open(lockfile_path, "w") as f:
        f.write(lockfile)

    # setup testing downloaded dependency
    deps_path = rooted_tmp_path.join_within_root(DEFAULT_DEPS_DIR)
    Path.mkdir(deps_path.path, parents=True, exist_ok=True)
    with open(deps_path.join_within_root("archive.zip"), "w") as f:
        f.write("Testfile")

    with pytest.raises(expected_exception) as exc_info:
        _resolve_generic_lockfile(lockfile_path.path, rooted_tmp_path)

    assert expected_err in str(exc_info.value)


@pytest.mark.parametrize(
    ["lockfile_content", "expected_components"],
    [
        pytest.param(
            LOCKFILE_VALID,
            [
                {
                    "externalReferences": [
                        {"type": "distribution", "url": "https://example.com/artifact"}
                    ],
                    "name": "archive.zip",
                    "properties": [{"name": f"{APP_NAME}:found_by", "value": f"{APP_NAME}"}],
                    "purl": "pkg:generic/archive.zip?checksum=md5:3a18656e1cea70504b905836dee14db0&download_url=https://example.com/artifact",
                    "type": "file",
                },
                {
                    "externalReferences": [
                        {
                            "type": "distribution",
                            "url": "https://example.com/more/complex/path/file.tar.gz?foo=bar#fragment",
                        }
                    ],
                    "name": "file.tar.gz",
                    "properties": [{"name": f"{APP_NAME}:found_by", "value": f"{APP_NAME}"}],
                    "purl": "pkg:generic/file.tar.gz?checksum=md5:32112bed1914cfe3799600f962750b1d&download_url=https://example.com/more/complex/path/file.tar.gz%3Ffoo%3Dbar%23fragment",
                    "type": "file",
                },
            ],
            id="valid_lockfile",
        ),
        pytest.param(
            LOCKFILE_VALID_MAVEN,
            [
                {
                    "externalReferences": [
                        {
                            "type": "distribution",
                            "url": "https://repo.spring.io/release/org/springframework/boot/spring-boot-starter/3.1.5/spring-boot-starter-3.1.5.jar",
                        }
                    ],
                    "name": "spring-boot-starter",
                    "properties": [{"name": f"{APP_NAME}:found_by", "value": f"{APP_NAME}"}],
                    "purl": "pkg:maven/org.springframework.boot/spring-boot-starter@3.1.5?checksum=sha256:c3c5e397008ba2d3d0d6e10f7f343b68d2e16c5a3fbe6a6daa7dd4d6a30197a5&repository_url=https://repo.spring.io/release&type=jar",
                    "type": "library",
                    "version": "3.1.5",
                },
                {
                    "externalReferences": [
                        {
                            "type": "distribution",
                            "url": "https://repo1.maven.org/maven2/io/netty/netty-transport-native-epoll/4.1.100.Final/netty-transport-native-epoll-4.1.100.Final-sources.jar",
                        }
                    ],
                    "name": "netty-transport-native-epoll",
                    "properties": [{"name": f"{APP_NAME}:found_by", "value": f"{APP_NAME}"}],
                    "purl": "pkg:maven/io.netty/netty-transport-native-epoll@4.1.100.Final?checksum=sha256:c3c5e397008ba2d3d0d6e10f7f343b68d2e16c5a3fbe6a6daa7dd4d6a30197a5&classifier=sources&repository_url=https://repo1.maven.org/maven2&type=jar",
                    "type": "library",
                    "version": "4.1.100.Final",
                },
            ],
            id="valid_lockfile_maven",
        ),
    ],
)
@mock.patch("hermeto.core.package_managers.generic.main.asyncio.run")
@mock.patch("hermeto.core.package_managers.generic.main.async_download_files")
@mock.patch("hermeto.core.package_managers.generic.main.must_match_any_checksum")
def test_resolve_generic_lockfile_valid(
    mock_checksums: mock.Mock,
    mock_download: mock.Mock,
    mock_asyncio_run: mock.Mock,
    lockfile_content: str,
    expected_components: list[dict[str, Any]],
    rooted_tmp_path: RootedPath,
) -> None:
    # setup lockfile
    lockfile_path = rooted_tmp_path.join_within_root(DEFAULT_LOCKFILE_NAME)
    with open(lockfile_path, "w") as f:
        f.write(lockfile_content)

    assert [
        c.model_dump(by_alias=True, exclude_none=True)
        for c in _resolve_generic_lockfile(lockfile_path.path, rooted_tmp_path)
    ] == expected_components
    mock_checksums.assert_called()


def test_load_generic_lockfile_valid(rooted_tmp_path: RootedPath) -> None:
    expected_lockfile = {
        "metadata": {"version": "1.0"},
        "artifacts": [
            {
                "download_url": "https://example.com/artifact",
                "filename": str(rooted_tmp_path.join_within_root("archive.zip")),
                "checksum": "md5:3a18656e1cea70504b905836dee14db0",
            },
            {
                "checksum": "md5:32112bed1914cfe3799600f962750b1d",
                "download_url": "https://example.com/more/complex/path/file.tar.gz?foo=bar#fragment",
                "filename": str(rooted_tmp_path.join_within_root("file.tar.gz")),
            },
        ],
    }

    # setup lockfile
    lockfile_path = rooted_tmp_path.join_within_root(DEFAULT_LOCKFILE_NAME)
    with open(lockfile_path, "w") as f:
        f.write(LOCKFILE_VALID)

    assert _load_lockfile(lockfile_path.path, rooted_tmp_path).model_dump() == expected_lockfile


def test_load_generic_lockfile_with_auth(rooted_tmp_path: RootedPath) -> None:
    """Test loading a lockfile with auth configuration."""
    expected_lockfile = {
        "metadata": {"version": "1.0"},
        "artifacts": [
            {
                "download_url": "https://gitlab.example.com/api/v4/projects/123/repository/archive.tar.gz",
                "filename": str(rooted_tmp_path.join_within_root("project.tar.gz")),
                "checksum": "sha256:c3c5e397008ba2d3d0d6e10f7f343b68d2e16c5a3fbe6a6daa7dd4d6a30197a5",
                "auth": {
                    "type": "header",
                    "header_name": "PRIVATE-TOKEN",
                    "value": "$GITLAB_TOKEN",
                },
            },
            {
                "download_url": "https://example.com/public-artifact.tar.gz",
                "filename": str(rooted_tmp_path.join_within_root("public-artifact.tar.gz")),
                "checksum": "md5:3a18656e1cea70504b905836dee14db0",
                "auth": None,
            },
        ],
    }

    # setup lockfile
    lockfile_path = rooted_tmp_path.join_within_root(DEFAULT_LOCKFILE_NAME)
    with open(lockfile_path, "w") as f:
        f.write(LOCKFILE_VALID_WITH_AUTH)

    assert _load_lockfile(lockfile_path.path, rooted_tmp_path).model_dump() == expected_lockfile


@mock.patch("hermeto.core.package_managers.generic.main.asyncio.run")
@mock.patch("hermeto.core.package_managers.generic.main.async_download_files")
@mock.patch("hermeto.core.package_managers.generic.main.must_match_any_checksum")
def test_resolve_generic_lockfile_with_auth(
    mock_checksums: mock.Mock,
    mock_download: mock.Mock,
    mock_asyncio_run: mock.Mock,
    rooted_tmp_path: RootedPath,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test that auth headers are passed to async_download_files."""
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test-token")

    # setup lockfile
    lockfile_path = rooted_tmp_path.join_within_root(DEFAULT_LOCKFILE_NAME)
    with open(lockfile_path, "w") as f:
        f.write(LOCKFILE_VALID_WITH_AUTH)

    _resolve_generic_lockfile(lockfile_path.path, rooted_tmp_path)

    # Verify async_download_files was called with headers_by_url
    mock_asyncio_run.assert_called_once()
    call_args = mock_asyncio_run.call_args
    # The coroutine is passed as the first argument
    # We need to check that the download was set up correctly
    mock_checksums.assert_called()
