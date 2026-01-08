import asyncio
import logging
import os
import re
from pathlib import Path

import yaml
from pydantic import ValidationError

from hermeto import APP_NAME
from hermeto.core.checksum import must_match_any_checksum
from hermeto.core.config import get_config
from hermeto.core.errors import FetchError, PackageRejected
from hermeto.core.models.input import Request
from hermeto.core.models.output import RequestOutput
from hermeto.core.models.sbom import Component
from hermeto.core.package_managers.general import async_download_files
from hermeto.core.package_managers.generic.models import ArtifactAuth, GenericLockfileV1
from hermeto.core.rooted_path import RootedPath

log = logging.getLogger(__name__)
DEFAULT_LOCKFILE_NAME = "artifacts.lock.yaml"
DEFAULT_DEPS_DIR = "deps/generic"


def _resolve_env_vars(template: str) -> str:
    """
    Resolve environment variable placeholders in a template string.

    :param template: String with $VAR placeholders (e.g., "Bearer $GITHUB_TOKEN").
    :return: String with placeholders replaced by environment variable values.
    :raises FetchError: If any referenced environment variable is not set.
    """
    pattern = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
    missing_vars = []

    def replace_var(match: re.Match[str]) -> str:
        var_name = match.group(1)
        value = os.environ.get(var_name)
        if value is None:
            missing_vars.append(var_name)
            return match.group(0)  # Keep original for error message
        return value

    result = pattern.sub(replace_var, template)

    if missing_vars:
        raise FetchError(
            f"Environment variable(s) required for authentication not set: "
            f"{', '.join(missing_vars)}"
        )

    return result


def resolve_artifact_auth(auth_config: ArtifactAuth | None) -> dict[str, str] | None:
    """
    Resolve authentication configuration to HTTP headers.

    :param auth_config: Authentication configuration from the lockfile artifact.
    :return: Dictionary of HTTP headers, or None if no auth configured.
    :raises FetchError: If required environment variable is not set.
    """
    if auth_config is None:
        return None

    if auth_config.type == "header":
        header_value = _resolve_env_vars(auth_config.value)
        return {auth_config.header_name: header_value}

    # Future auth types can be added here
    return None


def fetch_generic_source(request: Request) -> RequestOutput:
    """
    Resolve and fetch generic dependencies for a given request.

    :param request: the request to process
    """
    components = []
    for package in request.generic_packages:
        lockfile_path = _resolve_lockfile_path(
            request.source_dir,
            package.path,
            package.lockfile,
        )
        components.extend(_resolve_generic_lockfile(lockfile_path, request.output_dir))
    return RequestOutput.from_obj_list(components=components)


def _resolve_lockfile_path(
    source_dir: RootedPath,
    package_path: Path,
    lockfile_path: Path | None,
) -> Path:
    """
    Return the lockfile path for a package.
    """
    if lockfile_path and lockfile_path.is_absolute():
        return lockfile_path

    path = source_dir.join_within_root(package_path)
    lockfile_name = lockfile_path or DEFAULT_LOCKFILE_NAME
    lockfile = path.join_within_root(lockfile_name).path

    if not lockfile.is_relative_to(path.path):
        raise PackageRejected(
            f"Supplied generic lockfile path '{lockfile_name}' must be inside the package "
            f"path '{package_path}'.",
            solution="Use a lockfile path located within the package path.",
        )

    return lockfile


def _resolve_generic_lockfile(lockfile_path: Path, output_dir: RootedPath) -> list[Component]:
    """
    Resolve the generic lockfile and pre-fetch the dependencies.

    :param lockfile_path: absolute path to the lockfile
    :param output_dir: the output directory to store the dependencies
    """
    if not lockfile_path.exists():
        raise PackageRejected(
            f"{APP_NAME} generic lockfile '{lockfile_path}' does not exist, refusing to continue.",
            solution=(
                f"Make sure your repository has {APP_NAME} generic lockfile '{DEFAULT_LOCKFILE_NAME}' "
                f"checked in to the repository, or the supplied lockfile path is correct."
            ),
        )

    # output_dir is now the root and cannot be escaped
    output_dir = output_dir.re_root(DEFAULT_DEPS_DIR)

    log.info(f"Reading generic lockfile: {lockfile_path}")
    lockfile = _load_lockfile(lockfile_path, output_dir)
    to_download: dict[str, str | os.PathLike[str]] = {}
    headers_by_url: dict[str, dict[str, str]] = {}

    for artifact in lockfile.artifacts:
        # create the parent directory for the artifact
        Path.mkdir(Path(artifact.filename).parent, parents=True, exist_ok=True)
        url = str(artifact.download_url)
        to_download[url] = artifact.filename

        # resolve auth headers if configured (only LockfileArtifactUrl has auth)
        auth_config = getattr(artifact, "auth", None)
        headers = resolve_artifact_auth(auth_config)
        if headers:
            headers_by_url[url] = headers

    asyncio.run(
        async_download_files(
            to_download, get_config().runtime.concurrency_limit, headers_by_url=headers_by_url
        )
    )

    # verify checksums
    for artifact in lockfile.artifacts:
        must_match_any_checksum(artifact.filename, [artifact.formatted_checksum])
    return [artifact.get_sbom_component() for artifact in lockfile.artifacts]


def _load_lockfile(lockfile_path: Path, output_dir: RootedPath) -> GenericLockfileV1:
    """
    Load the generic lockfile from the given path.

    :param lockfile_path: the path to the lockfile
    :param output_dir: path to output directory
    """
    with open(lockfile_path) as f:
        try:
            lockfile_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise PackageRejected(
                f"{APP_NAME} lockfile '{lockfile_path}' yaml format is not correct: {e}",
                solution="Check correct 'yaml' syntax in the lockfile.",
            )

        try:
            lockfile = GenericLockfileV1.model_validate(
                lockfile_data, context={"output_dir": output_dir}
            )
        except ValidationError as e:
            loc = e.errors()[0]["loc"]
            msg = e.errors()[0]["msg"]
            raise PackageRejected(
                f"{APP_NAME} lockfile '{lockfile_path}' format is not valid: '{loc}: {msg}'",
                solution=(
                    "Check the correct format and whether any keys are missing in the lockfile."
                ),
            )
    return lockfile
