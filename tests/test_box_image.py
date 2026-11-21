"""Tests of ``image`` and ``dockerfile`` under ``[run]`` and ``[metric]`` (SKY-887)."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from openascent.cli import main
from openascent.contract import (
    CONSTRAINTS_FILE,
    ConstraintsError,
    RoleEnvironment,
    effective_environment,
    parse_constraints,
    read_constraints,
)
from openascent.schema import contract_schema

_DIGEST = "a" * 64
_IMAGE = f"ghcr.io/acme/box@sha256:{_DIGEST}"
_BASE = b'version = 1\n[paths]\neditable = ["src"]\n[run]\nentry = "run.py:main"\n'


def _contract(run: str = "", metric: str = "", paths: str = 'editable = ["src"]') -> bytes:
    """Build a contract with extra lines under ``[run]`` and ``[metric]``.

    Args:
        run: Lines to add under ``[run]``.
        metric: Lines to add under ``[metric]``.
        paths: The lines of ``[paths]``.

    Returns:
        The bytes of the contract.
    """
    return (
        f'version = 1\n[paths]\n{paths}\n[run]\nentry = "run.py:main"\n{run}\n[metric]\n{metric}\n'
    ).encode()


def _errors(raw: bytes) -> list[tuple[str | None, str | None, str]]:
    """Parse ``raw``, which must fail, and return each error's place and message.

    Args:
        raw: The contract bytes.

    Returns:
        ``(section, key, message)`` for each error.
    """
    with pytest.raises(ConstraintsError) as caught:
        parse_constraints(raw)
    return [(d.section, d.key, d.message) for d in caught.value.errors]


def _archive(tmp_path: Path, files: dict[str, bytes], links: dict[str, str] | None = None) -> Path:
    """Pack files, and optional symbolic links, as a repository snapshot.

    Args:
        tmp_path: Scratch folder.
        files: Root-relative path to bytes.
        links: Root-relative link path to its target.

    Returns:
        The archive.
    """
    archive = tmp_path / "tree.tgz"
    with tarfile.open(archive, "w:gz") as packed:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            packed.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.SYMTYPE, target
            packed.addfile(info)
    return archive


@pytest.mark.parametrize(
    "image",
    [
        f"python@sha256:{_DIGEST}",
        f"library/python@sha256:{_DIGEST}",
        _IMAGE,
        f"registry.example.com:5000/team/my-box_v2@sha256:{_DIGEST}",
    ],
)
@pytest.mark.parametrize("section", ["run", "metric"])
def test_each_role_accepts_an_image_pinned_by_its_digest(section: str, image: str) -> None:
    """A digest reference, with or without a registry host and port, is kept as written."""
    line = f'image = "{image}"'
    constraints = parse_constraints(_contract(**{section: line}))

    role = constraints.run_role if section == "run" else constraints.metric_role
    assert role.image == image
    assert role.dockerfile is None


@pytest.mark.parametrize("section", ["run", "metric"])
def test_each_role_accepts_a_dockerfile_path(section: str) -> None:
    """A Dockerfile path is kept, and the image stays unset."""
    line = 'dockerfile = "docker/Dockerfile"'
    constraints = parse_constraints(_contract(**{section: line}))

    role = constraints.run_role if section == "run" else constraints.metric_role
    assert role.dockerfile == "docker/Dockerfile"
    assert role.image is None
    assert constraints.dockerfiles == {f"[{section}]": "docker/Dockerfile"}


def test_the_two_roles_can_use_different_forms() -> None:
    """The candidate box can build from a Dockerfile while the metric box uses an image."""
    constraints = parse_constraints(
        _contract(run='dockerfile = "box/Dockerfile"', metric=f'image = "{_IMAGE}"')
    )

    assert constraints.run_role.dockerfile == "box/Dockerfile"
    assert constraints.metric_role.image == _IMAGE


@pytest.mark.parametrize("section", ["run", "metric"])
def test_a_box_with_both_keys_fails_with_one_error(section: str) -> None:
    """image and dockerfile are two ways to name one image, so a box sets only one."""
    lines = f'image = "{_IMAGE}"\ndockerfile = "docker/Dockerfile"'

    errors = _errors(_contract(**{section: lines}))

    assert errors == [
        (
            section,
            "dockerfile",
            f"{CONSTRAINTS_FILE}: [{section}] sets both image and dockerfile. Set one: image for a"
            " pinned image, or dockerfile to build the image from the repository.",
        )
    ]


@pytest.mark.parametrize(
    "value",
    [
        '"python:3.12"',
        '"python"',
        '"ghcr.io/acme/box:latest"',
        f'"python:3.12@sha256:{_DIGEST}"',
        f'"python@sha256:{"A" * 64}"',
        f'"python@sha256:{"a" * 63}"',
        f'"python@sha512:{"a" * 128}"',
        f'"Python@sha256:{_DIGEST}"',
        f'" python@sha256:{_DIGEST}"',
        f'"python@sha256:{_DIGEST}\\n"',
        '""',
        "1",
        f'["python@sha256:{_DIGEST}"]',
    ],
)
@pytest.mark.parametrize("section", ["run", "metric"])
def test_an_image_that_is_not_pinned_by_its_digest_fails_with_one_error(
    section: str, value: str
) -> None:
    """A tag, a bad digest or any other form fails with the one valid form."""
    errors = _errors(_contract(**{section: f"image = {value}"}))

    assert len(errors) == 1
    place, key, message = errors[0]
    assert (place, key) == (section, "image")
    assert message.startswith(f"{CONSTRAINTS_FILE}: [{section}] image must be pinned by its digest")
    assert "'name@sha256:<64 lowercase hex characters>'" in message


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ('"../Dockerfile"', "must be relative and stay inside the repository"),
        ('"/Dockerfile"', "must be relative and stay inside the repository"),
        ('"."', "must name one file, not the whole repository"),
        ('".git/Dockerfile"', "cannot name the .git folder"),
        ('"docker/*"', "looks like a pattern"),
        ('"docker//Dockerfile"', "must be relative and stay inside the repository"),
        ('"docker\\\\Dockerfile"', "must be written 'docker/Dockerfile'"),
        ("1", "must be a text path"),
    ],
)
@pytest.mark.parametrize("section", ["run", "metric"])
def test_a_bad_dockerfile_path_fails_like_any_other_file_key(
    section: str, value: str, message: str
) -> None:
    """dockerfile passes the same path checks as the other keys that name one file."""
    errors = _errors(_contract(**{section: f"dockerfile = {value}"}))

    assert len(errors) == 1
    assert errors[0][:2] == (section, "dockerfile")
    assert message in errors[0][2]


def test_a_contract_with_no_image_key_parses_as_before() -> None:
    """A contract with neither key gets the same objects and the same hash as before."""
    constraints = parse_constraints(_BASE)

    assert constraints.run_role == RoleEnvironment()
    assert constraints.metric_role == RoleEnvironment()
    assert constraints.dockerfiles == {}
    assert constraints.sha256 == hashlib.sha256(_BASE).hexdigest()
    environment = effective_environment(constraints, approved_editable=["src"], approved_setup=None)
    assert environment.protected_paths == (CONSTRAINTS_FILE,)
    record = environment.record(
        repository="o/r", commit="c" * 40, readonly_paths=[], secret_names=[]
    )
    assert "image" not in str(record) and "dockerfile" not in str(record)


@pytest.mark.parametrize("section", ["run", "metric"])
def test_the_dockerfile_is_a_protected_path(section: str) -> None:
    """A version cannot edit the Dockerfile, so it cannot change the image it is scored in."""
    constraints = parse_constraints(
        _contract(**{section: 'dockerfile = "docker/Dockerfile"'}, paths="")
    )

    environment = effective_environment(constraints, approved_editable=["src"], approved_setup=None)

    assert environment.protected_paths == (CONSTRAINTS_FILE, "docker/Dockerfile")


@pytest.mark.parametrize(
    ("dockerfile", "editable"),
    [
        ("src/Dockerfile", "src"),
        ("src/docker/Dockerfile", "src"),
        ("docker/Dockerfile", "docker/app.py"),
        ("Dockerfile", "src"),
    ],
)
def test_a_build_context_that_holds_an_editable_path_fails_the_check(
    dockerfile: str, editable: str
) -> None:
    """The build context is the Dockerfile's folder, and no editable path may overlap it."""
    errors = _errors(
        _contract(run=f'dockerfile = "{dockerfile}"', paths=f'editable = ["{editable}"]')
    )

    context = dockerfile.rpartition("/")[0] or "."
    assert errors == [
        (
            "run",
            "dockerfile",
            f"{CONSTRAINTS_FILE}: [run] dockerfile names '{dockerfile}', so the build context is"
            f" the folder '{context}', and the editable path '{editable}' overlaps it. A version"
            " could change what the image builds from. Put the Dockerfile in a folder that holds"
            " no editable path, or protect that folder.",
        )
    ]


def test_the_approved_editable_paths_also_obey_the_build_context_rule() -> None:
    """A contract that sets no editable paths is checked with the approved ones."""
    constraints = parse_constraints(_contract(metric='dockerfile = "docker/Dockerfile"', paths=""))

    with pytest.raises(
        ConstraintsError, match="the build context is the folder 'docker'"
    ) as caught:
        effective_environment(constraints, approved_editable=["."], approved_setup=None)

    assert (caught.value.section, caught.value.key) == ("metric", "dockerfile")
    environment = effective_environment(constraints, approved_editable=["src"], approved_setup=None)
    assert "docker/Dockerfile" in environment.protected_paths


def test_a_protected_build_context_may_sit_inside_an_editable_path() -> None:
    """Protected paths win over editable ones, so a protected context holds nothing editable."""
    constraints = parse_constraints(
        _contract(
            run='dockerfile = "docker/Dockerfile"',
            paths='editable = ["."]\nprotected = ["docker"]',
        )
    )

    environment = effective_environment(constraints, approved_editable=["."], approved_setup=None)

    assert environment.protected_paths == (CONSTRAINTS_FILE, "docker/Dockerfile", "docker")


def test_read_constraints_checks_that_the_dockerfile_is_a_regular_file(tmp_path: Path) -> None:
    """read_constraints accepts a Dockerfile of the snapshot and refuses a missing or linked one."""
    raw = _contract(run='dockerfile = "docker/Dockerfile"', metric='dockerfile = "m/Dockerfile"')
    files = {CONSTRAINTS_FILE: raw, "docker/Dockerfile": b"FROM scratch\n"}

    with pytest.raises(ConstraintsError) as caught:
        read_constraints(_archive(tmp_path, files, links={"m/Dockerfile": "../docker/Dockerfile"}))
    assert [(d.section, d.key) for d in caught.value.errors] == [("metric", "dockerfile")]
    assert "must be a regular file, not a link or folder" in caught.value.errors[0].message

    with pytest.raises(ConstraintsError, match="but the repository has no such file"):
        read_constraints(_archive(tmp_path, files))

    files["m/Dockerfile"] = b"FROM scratch\n"
    constraints = read_constraints(_archive(tmp_path, files))
    assert constraints is not None
    assert constraints.dockerfiles == {"[run]": "docker/Dockerfile", "[metric]": "m/Dockerfile"}


def test_ascent_check_accepts_each_key_and_refuses_the_bad_forms(tmp_path: Path, capsys) -> None:
    """``ascent check`` gives the same verdict as the parser."""
    good = tmp_path / "good.toml"
    good.write_bytes(_contract(run=f'image = "{_IMAGE}"', metric='dockerfile = "m/Dockerfile"'))
    bad = tmp_path / "bad.toml"
    bad.write_bytes(_contract(run='image = "python:3.12"'))

    assert main(["check", str(good)]) == 0
    assert main(["check", str(bad)]) == 1
    assert "[run] image must be pinned by its digest" in capsys.readouterr().out


def test_the_schema_describes_both_keys_and_refuses_both_together() -> None:
    """The JSON Schema takes each key in each role, and refuses a box that sets both."""
    validator = Draft202012Validator(contract_schema())
    base = {"version": 1, "run": {"entry": "run.py:main"}}

    for section in ("run", "metric"):
        assert validator.is_valid({**base, section: {**base.get(section, {}), "image": _IMAGE}})
        assert validator.is_valid(
            {**base, section: {**base.get(section, {}), "dockerfile": "d/Dockerfile"}}
        )
        both = {"image": _IMAGE, "dockerfile": "d/Dockerfile"}
        assert not validator.is_valid({**base, section: {**base.get(section, {}), **both}})
    assert not validator.is_valid({**base, "run": {**base["run"], "image": "python:3.12"}})
