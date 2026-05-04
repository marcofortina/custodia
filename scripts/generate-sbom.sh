#!/usr/bin/env bash
# Copyright (c) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of Custodia.
# Custodia is distributed under the GNU Affero General Public License v3.0.
# See the accompanying LICENSE file for details.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

: "${SBOM_DIR:=$root_dir/dist/sbom}"
: "${SBOM_FILE:=$SBOM_DIR/custodia-sbom.spdx.json}"
: "${VERSION:=0.0.0-dev}"
: "${COMMIT:=$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"
: "${DATE:=$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

mkdir -p "$SBOM_DIR"

python3 - "$SBOM_FILE" "$VERSION" "$COMMIT" "$DATE" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None

sbom_file, version, commit, date = sys.argv[1:]
root = Path.cwd()
packages = {}


def spdx_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", value)
    cleaned = cleaned.strip("-") or "package"
    return "SPDXRef-" + cleaned[:120]


def add_package(name, version_info="NOASSERTION", supplier="Organization: Custodia", originator="NOASSERTION", comment=""):
    key = (name, version_info)
    if key in packages:
        if comment and comment not in packages[key].get("comment", ""):
            packages[key]["comment"] = (packages[key].get("comment", "") + "; " + comment).strip("; ")
        return
    packages[key] = {
        "SPDXID": spdx_id(f"Package-{name}-{version_info}"),
        "name": name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "versionInfo": version_info,
        "supplier": supplier,
        "originator": originator,
    }
    if comment:
        packages[key]["comment"] = comment


def parse_go_mod(path: Path):
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    in_require = False
    for raw in lines:
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                add_package(f"go:{parts[1]}", parts[2], comment="go.mod direct requirement")
            continue
        if in_require:
            parts = line.split()
            if len(parts) >= 2:
                add_package(f"go:{parts[0]}", parts[1], comment="go.mod requirement")


def parse_package_json(path: Path):
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in data.get(section, {}).items():
            add_package(f"npm:{name}", str(spec), comment=f"package.json {section}")


def parse_pyproject(path: Path):
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    if tomllib is not None:
        data = tomllib.loads(text)
        for dep in data.get("project", {}).get("dependencies", []):
            add_package(f"pypi:{dep}", "NOASSERTION", comment="pyproject dependency")
        optional = data.get("project", {}).get("optional-dependencies", {})
        for group, deps in optional.items():
            for dep in deps:
                add_package(f"pypi:{dep}", "NOASSERTION", comment=f"pyproject optional dependency group {group}")
        return
    for match in re.finditer(r'"([A-Za-z0-9_.-]+[^"\n]*)"', text):
        value = match.group(1)
        if ">=" in value or "==" in value or "~=" in value:
            add_package(f"pypi:{value}", "NOASSERTION", comment="pyproject dependency")


def parse_cargo_toml(path: Path):
    if not path.exists() or tomllib is None:
        return
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                version_spec = spec
            elif isinstance(spec, dict):
                version_spec = spec.get("version", "NOASSERTION")
            else:
                version_spec = "NOASSERTION"
            add_package(f"cargo:{name}", str(version_spec), comment=f"Cargo.toml {section}")


def parse_cargo_lock(path: Path):
    if not path.exists():
        return
    name = None
    version_info = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line == "[[package]]":
            if name and version_info:
                add_package(f"cargo:{name}", version_info, comment="Cargo.lock locked package")
            name = None
            version_info = None
        elif line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = "):
            version_info = line.split("=", 1)[1].strip().strip('"')
    if name and version_info:
        add_package(f"cargo:{name}", version_info, comment="Cargo.lock locked package")


parse_go_mod(root / "go.mod")
parse_pyproject(root / "clients/python/pyproject.toml")
parse_package_json(root / "clients/node/package.json")
parse_cargo_toml(root / "clients/rust/Cargo.toml")
parse_cargo_lock(root / "clients/rust/Cargo.lock")

add_package("system:libcurl", "NOASSERTION", comment="C++ client transport link dependency")
add_package("system:openssl", "NOASSERTION", comment="C++ client crypto/TLS link dependency")
add_package("system:java.net.http", "NOASSERTION", comment="Java standard-library HTTP transport")

creation_info = {
    "created": date,
    "creators": ["Tool: scripts/generate-sbom.sh"],
    "licenseListVersion": "3.25",
}
spdx = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"custodia-{version}-sbom",
    "documentNamespace": f"https://github.com/marcofortina/custodia/sbom/{commit}/{version}",
    "creationInfo": creation_info,
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-custodia",
            "name": "custodia",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "AGPL-3.0-only",
            "licenseDeclared": "AGPL-3.0-only",
            "copyrightText": "NOASSERTION",
            "versionInfo": version,
            "supplier": "Organization: Custodia",
            "comment": f"Source commit {commit}",
        },
        *sorted(packages.values(), key=lambda item: (item["name"], item.get("versionInfo", ""))),
    ],
}
Path(sbom_file).write_text(json.dumps(spdx, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"generate-sbom: wrote {sbom_file}", file=sys.stderr)
PY
