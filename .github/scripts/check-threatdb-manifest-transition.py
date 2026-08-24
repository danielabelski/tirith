#!/usr/bin/env python3

"""Validate the public legacy ThreatDB manifest and reject rollbacks."""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Any


EXPECTED_KEYS = {"version", "sha256", "size", "url", "signature"}
ASSET_URL = re.compile(
    r"https://github\.com/sheeki03/tirith/releases/download/"
    r"threatdb-latest/tirith-threatdb-[1-9][0-9]*-[1-9][0-9]*\.dat\Z"
)
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_SAFE_SEQUENCE = 9_007_199_254_740_990


class ManifestError(ValueError):
    """Raised when a ThreatDB manifest violates the publication contract."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ManifestError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ManifestError) as error:
        raise ManifestError(f"{path}: unreadable manifest: {error}") from error

    if not isinstance(document, dict):
        raise ManifestError(f"{path}: manifest must be a JSON object")
    if set(document) != EXPECTED_KEYS:
        raise ManifestError(
            f"{path}: keys must be exactly {sorted(EXPECTED_KEYS)}"
        )

    version = document["version"]
    if type(version) is not int or not 0 <= version <= MAX_SAFE_SEQUENCE:
        raise ManifestError(f"{path}: version must be a safe non-negative integer")

    size = document["size"]
    if type(size) is not int or size <= 0:
        raise ManifestError(f"{path}: size must be a positive integer")

    sha256 = document["sha256"]
    if not isinstance(sha256, str) or LOWER_SHA256.fullmatch(sha256) is None:
        raise ManifestError(f"{path}: sha256 must be 64 lowercase hex characters")

    url = document["url"]
    if not isinstance(url, str) or ASSET_URL.fullmatch(url) is None:
        raise ManifestError(f"{path}: URL is outside the rolling ThreatDB release")

    signature = document["signature"]
    if not isinstance(signature, str):
        raise ManifestError(f"{path}: signature must be base64 text")
    try:
        decoded_signature = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ManifestError(f"{path}: signature is not valid base64") from error
    if len(decoded_signature) != 64:
        raise ManifestError(f"{path}: signature must encode 64 bytes")

    return document


def validate_transition(base_path: Path, candidate_path: Path) -> None:
    base = load_manifest(base_path)
    candidate = load_manifest(candidate_path)
    if candidate["version"] < base["version"]:
        raise ManifestError(
            "ThreatDB manifest version regressed "
            f"from {base['version']} to {candidate['version']}"
        )
    if candidate["version"] == base["version"] and candidate != base:
        raise ManifestError(
            f"ThreatDB manifest equivocates at version {candidate['version']}"
        )


def main(arguments: list[str]) -> int:
    try:
        if len(arguments) == 1:
            manifest = load_manifest(Path(arguments[0]))
            print(f"ThreatDB manifest v{manifest['version']} has a valid shape")
        elif len(arguments) == 2:
            validate_transition(Path(arguments[0]), Path(arguments[1]))
            print("ThreatDB manifest transition is monotonic")
        else:
            print(
                f"usage: {Path(sys.argv[0]).name} [base-manifest] candidate-manifest",
                file=sys.stderr,
            )
            return 64
    except ManifestError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
