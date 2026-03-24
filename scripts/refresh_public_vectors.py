#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def pretty_json_text(value) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2) + "\n"


def fixture_names(root: Path, fixture: str) -> list[str]:
    if fixture != "all":
        return [fixture]
    examples_root = root / "fixtures" / "public"
    return sorted(
        path.name
        for path in examples_root.iterdir()
        if path.is_dir() and (path / "profile.json").exists()
    )


def build_expected_summary(proof_bundle: dict) -> dict:
    return {
        "bundleId": proof_bundle["bundleId"],
        "expectedCounts": proof_bundle["summary"],
    }


def build_expected_claim_results(proof_bundle: dict) -> dict:
    return {
        "bundleId": proof_bundle["bundleId"],
        "expectedClaimResults": {
            claim["claimId"]: claim["result"] for claim in proof_bundle["claims"]
        },
    }


def build_expected_witness(proof_bundle: dict, replay_bundle: dict, witness_receipt: dict) -> dict:
    return {
        "bundleId": proof_bundle["bundleId"],
        "requiredReplayResult": witness_receipt["replayResult"],
        "requiredArtifacts": replay_bundle["materialInputs"] + replay_bundle["expectedOutputs"],
    }


def refresh_fixture(root: Path, fixture: str) -> None:
    fixture_root = root / "fixtures" / "public" / fixture
    vector_root = root / "conformance" / "vectors" / fixture

    proof_bundle = load_json(fixture_root / "proof-bundle.json")
    replay_bundle = load_json(fixture_root / "replay-bundle.json")
    witness_receipt = load_json(fixture_root / "witness-receipt.json")

    (vector_root / "expected-summary.json").write_text(
        pretty_json_text(build_expected_summary(proof_bundle)),
        encoding="utf-8",
    )
    (vector_root / "expected-claim-results.json").write_text(
        pretty_json_text(build_expected_claim_results(proof_bundle)),
        encoding="utf-8",
    )
    (vector_root / "expected-witness.json").write_text(
        pretty_json_text(build_expected_witness(proof_bundle, replay_bundle, witness_receipt)),
        encoding="utf-8",
    )


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Refresh synthetic public conformance vectors from checked-in fixtures.")
    parser.add_argument("--fixture", choices=["all", "minimal", "failed", "medium", "stale", "issued"], default="all")
    args = parser.parse_args()

    for fixture in fixture_names(root, args.fixture):
        refresh_fixture(root, fixture)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
