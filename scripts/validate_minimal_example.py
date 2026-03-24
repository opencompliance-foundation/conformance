#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_paths(script_path: Path, examples_override: str | None, schema_override: str | None) -> tuple[Path, Path, Path]:
    conformance_root = script_path.parents[1]

    if examples_override:
        examples_root = Path(examples_override).resolve()
    else:
        private_candidate = script_path.parents[2] / "fixtures" / "public" / "minimal"
        public_candidate = conformance_root.parent / "examples" / "minimal"
        if private_candidate.exists():
            examples_root = private_candidate
        elif public_candidate.exists():
            examples_root = public_candidate
        else:
            raise FileNotFoundError(
                "Could not locate the minimal example bundle. Pass --examples-root."
            )

    if schema_override:
        schema_root = Path(schema_override).resolve()
    else:
        private_candidate = script_path.parents[2] / "evidence-schema"
        public_candidate = conformance_root.parent / "evidence-schema"
        if private_candidate.exists():
            schema_root = private_candidate
        elif public_candidate.exists():
            schema_root = public_candidate
        else:
            raise FileNotFoundError(
                "Could not locate the evidence-schema repo. Pass --schema-root."
            )

    return conformance_root, examples_root, schema_root


def add_error(errors: list[str], message: str) -> None:
    errors.append(message)


def control_ids_from_selection(selection: dict) -> set[str]:
    ids: set[str] = set()
    for group in selection.get("control-selections", []):
        for include in group.get("include-controls", []):
            control_id = include.get("control-id")
            if control_id:
                ids.add(control_id)
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the ExampleCo minimal native and OSCAL projection remain consistent."
    )
    parser.add_argument("--examples-root", help="Path to the examples/minimal root.")
    parser.add_argument("--schema-root", help="Path to the evidence-schema repo root.")
    args = parser.parse_args()

    script_path = Path(__file__).resolve()
    conformance_root, examples_root, schema_root = detect_paths(
        script_path, args.examples_root, args.schema_root
    )

    vector_root = conformance_root / "vectors" / "minimal"
    oscal_root = examples_root / "oscal"

    proof_bundle = load_json(examples_root / "proof-bundle.json")
    evidence_claims = load_json(examples_root / "evidence-claims.json")
    witness_receipt = load_json(examples_root / "witness-receipt.json")
    expected_summary = load_json(vector_root / "expected-summary.json")
    expected_claim_results = load_json(vector_root / "expected-claim-results.json")
    expected_witness = load_json(vector_root / "expected-witness.json")
    schema_example = load_json(schema_root / "examples" / "evidence-claim.example.json")

    catalog = load_json(oscal_root / "opencompliance-minimal-catalog.json")
    profile = load_json(oscal_root / "exampleco-minimal-profile.json")
    ssp = load_json(oscal_root / "exampleco-minimal-ssp.json")
    assessment_plan = load_json(oscal_root / "exampleco-minimal-assessment-plan.json")
    assessment_results = load_json(oscal_root / "exampleco-minimal-assessment-results.json")
    proxy_targets = load_json(oscal_root / "family-proxy-targets.json")
    mapping_collection = load_json(oscal_root / "iso27001-soc2-family-overlap-mapping.json")

    errors: list[str] = []

    bundle_id = proof_bundle["bundleId"]
    if expected_summary["bundleId"] != bundle_id:
        add_error(errors, "expected-summary bundleId does not match proof bundle")
    if expected_claim_results["bundleId"] != bundle_id:
        add_error(errors, "expected-claim-results bundleId does not match proof bundle")
    if expected_witness["bundleId"] != bundle_id:
        add_error(errors, "expected-witness bundleId does not match proof bundle")
    if witness_receipt["bundleId"] != bundle_id:
        add_error(errors, "witness-receipt bundleId does not match proof bundle")

    actual_claim_results = {
        claim["claimId"]: claim["result"] for claim in proof_bundle["claims"]
    }
    if actual_claim_results != expected_claim_results["expectedClaimResults"]:
        add_error(errors, "claim-result mapping does not match expected vector")

    result_key_map = {
        "proved": "proved",
        "attested": "attested",
        "judgment_required": "judgmentRequired",
        "evidence_missing": "evidenceMissing",
    }
    actual_counts = {value: 0 for value in result_key_map.values()}
    for result in actual_claim_results.values():
        actual_counts[result_key_map[result]] += 1
    if actual_counts != expected_summary["expectedCounts"]:
        add_error(errors, "summary counts do not match expected vector")
    if actual_counts != proof_bundle["summary"]:
        add_error(errors, "proof bundle summary is inconsistent with claim results")

    witness_required = {
        item["path"]: item["sha256"] for item in expected_witness["requiredArtifacts"]
    }
    witness_checked = {
        item["path"]: item["sha256"] for item in witness_receipt["checkedArtifacts"]
    }
    if witness_receipt["replayResult"] != expected_witness["requiredReplayResult"]:
        add_error(errors, "witness replay result does not match expected vector")
    if witness_checked != witness_required:
        add_error(errors, "witness receipt artifacts do not match expected witness vector")

    for rel_path, expected_digest in witness_required.items():
        digest = sha256_file(examples_root / rel_path)
        if digest != expected_digest:
            add_error(errors, f"sha256 mismatch for {rel_path}")

    if schema_example["controlMappings"][0]["controlId"] != "soc2.family.access_control":
        add_error(errors, "schema example was not updated to use proxy controlId values")

    evidence_by_id = {claim["claimId"]: claim for claim in evidence_claims}
    proxy_target_ids = {target["id"] for target in proxy_targets["targets"]}
    evidence_control_ids = set()
    for claim in evidence_claims:
        for mapping in claim["controlMappings"]:
            control_id = mapping.get("controlId")
            if not control_id:
                add_error(errors, f"missing controlId on evidence claim {claim['claimId']}")
                continue
            evidence_control_ids.add(control_id)
            if control_id not in proxy_target_ids:
                add_error(errors, f"unknown proxy target id {control_id} in {claim['claimId']}")

    for claim in proof_bundle["claims"]:
        evidence_refs = claim.get("evidenceRefs", [])
        if not evidence_refs:
            continue
        expected_families = {
            mapping["family"]
            for evidence_ref in evidence_refs
            for mapping in evidence_by_id[evidence_ref]["controlMappings"]
        }
        if set(claim["frameworkFamilies"]) != expected_families:
            add_error(
                errors,
                f"{claim['claimId']} frameworkFamilies do not match referenced evidence controlMappings",
            )

    catalog_controls: set[str] = set()
    for group in catalog["catalog"]["groups"]:
        for control in group.get("controls", []):
            catalog_controls.add(control["id"])

    profile_controls = set(
        profile["profile"]["imports"][0]["include-controls"][0]["with-ids"]
    )
    if profile_controls != catalog_controls:
        add_error(errors, "profile control set does not match catalog control set")

    ssp_controls = {
        requirement["control-id"]
        for requirement in ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
    }
    if ssp_controls != catalog_controls:
        add_error(errors, "SSP implemented requirements do not match catalog control set")

    assessment_plan_controls = control_ids_from_selection(
        assessment_plan["assessment-plan"]["reviewed-controls"]
    )
    if assessment_plan_controls != catalog_controls:
        add_error(errors, "assessment plan reviewed controls do not match catalog control set")

    result_controls = control_ids_from_selection(
        assessment_results["assessment-results"]["results"][0]["reviewed-controls"]
    )
    if result_controls != catalog_controls:
        add_error(errors, "assessment results reviewed controls do not match catalog control set")

    mapping_root = mapping_collection["mapping-collection"]["mappings"][0]
    if mapping_root["source-resource"]["href"] != "./opencompliance-minimal-catalog.json":
        add_error(errors, "mapping source-resource href is unexpected")
    if mapping_root["target-resource"]["href"] != "./family-proxy-targets.json":
        add_error(errors, "mapping target-resource href is unexpected")

    mapped_source_ids = set()
    mapped_target_ids = set()
    for mapping in mapping_root["maps"]:
        if mapping["relationship"] != "subset-of":
            add_error(errors, "mapping relationship must stay subset-of in the seed example")
        for source in mapping["sources"]:
            mapped_source_ids.add(source["id-ref"])
            if source["id-ref"] not in catalog_controls:
                add_error(errors, f"mapping source id {source['id-ref']} is not in the catalog")
        for target in mapping["targets"]:
            mapped_target_ids.add(target["id-ref"])
            if target["id-ref"] not in proxy_target_ids:
                add_error(errors, f"mapping target id {target['id-ref']} is not in family-proxy-targets")

    if mapped_source_ids != catalog_controls:
        add_error(errors, "mapping source coverage does not match catalog control set")
    if not evidence_control_ids.issubset(proxy_target_ids):
        add_error(errors, "evidence controlIds are not fully covered by family proxy targets")

    expected_observation_claims = {
        claim_id
        for claim_id, result in actual_claim_results.items()
        if result != "judgment_required"
    }
    observed_claims: set[str] = set()
    for observation in assessment_results["assessment-results"]["results"][0]["observations"]:
        observed_claims.update(re.findall(r"EX-CLAIM-\d+", observation.get("remarks", "")))
    if observed_claims != expected_observation_claims:
        add_error(errors, "assessment-result observations do not cover the expected claim set")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("validated minimal example bundle, witness digests, and OSCAL projection")
    print(f"examples_root={examples_root}")
    print(f"schema_root={schema_root}")
    print(f"catalog_controls={sorted(catalog_controls)}")
    print(f"proxy_targets={len(proxy_target_ids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
