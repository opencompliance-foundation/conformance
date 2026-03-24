#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import re
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


def sha256_json(path: Path) -> str:
    value = load_json(path)
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def sha256_artifact(path: Path) -> str:
    if path.suffix == ".json":
        return sha256_json(path)
    return sha256_file(path)


def detect_paths(
    script_path: Path,
    examples_override: str | None,
    schema_override: str | None,
    specs_override: str | None,
) -> tuple[Path, Path, Path, Path]:
    conformance_root = script_path.parents[1]

    if examples_override:
        examples_root = Path(examples_override).resolve()
    else:
        private_candidate = script_path.parents[2] / "fixtures" / "public"
        public_candidate = conformance_root.parent / "examples"
        if private_candidate.exists():
            examples_root = private_candidate
        elif public_candidate.exists():
            examples_root = public_candidate
        else:
            raise FileNotFoundError(
                "Could not locate the public example bundles. Pass --examples-root."
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

    if specs_override:
        specs_root = Path(specs_override).resolve()
    else:
        private_candidate = script_path.parents[2] / "open-specs"
        public_candidate = conformance_root.parent / "specs"
        if private_candidate.exists():
            specs_root = private_candidate
        elif public_candidate.exists():
            specs_root = public_candidate
        else:
            raise FileNotFoundError(
                "Could not locate the specs repo. Pass --specs-root."
            )

    return conformance_root, examples_root, schema_root, specs_root


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


def list_fixture_names(conformance_root: Path, fixture: str) -> list[str]:
    if fixture != "all":
        return [fixture]
    vectors_root = conformance_root / "vectors"
    return sorted(path.name for path in vectors_root.iterdir() if path.is_dir())


def resolve_examples_fixture_root(examples_root: Path, fixture: str) -> Path:
    direct_candidate = examples_root / fixture
    if direct_candidate.exists():
        return direct_candidate
    if examples_root.name == fixture and (examples_root / "profile.json").exists():
        return examples_root
    raise FileNotFoundError(f"Could not locate fixture root for {fixture}")


def expected_oscal_paths(oscal_root: Path, fixture: str) -> dict[str, Path]:
    mapping_name = {
        "minimal": "iso27001-soc2-family-overlap-mapping.json",
        "failed": "iso27001-soc2-family-overlap-mapping.json",
        "medium": "iso27001-soc2-irap-gdpr-family-overlap-mapping.json",
        "issued": "iso27001-soc2-family-overlap-mapping.json",
    }[fixture]
    return {
        "catalog": oscal_root / f"opencompliance-{fixture}-catalog.json",
        "profile": oscal_root / f"exampleco-{fixture}-profile.json",
        "ssp": oscal_root / f"exampleco-{fixture}-ssp.json",
        "assessment_plan": oscal_root / f"exampleco-{fixture}-assessment-plan.json",
        "assessment_results": oscal_root / f"exampleco-{fixture}-assessment-results.json",
        "proxy_targets": oscal_root / "family-proxy-targets.json",
        "mapping_collection": oscal_root / mapping_name,
    }


def validate_schema_subset(instance, schema: dict, path: str, errors: list[str]) -> None:
    if "enum" in schema and instance not in schema["enum"]:
        add_error(errors, f"{path} is not one of the allowed enum values")
        return

    schema_type = schema.get("type")
    if schema_type == "object":
        if not isinstance(instance, dict):
            add_error(errors, f"{path} is not an object")
            return
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                add_error(errors, f"{path}.{key} is required")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                validate_schema_subset(value, properties[key], f"{path}.{key}", errors)
            elif schema.get("additionalProperties") is False:
                add_error(errors, f"{path}.{key} is not allowed")
    elif schema_type == "array":
        if not isinstance(instance, list):
            add_error(errors, f"{path} is not an array")
            return
        min_items = schema.get("minItems")
        if min_items is not None and len(instance) < min_items:
            add_error(errors, f"{path} has fewer than {min_items} items")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                validate_schema_subset(item, item_schema, f"{path}[{index}]", errors)
    elif schema_type == "string":
        if not isinstance(instance, str):
            add_error(errors, f"{path} is not a string")
            return
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            add_error(errors, f"{path} is shorter than {min_length}")
    elif schema_type == "integer":
        if not isinstance(instance, int) or isinstance(instance, bool):
            add_error(errors, f"{path} is not an integer")
            return
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            add_error(errors, f"{path} is less than {minimum}")
    elif schema_type == "boolean":
        if not isinstance(instance, bool):
            add_error(errors, f"{path} is not a boolean")


def validate_payloads(evidence_claims: list[dict], schema_root: Path, errors: list[str]) -> None:
    envelope_schema = load_json(schema_root / "schemas" / "evidence-claim.schema.json")
    claim_type_root = schema_root / "schemas" / "claim-types"
    for claim in evidence_claims:
        validate_schema_subset(claim, envelope_schema, claim["claimId"], errors)
        claim_type = claim["claimType"]
        schema_path = claim_type_root / f"{claim_type}.schema.json"
        if not schema_path.exists():
            add_error(errors, f"missing claim-type schema for {claim_type}")
            continue
        schema = load_json(schema_path)
        validate_schema_subset(claim["payload"], schema, f"{claim['claimId']}.payload", errors)


def validate_fixture(
    fixture: str,
    conformance_root: Path,
    examples_root: Path,
    schema_root: Path,
    specs_root: Path,
) -> list[str]:
    errors: list[str] = []
    fixture_root = resolve_examples_fixture_root(examples_root, fixture)
    vector_root = conformance_root / "vectors" / fixture
    oscal_root = fixture_root / "oscal"

    proof_bundle = load_json(fixture_root / "proof-bundle.json")
    verification_result = load_json(fixture_root / "verification-result.json")
    replay_bundle = load_json(fixture_root / "replay-bundle.json")
    evidence_claims = load_json(fixture_root / "evidence-claims.json")
    witness_receipt = load_json(fixture_root / "witness-receipt.json")
    revocation = load_json(fixture_root / "revocation.json")
    expected_summary = load_json(vector_root / "expected-summary.json")
    expected_claim_results = load_json(vector_root / "expected-claim-results.json")
    expected_witness = load_json(vector_root / "expected-witness.json")
    schema_example = load_json(schema_root / "examples" / "evidence-claim.example.json")
    control_boundaries = load_json(specs_root / "control-boundaries.json")
    proof_bundle_schema = load_json(specs_root / "schemas" / "proof-bundle.schema.json")
    verification_result_schema = load_json(specs_root / "schemas" / "verification-result.schema.json")
    replay_bundle_schema = load_json(specs_root / "schemas" / "replay-bundle.schema.json")
    certificate_schema = load_json(specs_root / "schemas" / "certificate.schema.json")
    punch_list_schema = load_json(specs_root / "schemas" / "punch-list.schema.json")
    witness_receipt_schema = load_json(specs_root / "schemas" / "witness-receipt.schema.json")
    revocation_schema = load_json(specs_root / "schemas" / "revocation.schema.json")
    boundaries_by_id = {
        control["controlId"]: control for control in control_boundaries["controls"]
    }

    oscal_paths = expected_oscal_paths(oscal_root, fixture)
    catalog = load_json(oscal_paths["catalog"])
    profile = load_json(oscal_paths["profile"])
    ssp = load_json(oscal_paths["ssp"])
    assessment_plan = load_json(oscal_paths["assessment_plan"])
    assessment_results = load_json(oscal_paths["assessment_results"])
    proxy_targets = load_json(oscal_paths["proxy_targets"])
    mapping_collection = load_json(oscal_paths["mapping_collection"])

    bundle_id = proof_bundle["bundleId"]
    if expected_summary["bundleId"] != bundle_id:
      add_error(errors, f"{fixture}: expected-summary bundleId does not match proof bundle")
    if expected_claim_results["bundleId"] != bundle_id:
      add_error(errors, f"{fixture}: expected-claim-results bundleId does not match proof bundle")
    if expected_witness["bundleId"] != bundle_id:
      add_error(errors, f"{fixture}: expected-witness bundleId does not match proof bundle")
    if witness_receipt["bundleId"] != bundle_id:
      add_error(errors, f"{fixture}: witness-receipt bundleId does not match proof bundle")
    if verification_result["bundleId"] != bundle_id:
      add_error(errors, f"{fixture}: verification-result bundleId does not match proof bundle")
    if replay_bundle["bundleId"] != bundle_id:
      add_error(errors, f"{fixture}: replay-bundle bundleId does not match proof bundle")

    actual_claim_results = {
        claim["claimId"]: claim["result"] for claim in proof_bundle["claims"]
    }
    if actual_claim_results != expected_claim_results["expectedClaimResults"]:
        add_error(errors, f"{fixture}: claim-result mapping does not match expected vector")

    result_key_map = {
        "proved": "proved",
        "attested": "attested",
        "failed": "failed",
        "judgment_required": "judgmentRequired",
        "evidence_missing": "evidenceMissing",
    }
    actual_counts = {value: 0 for value in result_key_map.values()}
    for result in actual_claim_results.values():
        actual_counts[result_key_map[result]] += 1
    if actual_counts != expected_summary["expectedCounts"]:
        add_error(errors, f"{fixture}: summary counts do not match expected vector")
    if actual_counts != proof_bundle["summary"]:
        add_error(errors, f"{fixture}: proof bundle summary is inconsistent with claim results")

    validate_schema_subset(proof_bundle, proof_bundle_schema, f"{fixture}.proof_bundle", errors)
    validate_schema_subset(verification_result, verification_result_schema, f"{fixture}.verification_result", errors)
    validate_schema_subset(replay_bundle, replay_bundle_schema, f"{fixture}.replay_bundle", errors)
    validate_schema_subset(witness_receipt, witness_receipt_schema, f"{fixture}.witness_receipt", errors)
    validate_schema_subset(revocation, revocation_schema, f"{fixture}.revocation", errors)

    witness_required = {
        item["path"]: item["sha256"] for item in expected_witness["requiredArtifacts"]
    }
    witness_checked = {
        item["path"]: item["sha256"] for item in witness_receipt["checkedArtifacts"]
    }
    if witness_receipt["replayResult"] != expected_witness["requiredReplayResult"]:
        add_error(errors, f"{fixture}: witness replay result does not match expected vector")
    if witness_checked != witness_required:
        add_error(errors, f"{fixture}: witness receipt artifacts do not match expected witness vector")

    for rel_path, expected_digest in witness_required.items():
        digest = sha256_artifact(fixture_root / rel_path)
        if digest != expected_digest:
            add_error(errors, f"{fixture}: sha256 mismatch for {rel_path}")

    replay_required = {
        item["path"]: item["sha256"]
        for item in replay_bundle["materialInputs"] + replay_bundle["expectedOutputs"]
    }
    if replay_required != witness_required:
        add_error(errors, f"{fixture}: replay-bundle artifacts do not match expected witness vector")

    outcome_artifact_path = verification_result["outcomeArtifact"]["path"]
    if not (fixture_root / outcome_artifact_path).exists():
        add_error(errors, f"{fixture}: outcome artifact {outcome_artifact_path} does not exist")
    expected_outcome = (
        "certificate_issued"
        if actual_counts["failed"] == 0 and actual_counts["judgmentRequired"] == 0 and actual_counts["evidenceMissing"] == 0
        else "punch_list_issued"
    )
    outcome_artifact = load_json(fixture_root / outcome_artifact_path) if (fixture_root / outcome_artifact_path).exists() else None
    if outcome_artifact is not None:
        outcome_schema = certificate_schema if expected_outcome == "certificate_issued" else punch_list_schema
        validate_schema_subset(outcome_artifact, outcome_schema, f"{fixture}.{outcome_artifact_path}", errors)
    if (fixture_root / outcome_artifact_path).exists() and verification_result["outcomeArtifact"]["sha256"] != sha256_json(fixture_root / outcome_artifact_path):
        add_error(errors, f"{fixture}: outcome artifact digest does not match verification-result")

    if verification_result["outcome"] != expected_outcome:
        add_error(errors, f"{fixture}: verification-result outcome is inconsistent with the proof summary")
    expected_path = "certificate.json" if expected_outcome == "certificate_issued" else "punch-list.json"
    if outcome_artifact_path != expected_path:
        add_error(errors, f"{fixture}: verification-result points at {outcome_artifact_path} but expected {expected_path}")
    if verification_result["blockingIssueCount"] != (
        actual_counts["failed"] + actual_counts["judgmentRequired"] + actual_counts["evidenceMissing"]
    ):
        add_error(errors, f"{fixture}: verification-result blockingIssueCount is inconsistent with proof summary")
    if verification_result["proofBundleSha256"] != sha256_json(fixture_root / "proof-bundle.json"):
        add_error(errors, f"{fixture}: verification-result proof bundle digest is inconsistent")
    if verification_result["trustSurfaceSha256"] != sha256_artifact(fixture_root / "trust-surface-report.md"):
        add_error(errors, f"{fixture}: verification-result trust surface digest is inconsistent")

    if schema_example["controlMappings"][0]["controlId"] != "soc2.family.access_control":
        add_error(errors, "schema example was not updated to use proxy controlId values")

    evidence_by_id = {claim["claimId"]: claim for claim in evidence_claims}
    proxy_target_ids = {target["id"] for target in proxy_targets["targets"]}
    evidence_control_ids = set()
    for claim in evidence_claims:
        for mapping in claim["controlMappings"]:
            control_id = mapping.get("controlId")
            if not control_id:
                add_error(errors, f"{fixture}: missing controlId on evidence claim {claim['claimId']}")
                continue
            evidence_control_ids.add(control_id)
            if control_id not in proxy_target_ids:
                add_error(errors, f"{fixture}: unknown proxy target id {control_id} in {claim['claimId']}")

    validate_payloads(evidence_claims, schema_root, errors)

    catalog_controls: set[str] = set()
    for group in catalog["catalog"]["groups"]:
        for control in group.get("controls", []):
            catalog_controls.add(control["id"])

    proof_control_refs: set[str] = set()
    for claim in proof_bundle["claims"]:
        framework_mappings = claim.get("frameworkMappings", [])
        if not framework_mappings:
            add_error(errors, f"{fixture}: {claim['claimId']} is missing frameworkMappings")
        evidence_refs = claim.get("evidenceRefs", [])
        control_refs = set(claim.get("controlRefs", []))
        proof_control_refs.update(control_refs)

        for control_ref in control_refs:
            if control_ref not in catalog_controls:
                add_error(errors, f"{fixture}: unknown controlRef {control_ref} in {claim['claimId']}")
            if control_ref not in boundaries_by_id:
                add_error(errors, f"{fixture}: controlRef {control_ref} is not in control-boundaries.json")

        for mapping in framework_mappings:
            control_id = mapping.get("controlId")
            if control_id and control_id not in proxy_target_ids:
                add_error(errors, f"{fixture}: proof bundle mapping controlId {control_id} is not in family proxy targets")

        if evidence_refs:
            expected_mappings = {
                (
                    mapping["framework"],
                    mapping["family"],
                    mapping.get("controlId", ""),
                )
                for evidence_ref in evidence_refs
                for mapping in evidence_by_id[evidence_ref]["controlMappings"]
            }
            actual_mappings = {
                (
                    mapping["framework"],
                    mapping["family"],
                    mapping.get("controlId", ""),
                )
                for mapping in framework_mappings
            }
            if actual_mappings != expected_mappings:
                add_error(
                    errors,
                    f"{fixture}: {claim['claimId']} frameworkMappings do not match referenced evidence controlMappings",
                )
            if not control_refs:
                add_error(errors, f"{fixture}: {claim['claimId']} has evidenceRefs but no controlRefs")

        if control_refs:
            allowed_results: set[str] = set()
            for control_ref in control_refs:
                classification = boundaries_by_id[control_ref]["classification"]
                if classification == "decidable":
                    allowed_results.update({"proved", "failed", "evidence_missing"})
                elif classification == "attestation":
                    allowed_results.update({"attested", "failed", "evidence_missing"})
                elif classification == "judgment":
                    allowed_results.add("judgment_required")
            if claim["result"] not in allowed_results:
                add_error(
                    errors,
                    f"{fixture}: {claim['claimId']} result {claim['result']} is inconsistent with control-boundaries classification",
                )

    if not catalog_controls.issubset(set(boundaries_by_id)):
        missing = sorted(catalog_controls - set(boundaries_by_id))
        add_error(errors, f"{fixture}: control-boundaries.json is missing catalog controls {missing}")

    if proof_control_refs != catalog_controls:
        add_error(errors, f"{fixture}: proof bundle controlRefs do not cover the catalog control set")

    profile_controls = set(
        profile["profile"]["imports"][0]["include-controls"][0]["with-ids"]
    )
    if profile_controls != catalog_controls:
        add_error(errors, f"{fixture}: profile control set does not match catalog control set")

    ssp_controls = {
        requirement["control-id"]
        for requirement in ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
    }
    if ssp_controls != catalog_controls:
        add_error(errors, f"{fixture}: SSP implemented requirements do not match catalog control set")

    assessment_plan_controls = control_ids_from_selection(
        assessment_plan["assessment-plan"]["reviewed-controls"]
    )
    if assessment_plan_controls != catalog_controls:
        add_error(errors, f"{fixture}: assessment plan reviewed controls do not match catalog control set")

    result_controls = control_ids_from_selection(
        assessment_results["assessment-results"]["results"][0]["reviewed-controls"]
    )
    if result_controls != catalog_controls:
        add_error(errors, f"{fixture}: assessment results reviewed controls do not match catalog control set")

    mapping_root = mapping_collection["mapping-collection"]["mappings"][0]
    if mapping_root["source-resource"]["href"] != f"./opencompliance-{fixture}-catalog.json":
        add_error(errors, f"{fixture}: mapping source-resource href is unexpected")
    if mapping_root["target-resource"]["href"] != "./family-proxy-targets.json":
        add_error(errors, f"{fixture}: mapping target-resource href is unexpected")

    mapped_source_ids = set()
    for mapping in mapping_root["maps"]:
        if mapping["relationship"] != "subset-of":
            add_error(errors, f"{fixture}: mapping relationship must stay subset-of in the seed example")
        for source in mapping["sources"]:
            mapped_source_ids.add(source["id-ref"])
            if source["id-ref"] not in catalog_controls:
                add_error(errors, f"{fixture}: mapping source id {source['id-ref']} is not in the catalog")
        for target in mapping["targets"]:
            if target["id-ref"] not in proxy_target_ids:
                add_error(errors, f"{fixture}: mapping target id {target['id-ref']} is not in family-proxy-targets")

    if mapped_source_ids != catalog_controls:
        add_error(errors, f"{fixture}: mapping source coverage does not match catalog control set")
    if not evidence_control_ids.issubset(proxy_target_ids):
        add_error(errors, f"{fixture}: evidence controlIds are not fully covered by family proxy targets")

    expected_observation_claims = {
        claim_id
        for claim_id, result in actual_claim_results.items()
        if result != "judgment_required"
    }
    observed_claims: set[str] = set()
    for observation in assessment_results["assessment-results"]["results"][0]["observations"]:
        observed_claims.update(re.findall(r"EX-CLAIM-\d+", observation.get("remarks", "")))
    if observed_claims != expected_observation_claims:
        add_error(errors, f"{fixture}: assessment-result observations do not cover the expected claim set")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the public synthetic OpenCompliance example bundles remain internally consistent."
    )
    parser.add_argument("--examples-root", help="Path to the examples repo root or private fixtures/public root.")
    parser.add_argument("--schema-root", help="Path to the evidence-schema repo root.")
    parser.add_argument("--specs-root", help="Path to the specs repo root.")
    parser.add_argument(
        "--fixture",
        choices=["minimal", "failed", "medium", "issued", "all"],
        default="all",
        help="Which fixture set to validate.",
    )
    args = parser.parse_args()

    script_path = Path(__file__).resolve()
    conformance_root, examples_root, schema_root, specs_root = detect_paths(
        script_path, args.examples_root, args.schema_root, args.specs_root
    )

    errors: list[str] = []
    fixture_names = list_fixture_names(conformance_root, args.fixture)
    for fixture in fixture_names:
        errors.extend(validate_fixture(fixture, conformance_root, examples_root, schema_root, specs_root))

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("validated public example bundles, payload schemas, witness digests, and OSCAL projections")
    print(f"examples_root={examples_root}")
    print(f"schema_root={schema_root}")
    print(f"specs_root={specs_root}")
    print(f"fixtures={','.join(fixture_names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
