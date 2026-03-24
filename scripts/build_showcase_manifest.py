#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path


SUMMARY_KEY_ORDER = [
    "proved",
    "attested",
    "failed",
    "staleEvidence",
    "judgmentRequired",
    "evidenceMissing",
]

CLAIM_RESULT_TO_SUMMARY_KEY = {
    "proved": "proved",
    "attested": "attested",
    "failed": "failed",
    "stale_evidence": "staleEvidence",
    "judgment_required": "judgmentRequired",
    "evidence_missing": "evidenceMissing",
}


def load_json(path: Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def detect_examples_root(script_path: Path, examples_override: str | None) -> Path:
    conformance_root = script_path.parents[1]
    if examples_override:
        return Path(examples_override).resolve()

    private_candidate = conformance_root.parent / "fixtures" / "public"
    public_candidate = conformance_root.parent / "examples"
    if private_candidate.exists():
        return private_candidate
    if public_candidate.exists():
        return public_candidate
    raise FileNotFoundError("Could not locate the examples root. Pass --examples-root.")


def resolve_showcase_root(examples_root: Path, showcase_root: str) -> Path:
    candidate = Path(showcase_root)
    if candidate.is_absolute():
        return candidate
    if candidate.exists():
        return candidate.resolve()
    direct = examples_root / candidate
    if direct.exists():
        return direct
    raise FileNotFoundError(f"Could not locate showcase root: {showcase_root}")


def github_blob(base_url: str, relative_path: str) -> str:
    return f"{base_url}/blob/main/{relative_path}"


def github_tree(base_url: str, relative_path: str) -> str:
    return f"{base_url}/tree/main/{relative_path}"


def summarize_corridor(
    examples_root: Path,
    config_entry: dict,
    examples_repo_url: str,
) -> tuple[dict, dict]:
    fixture = config_entry["fixture"]
    fixture_root = examples_root / fixture
    proof_bundle = load_json(fixture_root / "proof-bundle.json")
    verification_result = load_json(fixture_root / "verification-result.json")
    classification_result = load_json(fixture_root / "classification-result.json")
    profile = load_json(fixture_root / "profile.json")

    outcome_artifact_path = fixture_root / verification_result["outcomeArtifact"]["path"]
    claims = proof_bundle["claims"]

    control_refs = sorted(
        {
            control_ref
            for claim in claims
            for control_ref in claim.get("controlRefs", [])
        }
    )
    frameworks = sorted(
        set(proof_bundle.get("frameworkIntent", []))
        | {
            mapping["framework"]
            for claim in claims
            for mapping in claim.get("frameworkMappings", [])
        }
    )

    claim_titles_by_result = {key: [] for key in CLAIM_RESULT_TO_SUMMARY_KEY}
    framework_counts: dict[str, dict] = {}
    for claim in claims:
        result_key = claim["result"]
        claim_titles_by_result[result_key].append(claim["title"])
        for mapping in claim.get("frameworkMappings", []):
            framework = mapping["framework"]
            entry = framework_counts.setdefault(
                framework,
                {
                    "framework": framework,
                    "counts": {key: 0 for key in SUMMARY_KEY_ORDER},
                    "sampleClaimTitles": {key: [] for key in SUMMARY_KEY_ORDER},
                },
            )
            summary_key = CLAIM_RESULT_TO_SUMMARY_KEY[result_key]
            entry["counts"][summary_key] += 1
            samples = entry["sampleClaimTitles"][summary_key]
            if len(samples) < 3 and claim["title"] not in samples:
                samples.append(claim["title"])

    proof_runner = proof_bundle.get("proofRunner", {})
    boundary_inventory = proof_runner.get("boundaryInventory", {})
    route_summary = classification_result.get("routeSummary", {})
    mixed_controls = classification_result.get("mixedControls", [])
    artifact_paths = {
        "root": fixture,
        "readme": f"{fixture}/README.md",
        "profile": f"{fixture}/profile.json",
        "classificationResult": f"{fixture}/classification-result.json",
        "proofBundle": f"{fixture}/proof-bundle.json",
        "trustSurfaceReport": f"{fixture}/trust-surface-report.md",
        "verificationResult": f"{fixture}/verification-result.json",
        "outcomeArtifact": f"{fixture}/{verification_result['outcomeArtifact']['path']}",
        "replayBundle": f"{fixture}/replay-bundle.json",
        "witnessReceipt": f"{fixture}/witness-receipt.json",
        "transparencyLog": f"{fixture}/transparency-log.json",
        "inclusionProofs": f"{fixture}/inclusion-proofs.json",
        "oscal": f"{fixture}/oscal",
        "sourceExports": f"{fixture}/source-exports",
    }
    if (fixture_root / "company.json").exists():
        artifact_paths["company"] = f"{fixture}/company.json"

    artifact_urls = {
        name: github_blob(examples_repo_url, path)
        for name, path in artifact_paths.items()
        if not path.endswith("/oscal") and not path.endswith("/source-exports")
    }
    artifact_urls["root"] = github_tree(examples_repo_url, fixture)
    artifact_urls["oscal"] = github_tree(examples_repo_url, f"{fixture}/oscal")
    artifact_urls["sourceExports"] = github_tree(examples_repo_url, f"{fixture}/source-exports")

    corridor = {
        "fixture": fixture,
        "title": config_entry["title"],
        "objective": config_entry["objective"],
        "safeStatement": config_entry["safeStatement"],
        "whyIncluded": config_entry["whyIncluded"],
        "intendedAudience": config_entry["intendedAudience"],
        "organisation": proof_bundle["organisation"],
        "profileId": proof_bundle["profileId"],
        "bundleId": proof_bundle["bundleId"],
        "generatedAt": proof_bundle["generatedAt"],
        "verifierVersion": proof_bundle["verifierVersion"],
        "outcome": verification_result["outcome"],
        "blockingIssueCount": verification_result["blockingIssueCount"],
        "frameworks": frameworks,
        "frameworkIntent": proof_bundle.get("frameworkIntent", []),
        "controlRefs": control_refs,
        "claimSummary": {key: proof_bundle["summary"].get(key, 0) for key in SUMMARY_KEY_ORDER},
        "routeSummary": {
            "decidable": route_summary.get("decidable", 0),
            "attestation": route_summary.get("attestation", 0),
            "judgment": route_summary.get("judgment", 0),
        },
        "mixedControlCount": len(mixed_controls),
        "scope": {
            "inScope": profile["scope"]["inScope"],
            "outOfScope": profile["scope"]["outOfScope"],
            "note": profile["scope"]["note"],
        },
        "leanBoundary": {
            "status": proof_runner.get("status"),
            "theoremCount": proof_runner.get("theoremCount", 0),
            "leanBackedClaimCount": boundary_inventory.get("leanBackedClaimCount", 0),
            "provedClaimCount": boundary_inventory.get("provedClaimCount", 0),
            "omittedProvedClaimCount": len(boundary_inventory.get("omittedProvedClaims", [])),
        },
        "resultHighlights": {
            result: claim_titles_by_result[result][:3]
            for result in sorted(claim_titles_by_result.keys())
            if claim_titles_by_result[result]
        },
        "artifacts": {
            "paths": artifact_paths,
            "github": artifact_urls,
        },
    }
    return corridor, framework_counts


def build_showcase_report(showcase_root: Path, examples_root: Path) -> dict:
    config = load_json(showcase_root / "showcase-config.json")
    company = load_json(showcase_root / "company.json")
    examples_repo_url = config["examplesRepo"]

    corridors: list[dict] = []
    framework_index: dict[str, dict] = {}
    overall_summary = {key: 0 for key in SUMMARY_KEY_ORDER}
    route_totals = {"decidable": 0, "attestation": 0, "judgment": 0}
    all_control_refs: set[str] = set()
    all_frameworks: set[str] = set()
    certificate_count = 0
    blocked_count = 0
    total_lean_backed = 0
    total_omitted = 0

    for corridor_config in config["corridors"]:
        corridor, framework_counts = summarize_corridor(
            examples_root,
            corridor_config,
            examples_repo_url,
        )
        corridors.append(corridor)
        if corridor["outcome"] == "certificate_issued":
            certificate_count += 1
        else:
            blocked_count += 1
        for key in SUMMARY_KEY_ORDER:
            overall_summary[key] += corridor["claimSummary"][key]
        for key in route_totals:
            route_totals[key] += corridor["routeSummary"][key]
        all_control_refs.update(corridor["controlRefs"])
        all_frameworks.update(corridor["frameworks"])
        total_lean_backed += corridor["leanBoundary"]["leanBackedClaimCount"]
        total_omitted += corridor["leanBoundary"]["omittedProvedClaimCount"]

        for framework, counts in framework_counts.items():
            entry = framework_index.setdefault(
                framework,
                {
                    "framework": framework,
                    "corridors": [],
                    "claimSummary": {key: 0 for key in SUMMARY_KEY_ORDER},
                    "sampleClaimTitles": {key: [] for key in SUMMARY_KEY_ORDER},
                    "publicPosition": config["frameworkPositions"].get(framework, ""),
                },
            )
            if corridor["fixture"] not in entry["corridors"]:
                entry["corridors"].append(corridor["fixture"])
            for key in SUMMARY_KEY_ORDER:
                entry["claimSummary"][key] += counts["counts"][key]
                for sample in counts["sampleClaimTitles"][key]:
                    if len(entry["sampleClaimTitles"][key]) < 3 and sample not in entry["sampleClaimTitles"][key]:
                        entry["sampleClaimTitles"][key].append(sample)

    report = {
        "showcaseId": config["showcaseId"],
        "generatedAt": config["generatedAt"],
        "organisation": company["organisation"],
        "purpose": config["purpose"],
        "canonicalSite": config["canonicalSite"],
        "repositoryMap": config["repositoryMap"],
        "company": company,
        "summary": {
            "corridorCount": len(corridors),
            "certificateIssuedCount": certificate_count,
            "blockedCorridorCount": blocked_count,
            "uniqueFrameworkCount": len(all_frameworks),
            "uniqueControlRefCount": len(all_control_refs),
            "claimSummary": overall_summary,
            "routeSummary": route_totals,
            "leanBackedProvedClaims": total_lean_backed,
            "omittedProvedClaimsOutsidePublicLean": total_omitted,
        },
        "workflow": config["workflow"],
        "corridors": corridors,
        "frameworkCoverage": sorted(framework_index.values(), key=lambda item: item["framework"]),
        "commands": {
            "privateCheck": [
                "cd projects/dev/opencompliance",
                "python3 conformance/scripts/build_showcase_manifest.py --showcase-root fixtures/public/exampleco-showcase --check",
            ],
            "publicCheck": [
                "cd conformance",
                "python3 scripts/build_showcase_manifest.py --examples-root ../examples --showcase-root exampleco-showcase --check",
            ],
            "publicValidation": [
                "cd conformance",
                "python3 scripts/validate_public_examples.py --examples-root ../examples --specs-root ../specs --schema-root ../evidence-schema",
            ],
        },
        "github": {
            "examplesRepo": examples_repo_url,
            "conformanceRepo": config["conformanceRepo"],
            "showcaseRoot": github_tree(examples_repo_url, "exampleco-showcase"),
            "showcaseReport": github_blob(examples_repo_url, "exampleco-showcase/showcase-report.json"),
            "showcaseSummary": github_blob(examples_repo_url, "exampleco-showcase/showcase-summary.md"),
            "builderScript": github_blob(config["conformanceRepo"], "scripts/build_showcase_manifest.py"),
        },
    }
    return report


def render_report_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=True, indent=2) + "\n"


def render_summary_md(report: dict) -> str:
    lines = [
        f"# {report['organisation']} OpenCompliance Showcase",
        "",
        f"**Showcase:** `{report['showcaseId']}`  ",
        f"**Generated:** `{report['generatedAt']}`  ",
        f"**Canonical site:** `{report['canonicalSite']}`  ",
        f"**Repository map:** `{report['repositoryMap']}`",
        "",
        report["purpose"],
        "",
        "## What this pack demonstrates",
        "",
        f"- `{report['summary']['corridorCount']}` scoped corridors",
        f"- `{report['summary']['certificateIssuedCount']}` issued outcomes and `{report['summary']['blockedCorridorCount']}` blocked outcome",
        f"- `{report['summary']['claimSummary']['proved']}` proved claims across the showcased corridors",
        f"- `{report['summary']['claimSummary']['attested']}` attested claims across the showcased corridors",
        f"- `{report['summary']['claimSummary']['failed']}` failed claim, `{report['summary']['claimSummary']['judgmentRequired']}` judgment-required claim, and `{report['summary']['claimSummary']['evidenceMissing']}` evidence-missing claims across the selected corridors",
        "",
        "The right public statement is not that ExampleCo is fully certified. The right statement is that ExampleCo can publish a replayable package showing exactly what is proved, what is attested, and what still blocks issuance for each scoped corridor.",
        "",
        "## Workflow",
        "",
    ]

    for step in report["workflow"]:
        lines.append(f"- **{step['step']}**: {step['detail']}")

    lines.extend([
        "",
        "## Corridor summaries",
        "",
    ])

    for corridor in report["corridors"]:
        lines.extend(
            [
                f"### {corridor['title']} (`{corridor['fixture']}`)",
                "",
                f"- **Outcome**: `{corridor['outcome']}`",
                f"- **Claim summary**: proved `{corridor['claimSummary']['proved']}`, attested `{corridor['claimSummary']['attested']}`, failed `{corridor['claimSummary']['failed']}`, stale `{corridor['claimSummary']['staleEvidence']}`, judgment `{corridor['claimSummary']['judgmentRequired']}`, missing `{corridor['claimSummary']['evidenceMissing']}`",
                f"- **Safe statement**: {corridor['safeStatement']}",
                f"- **Why included**: {corridor['whyIncluded']}",
                f"- **Frameworks touched**: {', '.join(corridor['frameworks'])}",
                f"- **Artifacts**: `{corridor['artifacts']['paths']['trustSurfaceReport']}`, `{corridor['artifacts']['paths']['verificationResult']}`, `{corridor['artifacts']['paths']['outcomeArtifact']}`",
                "",
            ]
        )

    lines.extend([
        "## Framework view",
        "",
    ])

    for framework in report["frameworkCoverage"]:
        lines.extend(
            [
                f"### {framework['framework']}",
                "",
                f"- **Public position**: {framework['publicPosition']}",
                f"- **Corridors**: {', '.join(sorted(framework['corridors']))}",
                (
                    "- **Claim summary**: "
                    f"proved `{framework['claimSummary']['proved']}`, "
                    f"attested `{framework['claimSummary']['attested']}`, "
                    f"failed `{framework['claimSummary']['failed']}`, "
                    f"stale `{framework['claimSummary']['staleEvidence']}`, "
                    f"judgment `{framework['claimSummary']['judgmentRequired']}`, "
                    f"missing `{framework['claimSummary']['evidenceMissing']}`"
                ),
                "",
            ]
        )

    lines.extend(
        [
            "## Rebuild and check",
            "",
            "Inside the private working tree:",
            "",
            "```sh",
            *report["commands"]["privateCheck"],
            "```",
            "",
            "Inside a public multi-repo checkout:",
            "",
            "```sh",
            *report["commands"]["publicCheck"],
            "",
            *report["commands"]["publicValidation"],
            "```",
            "",
            "## Public roots",
            "",
            f"- Showcase repo root: {report['github']['showcaseRoot']}",
            f"- Showcase report: {report['github']['showcaseReport']}",
            f"- Showcase summary: {report['github']['showcaseSummary']}",
            f"- Builder script: {report['github']['builderScript']}",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def write_or_check(path: Path, expected: str, check: bool, write: bool) -> list[str]:
    errors: list[str] = []
    if write:
        path.write_text(expected, encoding="utf-8")
        return errors
    if check:
        if not path.exists():
            errors.append(f"missing generated file: {path}")
            return errors
        existing = path.read_text(encoding="utf-8")
        if existing != expected:
            errors.append(f"stale generated file: {path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Build or check the ExampleCo showcase manifest from public corridor artifacts.")
    parser.add_argument(
        "--examples-root",
        help="Path to the examples root. Defaults to the private fixtures/public directory or a sibling public examples repo.",
    )
    parser.add_argument(
        "--showcase-root",
        default="exampleco-showcase",
        help="Relative or absolute path to the showcase root. Defaults to exampleco-showcase under the examples root.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="Write generated showcase artifacts into the showcase root.")
    mode.add_argument("--check", action="store_true", help="Check generated showcase artifacts against the checked-in copies.")
    args = parser.parse_args()

    script_path = Path(__file__).resolve()
    examples_root = detect_examples_root(script_path, args.examples_root)
    showcase_root = resolve_showcase_root(examples_root, args.showcase_root)

    report = build_showcase_report(showcase_root, examples_root)
    report_json = render_report_json(report)
    summary_md = render_summary_md(report)

    if not args.write and not args.check:
        print(report_json, end="")
        return 0

    errors: list[str] = []
    errors.extend(write_or_check(showcase_root / "showcase-report.json", report_json, args.check, args.write))
    errors.extend(write_or_check(showcase_root / "showcase-summary.md", summary_md, args.check, args.write))

    if errors:
        raise SystemExit("\n".join(errors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
