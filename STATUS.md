# Conformance Status

## What exists today

- Descriptive vectors for the synthetic minimal, failed, medium, stale, and issued examples.
- Expected summary counts and claim-result mappings.
- Witness-receipt and replay-bundle expectations tied to the same examples.
- Public transparency-log and inclusion-proof validation tied to the same examples.
- A small executable consistency check covering the native bundles, classification artifacts, mixed-control decompositions, evidence and artifact schemas, machine-readable control boundaries, control-boundary mapping maturity metadata, the exact-anchor review pilot, witness digests, and seed OSCAL projections.
- A deterministic refresh script that repins the descriptive vectors from the checked-in synthetic fixtures.

## What does not exist yet

- No executable reference verifier harness.
- No cross-implementation test matrix.
- No serious negative test corpus beyond descriptive notes.

## Rule

The conformance repo should stay smaller than the examples repo until the verifier exists. Otherwise it will become a pile of fake tests for software that has not shipped.
