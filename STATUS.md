# Conformance Status

## What exists today

- Descriptive vectors for the synthetic minimal, medium, and issued examples.
- Expected summary counts and claim-result mappings.
- Witness-receipt and replay-bundle expectations tied to the same examples.
- A small executable consistency check covering the native bundles, typed payload schemas, machine-readable control boundaries, witness digests, and seed OSCAL projections.

## What does not exist yet

- No executable reference verifier harness.
- No cross-implementation test matrix.
- No serious negative test corpus beyond descriptive notes.

## Rule

The conformance repo should stay smaller than the examples repo until the verifier exists. Otherwise it will become a pile of fake tests for software that has not shipped.
