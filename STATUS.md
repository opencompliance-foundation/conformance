# Conformance Status

## What exists today

- Descriptive vectors for the synthetic minimal example.
- Expected summary counts and claim-result mappings.
- A witness-receipt expectation tied to the same example.
- A small executable consistency check covering the native bundle, witness digests, and seed OSCAL projection.

## What does not exist yet

- No executable reference verifier harness.
- No cross-implementation test matrix.
- No negative test corpus beyond descriptive notes.

## Rule

The conformance repo should stay smaller than the examples repo until the verifier exists. Otherwise it will become a pile of fake tests for software that has not shipped.
