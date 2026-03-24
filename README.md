# OpenCompliance Conformance

This directory is the private source of truth for the first public export to `opencompliance-foundation/conformance`.

The first release is intentionally small, but it now covers seven synthetic fixtures and more than one verification outcome.

It provides:

- expected outputs for the public synthetic examples,
- blocked, stale-evidence, and certificate-eligible Verify outcomes,
- dedicated cyber-baseline and AI-governance corridor packs,
- the promoted storage-encryption slice in the medium and issued ExampleCo corridors,
- a small executable consistency check for the public examples, their artifact schemas, their control-boundary mapping metadata, their exact-anchor review pilot, their mixed-control decompositions, and their OSCAL projections,
- a place to document what a verifier must reproduce,
- a public showcase builder that aggregates several corridor bundles into one company-level ExampleCo story,
- and a public statement of what does not yet exist.

## Run the public consistency checks

Inside the private source tree:

```sh
cd projects/dev/opencompliance
python3 conformance/scripts/validate_public_examples.py
```

Inside a public multi-repo checkout:

```sh
cd conformance
python3 scripts/validate_public_examples.py \
  --examples-root ../examples \
  --specs-root ../specs \
  --schema-root ../evidence-schema
```

## Compatibility wrapper

The old single-fixture command still exists:

```sh
cd projects/dev/opencompliance
python3 conformance/scripts/validate_minimal_example.py
```

## Refresh the descriptive vectors

When the checked-in synthetic fixtures change, repin the descriptive vectors from the current artifacts:

```sh
cd projects/dev/opencompliance
python3 conformance/scripts/refresh_public_vectors.py
```

To repin only one fixture:

```sh
cd projects/dev/opencompliance
python3 conformance/scripts/refresh_public_vectors.py --fixture stale
```

## Build the ExampleCo showcase summary

Inside the private source tree:

```sh
cd projects/dev/opencompliance
python3 conformance/scripts/build_showcase_manifest.py \
  --showcase-root fixtures/public/exampleco-showcase \
  --check
```

Inside a public multi-repo checkout:

```sh
cd conformance
python3 scripts/build_showcase_manifest.py \
  --examples-root ../examples \
  --showcase-root exampleco-showcase \
  --check
```
