# OpenCompliance Conformance

This directory is the private source of truth for the first public export to `opencompliance-foundation/conformance`.

The first release is intentionally small, but it now covers more than one synthetic fixture.

It provides:

- expected outputs for the public synthetic examples,
- a small executable consistency check for the public examples and their OSCAL projections,
- a place to document what a verifier must reproduce,
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
  --schema-root ../evidence-schema
```

## Compatibility wrapper

The old single-fixture command still exists:

```sh
cd projects/dev/opencompliance
python3 conformance/scripts/validate_minimal_example.py
```
