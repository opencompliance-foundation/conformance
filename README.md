# OpenCompliance Conformance

This directory is the private source of truth for the first public export to `opencompliance-foundation/conformance`.

The first release is intentionally small.

It provides:

- expected outputs for the minimal public example,
- a small executable consistency check for the minimal example and its OSCAL projection,
- a place to document what a verifier must reproduce,
- and a public statement of what does not yet exist.

## Run the minimal consistency check

Inside the private source tree:

```sh
python3 conformance/scripts/validate_minimal_example.py
```

Inside a public multi-repo checkout:

```sh
python3 conformance/scripts/validate_minimal_example.py \
  --examples-root ../examples/minimal \
  --schema-root ../evidence-schema
```
