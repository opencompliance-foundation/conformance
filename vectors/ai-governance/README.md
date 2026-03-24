# AI Governance Example Conformance Vector

This vector is tied to the synthetic ExampleCo AI governance fixture.

The checks stay intentionally narrow:

1. The bundle ID must match.
2. The claim-result mapping must match.
3. The summary counts must match.
4. The witness receipt must only be valid for `exact_match`.
5. The witness receipt must pin both replay inputs and outputs.
6. The proof bundle must stay aligned to the synthetic corridor control IDs.
7. The OSCAL projection must stay internally consistent with the native example set.
