# Stale-Evidence Example Conformance Vector

This vector is tied to the synthetic ExampleCo stale-evidence public fixture.

It exists to check the freshness-downgrade path without pretending the corridor is broad:

1. The bundle ID must match.
2. The claim-result mapping must match.
3. The summary counts must match.
4. The verification-result outcome must be `punch_list_issued`.
5. The replay-bundle and witness-receipt artifacts must pin the same exact inputs and outputs.
6. The OSCAL projection must stay internally consistent with the native example set.
