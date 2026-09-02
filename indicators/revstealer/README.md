# REVSTEALER indicators

This directory contains domain indicators associated with REVSTEALER, a credential-harvesting infostealer.

The indicators support the Elastic Security Labs research article [REVSTEALER: Credential-Harvesting Infostealer](https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer).

## Files

| File | Description |
| --- | --- |
| [`domains.csv`](domains.csv) | Defanged domain indicators associated with REVSTEALER. |

## Domain research

The domain set was developed through infrastructure analysis using the following pivots:

- Validin `BANNER_0_HASH`: `bf0bb4dc67d17b58ed1966c6c92addd3`
- VirusTotal relationships for SHA-256 hash [`5fb9480e8f21925a902c3006422cdfc3daeea608681574b15fbf23273b8db489`](https://www.virustotal.com/gui/file/5fb9480e8f21925a902c3006422cdfc3daeea608681574b15fbf23273b8db489/relations)
- Domains resolving to `104.143.36.164`
- Resolved dead-drop infrastructure, from domains extracted from the blockchain contract.

The `description` field in `domains.csv` identifies the applicable pivot(s) for each indicator. Domains are defanged using `[.]` to prevent accidental navigation.

These indicators represent a point-in-time research snapshot. Infrastructure may change, and indicators should be evaluated alongside additional context before use.
