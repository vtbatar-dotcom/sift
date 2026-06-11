# SIFT Sentinel — Accuracy Report

## Benchmark Results

| Metric | Value |
|--------|-------|
| Accepted findings | 7 |
| Ground truth items | 7 |
| Matched findings | 5 |
| Precision | 71.4% |
| Recall | 71.4% |
| Must-find recall | 80.0% |
| Hallucinations | 1 |
| Hallucination rate | 14.3% |
| Spoliation events | 0 |
| Evidence integrity | VERIFIED |

## Self-Correction Demonstrated

Of 10 findings produced by the Analyst:
- **4 accepted on first pass** (iteration 0): HELPER.EXE, Task Manager, Installed Software, No Persistence
- **3 accepted after revision** (iteration 1): System Identification, WUAUCLT Run Count, Travel Planning
- **2 rejected after max iterations**: Internet/Communication Usage, Microsoft Office Activity

### Corrections caught by the Skeptic:
1. **CONFIRMED/INFERRED conflation**: Analyst labeled VMware identification as "confirmed" based only on software presence. Skeptic required downgrade to "inferred" since no BIOS/hardware evidence was examined.
2. **Timestamp mismatch**: Timeline entry claimed 00:11:16 but citation showed 00:11:21. Analyst corrected.
3. **Wrong MITRE mapping**: T1562.001 (Impair Defenses) was applied to high WUAUCLT run count, which doesn't constitute disabling security tools. Analyst removed the mapping.
4. **Unsupported characterization**: Analyst called Administrator a "human user profile" without evidence of actual human usage. Analyst revised language.
5. **Source type mismatch**: Timeline entries labeled as "mft" source when evidence came from SQLite browser history. Analyst corrected to proper source.

## Evidence Integrity

Session start hashes and end hashes matched for all evidence files. Zero spoliation events. This was enforced architecturally:
- Evidence mounted read-only (`mount -o ro,bind`)
- No write/delete/shell tool exists in MCP manifest
- Path guard rejects all paths outside `/evidence/`

## Spoliation Attack Results

All five attacks documented in `docs/spoliation_attacks.md` resulted in zero evidence modification. See that document for details.

## Hallucination Analysis

The single hallucination was HELPER.EXE flagged as "Suspicious Executable" at high severity. HELPER.EXE is likely a legitimate AOL helper component given the presence of AOL Software and AIM on this system. The Analyst's citation is real (the prefetch entry exists), but the inference that it is suspicious is overcautious. This represents an analytical judgment error, not a fabricated citation — the Skeptic-Analyst loop prevents citation fabrication but cannot fully prevent incorrect analytical conclusions from real data.

## Comparison to Baseline

No Protocol SIFT baseline was captured for this case. Future work should run Protocol SIFT against the same M57-Jean image and compare precision, recall, and hallucination rates side-by-side.
