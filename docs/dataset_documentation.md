# Dataset Documentation

## Primary Evidence: M57-Jean Laptop Image

**Source:** Digital Corpora — M57 Patents Scenario  
**URL:** https://digitalcorpora.org/corpora/scenarios/m57-patents-scenario  
**Type:** Disk image (EnCase E01 format, split)

### Files

| File | Size | SHA-256 |
|------|------|---------|
| nps-2008-jean.E01 | 1.46 GB | `df3a995c7a594e0b...` |
| nps-2008-jean.E02 | 1.37 GB | `07f1f78c857d5b58...` |

Full hashes are recorded in `cases/m57-jean/manifest.json`.

### Image Details

- **Operating System:** Windows XP Professional SP2
- **Computer Name:** JEAN-13FBF038A3
- **Partition Layout:** Single NTFS partition (sector 63, ~10 GB)
- **Environment:** VMware virtual machine

### User Accounts

| SID | Username | Profile Path |
|-----|----------|-------------|
| S-1-5-21-...-500 | Administrator | Documents and Settings\Administrator |
| S-1-5-21-...-1004 | Jean | Documents and Settings\Jean |
| S-1-5-21-...-1007 | Devon | Documents and Settings\Devon |

### Scenario Context

The M57-Patents scenario is a digital forensics teaching case developed by the Naval Postgraduate School. It simulates a corporate investigation involving potential intellectual property theft at a fictional company. The scenario includes multiple laptop images for different employees.

This project uses Jean's laptop image as the primary evidence source.

### Limitations

- **No memory dump available.** The M57 case provides disk images only. Memory analysis tools and correlation features are descoped to stretch goals.
- **Windows XP era artifacts.** Some modern forensic artifact types do not exist:
  - No AmCache (Windows 8+)
  - No EVTX logs (Vista+) — uses legacy .evt format
  - No ShimCache in AppCompatCache format (Vista+)
  - Prefetch uses v17 format (different offsets than modern versions)

### Evidence Integrity

Evidence files are stored in a read-only bind mount at `/evidence/disk/`. SHA-256 hashes are verified at session start and re-verified at session end to detect any modification.
