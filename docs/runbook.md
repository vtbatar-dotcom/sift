# SIFT Sentinel Runbook

## Prerequisites

- Ubuntu 22.04+ (SIFT Workstation recommended)
- Python 3.11+
- Sleuth Kit tools: `fls`, `icat`, `istat`, `mmls`, `mactime`
- Anthropic API key with credits

## Setup

```bash
# Clone and install
git clone <repo-url>
cd sift-sentinel
pip install -e ".[dev]" --break-system-packages
export PATH="$HOME/.local/bin:$PATH"

# Verify
sentinel --version
python3 -m pytest tests/ -v
```

## Evidence Preparation

```bash
# Create evidence vault
sudo mkdir -p /evidence/disk
sudo cp nps-2008-jean.E01 nps-2008-jean.E02 /evidence/disk/

# Make it read-only
sudo mount --bind /evidence /evidence
sudo mount -o remount,ro,bind /evidence

# Verify
touch /evidence/test 2>&1  # Should fail

# Create cache directory for tool scratch space
sudo mkdir -p /var/cache/sentinel
sudo chown $USER:$USER /var/cache/sentinel
```

## Running an Investigation

```bash
# Set API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Create manifest (hashes evidence)
sentinel manifest create m57-jean /evidence/disk/nps-2008-jean.E01 /evidence/disk/nps-2008-jean.E02

# Start session (verifies hashes)
sentinel case start m57-jean

# Run investigation
sentinel investigate m57-jean --prompt "Identify user activity and suspicious behavior"

# Dry run (no API calls, tests evidence gathering)
sentinel investigate m57-jean --prompt "test" --dry-run
```

## Outputs

After investigation, find results in:

- `cases/m57-jean/sessions/<session-id>/report.md` — narrative report
- `cases/m57-jean/sessions/<session-id>/report.json` — structured findings
- `cases/m57-jean/sessions/<session-id>/execution.jsonl` — tool call audit log
- `cases/m57-jean/iterations/<finding-id>.jsonl` — Skeptic loop traces

## Troubleshooting

**`sentinel: command not found`**
```bash
export PATH="$HOME/.local/bin:$PATH"
```

**`PathGuardError: outside the evidence vault`**
Evidence files must be under `/evidence/`. Check the vault mount.

**`IntegrityError: mismatch`**
Evidence was modified since the manifest was created. Re-create the manifest or restore original files.

**API authentication errors**
Verify `ANTHROPIC_API_KEY` is set and has credits.
