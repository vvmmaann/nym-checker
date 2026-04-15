# Nym Node Checker

A health and compliance checker for [Nym mixnet](https://nymtech.net) operators. Verifies node version, firewall ports, IPv6 reachability, hardware, Terms & Conditions acceptance and exit policy declaration, then scores each node out of 100.

Single-file FastAPI backend + vanilla JS frontend, no build step.

Live instance: http://185.186.76.89:8000

## Features

- **Per-node check**: TCP/UDP/QUIC port probes, hardware specs, version against latest release, T&C, exit policy verification
- **Batch check**: up to 35 nodes in one request
- **Network stats**: aggregated view of the whole Nym network (compliance %, version distribution, mode split, top issues)
- **IPv6 detection** in three tiers: self-declared (API), DNS AAAA resolution, remote probe through a Stockholm agent
- **Auto-sync** reference data (latest version, firewall ports) from nymtech/nym GitHub releases every 3 hours
- **Exit policy**: fetches Nym's official policy, parses accepted ports, confirms each exit node declares it
- **Pagination, search, multi-language UI** (9 languages), dark/light theme, mobile-friendly

## Tech

- Backend: Python 3 + FastAPI + httpx + uvicorn
- Frontend: vanilla JS in a single HTML file, no framework, no build
- Storage: flat JSON files with atomic writes

## Run locally

Requires Python 3.10+.

```bash
pip install fastapi uvicorn httpx
export NYM_CHECKER_TOKEN="your-secret-admin-token"  # optional, locks admin endpoints
export STATIC_DIR="$(pwd)/static"
python3 nym_checker_backend.py
# -> http://0.0.0.0:8000
```

## Deploy

See `deploy/` for systemd unit template and auto-deploy script.

## License

MIT
