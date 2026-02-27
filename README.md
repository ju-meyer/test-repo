# Homelab AI Assistant (MVP)

A local-first AI-powered assistant for Docker-based homelab stacks.

## Stack
- Backend: Node.js + Express
- Frontend: React dashboard (served as static HTML)
- Docker access: Docker CLI (with Docker socket available at `/var/run/docker.sock`)

## Features (MVP)
- List all Docker containers.
- Read container logs.
- Summarize logs (ERROR, WARN, stack traces).
- Compute per-container health score:
  - Healthy
  - Warning
  - Critical
- Natural language diagnostics mapping for prompts such as:
  - "Why did Radarr fail to import?"
  - "Is my VPN working?"
  - "Restart unhealthy containers."
  - "Why are downloads stalled?"
- Safe command execution policy:
  - Read-only diagnostics are encouraged.
  - Restart actions require explicit confirmation.
  - No destructive actions are implemented.

## Run
```bash
npm install
npm start
```

Then open: `http://localhost:3000`

## API Endpoints
- `GET /api/containers`
- `GET /api/logs/:containerName?tail=200`
- `GET /api/log-summary/:containerName?tail=200`
- `GET /api/health`
- `GET /api/system-monitor` (CPU, RAM, and `/media` storage utilization)
- `GET /api/qbittorrent/torrents` (current torrent name, state, progress, and transfer stats)
- `POST /api/diagnose` with JSON body: `{ "query": "Is my VPN working?" }`
- `POST /api/execute` with JSON body:
  `{ "action": "restart_container", "containerName": "radarr", "confirmed": true }`
- `GET /api/safety`


## Optional qBittorrent API env vars
- `QBITTORRENT_URL` (default: `http://127.0.0.1:8080`)
- `QBITTORRENT_USERNAME`
- `QBITTORRENT_PASSWORD`
