# Agent 1 / Agent 2 dashboard integration

The active data path is `pipeline_runtime.py` → Redis `observation.v2` → Agent 2 worker → Redis `decision.v2` / `incident.v2` → this backend → dashboard REST and WebSocket clients.

The backend reads both V2 streams from their retained beginning on startup, then blocks for new entries. Its bounded product store deduplicates decisions and retains up to 10,000 decisions and incidents. This recovers records produced before the backend started or while it was disconnected. Redis stream retention limits recovery; Redis persistence must be enabled if records need to survive a Redis restart. `V2_STORE_PATH` optionally adds a local projection journal. The legacy `alert.new` subscription remains compatible with existing producers.

REST endpoints:

- `GET /api/v2/decisions` and `/api/v2/decisions/:id` return original V2 records, including benign decisions.
- `GET /api/v2/incidents` and `/api/v2/incidents/:id` return correlated timelines.
- `GET /api/alerts` projects non-benign decisions for the existing alert feed, retaining V2 evidence.
- `GET /api/stats` reads Agent 2 telemetry; `source=waiting_for_agent2` means no current snapshot is available.
- `GET /api/simulation`, `POST /api/simulation/start`, and `POST /api/simulation/stop` control a backend-owned Agent 1 simulator. Start/stop require a localhost client. They require the separately running Agent 2 worker to produce decisions.

Simulation starts `pipeline_runtime.py simulate --continuous --interval 0.05 --family all` with the backend's `REDIS_URL`. Python resolution prefers `.venv_linux/bin/python` on Linux, `.venv/Scripts/python.exe` on Windows, and accepts `PYTHON_EXECUTABLE` as an override. Stopping the simulator only terminates the process launched by this backend; a simulator launched from a terminal is managed from that terminal.

The dashboard distinguishes candidate scores from approved threat decisions. `POLICY_NOT_VALIDATED` remains visible, missing confidence stays null, and `label_probabilities` can be inspected even while the decision abstains as `UNCERTAIN`. The dashboard does not approve thresholds or manufacture incidents for candidate decisions.

Run `npm test -- --runInBand` in this directory and `npm run build` in `soc-dashboard` to validate integration.
