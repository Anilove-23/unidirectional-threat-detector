# SENTINEL-D — SIH26145 Frontend

Passive threat-detection SOC dashboard for **SIH26145 — AI-Based Detection of
Cyber Threats in Unidirectional IP Traffic** (NTRO). Built by Person 5
(Frontend & Integration).

This is a **read-only visualization layer**. It has no controls to block,
quarantine, reset, or otherwise act on the monitored network — it renders
alerts produced upstream by the detection pipeline.

## Stack

React 18 · Vite · Tailwind CSS · Zustand · Recharts · react-router-dom · native WebSocket

## Getting started

```bash
npm install
cp .env.example .env   # already done; edit if your backend runs elsewhere
npm run dev
```

The app starts on `http://localhost:5173`.

## Configuration

All backend endpoints are environment-driven — nothing is hardcoded in source.

| Variable              | Purpose                                              |
|------------------------|-------------------------------------------------------|
| `VITE_API_URL`         | Express backend REST base URL                        |
| `VITE_WS_URL`          | WebSocket endpoint streaming standardized JSON alerts |
| `VITE_USE_MOCK_DATA`   | `true` = run entirely on local mock data, no socket   |

### Switching from mock to the real backend

1. Set `VITE_USE_MOCK_DATA=false` in `.env`.
2. Point `VITE_WS_URL` at Person 4's Express/WebSocket service.
3. Restart the dev server.

No component code needs to change — `src/hooks/useWebSocket.js` is the only
place that decides between `WebSocketService` (real) and
`MockWebSocketService` (mock), and both implement the same interface.

## Alert contract

The dashboard is built around the standardized JSON alert schema in
`src/types/alert.js`. This is the single source of truth for field names —
if the backend contract changes, update that file first, and
`normalizeAlert()` will validate/normalize every incoming WebSocket message
against it (malformed frames are dropped, never rendered).

## Live Demo Mode

For the SIH demo, use the **"Run scripted demo sequence"** control on the
Dashboard (visible only in mock mode). It replays a fixed, narratively
ordered sequence of alerts — port scan → DNS tunnelling → DDoS → botnet C2 →
anomalous — through the same store path a real alert takes. It is a demo
utility only, not a simulation of live AI inference.

## Project structure

```
src/
├── components/
│   ├── layout/      Header, nav, pipeline signature strip
│   ├── dashboard/    charts, summary stats, demo control
│   ├── alerts/       live feed, filters, drill-down modal
│   └── common/       badges, connection status, score bars
├── pages/            Dashboard, Alerts, AlertDetailRoute
├── hooks/            useWebSocket, useLiveDemo
├── store/            alertStore (Zustand)
├── services/         websocket.js (real + mock transports)
├── utils/            formatters, threat/severity helpers
├── mock/             mockAlerts.js, demoMode.js
└── types/            alert.js — the schema contract
```

## Routes

- `/dashboard` — summary stats, charts, live feed
- `/alerts` — full filterable/searchable alert table
- `/alerts/:flowId` — deep-linkable drill-down (renders as a modal over `/alerts`)

## Notes on environment constraints

This project was authored in a sandboxed environment without npm registry
access, so dependencies could not be installed or the dev server run here.
The source is complete and self-contained — run `npm install && npm run dev`
locally to build and verify it. If anything doesn't compile, it's most
likely a version pin in `package.json` worth loosening rather than a
structural issue; open an issue against this repo's task tracker if you hit
one and it isn't obvious.
