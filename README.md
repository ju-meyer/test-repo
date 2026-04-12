# AlgoQuest: Sort & Search Academy (MVP)

AlgoQuest is a browser-based educational game that teaches sorting and searching algorithms through visual gameplay and C++-focused coding challenges.

## What this MVP includes
- A playable browser game loop with level progression.
- Real-time visual feedback on arrays (bars/cards) during comparisons and swaps.
- Early concept levels (no full coding required).
- Mid-tier challenge levels for prediction/debugging/fill-in style tasks.
- A first C++ challenge evaluator for scaffolded coding missions.
- Hints, stars, score, and world unlock progression.

## Quick start
```bash
npm install
npm start
```

Open: `http://localhost:3000`

## Scripts
- `npm start` — start local server
- `npm run dev` — same as start
- `npm run check` — syntax check backend JS

## High-level architecture
- `frontend/` — game UI, rendering, level engine, and interaction loop.
- `backend/` — Express server, static file hosting, level metadata API, and simple C++ challenge grading stub.
- `docs/` — MVP product requirements, progression plan, and phased roadmap.

## Notes on C++ execution for MVP
This MVP uses **structured challenge validation** (pattern checks + test-case style checks) rather than true native C++ execution.

Future-ready options are documented in `docs/MVP_PRD.md`:
1. WebAssembly C++ toolchain in-browser
2. Sandboxed remote compile/run service
3. Hybrid mode (local validation + remote verification)
