# AlgoQuest: Sort & Search Academy (MVP)

AlgoQuest is a browser-based educational game for learning searching and sorting algorithms through visual missions and C++ coding challenges.

## MVP gameplay scope
- 4 worlds with 16 levels.
- Foundations: compare, swap, sortedness, bubble step prediction.
- Searching: linear search, binary search midpoint/path, first-occurrence logic.
- Sorting: bubble, selection, insertion mechanics.
- C++ coding levels: bug-fixing and algorithm-writing challenges.
- Hints, stars, score, rank progression, and world unlocks.

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


## Quick verification
Run these checks before opening a PR:

```bash
npm run check
node --check frontend/app.js
```

## API endpoints
- `GET /api/health`
- `GET /api/levels`
- `POST /api/evaluate-cpp` with JSON body:
  - `challengeId` (`linear-search-fix`, `binary-first-occurrence`, `insertion-sort-core`)
  - `code` (C++ solution text)

## Architecture
- `frontend/`: game UI, level engine, progression logic, rendering.
- `backend/`: static hosting + level catalog + C++ challenge validator.
- `docs/`: PRD and roadmap.

## Notes
MVP challenge evaluation is structured validation (required/forbidden logic fragments), designed for fast feedback and single-developer build speed.
