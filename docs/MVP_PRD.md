# AlgoQuest MVP Product Requirements Document

## 1) Product vision
Build a polished, browser-based learning game that teaches search and sort algorithms as both:
- **Intuition** (how values move and why an algorithm works), and
- **Skill** (reading, debugging, and writing C++ algorithm code).

The game should feel like a mission-driven puzzle game, not a static quiz.

## 2) Target users
- Beginners learning DSA fundamentals.
- Students preparing for coding interviews/classes.
- Self-learners who prefer visual + interactive practice.

## 3) Core MVP principles
- Single-player only.
- Browser-first; no account required.
- Immediate visual feedback after each action.
- Progressive complexity from visual tasks to coding tasks.
- Tight scope suitable for one developer.

## 4) Learning progression (pedagogy-first)

### Stage A: Visual intuition (World 1)
Goal: understand compare/swap and sortedness.
- Recognize bigger vs smaller values.
- Predict what a swap will do.
- Identify sorted vs unsorted arrays.

### Stage B: Guided algorithms (World 2)
Goal: perform steps of search/sort with scaffolding.
- Linear search step-by-step.
- Binary search interval elimination.
- Bubble/selection/insertion mechanics via guided turns.

### Stage C: Debug/fill-in code (World 3)
Goal: translate concept to C++ syntax and logic.
- Fix off-by-one errors.
- Fill missing loop/condition logic.
- Predict output and explain bug causes.

### Stage D: Full implementations + strategy (World 4)
Goal: write complete C++ functions and select best algorithm.
- Implement full search/sort functions.
- Compare algorithm behavior by input shape.
- Reason about stability and performance intuition.

## 5) Algorithms/concepts included in MVP scope
- Comparing values
- Swapping
- Sorted vs unsorted arrays
- Linear search
- Binary search
- Bubble sort
- Selection sort
- Insertion sort
- Intro to merge and quick sort (visual intuition + selection, not full deep coding in MVP)
- Stability intuition
- Basic performance intuition (small, medium, large)
- Stretch scaffolding hooks for:
  - custom comparators
  - first/last occurrence in binary search
  - edge-case drills

## 6) Game systems

### Progression system
- **Worlds** unlock sequentially.
- Levels award 1–3 stars based on:
  - correctness
  - efficiency (few actions / lower operation count)
  - hint conservation
- Unlock rule: minimum star threshold from prior world.

### Scoring model (MVP)
- Base completion points.
- Bonus for first-try pass.
- Penalty for hints used.
- Efficiency bonus for fewer comparisons/swaps.

### Hint system
Three-tier hint ladder:
1. Concept hint
2. Algorithmic direction
3. Near-explicit instruction

## 7) Single-level gameplay loop
1. **Briefing**: mission + concept objective.
2. **Play phase**: user interacts (predict/drag/select/code).
3. **Run**: system animates steps and updates metrics.
4. **Feedback**: pass/fail + what was correct/incorrect.
5. **Reflect**: show operation counts, quick explanation, optional retry.
6. **Reward**: points/stars/badge progress.
7. **Next**: unlock next level or suggest remediation.

## 8) Coding challenge design for browser
- Use structured challenge templates:
  - prompt
  - starter C++ signature
  - hidden + visible test cases
  - target checks (tokens/patterns/edge behaviors)
- Challenge types:
  - fix-the-bug
  - fill-in-the-blank
  - write-function
- MVP grader returns:
  - pass/fail
  - failing case summary
  - hint trigger suggestions

## 9) C++ execution strategy (MVP recommendation)

### MVP default: simulated validation (recommended)
- No heavy compiler/runtime setup.
- Validate code by expected structure and deterministic pseudo-tests.
- Great for prototype speed and educational pacing.

### Post-MVP options
1. **In-browser WASM toolchain** (e.g., Clang/LLVM wasm-based runner)
2. **Remote sandbox execution service** with strict resource limits
3. **Hybrid mode** for instant feedback + authoritative compile check

## 10) Tech stack recommendation

### MVP stack (chosen for scaffold)
- **Frontend**: HTML/CSS/Vanilla JS modules (game loop + animation)
- **Backend**: Node.js + Express
- **State**: localStorage for progress/stars/settings
- **Visualization**: DOM/CSS bar animation (low complexity, easy polish)

### Why this stack
- Fastest route to polished prototype for one developer.
- Easy migration path to React + TypeScript later.
- Minimal operational complexity.

## 11) Proposed folder structure

```text
backend/
  server.js
frontend/
  index.html
  styles.css
  app.js
  data/
    levels.js
docs/
  MVP_PRD.md
README.md
package.json
```

## 12) Non-goals for MVP
- Multiplayer
- User accounts/cloud sync
- Complex backend analytics pipeline
- Full competitive leaderboard infra
- Full production-grade C++ sandboxing

## 13) Success criteria
- User can complete at least one world end-to-end.
- User experiences visual + coding challenge modes in one session.
- Progress and stars persist locally.
- Feedback feels immediate and game-like.

## 14) Development roadmap

### Phase 1: Core gameplay shell
- UI frame, world map, mission panel, stats panel.
- Basic level loader and state machine.
- Progress persistence.

### Phase 2: Visual algorithm interactions
- Bar animations, compare/swap highlighting.
- Guided levels for compare/swap/search intuition.
- Step replay and reset.

### Phase 3: Coding challenge foundation
- Embedded code editor textarea.
- Fill-in/debug challenge templates.
- Simple evaluator API + local feedback rendering.

### Phase 4: Progression polish
- Stars, badges, unlock gating.
- Hint ladder and scoring refinements.
- End-of-world summary screen.

### Phase 5: Quality and expansion hooks
- Add additional levels for insertion/selection/binary edge cases.
- Add performance comparison missions.
- Prepare for real C++ execution integration.
