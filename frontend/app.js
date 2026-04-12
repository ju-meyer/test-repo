const STORAGE_KEY = 'algoquest-progress-v1';
const levels = window.ALGOQUEST_LEVELS || [];

const state = {
  selectedWorld: 1,
  selectedLevelId: null,
  selectedIndices: [],
  hintIndex: 0,
  score: 0,
  stars: 0,
  completed: {},
  rank: 'Novice'
};

const el = {
  worlds: document.getElementById('worlds'),
  levels: document.getElementById('levels'),
  levelTitle: document.getElementById('level-title'),
  levelConcept: document.getElementById('level-concept'),
  levelMission: document.getElementById('level-mission'),
  arrayArea: document.getElementById('array-area'),
  promptArea: document.getElementById('prompt-area'),
  feedback: document.getElementById('feedback'),
  runBtn: document.getElementById('run-btn'),
  hintBtn: document.getElementById('hint-btn'),
  resetBtn: document.getElementById('reset-btn'),
  nextBtn: document.getElementById('next-btn'),
  score: document.getElementById('score'),
  stars: document.getElementById('stars'),
  rank: document.getElementById('rank')
};

function saveProgress() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    score: state.score,
    stars: state.stars,
    completed: state.completed
  }));
}

function loadProgress() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return;
  try {
    const parsed = JSON.parse(raw);
    state.score = parsed.score || 0;
    state.stars = parsed.stars || 0;
    state.completed = parsed.completed || {};
  } catch {
    // ignore malformed progress
  }
}

function deriveRank() {
  if (state.stars >= 10) return 'Algorithm Ranger';
  if (state.stars >= 6) return 'Code Scout';
  if (state.stars >= 3) return 'Array Apprentice';
  return 'Novice';
}

function renderStats() {
  state.rank = deriveRank();
  el.score.textContent = `Score: ${state.score}`;
  el.stars.textContent = `Stars: ${state.stars}`;
  el.rank.textContent = `Rank: ${state.rank}`;
}

function worldUnlocked(world) {
  if (world === 1) return true;
  const prevWorldStars = Object.entries(state.completed)
    .filter(([id]) => levels.find((l) => l.id === id)?.world === world - 1)
    .reduce((sum, [, data]) => sum + (data.stars || 0), 0);
  return prevWorldStars >= 2;
}

function renderWorlds() {
  const worlds = [...new Set(levels.map((l) => l.world))];
  el.worlds.innerHTML = '';
  worlds.forEach((world) => {
    const unlocked = worldUnlocked(world);
    const button = document.createElement('button');
    button.className = `world-btn ${unlocked ? '' : 'locked'}`;
    button.textContent = unlocked ? `World ${world}` : `World ${world} 🔒`;
    button.disabled = !unlocked;
    button.onclick = () => {
      state.selectedWorld = world;
      renderLevels();
    };
    el.worlds.appendChild(button);
  });
}

function renderLevels() {
  const worldLevels = levels.filter((l) => l.world === state.selectedWorld);
  el.levels.innerHTML = '';
  worldLevels.forEach((level, idx) => {
    const prev = worldLevels[idx - 1];
    const unlocked = idx === 0 || Boolean(state.completed[prev.id]);
    const button = document.createElement('button');
    const stars = state.completed[level.id]?.stars || 0;
    button.className = `level-btn ${unlocked ? '' : 'locked'}`;
    button.textContent = unlocked
      ? `${level.title} ${'★'.repeat(stars)}`
      : `${level.title} 🔒`;
    button.disabled = !unlocked;
    button.onclick = () => loadLevel(level.id);
    el.levels.appendChild(button);
  });
}

function getCurrentLevel() {
  return levels.find((l) => l.id === state.selectedLevelId);
}

function renderArrayBars(arr, highlight = []) {
  el.arrayArea.innerHTML = '';
  const max = Math.max(...arr, 1);
  arr.forEach((value, idx) => {
    const bar = document.createElement('button');
    bar.className = 'bar';
    bar.style.height = `${30 + (value / max) * 110}px`;
    bar.textContent = `${value}`;
    if (highlight.includes(idx)) {
      bar.classList.add('active');
    }
    bar.onclick = () => handleBarClick(idx);
    el.arrayArea.appendChild(bar);
  });
}

function renderPrompt(level) {
  el.promptArea.innerHTML = '';

  if (level.type === 'predict') {
    const { left, right } = level.question;
    const wrapper = document.createElement('div');
    wrapper.innerHTML = `
      <p>Choose the larger index:</p>
      <button data-ans="${left}">Index ${left}</button>
      <button data-ans="${right}">Index ${right}</button>
    `;
    wrapper.querySelectorAll('button').forEach((btn) => {
      btn.onclick = () => {
        state.selectedIndices = [Number(btn.dataset.ans)];
        renderArrayBars(level.array, [left, right, Number(btn.dataset.ans)]);
      };
    });
    el.promptArea.appendChild(wrapper);
  }

  if (level.type === 'search') {
    const input = document.createElement('input');
    input.type = 'number';
    input.placeholder = 'Enter found index';
    input.id = 'answer-index';
    el.promptArea.appendChild(input);
  }

  if (level.type === 'binary-choice') {
    const input = document.createElement('input');
    input.type = 'number';
    input.placeholder = 'Enter first mid index';
    input.id = 'answer-mid';
    el.promptArea.appendChild(input);
  }

  if (level.type === 'code') {
    const textarea = document.createElement('textarea');
    textarea.id = 'cpp-code';
    textarea.value = level.starterCode;
    el.promptArea.appendChild(textarea);
  }
}

function loadLevel(levelId) {
  state.selectedLevelId = levelId;
  state.selectedIndices = [];
  state.hintIndex = 0;

  const level = getCurrentLevel();
  el.levelTitle.textContent = `${level.title} (World ${level.world})`;
  el.levelConcept.textContent = `Concept: ${level.concept}`;
  el.levelMission.textContent = `Mission: ${level.mission}`;

  renderArrayBars(level.array || []);
  renderPrompt(level);
  el.feedback.textContent = 'Mission loaded. Complete the objective and click Run / Check.';
}

function markCompletion(level, passed, hintUsed) {
  if (!passed) return;

  const already = state.completed[level.id];
  const stars = hintUsed ? 2 : 3;
  const points = hintUsed ? 80 : 120;

  if (!already) {
    state.score += points;
    state.stars += stars;
    state.completed[level.id] = { stars };
  } else if (stars > already.stars) {
    state.stars += (stars - already.stars);
    state.completed[level.id].stars = stars;
  }

  saveProgress();
  renderStats();
  renderWorlds();
  renderLevels();
}

function isHintUsed() {
  return state.hintIndex > 0;
}

async function runCheck() {
  const level = getCurrentLevel();
  if (!level) return;

  let passed = false;
  let msg = '';

  if (level.type === 'predict') {
    passed = state.selectedIndices[0] === level.question.answer;
    msg = passed
      ? 'Correct! You identified the larger value.'
      : 'Not yet. Pick the index with the larger value.';
  }

  if (level.type === 'swap') {
    const arr = [...level.array];
    const [a, b] = state.selectedIndices;
    if (a === undefined || b === undefined) {
      msg = 'Select exactly two bars to swap.';
    } else {
      [arr[a], arr[b]] = [arr[b], arr[a]];
      passed = arr.join(',') === level.target.join(',');
      renderArrayBars(arr, [a, b]);
      msg = passed ? 'Nice swap! Array is now sorted.' : 'After swap, array is not sorted yet.';
    }
  }

  if (level.type === 'search') {
    const value = Number(document.getElementById('answer-index')?.value);
    passed = value === level.expectedIndex;
    msg = passed
      ? 'Linear search success: correct index.'
      : 'Incorrect index. Think left-to-right scan.';
    if (passed) {
      renderArrayBars(level.array, [level.expectedIndex]);
    }
  }

  if (level.type === 'binary-choice') {
    const value = Number(document.getElementById('answer-mid')?.value);
    passed = value === level.expectedMid;
    msg = passed
      ? 'Correct midpoint! Binary search begins there.'
      : 'Try midpoint formula with low=0 and high=n-1.';
    if (passed) renderArrayBars(level.array, [value]);
  }

  if (level.type === 'code') {
    const code = document.getElementById('cpp-code')?.value || '';
    try {
      const response = await fetch('/api/evaluate-cpp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId: level.id, code })
      });
      const result = await response.json();
      passed = Boolean(result.passed);
      msg = passed
        ? 'Great fix. Loop now checks all elements.'
        : `Validation failed: missing [${(result.checks?.missing || []).join(', ')}], forbidden [${(result.checks?.forbiddenFound || []).join(', ')}].`;
    } catch {
      const requiredOk = level.validator.requiredSubstrings.every((s) => code.includes(s));
      const forbiddenOk = level.validator.forbiddenSubstrings.every((s) => !code.includes(s));
      passed = requiredOk && forbiddenOk;
      msg = passed
        ? 'Great fix. Loop now checks all elements. (local fallback)'
        : 'Validation failed: check loop boundary and required logic.';
    }
  }

  el.feedback.textContent = msg;
  markCompletion(level, passed, isHintUsed());
}

function handleBarClick(idx) {
  const level = getCurrentLevel();
  if (!level || level.type !== 'swap') return;

  if (state.selectedIndices.includes(idx)) {
    state.selectedIndices = state.selectedIndices.filter((i) => i !== idx);
  } else if (state.selectedIndices.length < 2) {
    state.selectedIndices.push(idx);
  } else {
    state.selectedIndices = [state.selectedIndices[1], idx];
  }

  renderArrayBars(level.array, state.selectedIndices);
}

function showHint() {
  const level = getCurrentLevel();
  if (!level) return;
  const hint = level.hints[Math.min(state.hintIndex, level.hints.length - 1)];
  state.hintIndex += 1;
  el.feedback.textContent = `Hint ${Math.min(state.hintIndex, level.hints.length)}: ${hint}`;
}

function resetLevel() {
  if (!state.selectedLevelId) return;
  loadLevel(state.selectedLevelId);
}

function nextLevel() {
  const current = getCurrentLevel();
  if (!current) return;
  const worldLevels = levels.filter((l) => l.world === current.world);
  const idx = worldLevels.findIndex((l) => l.id === current.id);
  const next = worldLevels[idx + 1];
  if (next) {
    loadLevel(next.id);
  } else {
    el.feedback.textContent = 'World complete! Unlock the next world with earned stars.';
  }
}

function init() {
  loadProgress();
  renderStats();
  renderWorlds();
  renderLevels();

  el.runBtn.onclick = runCheck;
  el.hintBtn.onclick = showHint;
  el.resetBtn.onclick = resetLevel;
  el.nextBtn.onclick = nextLevel;

  const firstLevel = levels.find((l) => l.world === 1);
  if (firstLevel) loadLevel(firstLevel.id);
}

init();
