const STORAGE_KEY = 'algoquest-progress-v2';
const levels = window.ALGOQUEST_LEVELS || [];

const state = {
  selectedWorld: 1,
  selectedLevelId: null,
  selectedIndices: [],
  selectedChoice: '',
  hintIndex: 0,
  score: 0,
  stars: 0,
  completed: {},
  rank: 'Novice',
  currentArray: [],
  swapCount: 0
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

function normalizeCsv(value) {
  return String(value || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
    .join(',');
}

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
  if (state.stars >= 30) return 'Algorithm Master';
  if (state.stars >= 22) return 'Algorithm Ranger';
  if (state.stars >= 14) return 'Code Scout';
  if (state.stars >= 6) return 'Array Apprentice';
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
  const previousWorld = world - 1;
  const previousLevels = levels.filter((l) => l.world === previousWorld);
  const earned = previousLevels.reduce((sum, level) => sum + (state.completed[level.id]?.stars || 0), 0);
  return earned >= Math.max(6, previousLevels.length * 2);
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
      ? `${level.title} ${'★'.repeat(stars)}${'☆'.repeat(3 - stars)}`
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
  if (!arr || arr.length === 0) {
    el.arrayArea.innerHTML = '<p class="muted">This level is concept/code focused and does not use bar visualization.</p>';
    return;
  }

  const max = Math.max(...arr, 1);
  arr.forEach((value, idx) => {
    const bar = document.createElement('button');
    bar.className = 'bar';
    bar.style.height = `${30 + (value / max) * 110}px`;
    bar.textContent = `${value}`;
    if (highlight.includes(idx)) bar.classList.add('active');
    bar.onclick = () => handleBarClick(idx);
    el.arrayArea.appendChild(bar);
  });
}

function renderPrompt(level) {
  el.promptArea.innerHTML = '';

  const lesson = document.createElement('p');
  lesson.className = 'muted';
  lesson.textContent = `Learn: ${level.lesson}`;
  el.promptArea.appendChild(lesson);

  if (level.type === 'mcq') {
    level.choices.forEach((choice) => {
      const row = document.createElement('div');
      const input = document.createElement('input');
      input.type = 'radio';
      input.name = 'mcq';
      input.value = choice.value;
      input.onchange = () => {
        state.selectedChoice = choice.value;
      };
      const label = document.createElement('label');
      label.style.marginLeft = '0.5rem';
      label.textContent = choice.label;
      row.appendChild(input);
      row.appendChild(label);
      el.promptArea.appendChild(row);
    });
  }

  if (level.type === 'index-answer') {
    const input = document.createElement('input');
    input.type = 'number';
    input.id = 'index-answer';
    input.placeholder = 'Enter index answer';
    el.promptArea.appendChild(input);
  }

  if (level.type === 'text-answer') {
    const input = document.createElement('input');
    input.type = 'text';
    input.id = 'text-answer';
    input.placeholder = 'e.g. 1,3,2,4';
    input.style.width = '100%';
    el.promptArea.appendChild(input);
  }

  if (level.type === 'code') {
    const textarea = document.createElement('textarea');
    textarea.id = 'cpp-code';
    textarea.value = level.starterCode;
    el.promptArea.appendChild(textarea);
  }

  if (level.type === 'swap-target') {
    const info = document.createElement('p');
    info.className = 'muted';
    info.textContent = 'Select exactly two bars to perform one swap. Then click Run / Check.';
    el.promptArea.appendChild(info);
  }
}

function loadLevel(levelId) {
  state.selectedLevelId = levelId;
  state.selectedIndices = [];
  state.selectedChoice = '';
  state.hintIndex = 0;
  state.swapCount = 0;

  const level = getCurrentLevel();
  state.currentArray = [...(level.array || [])];

  el.levelTitle.textContent = `${level.title} (World ${level.world})`;
  el.levelConcept.textContent = `Concept: ${level.concept}`;
  el.levelMission.textContent = `Mission: ${level.mission}`;

  renderArrayBars(state.currentArray);
  renderPrompt(level);
  el.feedback.textContent = 'Mission loaded. Work through the concept, then click Run / Check.';
}

function computeStars(level, passed, hintUsed) {
  if (!passed) return 0;

  let stars = hintUsed ? 2 : 3;
  if (level.type === 'swap-target' && level.maxSwapsForBonus && state.swapCount > level.maxSwapsForBonus) {
    stars = Math.max(1, stars - 1);
  }
  return stars;
}

function markCompletion(level, passed, hintUsed) {
  if (!passed) return;

  const stars = computeStars(level, passed, hintUsed);
  const points = 80 + stars * 20;
  const previous = state.completed[level.id];

  if (!previous) {
    state.completed[level.id] = { stars };
    state.score += points;
    state.stars += stars;
  } else if (stars > previous.stars) {
    state.stars += stars - previous.stars;
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

async function evaluateCodeChallenge(level, code) {
  const response = await fetch('/api/evaluate-cpp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId: level.challengeId, code })
  });

  const result = await response.json();
  return {
    passed: Boolean(result.passed),
    message: result.passed
      ? 'Code challenge passed. Great algorithm logic!'
      : `Missing: ${(result.checks?.missing || []).join(', ') || 'none'} | Forbidden: ${(result.checks?.forbiddenFound || []).join(', ') || 'none'}`
  };
}

async function runCheck() {
  const level = getCurrentLevel();
  if (!level) return;

  let passed = false;
  let message = 'Not checked.';

  if (level.type === 'mcq') {
    passed = state.selectedChoice === level.answer;
    message = passed ? 'Correct decision.' : 'Not quite. Re-read the lesson line.';
  }

  if (level.type === 'index-answer') {
    const value = Number(document.getElementById('index-answer')?.value);
    passed = value === level.expectedIndex;
    message = passed ? 'Correct index.' : `Expected index logic mismatch.`;
    if (passed && level.array) renderArrayBars(level.array, [value]);
  }

  if (level.type === 'text-answer') {
    const value = normalizeCsv(document.getElementById('text-answer')?.value);
    passed = value === normalizeCsv(level.expectedText);
    message = passed ? 'Correct trace/result.' : `Expected format like: ${level.expectedText}`;
  }

  if (level.type === 'swap-target') {
    passed = normalizeCsv(state.currentArray) === normalizeCsv(level.target);
    message = passed
      ? `Sorted achieved in ${state.swapCount} swap(s).`
      : 'Array is not at target order yet. Continue swapping then Run / Check.';
  }

  if (level.type === 'code') {
    const code = document.getElementById('cpp-code')?.value || '';
    try {
      const result = await evaluateCodeChallenge(level, code);
      passed = result.passed;
      message = result.message;
    } catch {
      passed = false;
      message = 'Code evaluation service unavailable. Try again.';
    }
  }

  el.feedback.textContent = message;
  markCompletion(level, passed, isHintUsed());
}

function handleBarClick(index) {
  const level = getCurrentLevel();
  if (!level || level.type !== 'swap-target') return;

  if (state.selectedIndices.includes(index)) {
    state.selectedIndices = state.selectedIndices.filter((i) => i !== index);
  } else if (state.selectedIndices.length < 2) {
    state.selectedIndices.push(index);
  } else {
    state.selectedIndices = [state.selectedIndices[1], index];
  }

  if (state.selectedIndices.length === 2) {
    const [a, b] = state.selectedIndices;
    [state.currentArray[a], state.currentArray[b]] = [state.currentArray[b], state.currentArray[a]];
    state.swapCount += 1;
    state.selectedIndices = [];
    renderArrayBars(state.currentArray, [a, b]);
    el.feedback.textContent = `Swap performed. Total swaps: ${state.swapCount}`;
    return;
  }

  renderArrayBars(state.currentArray, state.selectedIndices);
}

function showHint() {
  const level = getCurrentLevel();
  if (!level) return;
  const hint = level.hints[Math.min(state.hintIndex, level.hints.length - 1)] || 'No hint available.';
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

  if (worldLevels[idx + 1]) {
    loadLevel(worldLevels[idx + 1].id);
    return;
  }

  const nextWorldFirst = levels.find((l) => l.world === current.world + 1);
  if (nextWorldFirst && worldUnlocked(nextWorldFirst.world)) {
    state.selectedWorld = nextWorldFirst.world;
    renderLevels();
    loadLevel(nextWorldFirst.id);
  } else {
    el.feedback.textContent = 'World complete. Earn more stars to unlock the next world.';
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
