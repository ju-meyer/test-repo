const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const levelCatalog = [
  { id: 'w1-l1', world: 1, title: 'Compare Values', type: 'mcq' },
  { id: 'w1-l2', world: 1, title: 'Single Swap Fix', type: 'swap-target' },
  { id: 'w1-l3', world: 1, title: 'Sorted vs Unsorted', type: 'mcq' },
  { id: 'w1-l4', world: 1, title: 'Predict Next Bubble Step', type: 'text-answer' },
  { id: 'w2-l1', world: 2, title: 'Linear Search Scan', type: 'index-answer' },
  { id: 'w2-l2', world: 2, title: 'Binary Search Midpoint', type: 'index-answer' },
  { id: 'w2-l3', world: 2, title: 'Binary Search Path', type: 'text-answer' },
  { id: 'w2-l4', world: 2, title: 'First Occurrence Logic', type: 'mcq' },
  { id: 'w3-l1', world: 3, title: 'Bubble Pass Result', type: 'text-answer' },
  { id: 'w3-l2', world: 3, title: 'Selection Sort Choice', type: 'index-answer' },
  { id: 'w3-l3', world: 3, title: 'Insertion Sort Insert Spot', type: 'index-answer' },
  { id: 'w3-l4', world: 3, title: 'Fix Linear Search Bug (C++)', type: 'code' },
  { id: 'w4-l1', world: 4, title: 'Choose Fastest Strategy', type: 'mcq' },
  { id: 'w4-l2', world: 4, title: 'Stability Check', type: 'mcq' },
  { id: 'w4-l3', world: 4, title: 'Write Binary Search First Occurrence (C++)', type: 'code' },
  { id: 'w4-l4', world: 4, title: 'Write Insertion Sort Core Loop (C++)', type: 'code' }
];

const challengeChecks = {
  'linear-search-fix': {
    requiredSubstrings: ['for', 'i < arr.size()', 'if (arr[i] == target)', 'return -1'],
    forbiddenSubstrings: ['arr.size() - 1']
  },
  'binary-first-occurrence': {
    requiredSubstrings: ['while (low <= high)', 'ans = mid', 'high = mid - 1', 'return ans'],
    forbiddenSubstrings: []
  },
  'insertion-sort-core': {
    requiredSubstrings: ['while (j >= 0 && arr[j] > key)', 'arr[j + 1] = arr[j]', 'arr[j + 1] = key'],
    forbiddenSubstrings: []
  }
};

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'algoquest-mvp', timestamp: new Date().toISOString() });
});

app.get('/api/levels', (_req, res) => {
  res.json({ count: levelCatalog.length, levels: levelCatalog });
});

app.post('/api/evaluate-cpp', (req, res) => {
  const { challengeId, code } = req.body;

  if (!challengeId || typeof code !== 'string') {
    return res.status(400).json({
      passed: false,
      error: 'challengeId and code are required.'
    });
  }

  const challenge = challengeChecks[challengeId];
  if (!challenge) {
    return res.status(400).json({
      passed: false,
      error: `Unknown challengeId: ${challengeId}`
    });
  }

  const missing = challenge.requiredSubstrings.filter((fragment) => !code.includes(fragment));
  const forbiddenFound = challenge.forbiddenSubstrings.filter((fragment) => code.includes(fragment));
  const passed = missing.length === 0 && forbiddenFound.length === 0;

  return res.json({
    passed,
    checks: {
      missing,
      forbiddenFound
    },
    feedback: passed
      ? 'All required checks passed for this challenge.'
      : 'Update algorithm logic and retry.'
  });
});

app.listen(PORT, () => {
  console.log(`AlgoQuest MVP running at http://localhost:${PORT}`);
});
