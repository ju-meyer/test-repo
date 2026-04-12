const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'frontend')));

const levelCatalog = [
  { id: 'w1-l1', world: 1, title: 'Compare & Predict', type: 'predict' },
  { id: 'w1-l2', world: 1, title: 'Swap to Sort', type: 'swap' },
  { id: 'w2-l1', world: 2, title: 'Linear Search Mission', type: 'search' },
  { id: 'w2-l2', world: 2, title: 'Binary Search Choice', type: 'binary-choice' },
  { id: 'w3-l1', world: 3, title: 'Fix the Bug (C++)', type: 'code' }
];

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

  if (challengeId !== 'w3-l1') {
    return res.status(400).json({
      passed: false,
      error: `Unknown challengeId: ${challengeId}`
    });
  }

  const requiredSubstrings = ['i < arr.size()', 'if (arr[i] == target)', 'return -1'];
  const forbiddenSubstrings = ['arr.size() - 1'];

  const missing = requiredSubstrings.filter((fragment) => !code.includes(fragment));
  const forbiddenFound = forbiddenSubstrings.filter((fragment) => code.includes(fragment));

  const passed = missing.length === 0 && forbiddenFound.length === 0;

  return res.json({
    passed,
    checks: {
      missing,
      forbiddenFound
    },
    feedback: passed
      ? 'All required checks passed for MVP validator.'
      : 'Adjust loop bounds and include expected conditions.'
  });
});

app.listen(PORT, () => {
  console.log(`AlgoQuest MVP running at http://localhost:${PORT}`);
});
