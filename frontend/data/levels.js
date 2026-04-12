window.ALGOQUEST_LEVELS = [
  {
    id: 'w1-l1',
    world: 1,
    title: 'Compare & Predict',
    type: 'predict',
    concept: 'Comparing values',
    mission: 'Which value is larger: index 1 or index 2?',
    array: [4, 9, 6, 2],
    question: { left: 1, right: 2, answer: 1 },
    hints: [
      'Compare bar heights or numeric values.',
      '9 and 6 are being compared in this mission.',
      'Index 1 is larger than index 2.'
    ]
  },
  {
    id: 'w1-l2',
    world: 1,
    title: 'Swap to Sort',
    type: 'swap',
    concept: 'Swapping and local order',
    mission: 'Click two indices to swap and make array sorted.',
    array: [1, 3, 2, 4],
    target: [1, 2, 3, 4],
    hints: [
      'Only one inversion exists.',
      'The values 3 and 2 are out of order.',
      'Swap index 1 and index 2.'
    ]
  },
  {
    id: 'w2-l1',
    world: 2,
    title: 'Linear Search Mission',
    type: 'search',
    concept: 'Linear search',
    mission: 'Find target 7 using linear scan.',
    array: [5, 1, 7, 8, 3],
    targetValue: 7,
    expectedIndex: 2,
    hints: [
      'Start from index 0 and move right.',
      'Check each value one by one until match.',
      'The target is at index 2.'
    ]
  },
  {
    id: 'w2-l2',
    world: 2,
    title: 'Binary Search Choice',
    type: 'binary-choice',
    concept: 'Binary search interval halving',
    mission: 'Sorted array shown. Choose the first mid index for target 22.',
    array: [3, 8, 12, 22, 31, 44, 50],
    targetValue: 22,
    expectedMid: 3,
    hints: [
      'mid = (low + high) / 2 with low=0 high=6.',
      'Integer division of (0 + 6) / 2 equals 3.',
      'Pick index 3.'
    ]
  },
  {
    id: 'w3-l1',
    world: 3,
    title: 'Fix the Bug (C++)',
    type: 'code',
    concept: 'Loop bounds in linear search',
    mission: 'Repair this C++ function so it checks all elements.',
    starterCode: `int linearSearch(const vector<int>& arr, int target) {\n  for (int i = 0; i < arr.size() - 1; i++) {\n    if (arr[i] == target) return i;\n  }\n  return -1;\n}`,
    validator: {
      requiredSubstrings: ['i < arr.size()', 'if (arr[i] == target)', 'return -1'],
      forbiddenSubstrings: ['arr.size() - 1']
    },
    hints: [
      'Off-by-one bug is in loop condition.',
      'The last element is currently skipped.',
      'Use i < arr.size().' 
    ]
  }
];
