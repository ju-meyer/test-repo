window.ALGOQUEST_LEVELS = [
  // World 1: Foundations
  {
    id: 'w1-l1',
    world: 1,
    title: 'Compare Values',
    type: 'mcq',
    concept: 'Comparison basics',
    mission: 'Pick the pair that should be swapped to move toward ascending order.',
    lesson: 'Sorting algorithms repeatedly compare nearby or selected values. A swap is useful when left > right in ascending sort.',
    array: [4, 9, 6, 2],
    choices: [
      { label: 'indices 0 and 1', value: '0,1' },
      { label: 'indices 1 and 2', value: '1,2' },
      { label: 'indices 2 and 3', value: '2,3' }
    ],
    answer: '1,2',
    hints: ['Look for a descending adjacent pair.', '9 and 6 break ascending order.']
  },
  {
    id: 'w1-l2',
    world: 1,
    title: 'Single Swap Fix',
    type: 'swap-target',
    concept: 'Swapping',
    mission: 'Click two bars to swap. Reach sorted array in one swap.',
    lesson: 'A swap exchanges two positions. Good algorithms minimize unnecessary swaps.',
    array: [1, 3, 2, 4],
    target: [1, 2, 3, 4],
    maxSwapsForBonus: 1,
    hints: ['Only one inversion exists.', 'Swap 3 and 2.']
  },
  {
    id: 'w1-l3',
    world: 1,
    title: 'Sorted vs Unsorted',
    type: 'mcq',
    concept: 'Sortedness',
    mission: 'Identify which array is fully sorted ascending.',
    lesson: 'An array is sorted ascending when every element is <= the next.',
    choices: [
      { label: '[1, 2, 2, 5, 9]', value: 'a' },
      { label: '[1, 3, 2, 4, 5]', value: 'b' },
      { label: '[2, 2, 1, 4, 9]', value: 'c' }
    ],
    answer: 'a',
    hints: ['Check each neighboring pair left-to-right.']
  },
  {
    id: 'w1-l4',
    world: 1,
    title: 'Predict Next Bubble Step',
    type: 'text-answer',
    concept: 'Bubble sort intuition',
    mission: 'After comparing first two values in [5,2,4], what does array become?',
    lesson: 'Bubble sort compares adjacent values. If left > right, swap them.',
    expectedText: '2,5,4',
    hints: ['Compare 5 and 2 only.', 'Since 5 > 2, they swap.']
  },

  // World 2: Searching
  {
    id: 'w2-l1',
    world: 2,
    title: 'Linear Search Scan',
    type: 'index-answer',
    concept: 'Linear search',
    mission: 'Find target 7 in [5,1,7,8,3]. Return index.',
    lesson: 'Linear search checks each element from left to right until match.',
    array: [5, 1, 7, 8, 3],
    expectedIndex: 2,
    hints: ['Start from index 0.', 'Stop when value equals 7.']
  },
  {
    id: 'w2-l2',
    world: 2,
    title: 'Binary Search Midpoint',
    type: 'index-answer',
    concept: 'Binary search first decision',
    mission: 'For sorted [3,8,12,22,31,44,50], first mid index?',
    lesson: 'Binary search starts with low=0, high=n-1, mid=(low+high)/2.',
    array: [3, 8, 12, 22, 31, 44, 50],
    expectedIndex: 3,
    hints: ['(0 + 6) / 2 = 3']
  },
  {
    id: 'w2-l3',
    world: 2,
    title: 'Binary Search Path',
    type: 'text-answer',
    concept: 'Search interval elimination',
    mission: 'In [2,4,6,8,10,12,14], target=12. Enter visited mids as comma indices.',
    lesson: 'Record each midpoint checked: compare, then discard half.',
    expectedText: '3,5',
    hints: ['mid 3 value 8 -> go right.', 'Then mid 5 value 12 found.']
  },
  {
    id: 'w2-l4',
    world: 2,
    title: 'First Occurrence Logic',
    type: 'mcq',
    concept: 'Binary search with duplicates',
    mission: 'When arr[mid] == target and you need first occurrence, what next?',
    lesson: 'For first occurrence, keep searching left half after saving answer.',
    choices: [
      { label: 'Return immediately', value: 'return' },
      { label: 'Move low = mid + 1', value: 'right' },
      { label: 'Store mid, move high = mid - 1', value: 'left' }
    ],
    answer: 'left',
    hints: ['You might find an earlier target to the left.']
  },

  // World 3: O(n^2) Sorting
  {
    id: 'w3-l1',
    world: 3,
    title: 'Bubble Pass Result',
    type: 'text-answer',
    concept: 'Bubble sort mechanics',
    mission: 'After one full bubble pass on [4,1,3,2], enter resulting array.',
    lesson: 'A full pass compares adjacent pairs from left to right; largest bubbles to end.',
    expectedText: '1,3,2,4',
    hints: ['Compare (4,1), (4,3), (4,2).', '4 ends at last index.']
  },
  {
    id: 'w3-l2',
    world: 3,
    title: 'Selection Sort Choice',
    type: 'index-answer',
    concept: 'Selection sort',
    mission: 'Array [7,3,5,2]. During pass 1, index of minimum?',
    lesson: 'Selection sort finds minimum in unsorted region and swaps to front.',
    expectedIndex: 3,
    hints: ['Minimum value is 2.']
  },
  {
    id: 'w3-l3',
    world: 3,
    title: 'Insertion Sort Insert Spot',
    type: 'index-answer',
    concept: 'Insertion sort',
    mission: 'Sorted prefix [2,5,8], key=6. Insert at what index?',
    lesson: 'Shift bigger elements right until correct key position.',
    expectedIndex: 2,
    hints: ['6 goes after 5 and before 8.']
  },
  {
    id: 'w3-l4',
    world: 3,
    title: 'Fix Linear Search Bug (C++)',
    type: 'code',
    concept: 'Loop bounds',
    mission: 'Fix off-by-one so all elements are checked.',
    lesson: 'Missing last element is a classic bug in loops.',
    challengeId: 'linear-search-fix',
    starterCode: `int linearSearch(const vector<int>& arr, int target) {\n  for (int i = 0; i < arr.size() - 1; i++) {\n    if (arr[i] == target) return i;\n  }\n  return -1;\n}`,
    hints: ['Replace arr.size()-1 bound.', 'Use i < arr.size().']
  },

  // World 4: Divide & Conquer + Writing
  {
    id: 'w4-l1',
    world: 4,
    title: 'Choose Fastest Strategy',
    type: 'mcq',
    concept: 'Performance intuition',
    mission: 'Need to sort 100,000 random numbers quickly. Best choice?',
    lesson: 'O(n log n) algorithms scale much better than O(n^2).',
    choices: [
      { label: 'Bubble sort', value: 'bubble' },
      { label: 'Insertion sort', value: 'insertion' },
      { label: 'Merge sort', value: 'merge' }
    ],
    answer: 'merge',
    hints: ['Prefer O(n log n) for large random inputs.']
  },
  {
    id: 'w4-l2',
    world: 4,
    title: 'Stability Check',
    type: 'mcq',
    concept: 'Stable sorting',
    mission: 'Which algorithm is stable in typical implementation?',
    lesson: 'Stable sorts keep equal-key items in original relative order.',
    choices: [
      { label: 'Merge sort', value: 'merge' },
      { label: 'Selection sort', value: 'selection' },
      { label: 'Quick sort (in-place)', value: 'quick' }
    ],
    answer: 'merge',
    hints: ['Think about preserving equal elements order.']
  },
  {
    id: 'w4-l3',
    world: 4,
    title: 'Write Binary Search First Occurrence (C++)',
    type: 'code',
    concept: 'Binary search variant',
    mission: 'Complete function logic for first occurrence.',
    lesson: 'Track answer and continue searching left after a match.',
    challengeId: 'binary-first-occurrence',
    starterCode: `int firstOccurrence(const vector<int>& arr, int target) {\n  int low = 0, high = (int)arr.size() - 1;\n  int ans = -1;\n  while (low <= high) {\n    int mid = low + (high - low) / 2;\n    // TODO\n  }\n  return ans;\n}`,
    hints: ['On match: ans = mid and high = mid - 1.', 'Use standard < and > branches.']
  },
  {
    id: 'w4-l4',
    world: 4,
    title: 'Write Insertion Sort Core Loop (C++)',
    type: 'code',
    concept: 'Writing full algorithm logic',
    mission: 'Implement key shifting loop for insertion sort.',
    lesson: 'Insertion sort builds sorted prefix one key at a time.',
    challengeId: 'insertion-sort-core',
    starterCode: `void insertionSort(vector<int>& arr) {\n  for (int i = 1; i < arr.size(); i++) {\n    int key = arr[i];\n    int j = i - 1;\n    // TODO shift bigger values right\n    // TODO place key\n  }\n}`,
    hints: ['Use while (j >= 0 && arr[j] > key).', 'Shift arr[j] to arr[j+1], then place key.']
  }
];
