'use strict';

function mean(arr) {
  if (!arr || arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function std(arr) {
  if (!arr || arr.length < 2) return 0;
  const m  = mean(arr);
  const sq = arr.map(x => (x - m) ** 2);
  return Math.sqrt(mean(sq));
}

module.exports = { mean, std };
