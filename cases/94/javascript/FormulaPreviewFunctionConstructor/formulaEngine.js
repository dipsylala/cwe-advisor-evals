'use strict';

function evaluateFormula(expression, order) {
  const fn = new Function('order', `return (${expression});`);
  return fn(order);
}

module.exports = { evaluateFormula };
