'use strict';

const { evaluateFormula } = require('./formulaEngine');

function previewFormula(req, res) {
  const expression = req.body.expression || '0';
  const sampleOrder = { total: 42, tax: 3 };

  const value = evaluateFormula(expression, sampleOrder);
  res.json({ value });
}

module.exports = { previewFormula };
