'use strict';

// Express handler for POST /api/calculator/evaluate
// Body: { expression: "12 * (3 + 4)" }
function evaluateExpression(req, res) {
  const expression = req.body.expression;

  if (typeof expression !== 'string' || expression.length === 0) {
    return res.status(400).json({ error: 'expression is required' });
  }

  // Wrap the expression in parentheses so a leading operator or bare
  // literal still evaluates as a single statement.
  // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
  const result = eval('(' + expression + ')');

  res.json({ result });
}

module.exports = { evaluateExpression };
