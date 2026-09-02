'use strict';

const vm = require('node:vm');

// Runs a merchant-authored "automation script" against the day's pending
// order batch. The script is expected to call emit(orderId, action) for
// each order it wants to flag; vm.runInNewContext is used to keep the
// script's globals separate from the host process's own globals.
function runAutomationScript(script, pendingOrders) {
  const flagged = [];
  const sandbox = {
    orders: pendingOrders,
    emit(orderId, action) {
      flagged.push({ orderId, action });
    },
  };

  // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
  vm.runInNewContext(script, sandbox, { timeout: 2000 });

  return flagged;
}

function handleAutomationPreview(req, res) {
  const { script } = req.body;
  if (typeof script !== 'string' || script.length === 0) {
    return res.status(400).json({ error: 'script is required' });
  }

  try {
    const flagged = runAutomationScript(script, req.app.locals.pendingOrders);
    res.json({ flagged });
  } catch (err) {
    res.status(400).json({ error: 'automation script failed', detail: err.message });
  }
}

module.exports = { runAutomationScript, handleAutomationPreview };
