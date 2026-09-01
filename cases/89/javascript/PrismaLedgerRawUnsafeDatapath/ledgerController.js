'use strict';

const { exportLedger } = require('./ledgerService');

async function ledgerExport(req, res) {
  const filters = {
    accountId: req.user.accountId,
    status: req.query.status || 'posted',
    table: req.query.ledger || 'ledger_entries',
  };

  const rows = await exportLedger(req.prisma, filters);
  res.json({ rows });
}

module.exports = { ledgerExport };
