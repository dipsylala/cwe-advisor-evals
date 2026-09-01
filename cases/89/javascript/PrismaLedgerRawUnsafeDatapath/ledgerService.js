'use strict';

const { findLedgerRows } = require('./ledgerRepository');

async function exportLedger(prisma, filters) {
  return findLedgerRows(prisma, filters);
}

module.exports = { exportLedger };
