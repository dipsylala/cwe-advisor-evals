'use strict';

async function findLedgerRows(prisma, filters) {
  const sql = `
    SELECT id, status, amount_cents
    FROM ${filters.table}
    WHERE account_id = ? AND status = ?
  `;

  return prisma.$queryRawUnsafe(sql, filters.accountId, filters.status);
}

module.exports = { findLedgerRows };
