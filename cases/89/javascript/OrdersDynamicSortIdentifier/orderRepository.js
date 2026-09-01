'use strict';

async function findOrders(db, accountId, sortColumn, direction) {
  const sql = [
    'SELECT id, total_cents, status, created_at',
    'FROM orders',
    'WHERE account_id = ?',
    `ORDER BY ${sortColumn} ${direction}`,
  ].join(' ');

  const [rows] = await db.execute(sql, [accountId]);
  return rows;
}

module.exports = { findOrders };
