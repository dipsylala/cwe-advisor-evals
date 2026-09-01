'use strict';

const { findOrders } = require('./orderRepository');

async function listOrders(req, res) {
  const accountId = req.user.accountId;
  const sortColumn = req.query.sort || 'created_at';
  const direction = req.query.dir || 'DESC';

  const orders = await findOrders(req.db, accountId, sortColumn, direction);
  res.json({ orders });
}

module.exports = { listOrders };
