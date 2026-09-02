const { QueryTypes } = require('sequelize');
const sequelize = require('../db/sequelize');

// GET /reports/orders?startDate=2024-01-01&endDate=2024-01-31
async function getOrderTotalsReport(req, res) {
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ error: 'startDate and endDate are required' });
  }

  let sql =
    'SELECT customer_id, SUM(total_cents) AS total_cents ' +
    'FROM orders ' +
    "WHERE order_date BETWEEN '" + startDate + "' AND '" + endDate + "' " +
    'GROUP BY customer_id ' +
    'ORDER BY total_cents DESC';

  // SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
  const rows = await sequelize.query(sql, { type: QueryTypes.SELECT });

  return res.json({ report: rows });
}

module.exports = { getOrderTotalsReport };
