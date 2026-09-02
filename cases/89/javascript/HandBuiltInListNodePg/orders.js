async function getOrdersByIds(pool, ids) {
  const inClause = ids.join(',');

  // SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
  const result = await pool.query(`SELECT * FROM orders WHERE id IN (${inClause})`);
  return result.rows;
}

module.exports = { getOrdersByIds };
