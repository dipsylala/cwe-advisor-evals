const express = require('express');
const db = require('./db');
const logger = require('./logger');

const app = express();

app.get('/orders/:id', async (req, res) => {
  try {
    const order = await db.findOrder(req.params.id);
    if (!order) {
      return res.status(404).json({ error: 'not found' });
    }
    return res.json(order);
  } catch (error) {
    logger.error(error);
    // SAST FINDING: CWE-209 (Information Exposure Through an Error Message) reported here. Sink is the next statement.
    return res.status(500).json({ error: error.message, stack: error.stack });
  }
});

app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

module.exports = app;
