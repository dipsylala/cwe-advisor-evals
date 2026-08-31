const express = require('express');
const libxmljs = require('libxmljs');

const app = express();

// Accept raw XML bodies posted by trading partners for order import.
app.use(express.text({ type: 'application/xml' }));

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
  const doc = libxmljs.parseXml(rawOrderXml);

  const orderId = doc.get('//order/id');
  if (!orderId) {
    return res.status(400).send('missing order id');
  }

  res.json({ orderId: orderId.text() });
});

module.exports = app;
