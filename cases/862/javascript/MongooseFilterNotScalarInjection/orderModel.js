'use strict';

const mongoose = require('mongoose');

// Note: mongoose.sanitizeFilter() is never called anywhere in this app, so a
// caller-supplied object under any query key - including ownerId - reaches
// MongoDB as a live query operator instead of a literal scalar value.

const orderSchema = new mongoose.Schema({
  ownerId: { type: String, required: true },
  status: { type: String, default: 'pending' },
  total: { type: Number, required: true },
  items: [{ sku: String, quantity: Number }],
});

module.exports = mongoose.model('Order', orderSchema);
