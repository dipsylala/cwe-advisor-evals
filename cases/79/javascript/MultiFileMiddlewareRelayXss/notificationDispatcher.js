'use strict';

const { DigestEntryFormatter } = require('./digestEntryFormatter');

class NotificationDispatcher {
  constructor(formatter = new DigestEntryFormatter()) {
    this.formatter = formatter;
    this.pendingDigest = [];
  }

  queueForDigest(recordId, authorName, rawComment, res) {
    const entry = {
      recordId,
      authorName,
      rawComment,
      queuedAt: Date.now()
    };

    this.pendingDigest.push(entry);
    console.log(`Digest queue depth: ${this.pendingDigest.length}`);

    this.formatter.formatEntry(entry, res);
  }
}

module.exports = { NotificationDispatcher };
