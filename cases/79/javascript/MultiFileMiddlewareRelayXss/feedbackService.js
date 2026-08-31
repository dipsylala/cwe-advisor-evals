'use strict';

const { NotificationDispatcher } = require('./notificationDispatcher');

let nextRecordId = 1000;

class FeedbackService {
  constructor(dispatcher = new NotificationDispatcher()) {
    this.dispatcher = dispatcher;
    this.records = new Map();
  }

  submitFeedback(submission, res) {
    const recordId = nextRecordId++;

    // Persist metadata for the record (comment body is not stored here;
    // it is only threaded through to the live digest dispatcher below).
    this.records.set(recordId, {
      authorName: submission.authorName,
      submittedAt: submission.submittedAt
    });

    this.dispatcher.queueForDigest(recordId, submission.authorName, submission.comment, res);

    return recordId;
  }
}

module.exports = { FeedbackService };
