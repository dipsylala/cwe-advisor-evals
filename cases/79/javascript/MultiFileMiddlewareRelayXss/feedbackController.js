'use strict';

const { FeedbackService } = require('./feedbackService');

class FeedbackSubmission {
  constructor(authorName, comment, submittedAt) {
    this.authorName = authorName;
    this.comment = comment;
    this.submittedAt = submittedAt;
  }
}

// POST /feedback - body: { authorName, comment }
// Responds with the refreshed activity digest fragment for the submitting client.
function handleFeedbackSubmission(req, res, feedbackService = new FeedbackService()) {
  const authorName = (req.body.authorName || 'Anonymous').slice(0, 80);
  const comment = req.body.comment || '';

  const submission = new FeedbackSubmission(authorName, comment, new Date());

  feedbackService.submitFeedback(submission, res);
}

module.exports = { handleFeedbackSubmission, FeedbackSubmission };
