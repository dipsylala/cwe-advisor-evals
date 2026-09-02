function renderCommentBody(sanitizer, rawBody) {
  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  return sanitizer.bypassSecurityTrustHtml(rawBody);
}

module.exports = { renderCommentBody };
