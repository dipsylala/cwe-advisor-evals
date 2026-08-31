'use strict';

class DigestPageRenderer {
  renderDigestPage(recordId, summaryHtml, res) {
    const pageTitle = `Digest #${recordId}`;
    const pageBody = `
      <header><h1>${pageTitle}</h1></header>
      <ul class="digest-list">${summaryHtml}</ul>
      <footer>Generated ${new Date().toISOString()}</footer>
    `;

    // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    res.send(`<!DOCTYPE html><html><body>${pageBody}</body></html>`);
  }
}

module.exports = { DigestPageRenderer };
