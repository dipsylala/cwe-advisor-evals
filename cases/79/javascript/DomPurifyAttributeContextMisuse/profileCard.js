const DOMPurify = require('dompurify');

function renderProfileCard(bioHtml) {
  const safeBio = DOMPurify.sanitize(bioHtml);

  // SAST FINDING: CWE-79 (Cross-site Scripting) reported here. Sink is the next statement.
  return `<div class="profile-card" title="${safeBio}">${safeBio}</div>`;
}
