'use strict';

function escapeAttribute(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderProfileWebsite(profile) {
  const displayName = escapeAttribute(profile.displayName || 'Member');
  const websiteUrl = escapeAttribute(profile.websiteUrl || '#');

  return `<a class="profile-link" href="${websiteUrl}" rel="nofollow">${displayName}</a>`;
}

module.exports = { renderProfileWebsite };
