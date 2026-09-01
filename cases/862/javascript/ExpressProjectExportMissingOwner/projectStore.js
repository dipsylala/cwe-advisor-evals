'use strict';

async function loadProjectExport(projectId) {
  return {
    projectId,
    format: 'json',
    rows: [],
  };
}

module.exports = { loadProjectExport };
