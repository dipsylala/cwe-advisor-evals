const express = require('express');
const path = require('path');
const { exec } = require('child_process');

const app = express();

// Kicks off the bundled Windows batch script that renders a named report
// template into the shared output folder. The .bat lives alongside this
// module so operators can tweak the rendering steps without touching code.
app.post('/reports/generate', (req, res) => {
  const reportName = req.body.reportName;

  if (!reportName) {
    return res.status(400).send('reportName is required');
  }

  const scriptPath = path.join(__dirname, 'scripts', 'generate-report.bat');

  // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
  exec(`"${scriptPath}" ${reportName}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('report generation failed');
    }
    res.type('text/plain').send(stdout);
  });
});

app.listen(3000);

module.exports = app;
