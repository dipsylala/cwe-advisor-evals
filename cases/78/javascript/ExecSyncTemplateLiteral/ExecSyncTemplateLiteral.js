const express = require("express");
const path = require("path");
const { execSync } = require("child_process");

const router = express.Router();
const UPLOAD_DIR = "/var/data/uploads";
const THUMB_DIR = "/var/data/thumbnails";

// Generates a thumbnail for a previously uploaded image using ImageMagick's
// `convert` CLI. The caller supplies the source filename and the desired
// output geometry (e.g. "200x200").
router.post("/api/images/:filename/thumbnail", (req, res) => {
  const filename = req.params.filename;
  const geometry = req.body.geometry || "200x200";

  const sourcePath = path.join(UPLOAD_DIR, filename);
  const thumbPath = path.join(THUMB_DIR, `thumb-${filename}`);

  // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
  execSync(`convert ${sourcePath} -resize ${geometry} ${thumbPath}`);

  res.json({ thumbnail: `thumb-${filename}` });
});

module.exports = router;
