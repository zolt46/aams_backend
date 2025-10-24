const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

function loadEnv() {
  const projectRoot = path.join(__dirname, '..');
  const modeRaw = (process.env.AAMS_ENV || process.env.NODE_ENV || '').trim();
  const mode = modeRaw ? modeRaw.toLowerCase() : '';

  const candidates = [
    { file: '.env', override: false },
    { file: '.env.local', override: true }
  ];

  if (mode) {
    candidates.push(
      { file: `.env.${mode}`, override: true },
      { file: `.env.${mode}.local`, override: true }
    );
  }

  for (const { file, override } of candidates) {
    const target = path.join(projectRoot, file);
    if (!fs.existsSync(target)) continue;
    dotenv.config({ path: target, override });
  }
}

module.exports = { loadEnv };
