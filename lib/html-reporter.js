/**
 * Standalone interactive HTML report generator for Node.js.
 * Produces clean, zero-emoji, responsive HTML audit reports.
 */

const fs = require('fs');
const path = require('path');

class HTMLReporter {
  /**
   * Generates a self-contained HTML audit report.
   * @param {object} report 
   * @param {string} outputPath 
   * @returns {boolean}
   */
  static generate(report, outputPath) {
    try {
      const { fileInfo, verdict, confidence } = report;

      let b64Img = '';
      if (fs.existsSync(fileInfo.filePath)) {
        const rawBuf = fs.readFileSync(fileInfo.filePath);
        const mime = fileInfo.format.toLowerCase() === 'png' ? 'image/png' : 'image/jpeg';
        b64Img = `data:${mime};base64,${rawBuf.toString('base64')}`;
      }

      let badgeClass = 'badge-neutral';
      let verdictTitle = 'INCONCLUSIVE';

      if (verdict.includes('CONFIRMED') || verdict.includes('HIGH')) {
        badgeClass = 'badge-danger';
        verdictTitle = 'AI GENERATED';
      } else if (verdict.includes('SUSPICIOUS')) {
        badgeClass = 'badge-warning';
        verdictTitle = 'SUSPICIOUS / LIKELY AI';
      } else if (verdict.includes('AUTHENTIC')) {
        badgeClass = 'badge-success';
        verdictTitle = 'AUTHENTIC PHOTO';
      }

      const findingsHtml = (report.keyFindings || []).map(f => `<li>${f}</li>`).join('');

      // C2PA section
      let c2paHtml = '';
      if (report.c2pa && report.c2pa.hasC2PA) {
        const c = report.c2pa;
        const actionsRows = (c.actions || []).map(a => 
          `<tr><td>${a.action}</td><td>${a.softwareName || 'N/A'} ${a.softwareVersion || ''}</td><td>${a.digitalSourceLabel || 'N/A'}</td></tr>`
        ).join('');

        c2paHtml = `
        <div class="card">
          <h3>Content Credentials & C2PA Provenance</h3>
          <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Media Engine</td><td>${c.claimGenerator || 'N/A'}</td></tr>
            <tr><td>Signing Authority</td><td>${c.issuer || 'N/A'} (${c.commonName || ''})</td></tr>
            <tr><td>Timestamp</td><td>${c.signatureTime || 'N/A'}</td></tr>
            <tr><td>Watermark Assertions</td><td>${(c.watermarks || []).join(', ') || 'None'}</td></tr>
          </table>
          <h4 style="margin-top:15px;">Actions Audit Trail</h4>
          <table>
            <tr><th>Action</th><th>Software</th><th>Source Type</th></tr>
            ${actionsRows}
          </table>
        </div>`;
      }

      // Metadata section
      let metaHtml = '';
      if (report.metadata && (report.metadata.hasAIMetadata || report.metadata.hasCameraExif)) {
        const m = report.metadata;
        const promptBox = m.prompt ? `
        <div class="prompt-box">
          <div class="prompt-label">Generation Prompt:</div>
          <div class="prompt-text">"${m.prompt}"</div>
          ${m.negativePrompt ? `<div class="neg-prompt">Negative Prompt: "${m.negativePrompt}"</div>` : ''}
        </div>` : '';

        metaHtml = `
        <div class="card">
          <h3>Embedded Generation Metadata</h3>
          ${promptBox}
          <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            ${m.detectedGenerator ? `<tr><td>Detected Generator</td><td>${m.detectedGenerator}</td></tr>` : ''}
            ${m.model ? `<tr><td>Model Checkpoint</td><td>${m.model}</td></tr>` : ''}
            ${m.sampler ? `<tr><td>Sampler</td><td>${m.sampler}</td></tr>` : ''}
            ${m.steps ? `<tr><td>Steps</td><td>${m.steps}</td></tr>` : ''}
            ${m.cfgScale ? `<tr><td>CFG Scale</td><td>${m.cfgScale}</td></tr>` : ''}
            ${m.seed !== null ? `<tr><td>Seed</td><td>${m.seed}</td></tr>` : ''}
            ${m.hasCameraExif ? `<tr><td>Camera Hardware</td><td>${m.cameraMake || ''} ${m.cameraModel || ''}</td></tr>` : ''}
          </table>
        </div>`;
      }

      // Forensics section
      let forensicsHtml = '';
      if (report.forensics) {
        const f = report.forensics;
        const fScore = Math.floor(f.forensicScore * 100);

        forensicsHtml = `
        <div class="card">
          <h3>Signal & Pixel Forensics (Anomaly Score: ${fScore}%)</h3>
          <table>
            <tr><th>Forensic Metric</th><th>Observed Status</th><th>Reference Baseline</th></tr>
            <tr><td>Texture & Skin Airbrushing</td><td><span class="badge ${f.smoothnessRatio > 0.3 ? 'badge-danger' : 'badge-success'}">${f.smoothnessRatio > 0.3 ? 'Synthetic Smoothing' : 'Natural Detail'}</span></td><td>Micro-texture variance</td></tr>
            <tr><td>Noise Residual Kurtosis</td><td><span class="badge ${f.noiseKurtosis > 20 ? 'badge-danger' : 'badge-success'}">${f.noiseKurtosis} (${f.noiseKurtosis > 20 ? 'High-tail Anomaly' : 'Natural'})</span></td><td>-1.0 to +6.0 (Gaussian)</td></tr>
            <tr><td>FFT Spectral Slope (alpha)</td><td><span class="badge ${f.psdSlope < -2.9 ? 'badge-danger' : 'badge-success'}">${f.psdSlope}</span></td><td>-1.8 to -2.4 (Power-law decay)</td></tr>
            <tr><td>Canvas Resolution</td><td>${f.width}x${f.height}</td><td>${f.aiResolutionDesc || 'Custom / Natural aspect'}</td></tr>
          </table>
        </div>`;
      }

      const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Detection Audit - ${fileInfo.fileName}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #131b2e;
      --border: #1e293b;
      --text: #f1f5f9;
      --text-dim: #94a3b8;
      --cyan: #06b6d4;
      --red: #ef4444;
      --green: #10b981;
      --yellow: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); padding: 30px 20px; line-height: 1.6; }
    .container { max-width: 950px; margin: 0 auto; }
    header { text-align: center; margin-bottom: 30px; border-bottom: 1px solid var(--border); padding-bottom: 20px; }
    header h1 { font-size: 26px; color: var(--cyan); margin-bottom: 6px; letter-spacing: -0.5px; }
    header p { color: var(--text-dim); font-size: 14px; }
    .grid-summary { display: grid; grid-template-columns: 280px 1fr; gap: 24px; margin-bottom: 24px; }
    @media(max-width: 768px) { .grid-summary { grid-template-columns: 1fr; } }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 22px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
    .img-card { text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: center; }
    .img-card img { max-width: 100%; max-height: 260px; border-radius: 8px; border: 1px solid var(--border); object-fit: contain; }
    .badge { display: inline-block; padding: 6px 14px; border-radius: 6px; font-weight: bold; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }
    .badge-success { background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }
    .badge-warning { background: rgba(245, 158, 11, 0.2); color: var(--yellow); border: 1px solid var(--yellow); }
    .badge-neutral { background: rgba(148, 163, 184, 0.2); color: var(--text-dim); border: 1px solid var(--text-dim); }
    .progress-bar-bg { background: #1e293b; border-radius: 999px; height: 12px; overflow: hidden; margin-top: 8px; }
    .progress-bar-fill { background: linear-gradient(90deg, var(--cyan), var(--yellow), var(--red)); height: 100%; border-radius: 999px; width: ${confidence}%; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #1e293b; }
    th { color: var(--cyan); font-weight: 600; }
    td { color: var(--text); }
    ul { padding-left: 20px; margin-top: 10px; color: var(--text); }
    li { margin-bottom: 6px; }
    .prompt-box { background: #0f172a; border-left: 4px solid var(--cyan); padding: 14px; border-radius: 4px; margin-bottom: 14px; }
    .prompt-label { font-size: 12px; color: var(--cyan); font-weight: bold; text-transform: uppercase; margin-bottom: 4px; }
    .prompt-text { font-style: italic; color: #fff; font-size: 14px; }
    .neg-prompt { color: var(--red); font-size: 13px; margin-top: 8px; }
    footer { text-align: center; color: var(--text-dim); font-size: 12px; margin-top: 40px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>AI IMAGE DETECTOR & FORENSIC SUITE</h1>
      <p>Cryptographic Content Credentials • Metadata Parsing • Signal & Spectral Forensics</p>
    </header>

    <div class="grid-summary">
      <div class="card img-card">
        ${b64Img ? `<img src="${b64Img}" alt="${fileInfo.fileName}">` : '<p style="color:var(--text-dim);">No preview</p>'}
        <p style="margin-top:10px; font-size:13px; color:var(--text-dim);">${fileInfo.fileName} (${fileInfo.dimensions})</p>
      </div>
      <div class="card">
        <div style="margin-bottom:14px;">
          <span class="badge ${badgeClass}">${verdictTitle}</span>
        </div>
        <div style="margin-bottom:12px;">
          <span style="font-size:22px; font-weight:bold;">${report.detectedGenerator || verdict}</span>
        </div>
        <div style="margin-bottom:16px;">
          <div style="display:flex; justify-content:space-between; font-size:14px;">
            <span>Confidence:</span>
            <strong style="color:var(--yellow);">${confidence.toFixed(1)}%</strong>
          </div>
          <div class="progress-bar-bg">
            <div class="progress-bar-fill"></div>
          </div>
        </div>
        <p style="font-size:14px; color:var(--text-dim);"><strong>Primary Indicator:</strong> ${report.primaryIndicator}</p>
        <p style="font-size:12px; color:var(--text-dim); margin-top:6px;"><strong>SHA-256:</strong> <code>${fileInfo.sha256}</code></p>
      </div>
    </div>

    <div class="card">
      <h3>Evidence & Findings Summary</h3>
      <ul>
        ${findingsHtml}
      </ul>
    </div>

    ${c2paHtml}
    ${metaHtml}
    ${forensicsHtml}

    <footer>
      Generated by AI Image Detector (Node.js) • Open Source MIT License
    </footer>
  </div>
</body>
</html>`;

      const outDir = path.dirname(outputPath);
      if (outDir && !fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
      }

      fs.writeFileSync(outputPath, htmlContent, 'utf8');
      return true;
    } catch (_) {
      return false;
    }
  }
}

module.exports = { HTMLReporter };
