/**
 * Master analysis engine orchestrating C2PA, metadata, and signal forensics for Node.js.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { C2PAChecker } = require('./c2pa-checker');
const { MetadataChecker } = require('./metadata-checker');
const { ForensicAnalyzer } = require('./forensics');

const Verdict = {
  CONFIRMED_AI_PROVENANCE: 'CONFIRMED AI (C2PA / Content Credentials)',
  CONFIRMED_AI_METADATA: 'CONFIRMED AI (Generation Metadata / Prompts)',
  HIGH_PROBABILITY_AI: 'HIGH PROBABILITY AI (Forensic Anomaly)',
  SUSPICIOUS_AI: 'SUSPICIOUS / LIKELY AI (Signal Irregularity)',
  INCONCLUSIVE: 'INCONCLUSIVE (Metadata Stripped / Ambiguous)',
  LIKELY_AUTHENTIC_CAMERA: 'LIKELY AUTHENTIC (Camera Hardware Markers)'
};

class AIImageDetector {
  constructor(options = {}) {
    this.threshold = options.threshold || 50.0;
  }

  /**
   * Analyzes an image file.
   * @param {string} filePath 
   * @returns {object}
   */
  analyze(filePath) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const fileInfo = this._getFileInfo(filePath);
    const c2paResult = C2PAChecker.inspect(filePath);
    const metadataResult = MetadataChecker.inspect(filePath);
    const forensicResult = ForensicAnalyzer.analyze(filePath);

    const { verdict, confidence, indicator, tool, findings } = this._evaluateSignals(
      c2paResult,
      metadataResult,
      forensicResult
    );

    return {
      fileInfo,
      verdict,
      confidence,
      primaryIndicator: indicator,
      detectedGenerator: tool,
      keyFindings: findings,
      c2pa: c2paResult,
      metadata: metadataResult,
      forensics: forensicResult,
      toJSON() {
        return {
          fileInfo,
          verdict,
          confidence: parseFloat(confidence.toFixed(1)),
          primaryIndicator: indicator,
          detectedGenerator: tool,
          keyFindings: findings,
          c2pa: c2paResult,
          metadata: metadataResult,
          forensics: forensicResult
        };
      }
    };
  }

  _getFileInfo(filePath) {
    const stats = fs.statSync(filePath);
    const sizeBytes = stats.size;
    let sizeHuman = `${sizeBytes} B`;
    if (sizeBytes >= 1024 * 1024) sizeHuman = `${(sizeBytes / (1024 * 1024)).toFixed(2)} MB`;
    else if (sizeBytes >= 1024) sizeHuman = `${(sizeBytes / 1024).toFixed(1)} KB`;

    const buf = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');

    const ext = path.extname(filePath).toUpperCase().replace('.', '') || 'UNKNOWN';

    // Dimension extraction (fast header read)
    let dims = 'UNKNOWN';
    if (buf.length > 24 && buf[0] === 0x89 && buf[1] === 0x50) {
      dims = `${buf.readUInt32BE(16)} x ${buf.readUInt32BE(20)}`;
    }

    return {
      filePath,
      fileName: path.basename(filePath),
      fileSizeBytes: sizeBytes,
      fileSizeHuman: sizeHuman,
      format: ext,
      dimensions: dims,
      sha256: hash
    };
  }

  _evaluateSignals(c2pa, meta, forensic) {
    const findings = [];
    let tool = null;

    // 1. C2PA Provenance
    if (c2pa.hasC2PA) {
      findings.push('C2PA Content Credentials manifest found and parsed.');
      if (c2pa.claimGenerator) findings.push(`Claim Generator: ${c2pa.claimGenerator}`);
      if (c2pa.issuer) findings.push(`Signed by certificate authority: ${c2pa.issuer}`);

      if (c2pa.isConfirmedAI) {
        tool = c2pa.detectedTool || 'AI Generative Model';
        findings.push(`C2PA digitalSourceType confirms trained algorithmic media (${tool}).`);
        if (c2pa.watermarks.length > 0) {
          findings.push(`Embedded watermarks identified: ${c2pa.watermarks.join(', ')}`);
        }
        return {
          verdict: Verdict.CONFIRMED_AI_PROVENANCE,
          confidence: 100.0,
          indicator: `C2PA Content Credentials (${tool})`,
          tool,
          findings
        };
      }
    }

    // 2. Direct Metadata / Generation Prompts
    if (meta.hasAIMetadata) {
      tool = meta.detectedGenerator || 'AI Generator';
      findings.push(`Embedded AI generation metadata found (${tool}).`);
      if (meta.prompt) findings.push(`Extracted generation prompt: "${meta.prompt.slice(0, 100)}..."`);
      if (meta.model) findings.push(`Model checkpoint: ${meta.model}`);
      if (meta.seed !== null) findings.push(`Generation seed: ${meta.seed}`);

      return {
        verdict: Verdict.CONFIRMED_AI_METADATA,
        confidence: 99.5,
        indicator: `Generation metadata & parameters (${tool})`,
        tool,
        findings
      };
    }

    // 3. Camera EXIF vs Forensics
    const hasCamera = meta.hasCameraExif;
    if (hasCamera) {
      findings.push(`Camera EXIF tags present: ${meta.cameraMake || ''} ${meta.cameraModel || ''}`);
    }

    findings.push(...forensic.anomalies);
    const fScore = forensic.forensicScore;

    if (hasCamera && fScore < 0.40) {
      return {
        verdict: Verdict.LIKELY_AUTHENTIC_CAMERA,
        confidence: Math.max(80.0, 100.0 - fScore * 50.0),
        indicator: 'Authentic camera hardware EXIF & natural sensor noise profile',
        tool: null,
        findings
      };
    }

    if (fScore >= 0.70) {
      const pct = parseFloat((fScore * 100).toFixed(1));
      return {
        verdict: Verdict.HIGH_PROBABILITY_AI,
        confidence: pct,
        indicator: `Multiple forensic signals indicate synthetic pixel patterns (${pct}%)`,
        tool: null,
        findings
      };
    }

    if (fScore >= 0.45) {
      const pct = parseFloat((fScore * 100).toFixed(1));
      return {
        verdict: Verdict.SUSPICIOUS_AI,
        confidence: pct,
        indicator: `Signal irregularities detected in frequency and noise domains (${pct}%)`,
        tool: null,
        findings
      };
    }

    if (hasCamera) {
      return {
        verdict: Verdict.LIKELY_AUTHENTIC_CAMERA,
        confidence: 75.0,
        indicator: 'Camera hardware markers present with minor processing artifacts',
        tool: null,
        findings
      };
    }

    findings.push('No C2PA manifest or generator metadata detected.');
    findings.push('Signal forensics did not reach anomaly threshold.');
    return {
      verdict: Verdict.INCONCLUSIVE,
      confidence: 30.0,
      indicator: 'Metadata absent, pixel forensics inconclusive',
      tool: null,
      findings
    };
  }
}

module.exports = { AIImageDetector, Verdict };
