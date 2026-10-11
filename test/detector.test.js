/**
 * Automated test suite for AI Image Detector (Node.js edition).
 */

const assert = require('assert');
const fs = require('fs');
const test = require('node:test');

const { AIImageDetector, Verdict } = require('../lib/analyzer');
const { C2PAChecker } = require('../lib/c2pa-checker');
const { MetadataChecker } = require('../lib/metadata-checker');
const { ForensicAnalyzer } = require('../lib/forensics');
const { HTMLReporter } = require('../lib/html-reporter');

const TEST_IMAGE = 'image.png';

test('C2PAChecker detects ChatGPT provenance in image.png', () => {
  if (!fs.existsSync(TEST_IMAGE)) return;
  const res = C2PAChecker.inspect(TEST_IMAGE);

  assert.strictEqual(res.hasC2PA, true);
  assert.strictEqual(res.isConfirmedAI, true);
  assert.strictEqual(res.issuer, 'OpenAI OpCo, LLC');
  assert.ok(res.detectedTool.includes('ChatGPT'));
  assert.ok(res.watermarks.includes('c2pa.watermarked.unbound'));
});

test('ForensicAnalyzer calculates non-zero kurtosis and frequency slope', () => {
  if (!fs.existsSync(TEST_IMAGE)) return;
  const f = ForensicAnalyzer.analyze(TEST_IMAGE);

  assert.strictEqual(f.width, 1353);
  assert.strictEqual(f.height, 1163);
  assert.ok(f.noiseKurtosis > 15.0);
  assert.ok(f.smoothnessRatio > 0.40);
  assert.ok(f.forensicScore > 0.40);
});

test('MetadataChecker parses cleanly without errors', () => {
  if (!fs.existsSync(TEST_IMAGE)) return;
  const meta = MetadataChecker.inspect(TEST_IMAGE);

  assert.ok(Array.isArray(meta.rawKeys));
  assert.strictEqual(typeof meta.hasAIMetadata, 'boolean');
});

test('AIImageDetector returns unified confirmed AI verdict', () => {
  if (!fs.existsSync(TEST_IMAGE)) return;
  const detector = new AIImageDetector();
  const report = detector.analyze(TEST_IMAGE);

  assert.strictEqual(report.verdict, Verdict.CONFIRMED_AI_PROVENANCE);
  assert.strictEqual(report.confidence, 100.0);
  assert.ok(report.detectedGenerator.includes('ChatGPT'));
  assert.ok(report.keyFindings.length > 0);

  const json = report.toJSON();
  assert.strictEqual(json.confidence, 100.0);
  assert.ok(json.c2pa.hasC2PA);
});

test('HTMLReporter exports valid standalone HTML report', () => {
  if (!fs.existsSync(TEST_IMAGE)) return;
  const detector = new AIImageDetector();
  const report = detector.analyze(TEST_IMAGE);
  const outPath = 'temp_test_report.html';

  try {
    const ok = HTMLReporter.generate(report, outPath);
    assert.strictEqual(ok, true);
    assert.ok(fs.existsSync(outPath));
    const content = fs.readFileSync(outPath, 'utf8');
    assert.ok(content.includes('AI IMAGE DETECTOR'));
    assert.ok(content.includes('ChatGPT'));
  } finally {
    if (fs.existsSync(outPath)) fs.unlinkSync(outPath);
  }
});
