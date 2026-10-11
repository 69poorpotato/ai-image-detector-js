#!/usr/bin/env node
/**
 * AI Image Detector & Forensic Suite (Node.js Edition)
 * Usage:
 *   node index.js image.png
 *   node index.js image.png --html report.html
 *   node index.js -i
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const pc = require('picocolors');

const { AIImageDetector, Verdict } = require('./lib/analyzer');
const { C2PAChecker } = require('./lib/c2pa-checker');
const { MetadataChecker } = require('./lib/metadata-checker');
const { ForensicAnalyzer } = require('./lib/forensics');
const { HTMLReporter } = require('./lib/html-reporter');
const { renderBanner, renderReport } = require('./lib/ui');

const SUPPORTED_EXTS = ['.png', '.jpg', '.jpeg', '.webp', '.tif', '.tiff', '.bmp'];

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    images: [],
    interactive: false,
    dir: null,
    html: null,
    output: null,
    json: false,
    verbose: false
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-i' || a === '--interactive') options.interactive = true;
    else if (a === '-j' || a === '--json') options.json = true;
    else if (a === '-v' || a === '--verbose') options.verbose = true;
    else if (a === '--html') options.html = args[++i] || 'audit_report.html';
    else if (a === '-o' || a === '--output') options.output = args[++i];
    else if (a === '-d' || a === '--dir') options.dir = args[++i];
    else if (a === '-h' || a === '--help') {
      printHelp();
      process.exit(0);
    } else if (!a.startsWith('-')) {
      options.images.push(a);
    }
  }

  return options;
}

function printHelp() {
  renderBanner();
  console.log(`
Usage:
  node index.js [images...] [options]

Options:
  -i, --interactive        Launch interactive drag-and-drop prompt
  --html [path]            Export standalone interactive HTML audit report
  -d, --dir <directory>    Scan all supported images in a folder
  -o, --output <file.json> Save analysis results to a JSON file
  -j, --json               Output machine-readable JSON to stdout
  -v, --verbose            Show detailed mathematical forensic logs
  -h, --help               Show this help message

Examples:
  node index.js image.png
  node index.js image.png --html report.html
  node index.js -i
  node index.js --dir ./photos -o scan.json
`);
}

function collectPaths(options) {
  const paths = [];

  if (options.dir) {
    if (!fs.existsSync(options.dir)) {
      console.error(pc.red(`Error: Directory '${options.dir}' not found.`));
      process.exit(1);
    }
    const files = fs.readdirSync(options.dir);
    for (const f of files) {
      const ext = path.extname(f).toLowerCase();
      if (SUPPORTED_EXTS.includes(ext)) {
        paths.push(path.join(options.dir, f));
      }
    }
  }

  for (const img of options.images) {
    const clean = img.replace(/^["']|["']$/g, '');
    if (fs.existsSync(clean)) {
      const stat = fs.statSync(clean);
      if (stat.isDirectory()) {
        const files = fs.readdirSync(clean);
        for (const f of files) {
          if (SUPPORTED_EXTS.includes(path.extname(f).toLowerCase())) {
            paths.push(path.join(clean, f));
          }
        }
      } else {
        paths.push(clean);
      }
    } else {
      console.warn(pc.yellow(`Warning: File '${clean}' not found.`));
    }
  }

  if (paths.length === 0 && !options.interactive && fs.existsSync('image.png')) {
    paths.push('image.png');
  }

  return [...new Set(paths)];
}

function runInteractive(detector, verbose) {
  renderBanner();
  console.log(pc.bold(pc.cyan('\nInteractive Mode:')) + ' Drag & drop an image file into this window and hit ' + pc.bold('Enter') + '.');
  console.log(pc.dim("Type 'q' or 'exit' to quit.\n"));

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const prompt = () => {
    rl.question('[Image file] > ', (line) => {
      const input = line.trim().replace(/^["'& ]+|["'& ]+$/g, '');
      if (input.toLowerCase() === 'q' || input.toLowerCase() === 'exit') {
        rl.close();
        return;
      }
      if (!input) {
        prompt();
        return;
      }
      if (!fs.existsSync(input)) {
        console.log(pc.red(`Error: File not found: '${input}'\n`));
        prompt();
        return;
      }

      try {
        const report = detector.analyze(input);
        renderReport(report, verbose);
      } catch (err) {
        console.log(pc.red(`Error: ${err.message}\n`));
      }
      prompt();
    });
  };

  prompt();
}

function renderBatchSummary(reports) {
  renderBanner();
  console.log(pc.bold('\nBATCH SCAN RESULTS:'));
  console.log(pc.cyan('----------------------------------------------------------------------------------'));
  console.log(`${pad('File', 24)} ${pad('Dimensions', 14)} ${pad('Verdict', 20)} ${pad('Confidence', 12)} Primary Indicator`);
  console.log(pc.cyan('----------------------------------------------------------------------------------'));

  for (const r of reports) {
    let vText = pc.dim('INCONCLUSIVE');
    if (r.verdict.includes('CONFIRMED') || r.verdict.includes('HIGH')) vText = pc.bold(pc.red('AI GENERATED'));
    else if (r.verdict.includes('SUSPICIOUS')) vText = pc.bold(pc.yellow('SUSPICIOUS'));
    else if (r.verdict.includes('AUTHENTIC')) vText = pc.bold(pc.green('AUTHENTIC'));

    const tool = r.detectedGenerator || r.primaryIndicator;
    console.log(`${pad(r.fileInfo.fileName, 24)} ${pad(r.fileInfo.dimensions, 14)} ${pad(vText, 20)} ${pad(`${r.confidence.toFixed(1)}%`, 12)} ${tool.slice(0, 32)}`);
  }
  console.log(pc.cyan('----------------------------------------------------------------------------------\n'));
}

function pad(str, len) {
  const clean = str.replace(/\x1b\[[0-9;]*m/g, '');
  const diff = len - clean.length;
  return diff > 0 ? str + ' '.repeat(diff) : str;
}

function main() {
  const options = parseArgs();
  const detector = new AIImageDetector();

  if (options.interactive) {
    runInteractive(detector, options.verbose);
    return;
  }

  const paths = collectPaths(options);

  if (paths.length === 0) {
    runInteractive(detector, options.verbose);
    return;
  }

  const reports = [];

  for (const p of paths) {
    try {
      const report = detector.analyze(p);
      reports.push(report);

      if (options.html) {
        let outHtml = options.html;
        if (paths.length > 1) {
          const ext = path.extname(outHtml);
          const base = outHtml.replace(ext, '');
          outHtml = `${base}_${report.fileInfo.fileName}${ext}`;
        }
        HTMLReporter.generate(report, outHtml);
        if (!options.json) {
          console.log(pc.green(`[OK] Interactive HTML report generated: ${pc.cyan(outHtml)}`));
        }
      }

      if (!options.json && paths.length === 1) {
        renderReport(report, options.verbose);
      }
    } catch (err) {
      console.error(pc.red(`Error analyzing '${p}': ${err.message}`));
    }
  }

  if (!options.json && paths.length > 1) {
    renderBatchSummary(reports);
  }

  const allData = reports.map(r => r.toJSON());

  if (options.json) {
    console.log(JSON.stringify(allData.length === 1 ? allData[0] : allData, null, 2));
  }

  if (options.output) {
    fs.writeFileSync(options.output, JSON.stringify(allData.length === 1 ? allData[0] : allData, null, 2), 'utf8');
    if (!options.json) {
      console.log(pc.green(`[OK] JSON report saved to: ${pc.cyan(options.output)}`));
    }
  }
}

// Module exports for programmatic library use
module.exports = {
  AIImageDetector,
  Verdict,
  C2PAChecker,
  MetadataChecker,
  ForensicAnalyzer,
  HTMLReporter,
  renderReport
};

if (require.main === module) {
  main();
}
