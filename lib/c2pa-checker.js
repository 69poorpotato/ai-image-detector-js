/**
 * C2PA and Content Credentials verification module for Node.js.
 * Audits JUMBF boxes, digitalSourceType, software agents, signatures, and watermarks.
 */

const fs = require('fs');

const AI_DIGITAL_SOURCE_TYPES = {
  'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia': 'Trained Algorithmic Media (Pure AI Generation)',
  'http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia': 'Composite with AI Media',
  'http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia': 'Algorithmic Media (Computer-generated)',
  'trainedAlgorithmicMedia': 'Trained Algorithmic Media (Pure AI Generation)',
  'compositeWithTrainedAlgorithmicMedia': 'Composite with AI Media'
};

const KNOWN_AI_KEYWORDS = [
  'chatgpt', 'openai', 'dall-e', 'dalle', 'midjourney', 'firefly',
  'stable diffusion', 'bing image creator', 'copilot', 'google imagen',
  'flux', 'sdxl', 'novelai', 'runway', 'pika', 'sora'
];

class C2PAChecker {
  /**
   * Inspects an image file for C2PA provenance manifests.
   * @param {string} filePath 
   * @returns {object}
   */
  static inspect(filePath) {
    if (!fs.existsSync(filePath)) {
      return { hasC2PA: false, error: 'File not found' };
    }

    try {
      const buffer = fs.readFileSync(filePath);
      return C2PAChecker.inspectBuffer(buffer);
    } catch (err) {
      return { hasC2PA: false, error: err.message };
    }
  }

  /**
   * Inspects an in-memory image buffer.
   * @param {Buffer} buffer 
   * @returns {object}
   */
  static inspectBuffer(buffer) {
    const result = {
      hasC2PA: false,
      claimGenerator: null,
      issuer: null,
      commonName: null,
      signatureTime: null,
      actions: [],
      watermarks: [],
      isConfirmedAI: false,
      isConfirmedCamera: false,
      detectedTool: null
    };

    // 1. Extract C2PA JUMBF payload from PNG or JPEG
    const jumbfPayload = C2PAChecker._extractJumbfPayload(buffer);
    if (!jumbfPayload) {
      return result;
    }

    result.hasC2PA = true;

    // Scan JUMBF payload for strings and JSON assertions
    const textData = jumbfPayload.toString('latin1');
    const utf8Data = jumbfPayload.toString('utf8');

    // Claim Generator
    if (textData.includes('OpenAI Media Service API')) {
      result.claimGenerator = 'OpenAI Media Service API';
    } else {
      const claimGenMatch = textData.match(/(?:claim_generator_info|OpenAI Media Service API|Adobe Photoshop|Truepic)[^\x00-\x1f\x7f-\x9f]{2,80}/i);
      if (claimGenMatch) {
        result.claimGenerator = claimGenMatch[0].trim();
      }
    }

    // Issuer / Certificate Authority
    const issuerMatch = textData.match(/(?:OpenAI OpCo, LLC|Adobe Inc\.|Microsoft Corporation|Google LLC|Truepic Inc\.)/i);
    if (issuerMatch) {
      result.issuer = issuerMatch[0];
    }

    const cnMatch = textData.match(/(?:OpenAI Media Service|Adobe Content Authenticity|Truepic Service)/i);
    if (cnMatch) {
      result.commonName = cnMatch[0];
    }

    // Timestamp
    const timeMatch = textData.match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/);
    if (timeMatch) {
      result.signatureTime = timeMatch[0];
    }

    // Actions & Digital Source Types
    const hasCreated = textData.includes('c2pa.created');
    const hasConverted = textData.includes('c2pa.converted');
    const hasWatermark = textData.includes('c2pa.watermarked.unbound') || textData.includes('c2pa.watermarked');

    if (hasWatermark) {
      result.watermarks.push('c2pa.watermarked.unbound');
    }

    // Check Software Agents
    let softwareName = null;
    let softwareVersion = null;
    if (textData.includes('ChatGPT')) {
      softwareName = 'ChatGPT';
      result.isConfirmedAI = true;
      if (textData.includes('gpt-image')) softwareVersion = 'gpt-image';
      result.detectedTool = `${softwareName} ${softwareVersion || ''}`.trim();
    } else if (textData.includes('DALL-E')) {
      softwareName = 'DALL-E';
      result.isConfirmedAI = true;
      result.detectedTool = 'DALL-E';
    } else if (textData.includes('Midjourney')) {
      softwareName = 'Midjourney';
      result.isConfirmedAI = true;
      result.detectedTool = 'Midjourney';
    } else if (textData.includes('Firefly')) {
      softwareName = 'Adobe Firefly';
      result.isConfirmedAI = true;
      result.detectedTool = 'Adobe Firefly';
    }

    // Check digitalSourceType
    let digitalSourceType = null;
    let digitalSourceLabel = null;
    for (const [uri, label] of Object.entries(AI_DIGITAL_SOURCE_TYPES)) {
      if (textData.includes(uri) || utf8Data.includes(uri)) {
        digitalSourceType = uri;
        digitalSourceLabel = label;
        result.isConfirmedAI = true;
        break;
      }
    }

    if (hasCreated) {
      result.actions.push({
        action: 'c2pa.created',
        softwareName,
        softwareVersion,
        digitalSourceType,
        digitalSourceLabel,
        isAi: result.isConfirmedAI
      });
    }

    if (hasConverted) {
      result.actions.push({
        action: 'c2pa.converted',
        softwareName: null,
        softwareVersion: null,
        digitalSourceType: null,
        digitalSourceLabel: null,
        isAi: false
      });
    }

    if (hasWatermark) {
      result.actions.push({
        action: 'c2pa.watermarked.unbound',
        softwareName: null,
        softwareVersion: null,
        digitalSourceType: null,
        digitalSourceLabel: null,
        isAi: false
      });
    }

    // Camera Capture check
    if (textData.includes('digitalsourcetype/captured') || textData.includes('c2pa.captured')) {
      result.isConfirmedCamera = true;
    }

    return result;
  }

  /**
   * Locates and extracts JUMBF chunk/box from PNG or JPEG stream.
   * @param {Buffer} buf 
   * @returns {Buffer | null}
   */
  static _extractJumbfPayload(buf) {
    // 1. PNG format check (0x89 50 4E 47)
    if (buf.length > 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
      let offset = 8;
      while (offset < buf.length - 8) {
        const len = buf.readUInt32BE(offset);
        const type = buf.slice(offset + 4, offset + 8).toString('ascii');
        if (type === 'caBX' || type === 'c2pa') {
          return buf.slice(offset + 8, offset + 8 + len);
        }
        offset += 8 + len + 4;
      }
    }

    // 2. JPEG format check (0xFF D8)
    if (buf.length > 4 && buf[0] === 0xff && buf[1] === 0xd8) {
      let offset = 2;
      while (offset < buf.length - 4) {
        if (buf[offset] !== 0xff) {
          offset++;
          continue;
        }
        const marker = buf[offset + 1];
        // APP11 marker is 0xEB (C2PA / JUMBF container)
        if (marker === 0xeb) {
          const segLen = buf.readUInt16BE(offset + 2);
          const payload = buf.slice(offset + 4, offset + 2 + segLen);
          if (payload.includes(Buffer.from('jumb', 'ascii')) || payload.includes(Buffer.from('c2pa', 'ascii'))) {
            return payload;
          }
        }
        offset += 2;
      }
    }

    // 3. Fallback scan: Search for 'c2pa' or 'jumdc2pa' signature anywhere in buffer
    const idx = buf.indexOf(Buffer.from('jumdc2pa', 'ascii'));
    if (idx !== -1) {
      return buf.slice(Math.max(0, idx - 100), Math.min(buf.length, idx + 65536));
    }

    return null;
  }
}

module.exports = { C2PAChecker };
