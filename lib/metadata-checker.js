/**
 * Metadata and AI Prompt extractor for Node.js.
 * Dissects PNG chunks (tEXt, zTXt, iTXt), EXIF, and XMP packets.
 */

const fs = require('fs');
const zlib = require('zlib');

const KNOWN_AI_SIGNATURES = [
  'automatic1111', 'comfyui', 'novelai', 'invokeai', 'fooocus',
  'midjourney', 'firefly', 'dall-e', 'bing image creator', 'copilot',
  'stable diffusion', 'flux', 'swarmui', 'easyedit', 'ideogram',
  'leonardo', 'playground', 'seaart', 'krea', 'sora', 'runway',
  'pika', 'luma', 'imagen', 'tensorart', 'sd3', 'sdxl'
];

const CAMERA_MANUFACTURERS = [
  'apple', 'canon', 'nikon', 'sony', 'leica', 'fujifilm',
  'panasonic', 'olympus', 'pentax', 'samsung', 'google', 'hasselblad'
];

class MetadataChecker {
  /**
   * Inspects image metadata for generation prompts and camera tags.
   * @param {string} filePath 
   * @returns {object}
   */
  static inspect(filePath) {
    const result = {
      hasAIMetadata: false,
      detectedGenerator: null,
      prompt: null,
      negativePrompt: null,
      model: null,
      sampler: null,
      steps: null,
      seed: null,
      cfgScale: null,
      generationParams: {},
      hasCameraExif: false,
      cameraMake: null,
      cameraModel: null,
      lensModel: null,
      rawKeys: []
    };

    if (!fs.existsSync(filePath)) return result;

    try {
      const buffer = fs.readFileSync(filePath);

      // 1. Parse PNG text chunks (tEXt, zTXt, iTXt)
      MetadataChecker._parsePngChunks(buffer, result);

      // 2. Parse embedded XMP & EXIF text
      MetadataChecker._parseXmpAndExif(buffer, result);

    } catch (err) {
      result.generationParams._error = err.message;
    }

    return result;
  }

  static _parsePngChunks(buf, res) {
    if (buf.length < 8 || buf[0] !== 0x89 || buf[1] !== 0x50 || buf[2] !== 0x4e || buf[3] !== 0x47) {
      return;
    }

    let offset = 8;
    const kvPairs = {};

    while (offset < buf.length - 8) {
      const len = buf.readUInt32BE(offset);
      const type = buf.slice(offset + 4, offset + 8).toString('ascii');
      const data = buf.slice(offset + 8, offset + 8 + len);

      if (type === 'tEXt') {
        const nullIdx = data.indexOf(0);
        if (nullIdx !== -1) {
          const key = data.slice(0, nullIdx).toString('latin1');
          const val = data.slice(nullIdx + 1).toString('latin1');
          kvPairs[key] = val;
        }
      } else if (type === 'zTXt') {
        const nullIdx = data.indexOf(0);
        if (nullIdx !== -1) {
          const key = data.slice(0, nullIdx).toString('latin1');
          const compressed = data.slice(nullIdx + 2); // null + compression method byte
          try {
            const decompressed = zlib.inflateSync(compressed).toString('latin1');
            kvPairs[key] = decompressed;
          } catch (_) {}
        }
      } else if (type === 'iTXt') {
        const nullIdx = data.indexOf(0);
        if (nullIdx !== -1) {
          const key = data.slice(0, nullIdx).toString('utf8');
          const isCompressed = data[nullIdx + 1] === 1;
          let textData = data.slice(nullIdx + 3); // null + comp flag + comp method
          // skip lang tag and trans key
          const secondNull = textData.indexOf(0);
          if (secondNull !== -1) textData = textData.slice(secondNull + 1);
          const thirdNull = textData.indexOf(0);
          if (thirdNull !== -1) textData = textData.slice(thirdNull + 1);

          try {
            const str = isCompressed ? zlib.inflateSync(textData).toString('utf8') : textData.toString('utf8');
            kvPairs[key] = str;
          } catch (_) {}
        }
      }

      offset += 8 + len + 4;
    }

    res.rawKeys = Object.keys(kvPairs);

    // Automatic1111 / WebUI / Forge 'parameters'
    if (kvPairs.parameters) {
      res.hasAIMetadata = true;
      const paramText = kvPairs.parameters;
      const lower = paramText.toLowerCase();

      if (lower.includes('flux')) {
        res.detectedGenerator = 'Flux.1 (via WebUI / Forge)';
      } else if (lower.includes('sd3')) {
        res.detectedGenerator = 'Stable Diffusion 3';
      } else if (lower.includes('sdxl')) {
        res.detectedGenerator = 'SDXL (Automatic1111 / WebUI)';
      } else {
        res.detectedGenerator = 'Stable Diffusion (Automatic1111 / WebUI)';
      }

      MetadataChecker._parseA1111Parameters(paramText, res);
    }

    // ComfyUI 'prompt' or 'workflow'
    if (kvPairs.prompt) {
      try {
        const pObj = JSON.parse(kvPairs.prompt);
        res.hasAIMetadata = true;
        res.detectedGenerator = res.detectedGenerator || 'ComfyUI';
        MetadataChecker._parseComfyUI(pObj, res);
      } catch (_) {}
    }

    if (kvPairs.workflow && !res.detectedGenerator) {
      res.hasAIMetadata = true;
      res.detectedGenerator = 'ComfyUI';
    }

    // Fooocus
    if (kvPairs.Fooocus) {
      res.hasAIMetadata = true;
      res.detectedGenerator = 'Fooocus';
      try {
        const fObj = JSON.parse(kvPairs.Fooocus);
        res.prompt = fObj.prompt;
        res.negativePrompt = fObj.negative_prompt;
        res.model = fObj.base_model;
      } catch (_) {}
    }

    // NovelAI
    if (kvPairs.Comment || kvPairs.Description) {
      const comm = kvPairs.Comment || kvPairs.Description;
      if (comm.trim().startsWith('{') && comm.toLowerCase().includes('prompt')) {
        try {
          const nObj = JSON.parse(comm);
          res.hasAIMetadata = true;
          res.detectedGenerator = 'NovelAI';
          res.prompt = nObj.prompt;
          res.negativePrompt = nObj.uc || nObj.negative_prompt;
          res.steps = nObj.steps;
          res.seed = nObj.seed;
          res.sampler = nObj.sampler;
        } catch (_) {}
      }
    }

    // Ideogram / generic prompt key
    for (const k of ['prompt', 'Prompt', 'ai_prompt']) {
      if (kvPairs[k] && !res.prompt && typeof kvPairs[k] === 'string' && kvPairs[k].length > 5) {
        res.hasAIMetadata = true;
        res.prompt = kvPairs[k].trim();
        res.detectedGenerator = res.detectedGenerator || 'AI Generated Media';
      }
    }

    // Software chunk
    if (kvPairs.Software) {
      const sw = kvPairs.Software.toLowerCase();
      for (const sig of KNOWN_AI_SIGNATURES) {
        if (sw.includes(sig)) {
          res.hasAIMetadata = true;
          res.detectedGenerator = kvPairs.Software;
        }
      }
    }
  }

  static _parseA1111Parameters(text, res) {
    const parts = text.split('Negative prompt:');
    res.prompt = parts[0].trim();

    const remaining = parts[1] || '';
    const negParts = remaining.split('Steps:');
    if (negParts.length > 1) {
      res.negativePrompt = negParts[0].trim();
      MetadataChecker._parseParamLine('Steps:' + negParts[1], res);
    } else {
      MetadataChecker._parseParamLine(remaining, res);
    }
  }

  static _parseParamLine(line, res) {
    const regex = /([A-Za-z0-9_ ]+):\s*([^,]+)(?:,|$)/g;
    let match;
    while ((match = regex.exec(line)) !== null) {
      const k = match[1].trim();
      const v = match[2].trim();
      res.generationParams[k] = v;

      const kLower = k.toLowerCase();
      if (kLower.includes('step')) res.steps = parseInt(v, 10) || null;
      else if (kLower.includes('sampler')) res.sampler = v;
      else if (kLower.includes('seed') && !kLower.includes('subseed')) res.seed = parseInt(v, 10) || null;
      else if (kLower.includes('cfg')) res.cfgScale = parseFloat(v) || null;
      else if (kLower.includes('model') && !kLower.includes('hash')) res.model = v;
    }
  }

  static _parseComfyUI(graph, res) {
    const prompts = [];
    for (const node of Object.values(graph)) {
      if (!node || typeof node !== 'object') continue;
      const cls = node.class_type || '';
      const inputs = node.inputs || {};

      if (cls.includes('CLIPTextEncode') && inputs.text && typeof inputs.text === 'string' && inputs.text.length > 3) {
        prompts.push(inputs.text.trim());
      }
      if (cls.includes('KSampler')) {
        if (inputs.steps) res.steps = inputs.steps;
        if (inputs.seed) res.seed = inputs.seed;
        if (inputs.cfg) res.cfgScale = inputs.cfg;
        if (inputs.sampler_name) res.sampler = inputs.sampler_name;
      }
      if (cls.includes('CheckpointLoader') && inputs.ckpt_name) {
        res.model = inputs.ckpt_name;
      }
    }
    if (prompts.length > 0 && !res.prompt) {
      res.prompt = prompts[0];
      if (prompts.length > 1) res.negativePrompt = prompts[1];
    }
  }

  static _parseXmpAndExif(buf, res) {
    const str = buf.toString('latin1');

    // Check XMP packets
    if (str.includes('<x:xmpmeta') || str.includes('<?xpacket')) {
      const lower = str.toLowerCase();
      for (const sig of KNOWN_AI_SIGNATURES) {
        if (lower.includes(sig)) {
          res.hasAIMetadata = true;
          res.detectedGenerator = res.detectedGenerator || `XMP Tag: ${sig.toUpperCase()}`;
        }
      }
      if (lower.includes('trainedalgorithmicmedia')) {
        res.hasAIMetadata = true;
        res.detectedGenerator = res.detectedGenerator || 'IPTC Trained Algorithmic Media';
      }
    }

    // Check Camera Manufacturers in EXIF
    for (const make of CAMERA_MANUFACTURERS) {
      const idx = str.toLowerCase().indexOf(make);
      if (idx !== -1) {
        res.hasCameraExif = true;
        res.cameraMake = make.toUpperCase();
        break;
      }
    }
  }
}

module.exports = { MetadataChecker };
