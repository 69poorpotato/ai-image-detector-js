/**
 * High-performance signal and pixel forensics engine for Node.js.
 * Vectorized Cooley-Tukey 2D FFT, noise residual kurtosis, local texture variance,
 * chromatic edge dispersion, and histogram smoothness.
 */

const fs = require('fs');
const { PNG } = require('pngjs');
const jpeg = require('jpeg-js');

const COMMON_AI_RESOLUTIONS = {
  '512x512': 'SD 1.5 standard square',
  '768x768': 'SD 2.1 standard square',
  '1024x1024': 'SDXL / Midjourney / DALL-E 3 square',
  '1152x896': 'SDXL landscape',
  '896x1152': 'SDXL portrait',
  '1216x832': 'SDXL widescreen',
  '832x1216': 'SDXL tall',
  '1344x768': 'SDXL cinematic 16:9',
  '768x1344': 'SDXL mobile 9:16',
  '1536x640': 'SDXL ultra-wide 2.4:1',
  '640x1536': 'SDXL ultra-tall',
  '1024x1792': 'DALL-E 3 portrait',
  '1792x1024': 'DALL-E 3 landscape',
  '1024x1536': 'Midjourney v6 portrait',
  '1536x1024': 'Midjourney v6 landscape',
  '1456x816': 'Flux.1 16:9 widescreen',
  '816x1456': 'Flux.1 9:16 portrait'
};

class ForensicAnalyzer {
  /**
   * Performs mathematical and signal-level forensics on an image.
   * @param {string} filePath 
   * @returns {object}
   */
  static analyze(filePath) {
    const result = {
      width: 0,
      height: 0,
      aspectRatio: '',
      isCommonAIResolution: false,
      aiResolutionDesc: null,
      psdSlope: 0.0,
      spectralGridScore: 0.0,
      noiseKurtosis: 0.0,
      noiseVariance: 0.0,
      smoothnessRatio: 0.0,
      chromaticDispersion: 0.0,
      histogramSmoothness: 0.0,
      forensicScore: 0.0,
      anomalies: []
    };

    if (!fs.existsSync(filePath)) return result;

    try {
      const buf = fs.readFileSync(filePath);
      const decoded = ForensicAnalyzer._decodeImage(buf);
      if (!decoded) return result;

      const { width, height, data } = decoded;
      result.width = width;
      result.height = height;

      // Aspect ratio & AI canvas resolution
      const gcd = ForensicAnalyzer._gcd(width, height);
      result.aspectRatio = gcd > 0 ? `${Math.floor(width / gcd)}:${Math.floor(height / gcd)}` : `${width}:${height}`;
      const dimKey = `${width}x${height}`;
      if (COMMON_AI_RESOLUTIONS[dimKey]) {
        result.isCommonAIResolution = true;
        result.aiResolutionDesc = COMMON_AI_RESOLUTIONS[dimKey];
      }

      // Convert to Grayscale Float32Array
      const gray = new Float32Array(width * height);
      const rChan = new Float32Array(width * height);
      const bChan = new Float32Array(width * height);

      for (let i = 0, p = 0; i < data.length; i += 4, p++) {
        const r = data[i], g = data[i + 1], b = data[i + 2];
        gray[p] = 0.299 * r + 0.587 * g + 0.114 * b;
        rChan[p] = r;
        bChan[p] = b;
      }

      // 1. Fast 2D FFT Frequency Analysis
      ForensicAnalyzer._analyzeFFT(gray, width, height, result);

      // 2. Noise Residual & Kurtosis
      ForensicAnalyzer._analyzeNoise(gray, width, height, result);

      // 3. Local Texture Variance (Airbrushing)
      ForensicAnalyzer._analyzeTexture(gray, width, height, result);

      // 4. Chromatic Edge Dispersion
      ForensicAnalyzer._analyzeChromaticDispersion(rChan, bChan, width, height, result);

      // 5. Histogram Smoothness
      ForensicAnalyzer._analyzeHistogram(gray, result);

      // 6. Aggregate Forensic Probability Score
      ForensicAnalyzer._calculateScore(result);

    } catch (err) {
      result.anomalies.push(`Forensic processing error: ${err.message}`);
    }

    return result;
  }

  static _decodeImage(buf) {
    // PNG check
    if (buf.length > 8 && buf[0] === 0x89 && buf[1] === 0x50) {
      const png = PNG.sync.read(buf);
      return { width: png.width, height: png.height, data: png.data };
    }
    // JPEG check
    if (buf.length > 4 && buf[0] === 0xff && buf[1] === 0xd8) {
      const j = jpeg.decode(buf, { useTArray: true });
      return { width: j.width, height: j.height, data: j.data };
    }
    return null;
  }

  static _gcd(a, b) {
    return b ? ForensicAnalyzer._gcd(b, a % b) : a;
  }

  static _analyzeFFT(gray, w, h, res) {
    const N = 256;
    const gScaled = new Float32Array(N * N);

    // Downsample to 256x256 grid
    const sx = w / N, sy = h / N;
    for (let y = 0; y < N; y++) {
      const srcY = Math.min(h - 1, Math.floor(y * sy));
      for (let x = 0; x < N; x++) {
        const srcX = Math.min(w - 1, Math.floor(x * sx));
        gScaled[y * N + x] = gray[srcY * w + srcX];
      }
    }

    const real = new Float32Array(gScaled);
    const imag = new Float32Array(N * N);

    // Row-wise FFT
    const rowR = new Float32Array(N), rowI = new Float32Array(N);
    for (let y = 0; y < N; y++) {
      for (let x = 0; x < N; x++) { rowR[x] = real[y * N + x]; rowI[x] = imag[y * N + x]; }
      ForensicAnalyzer._fft1d(rowR, rowI);
      for (let x = 0; x < N; x++) { real[y * N + x] = rowR[x]; imag[y * N + x] = rowI[x]; }
    }

    // Column-wise FFT
    const colR = new Float32Array(N), colI = new Float32Array(N);
    for (let x = 0; x < N; x++) {
      for (let y = 0; y < N; y++) { colR[y] = real[y * N + x]; colI[y] = imag[y * N + x]; }
      ForensicAnalyzer._fft1d(colR, colI);
      for (let y = 0; y < N; y++) { real[y * N + x] = colR[y]; imag[y * N + x] = colI[y]; }
    }

    // Centered 2D Power Spectral Density
    const half = N / 2;
    const psdShift = new Float32Array(N * N);
    let maxMid = 0, sumMid = 0, countMid = 0;

    for (let y = 0; y < N; y++) {
      const shiftY = (y + half) % N;
      for (let x = 0; x < N; x++) {
        const shiftX = (x + half) % N;
        const p = real[y * N + x] ** 2 + imag[y * N + x] ** 2;
        psdShift[shiftY * N + shiftX] = p;

        // Peak score
        const dy = Math.abs(shiftY - half), dx = Math.abs(shiftX - half);
        if (dy > 10 && dy < half - 10 && dx > 10 && dx < half - 10) {
          if (p > maxMid) maxMid = p;
          sumMid += p;
          countMid++;
        }
      }
    }

    if (countMid > 0 && sumMid > 0) {
      const avgMid = sumMid / countMid;
      res.spectralGridScore = parseFloat((maxMid / (avgMid + 1e-6)).toFixed(2));
    }

    // Radial Profile
    const radialSum = new Float64Array(half);
    const radialCount = new Int32Array(half);

    for (let y = 0; y < N; y++) {
      const dy = y - half;
      for (let x = 0; x < N; x++) {
        const dx = x - half;
        const r = Math.floor(Math.hypot(dx, dy));
        if (r > 0 && r < half) {
          radialSum[r] += psdShift[y * N + x];
          radialCount[r]++;
        }
      }
    }

    const logF = [], logP = [];
    for (let r = 5; r < half * 0.8; r++) {
      if (radialCount[r] > 0 && radialSum[r] > 0) {
        logF.push(Math.log10(r));
        logP.push(Math.log10(radialSum[r] / radialCount[r]));
      }
    }

    if (logF.length > 10) {
      // Linear regression
      let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
      const n = logF.length;
      for (let i = 0; i < n; i++) {
        sumX += logF[i]; sumY += logP[i];
        sumXY += logF[i] * logP[i]; sumXX += logF[i] * logF[i];
      }
      const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX + 1e-9);
      res.psdSlope = parseFloat(slope.toFixed(3));
    }
  }

  static _fft1d(real, imag) {
    const n = real.length;
    let j = 0;
    for (let i = 0; i < n; i++) {
      if (i < j) {
        let tr = real[i]; real[i] = real[j]; real[j] = tr;
        let ti = imag[i]; imag[i] = imag[j]; imag[j] = ti;
      }
      let bit = n >> 1;
      while (bit & j) { j ^= bit; bit >>= 1; }
      j ^= bit;
    }
    for (let len = 2; len <= n; len <<= 1) {
      const ang = -2 * Math.PI / len;
      const wlen_r = Math.cos(ang), wlen_i = Math.sin(ang);
      for (let i = 0; i < n; i += len) {
        let wr = 1, wi = 0;
        for (let k = 0; k < len / 2; k++) {
          const u_r = real[i + k], u_i = imag[i + k];
          const v_r = real[i + k + len / 2] * wr - imag[i + k + len / 2] * wi;
          const v_i = real[i + k + len / 2] * wi + imag[i + k + len / 2] * wr;
          real[i + k] = u_r + v_r; imag[i + k] = u_i + v_i;
          real[i + k + len / 2] = u_r - v_r; imag[i + k + len / 2] = u_i - v_i;
          const nw_r = wr * wlen_r - wi * wlen_i;
          wi = wr * wlen_i + wi * wlen_r;
          wr = nw_r;
        }
      }
    }
  }

  static _analyzeNoise(gray, w, h, res) {
    // 3x3 high-pass filter
    const residuals = new Float32Array(w * h);
    let sum = 0, sumSq = 0;
    let count = 0;

    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        const center = gray[y * w + x];
        const blur = (
          gray[(y - 1) * w + (x - 1)] + gray[(y - 1) * w + x] + gray[(y - 1) * w + (x + 1)] +
          gray[y * w + (x - 1)] + center * 4 + gray[y * w + (x + 1)] +
          gray[(y + 1) * w + (x - 1)] + gray[(y + 1) * w + x] + gray[(y + 1) * w + (x + 1)]
        ) / 12;

        const diff = center - blur;
        residuals[count++] = diff;
        sum += diff;
        sumSq += diff * diff;
      }
    }

    if (count > 0) {
      const mean = sum / count;
      const variance = (sumSq / count) - (mean * mean);
      res.noiseVariance = parseFloat(variance.toFixed(2));

      // Excess Kurtosis: E[(X-mu)^4] / sigma^4 - 3
      let m4 = 0;
      for (let i = 0; i < count; i++) {
        m4 += (residuals[i] - mean) ** 4;
      }
      const kurtosis = (m4 / count) / (variance * variance + 1e-9) - 3;
      res.noiseKurtosis = parseFloat(kurtosis.toFixed(2));
    }
  }

  static _analyzeTexture(gray, w, h, res) {
    const ksize = 16;
    let smoothCount = 0, totalBlocks = 0;

    for (let y = 0; y <= h - ksize; y += ksize) {
      for (let x = 0; x <= w - ksize; x += ksize) {
        let bSum = 0, bSumSq = 0;
        for (let by = 0; by < ksize; by++) {
          for (let bx = 0; bx < ksize; bx++) {
            const val = gray[(y + by) * w + (x + bx)];
            bSum += val;
            bSumSq += val * val;
          }
        }
        const bMean = bSum / 256;
        const bVar = (bSumSq / 256) - (bMean * bMean);
        if (bVar < 4.0) smoothCount++;
        totalBlocks++;
      }
    }

    if (totalBlocks > 0) {
      res.smoothnessRatio = parseFloat((smoothCount / totalBlocks).toFixed(3));
    }
  }

  static _analyzeChromaticDispersion(rChan, bChan, w, h, res) {
    let diffSum = 0, edgeCount = 0;
    for (let y = 1; y < h - 1; y += 2) {
      for (let x = 1; x < w - 1; x += 2) {
        const gradR = Math.abs(rChan[y * w + (x + 1)] - rChan[y * w + (x - 1)]);
        const gradB = Math.abs(bChan[y * w + (x + 1)] - bChan[y * w + (x - 1)]);
        if (gradR > 30) {
          diffSum += Math.abs(gradR - gradB);
          edgeCount++;
        }
      }
    }
    if (edgeCount > 0) {
      res.chromaticDispersion = parseFloat((diffSum / (edgeCount * 30)).toFixed(3));
    }
  }

  static _analyzeHistogram(gray, res) {
    const hist = new Int32Array(256);
    for (let i = 0; i < gray.length; i++) {
      const v = Math.min(255, Math.max(0, Math.floor(gray[i])));
      hist[v]++;
    }
    let d2Sum = 0;
    const total = gray.length;
    for (let i = 1; i < 255; i++) {
      const d2 = (hist[i + 1] - 2 * hist[i] + hist[i - 1]) / total;
      d2Sum += d2 * d2;
    }
    res.histogramSmoothness = parseFloat((Math.sqrt(d2Sum) * 1000).toFixed(2));
  }

  static _calculateScore(res) {
    let score = 0.0;
    const anomalies = [];

    // 1. Noise Kurtosis (Normal camera: -1 to 6)
    if (res.noiseKurtosis > 25.0) {
      score += 0.35;
      anomalies.push(`Extreme noise kurtosis (${res.noiseKurtosis} > 25): synthetic heavy-tailed denoising residual`);
    } else if (res.noiseKurtosis > 12.0) {
      score += 0.20;
      anomalies.push(`Elevated noise kurtosis (${res.noiseKurtosis}): non-sensor noise pattern`);
    }

    // 2. FFT Spectral Slope (Natural decay: -1.8 to -2.4)
    if (res.psdSlope < -2.9) {
      score += 0.25;
      anomalies.push(`Steep spectral rolloff (${res.psdSlope}): unnatural loss of physical micro-texture`);
    } else if (res.psdSlope > -1.5 && res.psdSlope !== 0.0) {
      score += 0.20;
      anomalies.push(`Abnormal flat spectral slope (${res.psdSlope}): high-frequency synthetic noise artifact`);
    }

    // 3. Texture Smoothness
    if (res.smoothnessRatio > 0.40) {
      score += 0.20;
      anomalies.push(`High textureless patch ratio (${(res.smoothnessRatio * 100).toFixed(1)}%): heavy synthetic airbrushing / denoising`);
    } else if (res.smoothnessRatio > 0.25) {
      score += 0.10;
      anomalies.push(`Moderate textureless patch ratio (${(res.smoothnessRatio * 100).toFixed(1)}%)`);
    }

    // 4. Standard AI Canvas Dimensions
    if (res.isCommonAIResolution) {
      score += 0.10;
      anomalies.push(`Canonical AI generator canvas size: ${res.width}x${res.height} (${res.aiResolutionDesc})`);
    }

    // 5. Chromatic Dispersion
    if (res.chromaticDispersion > 0.25) {
      score += 0.10;
      anomalies.push('Abnormal inter-channel edge dispersion inconsistent with optical glass');
    }

    res.forensicScore = Math.min(Math.max(score, 0.0), 1.0);
    res.anomalies = anomalies;
  }
}

module.exports = { ForensicAnalyzer };
