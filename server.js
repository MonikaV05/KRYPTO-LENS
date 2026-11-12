const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'cybershield-data.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ scans: [], reports: [] }, null, 2));
}

function readDB() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return {
      scans: Array.isArray(parsed.scans) ? parsed.scans : [],
      reports: Array.isArray(parsed.reports) ? parsed.reports : []
    };
  } catch {
    return { scans: [], reports: [] };
  }
}
function writeDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  frameguard: false
}));
app.use(express.json({ limit: '100kb' }));
app.use('/api', rateLimit({
  windowMs: 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

function analyze(type, data) {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [path.join(__dirname, 'analyzer.py')]);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => stdout += chunk.toString());
    child.stderr.on('data', chunk => stderr += chunk.toString());
    child.on('error', reject);
    child.on('close', code => {
      try {
        const result = JSON.parse(stdout);
        if (code !== 0 || result.error) {
          return reject(new Error(result.error || stderr || 'Analyzer failed'));
        }
        resolve(result);
      } catch {
        reject(new Error(stderr || 'Could not parse analyzer response'));
      }
    });
    child.stdin.end(JSON.stringify({ type, data }));
  });
}

async function safeBrowsing(url) {
  if (!process.env.GSB_KEY) return null;
  const response = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(process.env.GSB_KEY)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'cybershield-demo', clientVersion: '1.1' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    }
  );
  if (!response.ok) return null;
  const body = await response.json();
  return body.matches?.length ? 'Google Safe Browsing reported a threat' : null;
}

async function virusTotal(url) {
  if (!process.env.VT_KEY) return null;
  // VirusTotal URL identifiers use URL-safe base64 without padding.
  const id = Buffer.from(url).toString('base64').replace(/=+$/g, '')
    .replace(/\+/g, '-').replace(/\//g, '_');
  const response = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
    headers: { 'x-apikey': process.env.VT_KEY }
  });
  if (!response.ok) return null;
  const body = await response.json();
  const stats = body.data?.attributes?.last_analysis_stats;
  if (!stats) return null;
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  return malicious + suspicious > 0
    ? `VirusTotal: ${malicious} malicious, ${suspicious} suspicious detections`
    : null;
}

// Specific routes MUST be declared BEFORE generic parameter routes like /api/scan/:type
// QR analysis reuses the existing Python URL/message analyzer. QR contents are
// never opened or fetched; URL redirects are not followed by this application.
app.post('/api/scan/qr', async (req, res) => {
  try {
    const content = String(req.body?.data ?? '').trim().slice(0, 20000);
    if (!content) return res.status(400).json({ error: 'No QR content was decoded' });
    const looksLikeUrl = /^(https?:\/\/|www\.)/i.test(content) || /^[a-z0-9.-]+\.[a-z]{2,}(\/|$)/i.test(content);
    const scanType = looksLikeUrl ? 'url' : 'phishing';
    const result = await analyze(scanType, content);
    result.qrContentType = looksLikeUrl ? 'URL' : 'Text';
    result.extractedContent = content.slice(0, 500);
    result.sources = ['CyberShield heuristic checks (QR content)'];
    if (looksLikeUrl) {
      const hits = (await Promise.allSettled([safeBrowsing(content), virusTotal(content)]))
        .filter(x => x.status === 'fulfilled' && x.value).map(x => x.value);
      if (hits.length) {
        result.score = Math.max(Number(result.score) || 0, 90);
        result.verdict = 'Dangerous';
        result.flags = [...hits, ...(result.flags || [])];
        result.sources.push('External reputation services');
      }
    }
    const db = readDB();
    db.scans.unshift({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      type: 'qr', input: `QR ${result.qrContentType}: ${content.slice(0, 160)}`,
      score: result.score, risk: result.score, verdict: result.verdict,
      flags: result.flags || [], createdAt: new Date().toISOString()
    });
    db.scans = db.scans.slice(0, 500);
    writeDB(db);
    res.json(result);
  } catch (error) {
    console.error('QR scan error:', error.message);
    res.status(500).json({ error: 'QR analysis failed' });
  }
});

app.post('/api/scan/:type', async (req, res) => {
  try {
    const type = req.params.type;
    const data = String(req.body?.data ?? '').trim().slice(0, 20000);
    if (!['url', 'phishing', 'email', 'password', 'qr'].includes(type)) {
      return res.status(400).json({ error: 'Unsupported scan type' });
    }
    if (!data) return res.status(400).json({ error: 'Please enter something to scan' });

    const result = await analyze(type, data);
    result.sources = ['CyberShield heuristic checks'];

    if (type === 'url') {
      const reputationResults = await Promise.allSettled([
        safeBrowsing(data), virusTotal(data)
      ]);
      const hits = reputationResults
        .filter(item => item.status === 'fulfilled' && item.value)
        .map(item => item.value);
      if (hits.length) {
        result.score = Math.max(Number(result.score) || 0, 90);
        result.verdict = 'Dangerous';
        result.flags = [...hits, ...(result.flags || [])];
        result.sources.push('External reputation services');
      }
    }

    const risk = type === 'password' ? 100 - result.score : result.score;
    // Never persist the submitted password or message body.
    const savedInput = type === 'password'
      ? `Password not stored (${data.length} characters)`
      : data.slice(0, 200);
    const db = readDB();
    db.scans.unshift({
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      type,
      input: savedInput,
      score: result.score,
      risk,
      verdict: result.verdict,
      flags: result.flags || [],
      createdAt: new Date().toISOString()
    });
    db.scans = db.scans.slice(0, 500);
    writeDB(db);
    res.json(result);
  } catch (error) {
    console.error('Scan error:', error.message);
    res.status(500).json({ error: 'Scan failed. Check the server log for details.' });
  }
});

app.get('/api/dashboard', (_req, res) => {
  const db = readDB();
  const history = db.scans.slice(0, 10);
  const alerts = db.scans
    .filter(scan => scan.risk >= 30 && scan.type !== 'password')
    .slice(0, 6);
  const recent = db.scans.slice(0, 20);
  const averageRisk = recent.length
    ? recent.reduce((sum, scan) => sum + (Number(scan.risk) || 0), 0) / recent.length
    : 0;
  res.json({
    history,
    alerts,
    score: Math.round(100 - averageRisk),
    stats: {
      total: db.scans.length,
      emails: db.scans.filter(s => s.type === 'email' || s.type === 'phishing').length,
      urls: db.scans.filter(s => s.type === 'url').length,
      qrs: db.scans.filter(s => s.type === 'qr').length,
      safe: db.scans.filter(s => s.verdict === 'Safe').length,
      suspicious: db.scans.filter(s => s.verdict === 'Suspicious').length,
      dangerous: db.scans.filter(s => s.verdict === 'Dangerous').length,
      threats: db.scans.filter(scan => scan.verdict === 'Dangerous').length,
      reports: db.reports.length
    }
  });
});

app.get('/api/ip', async (_req, res) => lookupIP('', res));
app.get('/api/ip/:ip', async (req, res) => lookupIP(req.params.ip, res));

async function lookupIP(ip, res) {
  const net = require('net');
  if (ip && !net.isIP(ip)) {
    return res.status(400).json({ error: 'Enter a valid IPv4 or IPv6 address' });
  }
  try {
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (!response.ok) throw new Error('IP lookup service returned an error');
    const body = await response.json();
    if (!body.success) {
      return res.status(404).json({ error: body.message || 'IP lookup failed' });
    }
    res.json({
      ip: body.ip,
      type: body.type,
      country: body.country,
      region: body.region,
      city: body.city,
      isp: body.connection?.isp || null,
      org: body.connection?.org || null,
      asn: body.connection?.asn || null,
      timezone: body.timezone?.id || null
    });
  } catch (error) {
    console.error('IP lookup error:', error.message);
    res.status(502).json({ error: 'IP lookup service is currently unavailable' });
  }
}

app.post('/api/report', (req, res) => {
  const url = String(req.body?.url ?? '').trim().slice(0, 500);
  const note = String(req.body?.note ?? '').trim().slice(0, 1000);
  if (!url) return res.status(400).json({ error: 'URL is required' });
  const db = readDB();
  db.reports.unshift({
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    url,
    note,
    createdAt: new Date().toISOString()
  });
  db.reports = db.reports.slice(0, 500);
  writeDB(db);
  res.json({ ok: true });
});

app.use(express.static(PUBLIC_DIR));
app.get('*', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

app.use((err, _req, res, _next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({ error: 'Unexpected server error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`KRYPTO LENS is running on port ${PORT}`);
  console.log('Local demo storage: cybershield/data/cybershield-data.json');
  console.log('Optional threat-intelligence APIs:', Boolean(process.env.GSB_KEY || process.env.VT_KEY));
});
