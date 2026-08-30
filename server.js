const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const VALID_KEYS = new Map([
  ['A381-7K2M-9X4P', { used: false, token: null }],
  ['B72F-3N8Q-XL1Z', { used: false, token: null }],
  ['C6D4-9RPW-2T5K', { used: false, token: null }],
  ['D1QX-8Y3M-7VBN', { used: false, token: null }],
  ['E9ZL-5CW6-4RT2', { used: false, token: null }],
  ['F4KP-2MX8-7Y1S', { used: false, token: null }],
  ['G8TN-6B9C-3VQX', { used: false, token: null }],
  ['H3WR-1PD7-9KM4', { used: false, token: null }],
  ['J5YV-4CN2-8TL6', { used: false, token: null }],
  ['K7XM-9FT3-2QWP', { used: false, token: null }],
]);

const SESSIONS = new Map();
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' };

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url);
  const pathname = parsed.pathname;

  if (pathname === '/api/auth' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { key } = JSON.parse(body);
        const record = VALID_KEYS.get(key);
        if (!record) { res.end(JSON.stringify({ ok: false, msg: '卡密无效' })); return; }
        if (record.used) { res.end(JSON.stringify({ ok: false, msg: '卡密已被使用，不可二次登录' })); return; }
        const token = crypto.randomBytes(16).toString('hex');
        record.used = true;
        record.token = token;
        SESSIONS.set(token, Date.now() + 120000);
        res.end(JSON.stringify({ ok: true, token }));
      } catch(e) { res.end(JSON.stringify({ ok: false })); }
    });
    return;
  }

  if (pathname === '/api/check' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { token } = JSON.parse(body);
        const expire = SESSIONS.get(token);
        if (!expire || Date.now() > expire) {
          SESSIONS.delete(token);
          res.end(JSON.stringify({ ok: false }));
          return;
        }
        SESSIONS.set(token, Date.now() + 120000);
        res.end(JSON.stringify({ ok: true }));
      } catch(e) { res.end(JSON.stringify({ ok: false })); }
    });
    return;
  }

  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.join(__dirname, filePath);
  if (!filePath.startsWith(__dirname)) { res.writeHead(403); return res.end('Forbidden'); }
  const ext = path.extname(filePath);
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'text/plain' });
    res.end(data);
  });
});

server.listen(3000, () => console.log('Server on :3000'));
