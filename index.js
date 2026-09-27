const express     = require('express');
const admin       = require('firebase-admin');
const bodyParser  = require('body-parser');
const cors        = require('cors');
const crypto      = require('crypto');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ── Firebase Admin initialize ──
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// ════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════

function isValidAppId(appId) {
  return appId && /^[a-zA-Z0-9._\-]{3,100}$/.test(appId);
}

function tokenDocId(token) {
  return token.replace(/[^a-zA-Z0-9]/g, '').substring(0, 20);
}

function devicesRef(appId) {
  return db.collection('push_tokens').doc(appId).collection('devices');
}

function appMetaRef(appId) {
  return db.collection('push_app_meta').doc(appId);
}

// Password → SHA-256 hash
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Password verify করো Firestore থেকে
async function verifyPassword(appId, password) {
  if (!password) return { ok: false, reason: 'password_required' };
  const doc = await appMetaRef(appId).get();
  if (!doc.exists) return { ok: false, reason: 'app_not_registered' };
  const stored = doc.data().passwordHash;
  if (!stored) return { ok: false, reason: 'no_password_set' };
  if (stored !== hashPassword(password)) return { ok: false, reason: 'invalid_password' };
  return { ok: true };
}

// ════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.send('Wevlo Push Notification Server is Running!');
});

// ── Register App (APK build থেকে password সেট হয়) ──
// POST /register-app  { appId, password }
app.post('/register-app', async (req, res) => {
  const { appId, password } = req.body;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });
  if (!password || password.length < 6) return res.status(400).json({ success: false, error: 'password min 6 chars' });

  try {
    const ref = appMetaRef(appId);
    const doc = await ref.get();

    if (doc.exists && doc.data().passwordHash) {
      // App already registered — existing password দিয়ে verify করতে হবে
      const { currentPassword } = req.body;
      if (!currentPassword) {
        // First-time setup থেকে আলাদা — ignore করো (APK rebuild scenario)
        // নতুন password hash update করো যদি same password হয়
        if (doc.data().passwordHash === hashPassword(password)) {
          return res.json({ success: true, message: 'already registered' });
        }
        return res.status(409).json({ success: false, error: 'app_already_registered' });
      }
      if (doc.data().passwordHash !== hashPassword(currentPassword)) {
        return res.status(401).json({ success: false, error: 'invalid_current_password' });
      }
    }

    await ref.set({
      appId,
      passwordHash: hashPassword(password),
      registeredAt: doc.exists ? doc.data().registeredAt : Date.now(),
      updatedAt:    Date.now()
    }, { merge: true });

    console.log(`[${appId}] App registered/updated`);
    res.json({ success: true, message: 'app registered' });
  } catch (e) {
    console.error('Register-app error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Register Token (APK থেকে আসে) ──
// POST /register-token  { token, appId, userAgent?, password? }
app.post('/register-token', async (req, res) => {
  const { token, appId, userAgent, password } = req.body;

  if (!token)               return res.status(400).json({ success: false, error: 'token required' });
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  // Password দিলে verify করো, না দিলে allow করো (পুরনো APK backward compat)
  if (password) {
    const auth = await verifyPassword(appId, password);
    if (!auth.ok && auth.reason === 'invalid_password') {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }
  }

  try {
    await devicesRef(appId).doc(tokenDocId(token)).set({
      token,
      appId,
      userAgent:    userAgent || '',
      registeredAt: Date.now(),
      updatedAt:    Date.now()
    }, { merge: true });

    console.log(`[${appId}] Token registered: ${token.substring(0, 20)}...`);
    res.json({ success: true });
  } catch (e) {
    console.error('Register error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Get tokens by appId (password required) ──
// GET /tokens?appId=com.myapp.xyz&password=xxx
app.get('/tokens', async (req, res) => {
  const { appId, password } = req.query;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  // Password verify
  const auth = await verifyPassword(appId, password);
  if (!auth.ok) {
    // app_not_registered মানে এই app এখনো /register-app করেনি
    // সেক্ষেত্রে password ছাড়াই allow করো (পুরনো flow)
    if (auth.reason !== 'app_not_registered' && auth.reason !== 'no_password_set') {
      return res.status(401).json({ success: false, error: auth.reason });
    }
    // app registered নেই — password check skip
  }

  try {
    const snap   = await devicesRef(appId).get();
    const tokens = snap.docs.map(d => ({
      token:        d.data().token,
      registeredAt: d.data().registeredAt,
      userAgent:    d.data().userAgent || ''
    }));
    res.json({ success: true, appId, count: tokens.length, tokens });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Send to one token (password required) ──
// POST /send-notification  { token, title, body, password, appId }
app.post('/send-notification', async (req, res) => {
  const { token, title, body, imageUrl, password, appId } = req.body;
  if (!token) return res.status(400).json({ success: false, error: 'token required' });

  // Password verify (appId দিলে verify করো)
  if (appId && password) {
    const auth = await verifyPassword(appId, password);
    if (!auth.ok && auth.reason === 'invalid_password') {
      return res.status(401).json({ success: false, error: 'invalid_password' });
    }
    // app_not_registered বা no_password_set হলে allow করো
  } else if (!appId || !password) {
    // পুরনো client যারা appId/password পাঠায় না — allow করো
  }

  try {
    const t = title || 'Notification';
    const b = body  || '';

    const message = {
      token,
      data: { title: t, body: b, ...(imageUrl ? { imageUrl } : {}) },
      android: { priority: 'high' }
    };

    const msgId = await admin.messaging().send(message);
    res.json({ success: true, messageId: msgId });
  } catch (e) {
    console.error('Send error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Send to ALL tokens of an appId (password required) ──
// POST /send-all  { appId, title, body, password }
app.post('/send-all', async (req, res) => {
  const { appId, title, body, imageUrl, password } = req.body;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  // Password verify
  const auth = await verifyPassword(appId, password);
  if (!auth.ok) return res.status(401).json({ success: false, error: auth.reason });

  try {
    const snap = await devicesRef(appId).get();
    if (snap.empty) return res.json({ success: false, error: 'No tokens found for this app' });

    const tokens = snap.docs.map(d => d.data().token).filter(Boolean);
    const t = title || 'Notification';
    const b = body  || '';
    const messages = tokens.map(token => ({
      token,
      data: { title: t, body: b, ...(imageUrl ? { imageUrl } : {}) },
      android: { priority: 'high' }
    }));

    const result = await admin.messaging().sendEach(messages);
    console.log(`[${appId}] Sent: ${result.successCount} ok, ${result.failureCount} failed`);

    // invalid token গুলো Firestore থেকে delete করো
    const batch = db.batch();
    let removed = 0;
    result.responses.forEach((r, i) => {
      if (!r.success) { batch.delete(snap.docs[i].ref); removed++; }
    });
    if (removed > 0) await batch.commit();

    res.json({
      success:      true,
      appId,
      total:        tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount
    });
  } catch (e) {
    console.error('Send-all error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Delete a token (password required) ──
// DELETE /token?appId=com.myapp&token=xxx&password=yyy
app.delete('/token', async (req, res) => {
  const { appId, token, password } = req.query;
  if (!isValidAppId(appId) || !token) return res.status(400).json({ success: false, error: 'appId and token required' });

  const auth = await verifyPassword(appId, password);
  if (!auth.ok) return res.status(401).json({ success: false, error: auth.reason });

  try {
    await devicesRef(appId).doc(tokenDocId(token)).delete();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 7860;
app.listen(PORT, () => console.log(`Wevlo Push Server running on port ${PORT}`));