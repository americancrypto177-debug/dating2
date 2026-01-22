import http from 'http';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import { v4 as uuidv4 } from 'uuid';

import { config } from './config.js';
import { initDb, query, tx } from './db.js';
import { Roles, authMiddleware, hashPassword, comparePassword, signToken, requireSiteKey } from './auth.js';
import { initSocket, pickOperatorRoundRobin, socketEmitToOperators, socketEmitToSupervisors, socketEmitToUser } from './socket.js';
import { createCheckoutSession, handleStripeWebhook } from './stripe.js';

function cleanEmail(v) {
  return String(v || '').trim().toLowerCase();
}

function cleanText(v) {
  return String(v || '').trim();
}


function siteRedirectUrl(siteKey) {
  const k = String(siteKey || '').toLowerCase();
  if (k === 'szerelmesszivek') return config.siteSzerelmesSzivekUrl;
  return config.siteForrorandiUrl; // default
}


async function ensureSeedData() {
  // Seed required sites
  const sites = [
    { site_key: 'forrorandi', name: 'ForróRandi' },
    { site_key: 'szerelmesszivek', name: 'Szerelmes Szívek' }
  ];
  for (const s of sites) {
    await query('INSERT INTO sites (site_key, name) VALUES ($1,$2) ON CONFLICT (site_key) DO NOTHING', [s.site_key, s.name]);
  }

  // Seed staff accounts (admin + supervisors + operators)
  const staff = [];
  staff.push({ email: 'adminzola1998', display_name: 'Admin', role: 'admin', password: 'Sasfioka98' });
  staff.push({ email: 'sup_1', display_name: 'SUP_1', role: 'supervisor', password: 'JP*o$QDmIlU%MK7A' });
  staff.push({ email: 'sup_2', display_name: 'SUP_2', role: 'supervisor', password: 'PNwpx%=2wv-98zvR' });
  staff.push({ email: 'sup_3', display_name: 'SUP_3', role: 'supervisor', password: 'MS&i+W8=yt*av+-V' });
  staff.push({ email: 'op_001', display_name: 'OP_001', role: 'operator', password: 'iQAaFiUDsUq&dh?n' });
  staff.push({ email: 'op_002', display_name: 'OP_002', role: 'operator', password: '21os6D$5xP6LQ=E9' });
  staff.push({ email: 'op_003', display_name: 'OP_003', role: 'operator', password: 'K8P+d!*dcj3nWd7q' });
  staff.push({ email: 'op_004', display_name: 'OP_004', role: 'operator', password: 'osk1bVvDAU8O@!#p' });
  staff.push({ email: 'op_005', display_name: 'OP_005', role: 'operator', password: 'jKC=$m4Piny!&Sjk' });
  staff.push({ email: 'op_006', display_name: 'OP_006', role: 'operator', password: 'rs$jveMMWulK1bGZ' });
  staff.push({ email: 'op_007', display_name: 'OP_007', role: 'operator', password: 'O#eBMHo2Ex=GWRh7' });
  staff.push({ email: 'op_008', display_name: 'OP_008', role: 'operator', password: 'Mt9H4-v4GH+0j^VH' });
  staff.push({ email: 'op_009', display_name: 'OP_009', role: 'operator', password: 'Phsh=w0=B90HBPrS' });
  staff.push({ email: 'op_010', display_name: 'OP_010', role: 'operator', password: 'kttA9zx!dv&UVmmI' });
  staff.push({ email: 'op_011', display_name: 'OP_011', role: 'operator', password: 'u#OEt#fp&@1Te?#R' });
  staff.push({ email: 'op_012', display_name: 'OP_012', role: 'operator', password: 'CEXV7T^Ec_AyH5BV' });
  staff.push({ email: 'op_013', display_name: 'OP_013', role: 'operator', password: 'Wpz=Alj+#HyQmcq1' });
  staff.push({ email: 'op_014', display_name: 'OP_014', role: 'operator', password: 'AegEv^iM1^jJf1T6' });
  staff.push({ email: 'op_015', display_name: 'OP_015', role: 'operator', password: 'Ej_!xpgH9GqOKU_u' });
  staff.push({ email: 'op_016', display_name: 'OP_016', role: 'operator', password: '1cnt&HIaiviro@eB' });
  staff.push({ email: 'op_017', display_name: 'OP_017', role: 'operator', password: 'W&7Hyft0Pq*h8U8l' });
  staff.push({ email: 'op_018', display_name: 'OP_018', role: 'operator', password: 'AilDGmTTgB$Jh6^I' });
  staff.push({ email: 'op_019', display_name: 'OP_019', role: 'operator', password: '7pK5*3KboHbgqh1?' });
  staff.push({ email: 'op_020', display_name: 'OP_020', role: 'operator', password: '_tX-B&vyA1$&FL?f' });
  staff.push({ email: 'op_021', display_name: 'OP_021', role: 'operator', password: 'w2B+^36%Mwh4n^iK' });
  staff.push({ email: 'op_022', display_name: 'OP_022', role: 'operator', password: 'x+jwO2@@1$ucP!y#' });
  staff.push({ email: 'op_023', display_name: 'OP_023', role: 'operator', password: 'bfp0FOAx%kFgmiFD' });
  staff.push({ email: 'op_024', display_name: 'OP_024', role: 'operator', password: '+^WmR=hbePE8Q?i@' });
  staff.push({ email: 'op_025', display_name: 'OP_025', role: 'operator', password: 'GG-JY#uMw=5=9b$k' });
  staff.push({ email: 'op_adminzola', display_name: 'OP_ADMINZOLA', role: 'operator', password: 'qxoiMLux?O0l0d?S' });
  staff.push({ email: 'op_sup_1', display_name: 'OP_SUP_1', role: 'operator', password: '%V+^*KwnjjV@$3J2' });
  staff.push({ email: 'op_sup_2', display_name: 'OP_SUP_2', role: 'operator', password: 'TI@D4jlQN8lG+W+N' });
  staff.push({ email: 'op_sup_3', display_name: 'OP_SUP_3', role: 'operator', password: 'EGtD%hyU-^H8Ry4K' });

  for (const a of staff) {
    const r = await query('SELECT id FROM operators WHERE email=$1', [a.email]);
    if (r.rows.length) continue;
    const ph = await hashPassword(a.password);
    await query('INSERT INTO operators (email, display_name, role, password_hash) VALUES ($1,$2,$3,$4)', [a.email, a.display_name, a.role, ph]);
  }
}

async function getSiteId(siteKey) {
  const r = await query('SELECT id FROM sites WHERE site_key=$1', [siteKey]);
  if (!r.rows.length) throw new Error('Unknown siteKey');
  return r.rows[0].id;
}

async function getUserCredits(userId) {
  const r = await query('SELECT COALESCE(SUM(delta),0) AS credits FROM credit_ledger WHERE user_id=$1', [userId]);
  return Number(r.rows[0].credits || 0);
}

const app = express();

// Raw body needed for Stripe webhook
app.post('/v1/stripe/webhook', express.raw({ type: '*/*' }), async (req, res) => {
  try {
    const sig = req.headers['stripe-signature'];
    if (!sig) return res.status(400).send('Missing stripe-signature');
    const result = await handleStripeWebhook(req.body, sig);
    return res.json(result);
  } catch (e) {
    return res.status(400).send(`Webhook error: ${e.message}`);
  }
});

app.use(express.json({ limit: '1mb' }));
app.use(helmet());
app.use(morgan('tiny'));

app.use(cors({
  origin: config.corsOrigins.length ? config.corsOrigins : true,
  credentials: true
}));

// Health
app.get('/health', (req, res) => {
  if (config.healthToken) {
    const token = req.query.token || req.headers['x-health-token'];
    if (token !== config.healthToken) return res.status(401).json({ ok: false });
  }
  res.json({ ok: true, ts: Date.now() });
});

// Stripe return (redirect back to the correct Netlify site)
app.get('/stripe/success', (req, res) => {
  const site = req.query.site;
  return res.redirect(302, siteRedirectUrl(site));
});

app.get('/stripe/cancel', (req, res) => {
  const site = req.query.site;
  return res.redirect(302, siteRedirectUrl(site));
});

// Packages
app.get('/v1/credits/packages', (req, res) => {
  const siteKey = requireSiteKey(req, res);
  if (!siteKey) return;
  // Expose safe info for UI (only this site)
  const safe = config.stripePackages
    .filter(p => p.site === siteKey)
    .map(p => ({ id: p.id, name: p.name, credits: p.credits, amountHuf: p.amountHuf }));
  res.json({ packages: safe });
});

// Auth - user register
app.post('/v1/auth/register', async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');
    const nickname = cleanText(req.body.nickname || '');
    if (!email || !password || !nickname) return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

    const siteId = await getSiteId(siteKey);
    const passHash = await hashPassword(password);

    const user = await tx(async (client) => {
      const ins = await client.query(
        `INSERT INTO users (id, site_id, email, password_hash, nickname)
         VALUES ($1,$2,$3,$4,$5)
         RETURNING id, email, nickname, created_at`,
        [uuidv4(), siteId, email, passHash, nickname]
      );
      return ins.rows[0];
    });

    const token = signToken({ role: Roles.USER, userId: user.id });

    // Real-time: notify staff
    socketEmitToOperators(siteKey, 'user:new', { user });
    socketEmitToSupervisors(siteKey, 'user:new', { user });

    res.json({ token, user: { id: user.id, email: user.email, nickname: user.nickname, created_at: user.created_at } });
  } catch (e) {
    if (String(e.message || '').includes('duplicate key')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: e.message });
  }
});

// Auth - user login
app.post('/v1/auth/login', async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const siteId = await getSiteId(siteKey);
    const r = await query('SELECT id, email, nickname, password_hash FROM users WHERE site_id=$1 AND email=$2', [siteId, email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const u = r.rows[0];
    const ok = await comparePassword(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ role: Roles.USER, userId: u.id });
    const credits = await getUserCredits(u.id);
    res.json({ token, user: { id: u.id, email: u.email, nickname: u.nickname }, credits });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Auth - operator/supervisor login
app.post('/v1/auth/staff-login', async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const r = await query('SELECT id, email, display_name, role, password_hash FROM operators WHERE email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const o = r.rows[0];
    const ok = await comparePassword(password, o.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ role: o.role, userId: o.id });
    res.json({ token, staff: { id: o.id, email: o.email, displayName: o.display_name, role: o.role }, siteKey });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Me
app.get('/v1/me', authMiddleware([Roles.USER, Roles.OPERATOR, Roles.SUPERVISOR]), async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;

    if (req.auth.role === Roles.USER) {
      const siteId = await getSiteId(siteKey);
      const r = await query('SELECT id, email, nickname, created_at FROM users WHERE id=$1 AND site_id=$2', [req.auth.userId, siteId]);
      if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
      const credits = await getUserCredits(req.auth.userId);
      return res.json({ role: Roles.USER, user: r.rows[0], credits });
    } else {
      const r = await query('SELECT id, email, display_name, role, created_at FROM operators WHERE id=$1', [req.auth.userId]);
      if (!r.rows.length) return res.status(404).json({ error: 'Staff not found' });
      return res.json({ role: r.rows[0].role, staff: { id: r.rows[0].id, email: r.rows[0].email, displayName: r.rows[0].display_name, created_at: r.rows[0].created_at } });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin - create operator/supervisor (supervisors can create operators)
app.post('/v1/admin/create-staff', authMiddleware([Roles.SUPERVISOR]), async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');
    const displayName = cleanText(req.body.displayName || '');
    const role = cleanText(req.body.role || Roles.OPERATOR);
    if (!email || !password || !displayName) return res.status(400).json({ error: 'Missing fields' });
    if (![Roles.OPERATOR, Roles.SUPERVISOR].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const passHash = await hashPassword(password);
    const r = await query(
      `INSERT INTO operators (id, email, password_hash, display_name, role)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, email, display_name, role`,
      [uuidv4(), email, passHash, displayName, role]
    );
    res.json({ staff: { id: r.rows[0].id, email: r.rows[0].email, displayName: r.rows[0].display_name, role: r.rows[0].role } });
  } catch (e) {
    if (String(e.message || '').includes('duplicate key')) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: e.message });
  }
});

// Stripe - start checkout session
app.post('/v1/credits/checkout', authMiddleware([Roles.USER]), async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const packageId = cleanText(req.body.packageId || '');
    if (!packageId) return res.status(400).json({ error: 'Missing packageId' });

    const siteId = await getSiteId(siteKey);
    const r = await query('SELECT id, email FROM users WHERE id=$1 AND site_id=$2', [req.auth.userId, siteId]);
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });

    const session = await createCheckoutSession({ userId: r.rows[0].id, email: r.rows[0].email, packageId, siteKey });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Chat - user sends message (costs credits)
app.post('/v1/chat/send', authMiddleware([Roles.USER]), async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const body = cleanText(req.body.body || '');
    if (!body) return res.status(400).json({ error: 'Empty message' });

    const siteId = await getSiteId(siteKey);

    const result = await tx(async (client) => {
      // Verify user
      const ur = await client.query('SELECT id FROM users WHERE id=$1 AND site_id=$2', [req.auth.userId, siteId]);
      if (!ur.rows.length) return { error: 'User not found', status: 404 };

      // Check credits
      const cr = await client.query('SELECT COALESCE(SUM(delta),0) AS credits FROM credit_ledger WHERE user_id=$1', [req.auth.userId]);
      const credits = Number(cr.rows[0].credits || 0);
      if (credits < config.messageCostCredits) {
        return { error: 'Nincs elég kredit', status: 402, credits };
      }

      // Get or create open conversation
      let conv = await client.query(
        `SELECT id, assigned_operator_id FROM conversations
         WHERE site_id=$1 AND user_id=$2 AND status='open'
         ORDER BY created_at DESC LIMIT 1`,
        [siteId, req.auth.userId]
      );

      let conversationId;
      let assignedOperatorId;

      if (!conv.rows.length) {
        assignedOperatorId = pickOperatorRoundRobin(siteKey);
        const ins = await client.query(
          `INSERT INTO conversations (id, site_id, user_id, assigned_operator_id)
           VALUES ($1,$2,$3,$4)
           RETURNING id, assigned_operator_id`,
          [uuidv4(), siteId, req.auth.userId, assignedOperatorId]
        );
        conversationId = ins.rows[0].id;
        assignedOperatorId = ins.rows[0].assigned_operator_id;
      } else {
        conversationId = conv.rows[0].id;
        assignedOperatorId = conv.rows[0].assigned_operator_id;
        if (!assignedOperatorId) {
          const pick = pickOperatorRoundRobin(siteKey);
          if (pick) {
            const up = await client.query(
              'UPDATE conversations SET assigned_operator_id=$1 WHERE id=$2 RETURNING assigned_operator_id',
              [pick, conversationId]
            );
            assignedOperatorId = up.rows[0].assigned_operator_id;
          }
        }
      }

      // Insert message
      const msg = await client.query(
        `INSERT INTO messages (id, conversation_id, sender_role, sender_id, body)
         VALUES ($1,$2,'user',$3,$4)
         RETURNING id, conversation_id, sender_role, sender_id, body, created_at`,
        [uuidv4(), conversationId, req.auth.userId, body]
      );

      // Deduct credits
      await client.query(
        `INSERT INTO credit_ledger (id, user_id, delta, reason)
         VALUES ($1,$2,$3,$4)`,
        [uuidv4(), req.auth.userId, -config.messageCostCredits, 'message']
      );

      const newCredits = credits - config.messageCostCredits;

      return { message: msg.rows[0], conversationId, assignedOperatorId, credits: newCredits };
    });

    if (result?.error) return res.status(result.status || 400).json(result);

    // Real-time broadcast
    socketEmitToOperators(siteKey, 'message:new', result);
    socketEmitToSupervisors(siteKey, 'message:new', result);
    socketEmitToUser(siteKey, req.auth.userId, 'message:new', result);

    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Operator inbox
app.get('/v1/operator/inbox', authMiddleware([Roles.OPERATOR, Roles.SUPERVISOR]), async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const siteId = await getSiteId(siteKey);

    const rows = await query(
      `SELECT c.id AS conversation_id, c.user_id, c.assigned_operator_id, c.status, c.created_at, c.updated_at,
              u.nickname,
              (SELECT body FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
              (SELECT created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message_at
       FROM conversations c
       JOIN users u ON u.id = c.user_id
       WHERE c.site_id=$1 AND c.status='open'
       ORDER BY c.updated_at DESC
       LIMIT 200`,
      [siteId]
    );

    res.json({ conversations: rows.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Operator assign self
app.post('/v1/operator/conversations/:id/assign', authMiddleware([Roles.OPERATOR, Roles.SUPERVISOR]), async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const siteId = await getSiteId(siteKey);
    const conversationId = req.params.id;

    const r = await query(
      `UPDATE conversations SET assigned_operator_id=$1
       WHERE id=$2 AND site_id=$3
       RETURNING id, assigned_operator_id`,
      [req.auth.userId, conversationId, siteId]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Conversation not found' });

    socketEmitToOperators(siteKey, 'conversation:assigned', { conversationId, operatorId: req.auth.userId });
    socketEmitToSupervisors(siteKey, 'conversation:assigned', { conversationId, operatorId: req.auth.userId });

    res.json({ ok: true, conversation: r.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Operator reply
app.post('/v1/operator/conversations/:id/reply', authMiddleware([Roles.OPERATOR, Roles.SUPERVISOR]), async (req, res) => {
  try {
    const siteKey = requireSiteKey(req, res);
    if (!siteKey) return;
    const siteId = await getSiteId(siteKey);
    const conversationId = req.params.id;
    const body = cleanText(req.body.body || '');
    if (!body) return res.status(400).json({ error: 'Empty message' });

    const result = await tx(async (client) => {
      const conv = await client.query('SELECT id, user_id FROM conversations WHERE id=$1 AND site_id=$2', [conversationId, siteId]);
      if (!conv.rows.length) return { error: 'Conversation not found', status: 404 };

      // Ensure assigned to self or unassigned (supervisors can reply anyway)
      if (req.auth.role === Roles.OPERATOR) {
        const chk = await client.query('SELECT assigned_operator_id FROM conversations WHERE id=$1', [conversationId]);
        const assigned = chk.rows[0].assigned_operator_id;
        if (assigned && assigned !== req.auth.userId) {
          return { error: 'Conversation assigned to another operator', status: 403 };
        }
        if (!assigned) {
          await client.query('UPDATE conversations SET assigned_operator_id=$1 WHERE id=$2', [req.auth.userId, conversationId]);
        }
      }

      const msg = await client.query(
        `INSERT INTO messages (id, conversation_id, sender_role, sender_id, body)
         VALUES ($1,$2,$3,$4,$5)
         RETURNING id, conversation_id, sender_role, sender_id, body, created_at`,
        [uuidv4(), conversationId, req.auth.role, req.auth.userId, body]
      );

      return { message: msg.rows[0], conversationId, userId: conv.rows[0].user_id };
    });

    if (result.error) return res.status(result.status || 400).json(result);

    socketEmitToUser(siteKey, result.userId, 'message:new', result);
    socketEmitToOperators(siteKey, 'message:new', result);
    socketEmitToSupervisors(siteKey, 'message:new', result);

    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Start
const server = http.createServer(app);

async function start() {
  await initDb();
  await ensureSeedData();
  initSocket(server, { corsOrigins: config.corsOrigins });
  server.listen(config.port, () => {
    console.log(`API listening on :${config.port}`);
  });
}

start().catch((e) => {
  console.error(e);
  process.exit(1);
});
