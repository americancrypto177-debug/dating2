import Stripe from 'stripe';
import { config, requireStripe } from './config.js';
import { query, tx } from './db.js';
import { v4 as uuidv4 } from 'uuid';

let stripe = null;

function withSiteParam(url, siteKey) {
  if (!url) return url;
  const join = url.includes('?') ? '&' : '?';
  return `${url}${join}site=${encodeURIComponent(siteKey)}`;
}

export function getStripe() {
  requireStripe();
  if (!stripe) {
    stripe = new Stripe(config.stripeSecretKey, { apiVersion: '2024-06-20' });
  }
  return stripe;
}

export function findPackage(packageId) {
  const p = config.stripePackages.find(x => x.id === packageId);
  if (!p) throw new Error('Unknown packageId');
  if (!p.priceId || !p.credits) throw new Error('Invalid package config');
  return p;
}

export async function createCheckoutSession({ userId, email, packageId, siteKey }) {
  const s = getStripe();
  const pack = findPackage(packageId);

  // Get or create Stripe customer
  let customerId = null;
  const existing = await query('SELECT stripe_customer_id FROM stripe_customers WHERE user_id=$1', [userId]);
  if (existing.rows.length) customerId = existing.rows[0].stripe_customer_id;
  if (!customerId) {
    const customer = await s.customers.create({ email, metadata: { userId, siteKey } });
    customerId = customer.id;
    await query('INSERT INTO stripe_customers(user_id, stripe_customer_id) VALUES ($1,$2) ON CONFLICT (user_id) DO UPDATE SET stripe_customer_id=EXCLUDED.stripe_customer_id', [userId, customerId]);
  }

  const session = await s.checkout.sessions.create({
    mode: 'payment',
    customer: customerId,
    line_items: [{ price: pack.priceId, quantity: 1 }],
    success_url: withSiteParam(config.stripeSuccessUrl, siteKey),
    cancel_url: withSiteParam(config.stripeCancelUrl, siteKey),
    metadata: {
      userId,
      siteKey,
      packageId: pack.id,
      credits: String(pack.credits)
    }
  });

  return session;
}

export async function handleStripeWebhook(rawBody, signature) {
  const s = getStripe();
  const event = s.webhooks.constructEvent(rawBody, signature, config.stripeWebhookSecret);

  // Deduplicate events
  const eventId = event.id;
  const already = await query('SELECT event_id FROM stripe_events WHERE event_id=$1', [eventId]);
  if (already.rows.length) {
    return { ok: true, deduped: true, type: event.type };
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata?.userId;
    const credits = Number(session.metadata?.credits || 0);
    const packageId = session.metadata?.packageId || 'unknown';

    if (userId && credits > 0) {
      await tx(async (client) => {
        await client.query(
          'INSERT INTO credit_ledger(id, user_id, delta, reason) VALUES ($1,$2,$3,$4)',
          [uuidv4(), userId, credits, `stripe:${packageId}`]
        );
        await client.query('INSERT INTO stripe_events(event_id, processed_at) VALUES ($1, NOW())', [eventId]);
      });
    } else {
      await query('INSERT INTO stripe_events(event_id, processed_at) VALUES ($1, NOW())', [eventId]);
    }

    return { ok: true, type: event.type };
  }

  // Store unknown events to dedupe
  await query('INSERT INTO stripe_events(event_id, processed_at) VALUES ($1, NOW())', [eventId]);
  return { ok: true, type: event.type };
}
