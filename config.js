import dotenv from 'dotenv';

dotenv.config();

function parseJsonEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in env ${name}`);
  }
}

const defaultSites = [
  { key: 'forrorandi', name: 'ForróRandi' },
  { key: 'szerelmesszivek', name: 'SzerelmesSzívek' }
];

// Default Stripe packages are baked in, so you only need to set STRIPE_SECRET_KEY + STRIPE_WEBHOOK_SECRET.
// You can still override them via STRIPE_PACKAGES env if you want.
const defaultStripePackages = [
  // ForróRandi
  { id: 'forro_100', site: 'forrorandi', name: '100 kredit',  priceId: 'price_1SlsEBEAcUmosVgk7FDZPejh', credits: 100,  amountHuf: 3000 },
  { id: 'forro_200', site: 'forrorandi', name: '200 kredit',  priceId: 'price_1SlsM4EAcUmosVgktdb14FOA', credits: 200,  amountHuf: 6000 },
  { id: 'forro_400', site: 'forrorandi', name: '400 kredit',  priceId: 'price_1SlsSjEAcUmosVgkUXLg6F2f', credits: 400,  amountHuf: 10000 },
  { id: 'forro_600', site: 'forrorandi', name: '600 kredit',  priceId: 'price_1SlsVOEAcUmosVgk9rYPohCW', credits: 600,  amountHuf: 12000 },
  { id: 'forro_1000', site: 'forrorandi', name: '1000 kredit', priceId: 'price_1SlsX6EAcUmosVgkZBVOsck7', credits: 1000, amountHuf: 16000 },
  { id: 'forro_1500', site: 'forrorandi', name: '1500 kredit', priceId: 'price_1SlsZ5EAcUmosVgkLsqfGPPc', credits: 1500, amountHuf: 20000 },

  // SzerelmesSzívek (ugyanazok a priceId-k)
  { id: 'szivek_100', site: 'szerelmesszivek', name: '100 kredit',  priceId: 'price_1SlsEBEAcUmosVgk7FDZPejh', credits: 100,  amountHuf: 3000 },
  { id: 'szivek_200', site: 'szerelmesszivek', name: '200 kredit',  priceId: 'price_1SlsM4EAcUmosVgktdb14FOA', credits: 200,  amountHuf: 6000 },
  { id: 'szivek_400', site: 'szerelmesszivek', name: '400 kredit',  priceId: 'price_1SlsSjEAcUmosVgkUXLg6F2f', credits: 400,  amountHuf: 10000 },
  { id: 'szivek_600', site: 'szerelmesszivek', name: '600 kredit',  priceId: 'price_1SlsVOEAcUmosVgk9rYPohCW', credits: 600,  amountHuf: 12000 },
  { id: 'szivek_1000', site: 'szerelmesszivek', name: '1000 kredit', priceId: 'price_1SlsX6EAcUmosVgkZBVOsck7', credits: 1000, amountHuf: 16000 },
  { id: 'szivek_1500', site: 'szerelmesszivek', name: '1500 kredit', priceId: 'price_1SlsZ5EAcUmosVgkLsqfGPPc', credits: 1500, amountHuf: 20000 }
];

export const config = {
  port: Number(process.env.PORT || 10000),
  nodeEnv: process.env.NODE_ENV || 'development',

  // Security
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-me',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',

  // Database
  databaseUrl: process.env.DATABASE_URL || null,

  // CORS (comma-separated origins)
  corsOrigins: (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),

  // Multi-site
  sites: parseJsonEnv('SITES', defaultSites),

  // Credits
  messageCostCredits: Number(process.env.MESSAGE_COST_CREDITS || 10),

  // Stripe
  stripeSecretKey: process.env.STRIPE_SECRET_KEY || null,
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET || null,
  stripeSuccessUrl: process.env.STRIPE_SUCCESS_URL || null,
  stripeCancelUrl: process.env.STRIPE_CANCEL_URL || null,

  // Success/cancel redirect targets (Netlify)
  siteForrorandiUrl: process.env.SITE_FORRORANDI_URL || 'https://forrorandi.netlify.app/#credits',
  siteSzerelmesSzivekUrl: process.env.SITE_SZERELMESSZIVEK_URL || 'https://szerelmesszivek.netlify.app/#credits',

  // Packages (overrideable)
  stripePackages: parseJsonEnv('STRIPE_PACKAGES', defaultStripePackages),

  // Ops
  healthToken: process.env.HEALTH_TOKEN || null
};

export function requireStripe() {
  if (!config.stripeSecretKey) throw new Error('Stripe not configured (missing STRIPE_SECRET_KEY)');
  if (!config.stripeWebhookSecret) throw new Error('Stripe not configured (missing STRIPE_WEBHOOK_SECRET)');
  if (!config.stripeSuccessUrl || !config.stripeCancelUrl) throw new Error('Stripe not configured (missing STRIPE_SUCCESS_URL / STRIPE_CANCEL_URL)');
}

export function requireDb() {
  if (!config.databaseUrl) throw new Error('Database not configured (missing DATABASE_URL). Use Render Postgres or any Postgres DB.');
}
