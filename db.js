import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import { config, requireDb } from './config.js';

const { Pool } = pg;

let pool = null;

function shouldUseSsl(connStr) {
  const lower = connStr.toLowerCase();
  return lower.includes('sslmode=require') || lower.includes('render.com') || lower.includes('neon.tech') || lower.includes('supabase');
}

export async function initDb() {
  requireDb();
  const ssl = shouldUseSsl(config.databaseUrl) ? { rejectUnauthorized: false } : undefined;
  pool = new Pool({ connectionString: config.databaseUrl, ssl });

  // Verify connection
  await pool.query('SELECT 1');

  // Run schema (idempotent)
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const schemaPath = path.join(__dirname, '..', 'migrations', 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');
  await pool.query(schemaSql);

  // Ensure sites exist
  for (const s of config.sites) {
    await pool.query(
      `INSERT INTO sites (site_key, site_name)
       VALUES ($1, $2)
       ON CONFLICT (site_key) DO UPDATE SET site_name = EXCLUDED.site_name`,
      [s.key, s.name]
    );
  }
}

export function db() {
  if (!pool) throw new Error('DB not initialized');
  return pool;
}

export async function query(text, params = []) {
  return db().query(text, params);
}

export async function tx(fn) {
  const client = await db().connect();
  try {
    await client.query('BEGIN');
    const res = await fn(client);
    await client.query('COMMIT');
    return res;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
