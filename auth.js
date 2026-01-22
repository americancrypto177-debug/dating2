import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { config } from './config.js';

export const Roles = {
  USER: 'user',
  OPERATOR: 'operator',
  SUPERVISOR: 'supervisor',
  ADMIN: 'admin'
};

export function signToken(payload) {
  return jwt.sign(payload, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
}

export function verifyToken(token) {
  return jwt.verify(token, config.jwtSecret);
}

export async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

export async function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

export function authMiddleware(requiredRoles = null) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing bearer token' });
    try {
      const payload = verifyToken(token);
      req.auth = payload;
      if (requiredRoles && !requiredRoles.includes(payload.role)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid/expired token' });
    }
  };
}

export function getSiteKey(req) {
  // Preferred: X-Site-Key header.
  // Fallback: ?siteKey=... in query.
  const hdr = req.headers['x-site-key'];
  const q = req.query.siteKey;
  const v = (Array.isArray(hdr) ? hdr[0] : hdr) || q;
  if (!v) return null;
  return String(v).toLowerCase().trim();
}

export function requireSiteKey(req, res) {
  const siteKey = getSiteKey(req);
  if (!siteKey) {
    res.status(400).json({ error: 'Missing site key (X-Site-Key header or ?siteKey=...)' });
    return null;
  }
  return siteKey;
}
