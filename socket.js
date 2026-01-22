import { Server } from 'socket.io';
import { verifyToken, Roles } from './auth.js';

let io = null;

// siteKey -> Array of online operatorIds
const onlineOperators = new Map();

function addOnlineOperator(siteKey, operatorId) {
  const set = onlineOperators.get(siteKey) || new Set();
  set.add(operatorId);
  onlineOperators.set(siteKey, set);
}

function removeOnlineOperator(siteKey, operatorId) {
  const set = onlineOperators.get(siteKey);
  if (!set) return;
  set.delete(operatorId);
}

export function getOnlineOperatorIds(siteKey) {
  const set = onlineOperators.get(siteKey);
  return set ? Array.from(set) : [];
}

export function pickOperatorRoundRobin(siteKey) {
  const ops = getOnlineOperatorIds(siteKey);
  if (!ops.length) return null;
  // deterministic-ish selection: rotate by timestamp to spread load
  const idx = Math.floor(Date.now() / 1000) % ops.length;
  return ops[idx];
}

export function initSocket(httpServer, { corsOrigins }) {
  io = new Server(httpServer, {
    cors: {
      origin: corsOrigins.length ? corsOrigins : true,
      credentials: true
    }
  });

  io.use((socket, next) => {
    try {
      const token = socket.handshake.auth?.token || socket.handshake.query?.token;
      const siteKey = (socket.handshake.auth?.siteKey || socket.handshake.query?.siteKey || '').toString().toLowerCase().trim();
      if (!token) return next(new Error('Missing token'));
      if (!siteKey) return next(new Error('Missing siteKey'));
      const payload = verifyToken(token);
      socket.data.auth = payload;
      socket.data.siteKey = siteKey;
      return next();
    } catch {
      return next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    const { auth, siteKey } = socket.data;

    // Base rooms
    socket.join(`site:${siteKey}`);

    if (auth.role === Roles.USER) {
      socket.join(`site:${siteKey}:user:${auth.userId}`);
    }

    if (auth.role === Roles.OPERATOR || auth.role === Roles.SUPERVISOR) {
      addOnlineOperator(siteKey, auth.userId);
      socket.join(`site:${siteKey}:operators`);
      if (auth.role === Roles.SUPERVISOR) {
        socket.join(`site:${siteKey}:supervisors`);
      }
      io.to(`site:${siteKey}:supervisors`).emit('operator:online', { operatorId: auth.userId, at: Date.now() });
    }

    socket.on('disconnect', () => {
      if (auth.role === Roles.OPERATOR || auth.role === Roles.SUPERVISOR) {
        removeOnlineOperator(siteKey, auth.userId);
        io.to(`site:${siteKey}:supervisors`).emit('operator:offline', { operatorId: auth.userId, at: Date.now() });
      }
    });
  });

  return io;
}

export function socketEmitToUser(siteKey, userId, event, payload) {
  if (!io) return;
  io.to(`site:${siteKey}:user:${userId}`).emit(event, payload);
}

export function socketEmitToOperators(siteKey, event, payload) {
  if (!io) return;
  io.to(`site:${siteKey}:operators`).emit(event, payload);
}

export function socketEmitToSupervisors(siteKey, event, payload) {
  if (!io) return;
  io.to(`site:${siteKey}:supervisors`).emit(event, payload);
}
