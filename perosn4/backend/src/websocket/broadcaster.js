const { WebSocketServer, WebSocket } = require('ws');

let wss = null;

/**
 * Initialize WebSocket server attached to HTTP server
 * @param {http.Server} server 
 */
function initBroadcaster(server) {
  wss = new WebSocketServer({ server, path: '/ws' });

  console.log('[WebSocket] Broadcaster initialized on path /ws');

  wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    const clientIp = req.socket.remoteAddress;
    console.log(`[WebSocket] Client connected from ${clientIp}. Total clients: ${wss.clients.size}`);

    // Send connection welcome message
    ws.send(JSON.stringify({
      event: 'connection_established',
      message: 'Connected to SIH26145 Real-Time Threat Stream',
      timestamp: new Date().toISOString()
    }));

    ws.on('pong', () => {
      ws.isAlive = true;
    });

    ws.on('close', () => {
      console.log(`[WebSocket] Client disconnected. Total clients: ${wss.clients.size}`);
    });

    ws.on('error', (err) => {
      console.error('[WebSocket] Client error:', err.message);
    });
  });

  // Keep-alive heartbeat ping every 30 seconds
  const interval = setInterval(() => {
    if (!wss) return;
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);
  interval.unref();

  wss.on('close', () => {
    clearInterval(interval);
  });

  return wss;
}

/**
 * Broadcast an alert to all connected WebSocket clients
 * @param {Object} alertData 
 */
function broadcastAlert(alertData) {
  if (!wss) {
    console.warn('[WebSocket] Broadcaster not initialized yet');
    return;
  }

  const payload = JSON.stringify({
    event: 'alert',
    data: alertData,
    timestamp: new Date().toISOString()
  });

  let activeCount = 0;
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
      activeCount++;
    }
  });

  if (activeCount > 0) {
    console.log(`[WebSocket] Broadcast alert ${alertData.flow_id} (${alertData.threat_class}) to ${activeCount} client(s)`);
  }
}

/**
 * Get count of connected clients
 */
function getClientCount() {
  return wss ? wss.clients.size : 0;
}

module.exports = {
  initBroadcaster,
  broadcastAlert,
  getClientCount
};
