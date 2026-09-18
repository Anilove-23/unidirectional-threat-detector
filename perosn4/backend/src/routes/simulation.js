const express = require('express');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const config = require('../config');

const router = express.Router();
const root = path.resolve(__dirname, '../../../..');
let child = null;
let lastError = null;
let startedAt = null;

function status() {
  return { running: !!child, started_at: startedAt, error: lastError, source: 'agent1_simulation', policy: 'candidate_unapproved' };
}

// Process controls are local developer controls, not a remote execution API.
router.use((req, res, next) => {
  if (req.method !== 'GET' && !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress)) {
    return res.status(403).json({ status: 'error', message: 'Simulation controls are available on localhost only' });
  }
  next();
});

router.get('/', (req, res) => res.json({ status: 'success', data: status() }));
router.post('/start', (req, res) => {
  if (child) return res.status(409).json({ status: 'error', message: 'Simulation is already running', data: status() });
  const candidates = process.platform === 'win32'
    ? ['.venv/Scripts/python.exe'] : ['.venv_linux/bin/python', '.venv/bin/python'];
  const python = process.env.PYTHON_EXECUTABLE || candidates.map(candidate => path.join(root, candidate)).find(candidate => fs.existsSync(candidate)) || (process.platform === 'win32' ? 'python' : 'python3');
  lastError = null;
  const processHandle = spawn(python, ['-u', path.join(root, 'pipeline_runtime.py'), 'simulate', '--redis-url', config.redisUrl, '--continuous', '--interval', '0.05', '--family', 'all'], {
    cwd: root, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true,
  });
  child = processHandle;
  startedAt = new Date().toISOString();
  let stderr = '';
  processHandle.stderr.on('data', data => { stderr = (stderr + data.toString()).slice(-2000); });
  processHandle.once('error', error => { lastError = error.message; child = null; });
  processHandle.once('exit', (code, signal) => {
    if (child === processHandle) child = null;
    if (code && !signal) lastError = stderr || `Simulator exited with code ${code}`;
  });
  res.status(202).json({ status: 'success', data: status() });
});
router.post('/stop', (req, res) => {
  child?.kill();
  res.json({ status: 'success', data: status() });
});

function stopSimulation() { child?.kill(); }
module.exports = { router, stopSimulation };
