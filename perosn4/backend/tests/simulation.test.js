const { EventEmitter } = require('events');
const request = require('supertest');
jest.mock('child_process', () => ({ spawn: jest.fn() }));
const { spawn } = require('child_process');
const { app } = require('../src/server');

test('simulation controls launch the Agent 1 observation producer and stop only their own process', async () => {
  const child = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = jest.fn(() => child.emit('exit', null, 'SIGTERM'));
  spawn.mockReturnValue(child);
  const initial = await request(app).get('/api/simulation');
  expect(initial.body.data.running).toBe(false);
  const started = await request(app).post('/api/simulation/start');
  expect(started.status).toBe(202);
  expect(started.body.data.running).toBe(true);
  expect(spawn.mock.calls[0][1]).toEqual(expect.arrayContaining(['simulate', '--continuous', '--redis-url', '--family', 'all']));
  expect(spawn.mock.calls[0][1][1]).toMatch(/pipeline_runtime\.py$/);
  expect((await request(app).post('/api/simulation/start')).status).toBe(409);
  await request(app).post('/api/simulation/stop');
  expect(child.kill).toHaveBeenCalledTimes(1);
  expect((await request(app).get('/api/simulation')).body.data.running).toBe(false);
});
