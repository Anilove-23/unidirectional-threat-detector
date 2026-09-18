const request = require('supertest');
jest.mock('../src/websocket/broadcaster', () => ({
  initBroadcaster: jest.fn(), broadcastAlert: jest.fn(), broadcastEvent: jest.fn(), getClientCount: () => 0,
}));
const { app } = require('../src/server');
const { handleV2Message, productStore, consumeStreams } = require('../src/redis/subscriber');
const { broadcastAlert, broadcastEvent } = require('../src/websocket/broadcaster');
const AlertModel = require('../src/db/models/Alert');

function decision(overrides = {}) {
  return {
    schema_version: '2.0.0', decision_id: 'decision-1', event_id: 'event-1', sensor_id: 'sensor-1',
    event_time: '2026-09-17T00:00:00Z', entity_keys: { flow_id: 'flow-1', source: '192.0.2.1', destination: '198.51.100.1' },
    protocol: 'TCP', decision_state: 'UNCERTAIN', primary_class: null, labels: {}, label_probabilities: { DDoS: .93 }, confidence: null,
    uncertainty: { ood: null, epistemic_proxy: null, expert_disagreement: 0, overall: 1 },
    ood: { energy: null, ae_error: null, if_score: null, latent_distance: null },
    visibility_ratio: .6, visibility: { dns_response_visible: false }, history_length: 2, history: { window_complete: false },
    threshold_version: 'candidate-v1', thresholds: { DDoS: .85 }, routing_policy_version: 'routing-v2', routing: {},
    score_presence: { DDoS: true }, reason_codes: ['POLICY_NOT_VALIDATED'], model_versions: { flow: 'candidate-v1' },
    evidence: {}, drift_status: 'NONE', model_profile: 'candidate-v1', ...overrides,
  };
}

beforeEach(async () => {
  await AlertModel.clearAll();
  productStore.decisions.clear();
  productStore.incidents.clear();
  jest.clearAllMocks();
});

test('candidate decisions preserve scores, missing confidence, and visibility in REST and WebSocket alerts', async () => {
  await handleV2Message('decision.new', JSON.stringify(decision()));
  const result = await request(app).get('/api/alerts/decision-1');
  expect(result.body.data).toMatchObject({ decision_state: 'UNCERTAIN', confidence_score: null, severity: 'LOW', label_probabilities: { DDoS: .93 } });
  expect(broadcastAlert).toHaveBeenCalledWith(expect.objectContaining({ reason_codes: ['POLICY_NOT_VALIDATED'] }));
  const detail = await request(app).get('/api/v2/decisions/decision-1');
  expect(detail.body.data.visibility.dns_response_visible).toBe(false);
});

test('stream and pub/sub retries produce one alert', async () => {
  const payload = JSON.stringify(decision());
  expect(await handleV2Message('decision.new', payload)).toBe(true);
  expect(await handleV2Message('decision.new', payload)).toBe(false);
  expect(await AlertModel.getCount()).toBe(1);
  expect(broadcastAlert).toHaveBeenCalledTimes(1);
});

test('benign decisions are queryable without appearing in the alert feed', async () => {
  await handleV2Message('decision.new', JSON.stringify(decision({ decision_state: 'BENIGN', reason_codes: [] })));
  expect(await AlertModel.getCount()).toBe(0);
  const result = await request(app).get('/api/v2/decisions?state=BENIGN');
  expect(result.body.data.total).toBe(1);
});

test('invalid and contradictory decisions never mutate the product store', async () => {
  await expect(handleV2Message('decision.new', '{}')).rejects.toThrow('Invalid V2 payload');
  await expect(handleV2Message('decision.new', JSON.stringify(decision({ decision_state: 'KNOWN_ATTACK', primary_class: 'DGA', labels: { DDoS: .93 }, confidence: .93 })))).rejects.toThrow('Primary class');
  expect(productStore.decisions.size).toBe(0);
});

test('incident timelines reach REST and WebSocket clients', async () => {
  const value = { schema_version: '2.0.0', incident_id: 'incident-1', sensor_id: 'sensor-1', entity: '192.0.2.1', family: 'ddos', action: 'create', status: 'open', first_seen: '2026-09-17T00:00:00Z', last_seen: '2026-09-17T00:00:00Z', count: 1, labels: { DDoS: .93 }, severity: 'HIGH', reason_codes: [], timeline: [{ decision_id: 'decision-1', event_time: '2026-09-17T00:00:00Z', labels: ['DDoS'], evidence: {} }] };
  await handleV2Message('incident.update', JSON.stringify(value));
  const result = await request(app).get('/api/v2/incidents/incident-1');
  expect(result.body.data.timeline[0].decision_id).toBe('decision-1');
  expect(broadcastEvent).toHaveBeenCalledWith('incident', value);
});

test('retained Redis stream entries rebuild the projection and advance cursors', async () => {
  const client = { status: 'ready', xread: jest.fn() };
  client.xread.mockResolvedValueOnce([['decision.v2', [['1-0', ['payload', JSON.stringify(decision())]]]]]);
  client.xread.mockImplementationOnce(async () => { client.status = 'end'; return null; });
  await consumeStreams(client);
  expect(productStore.decisions.size).toBe(1);
  expect(client.xread.mock.calls[1].slice(-2)).toEqual(['1-0', '0-0']);
});

test('V2 pagination is bounded', async () => {
  expect((await request(app).get('/api/v2/decisions?limit=501')).status).toBe(400);
});
