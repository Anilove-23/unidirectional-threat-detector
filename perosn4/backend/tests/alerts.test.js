const request = require('supertest');
const { app } = require('../src/server');
const AlertModel = require('../src/db/models/Alert');

describe('Person 4 Backend REST API Endpoints', () => {
  beforeEach(async () => {
    await AlertModel.clearAll();
  });

  const sampleAlert = {
    timestamp: '2026-08-30T10:00:00.000Z',
    flow_id: 'test-flow-uuid-001',
    five_tuple: {
      src_ip: '10.44.1.100',
      dst_ip: '198.51.100.5',
      src_port: 54321,
      dst_port: 443,
      protocol: 'TCP/TLS'
    },
    threat_class: 'BOTNET_C2_BEACONING',
    confidence_score: 0.95,
    severity: 'HIGH',
    model_source: {
      supervised_score: 0.88,
      anomaly_score: 0.92,
      fired_models: ['lstm_beacon_v2']
    },
    evidence: {
      beacon_interval_seconds: 60.0
    },
    ingestion_meta: {
      sensor_id: 'diode-sensor-01',
      capture_interface: 'eth1-rx-only',
      pipeline_version: '1.3.0'
    }
  };

  test('GET /api/health returns system status', async () => {
    const res = await request(app).get('/api/health');
    expect(res.statusCode).toEqual(200);
    expect(res.body.status).toEqual('healthy');
    expect(res.body.service).toEqual('SIH26145-Backend-Person4');
    expect(res.body.components).toBeDefined();
  });

  test('GET /api/alerts returns empty list initially', async () => {
    const res = await request(app).get('/api/alerts');
    expect(res.statusCode).toEqual(200);
    expect(res.body.status).toEqual('success');
    expect(res.body.data.alerts).toEqual([]);
    expect(res.body.data.total).toEqual(0);
  });

  test('GET /api/alerts returns saved alerts', async () => {
    await AlertModel.saveAlert(sampleAlert);

    const res = await request(app).get('/api/alerts');
    expect(res.statusCode).toEqual(200);
    expect(res.body.data.total).toEqual(1);
    expect(res.body.data.alerts[0].flow_id).toEqual('test-flow-uuid-001');
  });

  test('GET /api/alerts/:flow_id fetches alert details', async () => {
    await AlertModel.saveAlert(sampleAlert);

    const res = await request(app).get('/api/alerts/test-flow-uuid-001');
    expect(res.statusCode).toEqual(200);
    expect(res.body.data.flow_id).toEqual('test-flow-uuid-001');
    expect(res.body.data.threat_class).toEqual('BOTNET_C2_BEACONING');
  });

  test('GET /api/alerts/:flow_id returns 404 for unknown flow_id', async () => {
    const res = await request(app).get('/api/alerts/unknown-id');
    expect(res.statusCode).toEqual(404);
    expect(res.body.status).toEqual('error');
  });

  test('GET /api/alerts/search filters by severity and threat_class', async () => {
    await AlertModel.saveAlert(sampleAlert);
    await AlertModel.saveAlert({
      ...sampleAlert,
      flow_id: 'test-flow-uuid-002',
      severity: 'LOW',
      threat_class: 'PORT_SCAN_RECON'
    });

    const resHigh = await request(app).get('/api/alerts/search?severity=HIGH');
    expect(resHigh.statusCode).toEqual(200);
    expect(resHigh.body.data.total).toEqual(1);
    expect(resHigh.body.data.alerts[0].flow_id).toEqual('test-flow-uuid-001');

    const resScan = await request(app).get('/api/alerts/search?threat_class=PORT_SCAN_RECON');
    expect(resScan.statusCode).toEqual(200);
    expect(resScan.body.data.total).toEqual(1);
    expect(resScan.body.data.alerts[0].flow_id).toEqual('test-flow-uuid-002');
  });
});
