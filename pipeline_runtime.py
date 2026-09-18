"""Linux/Windows launcher and Agent 1 -> Redis Streams bridge.

Simulation is offline packet generation: it never transmits attack traffic.
Candidate models retain their unapproved policy and publish reviewable scores.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
STATE = ROOT / '.runtime' / 'supervisor.json'
FAMILIES = ('benign_mixed', 'ddos', 'port_scan', 'slow_scan', 'dga', 'dns_tunnel',
            'low_rate_dns_tunnel', 'c2', 'botnet', 'encrypted_malware',
            'exfiltration', 'low_slow_exfiltration')


def current_release():
    pointer = ROOT / 'artifacts/pipeline/current.json'
    return json.loads(pointer.read_text()) if pointer.exists() else {}


def resolve_path(value):
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def load_config(path=None):
    from agent1_observation_dns.configs import Settings
    path = path or current_release().get('agent1_config')
    config = Settings.load(resolve_path(path)) if path else Settings()
    return config.model_copy(update={'model_paths': {
        key: str(resolve_path(value)) for key, value in config.model_paths.items()}})


def adapt_score(score, envelope):
    """Explicit producer/consumer bridge; never invent calibration approval."""
    raw = score.model_dump(mode='json')
    return {
        'schema_version': raw['schema_version'], 'event_id': raw['event_id'],
        'sensor_id': envelope['sensor_id'], 'label': raw['specialist'],
        'model_id': 'agent1_' + raw['specialist'].lower(),
        'model_version': raw['model_version'], 'probability': raw['probability'],
        'score_present': raw['score_present'], 'applicable': raw['applicable'],
        'calibrated': raw['evidence'].get('calibrated') is True,
        'evidence': raw['evidence'], 'reason_codes': raw['reason_codes'],
    }


class Publisher:
    def __init__(self, client, config):
        from agent1_observation_dns.pipeline import ObservationPipeline
        from agent1_observation_dns.models.dga_char_attention.specialist import DGASpecialist
        from agent1_observation_dns.models.dga_char_attention.model import CharacterBranch
        from agent1_observation_dns.models.dga_context_xgb.model import ContextBranch
        from agent1_observation_dns.routing_dns.router import TunnelSpecialist
        self.pipeline = ObservationPipeline(config)
        paths = config.model_paths
        self.dga = DGASpecialist(
            CharacterBranch(paths['dga_char_attention']) if paths.get('dga_char_attention') else None,
            ContextBranch(paths['dga_context_xgb']) if paths.get('dga_context_xgb') else None,
            baseline=False)
        self.tunnel = TunnelSpecialist(config)
        self.client = client
        self.count = 0

    def publish(self, event):
        envelope = event.model_dump(mode='json')
        query = event.features.dns.get('query_name')
        domain = query.value if query and query.available else None
        context = {**event.features.dns, 'graph': self.pipeline.graph.structural_snapshot()}
        scores = [adapt_score(score, envelope) for score in (
            self.dga.predict(event.event_id, domain, context),
            self.tunnel.predict(event.event_id, domain, context))]
        self.client.xadd('observation.v2', {'payload': json.dumps({
            'observation': envelope, 'specialist_scores': scores}, allow_nan=False)}, maxlen=100000)
        self.count += 1

    def frame(self, frame):
        for event in self.pipeline.process(frame):
            self.publish(event)


def produce(args):
    import redis
    client = redis.Redis.from_url(args.redis_url, decode_responses=True)
    client.ping()
    config = load_config(args.config)
    # Each independent run has its own sensor/state identity and UTC event clock.
    config = config.model_copy(update={'sensor_id': f'{args.mode}-{secrets.token_hex(6)}'})
    publisher = Publisher(client, config)
    if args.mode == 'capture':
        from agent1_observation_dns.capture.live import capture
        capture(args.interface, publisher.frame, timeout_s=args.timeout, packet_limit=args.limit)
        for flow, reason in publisher.pipeline.flows.flush():
            publisher.publish(publisher.pipeline.envelope(flow, final=True, reason=reason))
    elif args.mode == 'pcap':
        from agent1_observation_dns.replay.pcap import PcapSource
        for event in publisher.pipeline.run(PcapSource(args.input, config.max_frame_bytes)):
            publisher.publish(event)
            if args.interval:
                time.sleep(args.interval)
    else:
        from agent1_observation_dns.simulation.registry import training_scenario
        from agent1_observation_dns.simulation.v2_generator import generate_frames
        families = FAMILIES if args.family == 'all' else (args.family,)
        start = datetime.now(timezone.utc)
        cycle = 0
        while True:
            for family in families:
                spec = training_scenario(family, seed=args.seed + cycle, split_assignment='test')
                phases = tuple(replace(p, start_s=5, end_s=args.duration - 1) for p in spec.phases)
                spec = replace(spec, duration_s=args.duration, phases=phases, start=start)
                print(f'Agent 1 simulation: {family}, seed={spec.seed}', flush=True)
                for event in publisher.pipeline.run(generate_frames(spec)):
                    publisher.publish(event)
                    if args.interval:
                        time.sleep(args.interval)
                start += timedelta(seconds=args.duration + config.flow_ttl_s + 1)
                cycle += 1
            if not args.continuous:
                break
    print(json.dumps({'observations_published': publisher.count}), flush=True)


def stop():
    if not STATE.exists():
        print('No pipeline supervisor is running.')
        return
    state = json.loads(STATE.read_text())
    request = Request(f"http://127.0.0.1:{state['port']}/stop", data=b'',
                      headers={'Authorization': 'Bearer ' + state['token']}, method='POST')
    try:
        with urlopen(request, timeout=3) as response:
            print(response.read().decode())
    except OSError as exc:
        raise SystemExit(f'Cannot reach saved supervisor: {exc}. No unrelated processes were stopped.')


def start(args):
    import redis
    if STATE.exists():
        raise SystemExit('Supervisor state already exists. Run stop first; inspect .runtime if a previous run crashed.')
    node = shutil.which('node')
    vite = ROOT / 'soc-dashboard/node_modules/vite/bin/vite.js'
    if not node or not vite.exists() or not (ROOT / 'perosn4/backend/node_modules/express').exists():
        raise SystemExit('Install Node dependencies with npm install in soc-dashboard and perosn4/backend.')
    release = args.release or current_release().get('agent2_release')
    if not release:
        raise SystemExit('Train first: python train_pipeline.py --output artifacts/pipeline/2.0.0-local')
    release = resolve_path(release)
    from agent2_detection_product.orchestration.registry import verify_manifest
    verify_manifest(release, approved=False)
    children = []
    stopping = False
    token = secrets.token_urlsafe(32)

    class Control(BaseHTTPRequestHandler):
        def do_POST(self):
            nonlocal stopping
            if self.path != '/stop' or self.headers.get('Authorization') != 'Bearer ' + token:
                self.send_error(403)
                return
            stopping = True
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Stopping this pipeline and its child services.\n')

        def log_message(self, *_args):
            pass

    def launch(name, command, cwd=ROOT):
        env = dict(os.environ, REDIS_URL=args.redis_url, PYTHON_EXECUTABLE=sys.executable,
                   PYTHONUNBUFFERED='1', OMP_NUM_THREADS='2', MKL_NUM_THREADS='2',
                   OPENBLAS_NUM_THREADS='2')
        child = subprocess.Popen(command, cwd=cwd, env=env, start_new_session=os.name != 'nt')
        children.append((name, child))
        print(f'Started {name} (PID {child.pid})', flush=True)

    def terminate(*_args):
        nonlocal stopping
        stopping = True

    server = HTTPServer(('127.0.0.1', 0), Control)
    server.timeout = 0.3
    STATE.parent.mkdir(exist_ok=True)
    try:
        with STATE.open('x') as stream:
            json.dump({'port': server.server_port, 'token': token, 'pid': os.getpid()}, stream)
    except Exception:
        server.server_close()
        raise
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        client = redis.Redis.from_url(args.redis_url, socket_connect_timeout=1, socket_timeout=1)
        try:
            client.ping()
        except redis.ConnectionError:
            if args.redis_url not in ('redis://localhost:6379/0', 'redis://127.0.0.1:6379/0') or not shutil.which('redis-server'):
                raise SystemExit('Start Redis at the selected REDIS_URL before launching.')
            launch('Redis', ['redis-server', '--bind', '127.0.0.1', '--port', '6379', '--save', '', '--appendonly', 'no'])
            for _ in range(30):
                try:
                    client.ping()
                    break
                except redis.ConnectionError:
                    time.sleep(.1)
            else:
                raise SystemExit('Redis did not become ready.')
        launch('Backend', [node, 'src/server.js'], ROOT / 'perosn4/backend')
        from agent2_detection_product.orchestration.registry import sha256
        checkpoint = ROOT / '.runtime' / f'agent2-{sha256(release)[:16]}.sqlite3'
        launch('Agent 2 candidate detection', [sys.executable, '-m', 'agent2_detection_product', 'redis',
            '--development', '--release', str(release), '--redis-url', args.redis_url, '--checkpoint', str(checkpoint)])
        launch('Dashboard', [node, str(vite), '--host', '127.0.0.1'], ROOT / 'soc-dashboard')
        if args.sim:
            command = [sys.executable, str(ROOT / 'pipeline_runtime.py'), 'simulate', '--continuous',
                       '--redis-url', args.redis_url, '--family', args.family, '--interval', str(args.interval)]
            if args.config:
                command.extend(['--config', args.config])
            launch('Agent 1 simulation', command)
        elif args.interface:
            command = [sys.executable, str(ROOT / 'pipeline_runtime.py'), 'capture', '--interface', args.interface,
                       '--timeout', str(args.timeout), '--redis-url', args.redis_url]
            if args.config:
                command.extend(['--config', args.config])
            launch('Agent 1 passive capture', command)
        print('Dashboard: http://localhost:5173 | Candidate model scores; unvalidated decisions abstain.', flush=True)
        while not stopping:
            server.handle_request()
            for name, child in children:
                if child.poll() is not None:
                    raise SystemExit(f'{name} exited ({child.returncode}); stopping this pipeline.')
    finally:
        for _, child in reversed(children):
            if child.poll() is None:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], capture_output=True)
                else:
                    os.killpg(child.pid, signal.SIGTERM)
        for _, child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name != 'nt':
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        server.server_close()
        STATE.unlink(missing_ok=True)


def main():
    os.chdir(ROOT)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    commands.add_parser('stop')
    for name in ('start', 'simulate', 'pcap', 'capture'):
        sub = commands.add_parser(name)
        sub.add_argument('--redis-url', default=os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
        sub.add_argument('--config')
        if name in ('start', 'simulate', 'pcap'):
            sub.add_argument('--interval', type=float, default=.05)
        if name in ('start', 'simulate'):
            sub.add_argument('--family', choices=('all', *FAMILIES), default='all')
        if name in ('start', 'capture'):
            sub.add_argument('--interface', required=name == 'capture')
            sub.add_argument('--timeout', type=float, default=3600)
        if name == 'start':
            sub.add_argument('--sim', action='store_true')
            sub.add_argument('--release')
        if name == 'capture':
            sub.add_argument('--limit', type=int, default=0)
        if name == 'pcap':
            sub.add_argument('--input', type=Path, required=True)
        if name == 'simulate':
            sub.add_argument('--seed', type=int, default=260918)
            sub.add_argument('--continuous', action='store_true')
            sub.add_argument('--duration', type=float, default=60)
    args = parser.parse_args()
    if getattr(args, 'interval', 0) < 0 or getattr(args, 'duration', 60) <= 6:
        parser.error('interval must be nonnegative and duration must exceed 6 seconds')
    if args.mode == 'start' and args.sim and args.interface:
        parser.error('select simulation or capture, not both')
    try:
        if args.mode == 'stop':
            stop()
        elif args.mode == 'start':
            start(args)
        else:
            produce(args)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
