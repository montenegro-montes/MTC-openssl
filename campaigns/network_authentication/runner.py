"""Manual Docker executor. Imported only by an explicit --execute request."""
import json
from pathlib import Path
import re
import statistics
import subprocess
import time
import uuid
from .common import OPENSSL, LIBS, cases, schedule, save, sha, require, frozen, tls_arguments, fixture_inventory, verify_inventory, load
from .metrics import parse_metrics, validate


class Lab:
    def __init__(self, manifest, directory):
        self.m = manifest
        self.directory = directory
        self.token = 'mtnetauth-' + uuid.uuid4().hex[:12]
        self.network = self.token
        self.nodes = {role: self.token + '-' + role for role in ['server', 'client']}
        self.created = []
        self.network_created = False
        self.command_index = 0

    def command(self, args, *, check=True, timeout=60):
        self.command_index += 1
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        save(self.directory / f'command-{self.command_index:04d}.json',
             {'argv': args, 'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        if check:
            require(result.returncode == 0, f'Infrastructure command failed ({result.returncode}); see command log')
        return result

    def exec(self, role, args, **kwargs):
        return self.command(['docker', 'exec', self.nodes[role], *args], **kwargs)

    def start(self):
        info = json.loads(self.command(['docker', 'image', 'inspect', self.m['image_id']]).stdout)[0]
        require(info['Id'] == self.m['image_id'], 'Image mismatch')
        save(self.directory / 'image.json', {k: info.get(k) for k in ['Id', 'Architecture', 'Os', 'RootFS']})
        self.command(['docker', 'network', 'create', '--internal', '--label', 'org.mt.experiment=network-authentication-v1', self.network])
        self.network_created = True
        metrics = self.directory / 'server-metrics'; metrics.mkdir()
        for role, name in self.nodes.items():
            cmd = ['docker', 'run', '-d', '--name', name, '--network', self.network,
                   '--network-alias', role, '--label', 'org.mt.experiment=network-authentication-v1',
                   '--cap-add', 'NET_ADMIN', '--cpus', '2', '--memory', '1g',
                   '-e', 'LC_ALL=C', '-e', f'LD_LIBRARY_PATH={LIBS}', '-e', 'PROFILE_DETAIL=0',
                   '-e', 'PROFILE_METRICS_DIR=/metrics',
                   '-v', f"{self.m['fixtures']}:/fixtures:ro",
                   '--entrypoint', 'sleep']
            if role == 'server':
                cmd += ['-v', f'{metrics}:/metrics']
            cmd += [self.m['image_id'], 'infinity']
            self.command(cmd); self.created.append(name)
        self.exec('server', ['sh', '-c', 'command -v tc && command -v iperf3 && command -v timeout && command -v pkill'])
        self.exec('client', ['sh', '-c', 'command -v ping && command -v iperf3 && command -v tc'])
        self.command(['docker', 'info', '--format', '{{json .}}'])
        self.exec('server', [OPENSSL, 'version', '-a'])
        self.exec('server', [OPENSSL, 'list', '-providers', '-verbose'])
        self.exec('server', ['sha256sum', OPENSSL, '/opt/src/openssl-mtc/apps/metrics.c'])

    def shape(self, condition):
        rate, rtt, loss = condition['rate_mbit'], condition['rtt_ms'], condition['loss_percent']
        for role in self.nodes:
            netem = ['netem', 'delay', f'{rtt / 2:g}ms']
            if loss:
                netem += ['loss', 'random', f'{loss:g}%']
            if rate is not None:
                burst = max(1600, int(rate * 1250))
                self.exec(role, ['tc', 'qdisc', 'add', 'dev', 'eth0', 'root', 'handle', '1:', 'tbf',
                                 'rate', f'{rate}mbit', 'burst', str(burst), 'latency', '1000ms'])
                self.exec(role, ['tc', 'qdisc', 'add', 'dev', 'eth0', 'parent', '1:1', 'handle', '10:', *netem])
            else:
                self.exec(role, ['tc', 'qdisc', 'add', 'dev', 'eth0', 'root', 'handle', '10:', *netem])
        self.qdisc('configured')

    def qdisc(self, name):
        records = {}
        for role in self.nodes:
            records[role] = json.loads(self.exec(role, ['tc', '-s', '-j', 'qdisc', 'show', 'dev', 'eth0']).stdout)
        save(self.directory / f'qdisc-{name}.json', records)
        return records

    def probe(self, condition):
        ping = self.exec('client', ['ping', '-n', '-c', '20', '-i', '0.1', '-W', '2', 'server'], check=False)
        require(ping.returncode in [0, 1], 'Ping execution failed')
        times = [float(t) for t in re.findall(r'time[=<]([\d.]+)\s*ms', ping.stdout)]
        require(len(times) > 0, 'No successful RTT probe')
        observed = statistics.median(times)
        tolerance = max(10, condition['rtt_ms'] * .15)
        require(abs(observed - condition['rtt_ms']) <= tolerance, 'RTT gate failed')
        if not condition['loss_percent']:
            require(len(times) == 20, 'Unexpected probe loss')
        record = {'rtt_median_ms': observed, 'received': len(times), 'sent': 20,
                  'configured': condition, 'goodput': []}
        if condition['rate_mbit'] is not None:
            self.exec('server', ['iperf3', '-s', '-D'])
            for reverse in [False, True]:
                cmd = ['iperf3', '-c', 'server', '-t', '4', '-O', '4', '-J'] + (['-R'] if reverse else [])
                data = json.loads(self.exec('client', cmd).stdout)
                require('error' not in data, 'iperf failed')
                end = data['end']; goodput = end['sum_received']['bits_per_second'] / 1e6
                retrans = end['sum_sent'].get('retransmits')
                record['goodput'].append({'reverse': reverse, 'mbit': goodput, 'retransmits': retrans})
                # Lossy TCP goodput is an outcome, not a shaping-accuracy criterion.
                if not condition['loss_percent']:
                    require(.8 <= goodput / condition['rate_mbit'] <= 1.05, 'Goodput gate failed')
                    require(retrans == 0, 'Unexpected probe retransmissions')
        q = self.qdisc('after-probe')
        if not condition['loss_percent']:
            require(all(x.get('drops', 0) == 0 for data in q.values() for x in data), 'Unexpected qdisc drop')
        save(self.directory / 'network-validation.json', {'passed': True, **record})
        return record

    def attempt(self, case, stem, *, missing_client=False):
        raw = self.directory / 'raw'; raw.mkdir(exist_ok=True)
        client_path = raw / (stem + '.client.log'); server_path = raw / (stem + '.server.log')
        require(not client_path.exists() and not server_path.exists(), 'Refusing to overwrite raw evidence')
        server_args, client_args = tls_arguments(case, missing_client=missing_client)
        timeout = self.m['protocol']['handshake_timeout_seconds']
        cmd = ['docker', 'exec', self.nodes['server'], 'timeout', str(timeout + 10), OPENSSL, 's_server', *server_args]
        save(raw / (stem + '.commands.json'), {'server': cmd, 'client': [OPENSSL, 's_client', *client_args]})
        timed_out = False
        with server_path.open('w') as log:
            process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, text=True)
            try:
                # Readiness without making an extra TLS or TCP connection.
                ready = False
                for _ in range(60):
                    if process.poll() is not None:
                        break
                    if 'ACCEPT' in server_path.read_text():
                        ready = True; break
                    time.sleep(.05)
                require(ready, 'Server startup failed; inspect raw server log')
                client_cmd = ['docker', 'exec', '-i', self.nodes['client'], 'timeout', str(timeout), OPENSSL, 's_client', *client_args]
                try:
                    result = subprocess.run(client_cmd, input='', capture_output=True, text=True, timeout=timeout + 5)
                    client_log = (result.stdout or '') + (result.stderr or '')
                    rc = result.returncode; timed_out = rc == 124
                except subprocess.TimeoutExpired as exc:
                    timed_out = True; rc = 124
                    def decode(s): return s.decode(errors='replace') if isinstance(s, bytes) else (s or '')
                    client_log = decode(exc.stdout) + decode(exc.stderr)
                    self.exec('client', ['pkill', '-x', 'openssl'], check=False)
                client_path.write_text(client_log)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.exec('server', ['pkill', '-x', 'openssl'], check=False)
                    process.wait(timeout=5)
            finally:
                if process.poll() is None:
                    self.exec('server', ['pkill', '-x', 'openssl'], check=False)
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait()
        server_log = server_path.read_text()
        if missing_client:
            # An explicit authenticated-server rejection is required; a timeout is not a negative PASS.
            rejected = 'peer did not return a certificate' in server_log or 'certificate required' in server_log.lower()
            require(not timed_out and rejected and 'SSL_accept:SSLv3/TLS read finished' not in server_log,
                    'Missing-client control did not demonstrate explicit rejection')
            return {'success': 0, 'expected_rejection': True, 'failure_kind': 'missing-client-certificate'}
        require(rc not in [125, 126, 127], 'Container/client execution failed')
        if rc != 0 or 'SSL_accept:SSLv3/TLS read finished' not in server_log:
            return {'success': 0, 'failure_kind': 'timeout' if timed_out else 'tls-error', 'client_returncode': rc}
        client = parse_metrics(client_log)
        require(bool(re.fullmatch('[a-fA-F0-9]{64}', client['client_random'])), 'Unsafe metric identity')
        metric = self.directory / 'server-metrics' / (client['client_random'] + '.json')
        require(metric.is_file(), 'Missing server endpoint metrics')
        server = load(metric)
        save(raw / (stem + '.server-metrics.json'), server)
        metrics = validate(case, client_log, server_log, client, server)
        base = Path(self.m['fixtures']) / case['profile']
        metrics['predistributed_trust_bytes'] = sum(
            (base / role / f"mtc-n{case['tree_size']}" / 'trust.bin').stat().st_size
            for role in (['server', 'client'] if case['authentication'] == 'mutual' else ['server'])
        ) if case['credential'] == 'mtc-landmark' else None
        return {'success': 1, 'failure_kind': None, 'client_returncode': rc, **metrics}

    def close(self):
        errors = []
        for name in reversed(self.created):
            result = self.command(['docker', 'rm', '-f', name], check=False)
            if result.returncode: errors.append(name)
        if self.network_created:
            result = self.command(['docker', 'network', 'rm', self.network], check=False)
            if result.returncode: errors.append(self.network)
        require(not errors, 'Cleanup failed: ' + ', '.join(errors))


def gate(root, stage):
    directory = root / stage
    status = load(directory / 'status.json')
    require(status['passed'] is True, stage + ' has not passed')
    require(status['manifest_sha256'] == sha(root / 'manifest.json'), 'Gate belongs to another manifest')
    verify_inventory(directory, load(directory / 'integrity.json'))


def seal(directory):
    save(directory / 'integrity.json', fixture_inventory(directory))


def execute(root, stage, manifest):
    if stage in ['smoke', 'full']:
        gate(root, 'preflight')
    if stage == 'full':
        gate(root, 'smoke')
    directory = root / stage
    require(not directory.exists(), 'Stage exists; choose a fresh frozen root after any failure')
    directory.mkdir()
    status = {'passed': False, 'stage': stage, 'state': 'running', 'manifest_sha256': sha(root / 'manifest.json')}
    save(directory / 'status.json', status)
    try:
        for block in schedule(manifest['protocol'], stage):
            out = directory / block['id']; out.mkdir()
            lab = Lab(manifest, out)
            try:
                lab.start(); lab.shape(block['condition']); lab.probe(block['condition'])
                lab.exec('server', ['nstat', '-az'])
                lab.exec('client', ['nstat', '-az'])
                with (out / 'observations.jsonl').open('x') as stream:
                    for rnd in block['rounds']:
                        for order, case in enumerate(rnd['cases'], 1):
                            stem = f"{rnd['phase']}-r{rnd['round']:03d}-o{order:02d}"
                            row = {'case': case, 'condition': block['condition']['name'], 'campaign': block['id'],
                                   'repetition': block['repetition'], 'phase': rnd['phase'], 'round': rnd['round'],
                                   'order': order, 'raw_stem': stem}
                            try:
                                row.update(lab.attempt(case, stem))
                            except Exception as error:
                                row.update(success=0, failure_kind='integrity-or-infrastructure', error=str(error))
                                stream.write(json.dumps(row) + '\n'); stream.flush(); raise
                            stream.write(json.dumps(row) + '\n'); stream.flush()
                            if stage != 'full' or not block['condition']['loss_percent']:
                                require(row['success'] == 1, 'Positive gate failed; preserve output and use a fresh root')
                if stage == 'preflight':
                    controls = []
                    for index, case in enumerate(c for c in cases(manifest['protocol']) if c['authentication'] == 'mutual'):
                        controls.append({'case': case, **lab.attempt(case, f'negative-{index:02d}', missing_client=True)})
                    save(out / 'negative-controls.json', controls)
                q = lab.qdisc('after-measurement')
                if not block['condition']['loss_percent']:
                    require(all(x.get('drops', 0) == 0 for data in q.values() for x in data), 'Unexpected qdisc drops')
                lab.exec('server', ['nstat', '-az']); lab.exec('client', ['nstat', '-az'])
            finally:
                lab.close()
            print(block['id'], 'complete', flush=True)
        frozen(root)
        status.update(passed=True, state='complete')
    except BaseException as error:
        status.update(passed=False, state='failed', error=str(error)); raise
    finally:
        save(directory / 'status.json', status)
        seal(directory)
