import signal
import socket
import subprocess
import sys
import time
from scenarios import SCENARIOS, server_args
if '--health' in sys.argv:
    for index in range(len(SCENARIOS)):
        with socket.create_connection(('127.0.0.1', 4433 + index), timeout=.15): pass
    raise SystemExit(0)
processes = []
streams = []
def stop(*args):
    for process in processes:
        if process.poll() is None: process.terminate()
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    for index, scenario in enumerate(SCENARIOS):
        stream = open('/tmp/' + scenario + '.log', 'w'); streams.append(stream)
        processes.append(subprocess.Popen(server_args(scenario, 4433 + index), stdout=stream, stderr=stream))
        print(scenario, 4433 + index, flush=True)
    while True:
        for scenario, process in zip(SCENARIOS, processes):
            if process.poll() is not None:
                raise RuntimeError('Server exited: ' + scenario + '; inspect /tmp/' + scenario + '.log')
        time.sleep(.5)
finally:
    for process in processes:
        if process.poll() is None: process.terminate()
    for process in processes:
        try: process.wait(timeout=3)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
    for stream in streams: stream.close()
