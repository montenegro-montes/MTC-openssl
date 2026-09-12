#!/usr/bin/env python3
import json,os,subprocess,sys
sys.path.insert(0,"/opt/network-combined")
from network import commands
p=json.loads(os.environ["NETWORK_PROFILE_JSON"])
for command in commands(p): subprocess.run(command,check=True)
