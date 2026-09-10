"""Compatibility entry point; the compose client uses the frozen failure-aware loss driver."""
import runpy
runpy.run_path('/opt/network-loss/measure.py',run_name='__main__')
