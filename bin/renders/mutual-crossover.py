#!/usr/bin/env python3
"""Render sampled, exact, and audited mutual-authentication crossovers."""
import argparse,csv
from html import escape
from pathlib import Path
def rows(path):
 with path.open(newline='') as f:return list(csv.DictReader(f))
def table(data,fields):
 h=''.join(f'<th>{escape(label)}</th>' for _,label in fields);b=''.join('<tr>'+''.join(f'<td>{escape(str(r.get(key,"")))}</td>' for key,_ in fields)+'</tr>' for r in data);return f'<div><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--analysis',type=Path,required=True);p.add_argument('--exact',type=Path,required=True);p.add_argument('--audit',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():p.error('output exists')
 sampled=rows(a.analysis/'crossover-n.csv');exact=rows(a.exact/'mutual-crossover-exact.csv');audit=rows(a.audit/'mutual-boundary-audit.csv')
 html=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Mutual-authentication crossover</title><style>body{{font:15px system-ui;max-width:1250px;margin:auto;padding:30px;color:#172b4d}}div{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{padding:8px;border-bottom:1px solid #ccd6e0;text-align:left;white-space:nowrap}}th{{background:#edf3f8}}section{{margin:30px 0}}</style></head><body><h1>Mutual-authentication crossover</h1><p>The measured quantity is the sum of the server and client TLS Certificate handshake messages. Client and server MTC encodings are modeled independently. The empirical audit executes N-1 and N for each exact boundary supported by the native implementation.</p><section><h2>Sampled crossover intervals</h2>{table(sampled,[('profile','Profile'),('chain_profile','X.509 baseline'),('x509_certificate_total_bytes','X.509 total'),('crossover_interval','Sampled interval')])}</section><section><h2>Exact calculated boundaries</h2>{table(exact,[('profile','Profile'),('chain_profile','X.509 baseline'),('x509_certificate_total_bytes','X.509 total'),('crossover_N','Exact N'),('mtc_total_bytes_before','MTC at N-1'),('mtc_total_bytes_at_crossover','MTC at N'),('native_auditable','Auditable')])}</section><section><h2>Empirical boundary audit</h2>{table(audit,[('profile','Profile'),('chain_profile','X.509 baseline'),('predicted_crossover_n','Predicted N'),('mtc_total_before','Observed N-1'),('x509_total_bytes','X.509 total'),('mtc_total_at','Observed N'),('result','Audit')])}</section></body></html>'''
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(html);print(a.output)
if __name__=='__main__':main()
