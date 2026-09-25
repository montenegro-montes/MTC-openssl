#!/usr/bin/env python3
"""Render analytical crossover results and their empirical boundary audit."""
import argparse,base64,csv
from html import escape
from pathlib import Path
from host_info import collect_host_info, host_rows
def rows(path):
 with path.open(newline='') as f:return list(csv.DictReader(f))
def table(data,fields):
 h=''.join(f'<th>{escape(label)}</th>' for _,label in fields);b=''.join('<tr>'+''.join(f'<td>{escape(str(r.get(key,"")))}</td>' for key,_ in fields)+'</tr>' for r in data);return f'<div class="scroll"><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'
def image(path,caption):
 if not path.is_file():return ''
 return f'<figure><img src="data:image/png;base64,{base64.b64encode(path.read_bytes()).decode()}" alt="{escape(caption)}"><figcaption>{escape(caption)}</figcaption></figure>'

def effective_display(row,pct):
 status=row.get(f'effective_{pct}pct_status','')
 value=row.get(f'effective_{pct}pct_max_N','')
 if status=='NO_N_WITH_REQUIRED_MARGIN':return 'none'
 if status=='PRESERVED_THROUGH_PROTOCOL_RANGE':
  limit=str(row.get('maximum_supported_N',''))
  if limit==str((1<<48)-1):
   return 'through 2^48 - 1'
  return 'through '+limit
 return value
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--analysis',type=Path,required=True);p.add_argument('--audit',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():p.error('output exists')
 analytical=rows(a.analysis/'crossover_extended.csv');audit=rows(a.audit/'crossover-boundary-audit.csv');figures=image(a.analysis/'crossover-by-depth.png','Calculated crossover by X.509 chain depth.')+image(a.analysis/'crossover-curves.png','MTC size curves and X.509 reference boundaries.')

 required={
  'effective_1pct_max_N','effective_1pct_status',
  'effective_5pct_max_N','effective_5pct_status',
  'effective_10pct_max_N','effective_10pct_status'
 }
 if not analytical:
  p.error('empty crossover_extended.csv')
 missing=sorted(required-set(analytical[0]))
 if missing:
  p.error('analysis does not contain effective crossover fields: '+', '.join(missing))

 effective=[]
 for r in analytical:
  effective.append({
   'algorithm':r.get('algorithm',''),
   'x509_depth':r.get('x509_depth',''),
   'x509_bytes':r.get('x509_bytes',''),
   'crossover_display':r.get('crossover_display',''),
   'n1':effective_display(r,1),
   'n5':effective_display(r,5),
   'n10':effective_display(r,10),
  })

 host=[{'field':key,'value':value} for key,value in host_rows(collect_host_info())]
 html=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Advanced crossover report</title><style>body{{font:15px system-ui;max-width:1250px;margin:auto;padding:30px;color:#172b4d}}section{{margin:28px 0}}.scroll{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{padding:8px;border-bottom:1px solid #ccd6e0;text-align:left;white-space:nowrap}}th{{background:#edf3f8}}img{{max-width:100%}}figcaption{{text-align:center;color:#53647c}}</style></head><body><h1>Advanced MTC/X.509 crossover</h1><p>The analytical model finds the first integer N where MTC is at least as large as the selected X.509 Certificate-message reference. The empirical audit independently executes N-1 and N for boundaries supported by the native implementation (N≤1024).</p><section><h2>Calculated boundaries</h2>{table(analytical,[('algorithm','Profile'),('x509_depth','X.509 depth'),('x509_bytes','X.509 bytes'),('crossover_display','Calculated cutoff'),('implementation_crossover_N','Native cutoff'),('reference_source','Reference')])}</section><section><h2>Practical-margin crossover</h2><p><strong>N*</strong> is the first integer N where landmark MTC is at least as large as the selected X.509 Certificate-message reference. <strong>N*1%</strong>, <strong>N*5%</strong> and <strong>N*10%</strong> are the largest integer populations for which MTC still retains at least the corresponding percentage reduction in Certificate-message bytes. These effective thresholds distinguish a mathematical size advantage from a practically meaningful margin. A value shown as <strong>through 2^48 - 1</strong> means that the required margin is preserved throughout the complete modeled protocol range; no loss of that margin was found within the analytical domain, and it does not imply native execution at that population size.</p>{table(effective,[('algorithm','Profile'),('x509_depth','X.509 depth'),('x509_bytes','X.509 bytes'),('crossover_display','N*'),('n1','N*1%'),('n5','N*5%'),('n10','N*10%')])}</section><section><h2>Empirical N-1/N audit</h2>{table(audit,[('profile','Profile'),('x509_depth','X.509 depth'),('predicted_crossover_n','Predicted N'),('bytes_before','Bytes at N-1'),('bytes_at','Bytes at N'),('x509_bytes','X.509 bytes'),('result','Audit')])}</section><section><h2>Figures</h2>{figures}</section><section><h2>Time and computer</h2>{table(host,[('field','Field'),('value','Value')])}</section></body></html>'''
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(html);print(a.output)
if __name__=='__main__':main()
