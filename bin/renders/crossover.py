#!/usr/bin/env python3
"""Render static X.509/MTC crossover evidence as self-contained HTML."""
import argparse, base64, csv
from html import escape
from pathlib import Path

def rows(path):
    with path.open(newline="") as stream: return list(csv.DictReader(stream))

def table(data, columns):
    head="".join(f"<th>{escape(label)}</th>" for _,label in columns)
    body="".join("<tr>"+"".join(f"<td>{escape(str(row.get(key,'')))}</td>" for key,_ in columns)+"</tr>" for row in data)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

def image(path, caption):
    if not path.is_file(): return ""
    data=base64.b64encode(path.read_bytes()).decode()
    return f'<figure><img src="data:image/png;base64,{data}" alt="{escape(caption)}"><figcaption>{escape(caption)}</figcaption></figure>'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("directory",type=Path);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    if a.output.exists(): p.error("output exists")
    for name in ("crossover.csv","chain_sizes.csv","mtc_sizes.csv"):
        if not (a.directory/name).is_file(): p.error(f"missing {name}")
    cross,chain,mtc=(rows(a.directory/name) for name in ("crossover.csv","chain_sizes.csv","mtc_sizes.csv"));plots=a.directory/"plots"
    figures="".join((image(plots/"certificate-size.png","Certificate size by cryptographic profile."),image(plots/"x509-chain-scaling.png","X.509 TLS Certificate message size as chain depth increases."),image(plots/"mtc-scaling.png","MTC landmark TLS Certificate message size as the Merkle population grows."),image(plots/"mtc-standalone-vs-landmark.png","Standalone and landmark MTC encodings for the measured fixture.")))
    html=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MTC crossover report</title><style>body{{font:15px system-ui,sans-serif;background:#f1f5f9;color:#172b4d;margin:0}}main{{max-width:1200px;margin:auto;padding:28px}}header,section{{background:#fff;border:1px solid #dbe3ed;border-radius:12px;padding:22px;margin:16px 0}}h1{{margin:.2em 0}}p{{line-height:1.55}}.scroll{{overflow:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{padding:9px;border-bottom:1px solid #dde4ee;text-align:left;white-space:nowrap}}th{{background:#edf3f8}}figure{{margin:28px 0}}img{{display:block;max-width:100%;height:auto;margin:auto}}figcaption{{text-align:center;color:#53647c;margin-top:8px}}</style></head><body><main><header><h1>MTC and X.509 crossover</h1><p>This report presents static serialization evidence for all nine cryptographic profiles. A crossover interval identifies the two tested Merkle population sizes between which the MTC landmark TLS Certificate message becomes larger than the X.509 message. It is a size comparison, not a handshake-time measurement.</p><p><strong>Scope:</strong> X.509 chain depths and MTC landmark/standalone encodings. CSV and JSON files remain the canonical evidence.</p></header><section><h2>Crossover results</h2><p><code>CROSSED</code> means the cutoff is bounded by the lower and upper N values. Difference is MTC minus X.509 at the upper bound.</p>{table(cross,[('algorithm','Profile'),('x509_depth','X.509 depth'),('x509_bytes','X.509 bytes'),('mtc_previous_N','Lower N'),('mtc_previous_bytes','MTC bytes at lower N'),('mtc_cross_N','Upper N'),('mtc_cross_bytes','MTC bytes at upper N'),('difference_bytes','Difference'),('status','Result')])}</section><section><h2>Figures</h2>{figures or '<p>PNG figures are unavailable. Re-run the plotting stage with current renderer support.</p>'}</section><section><h2>X.509 chain sizes</h2>{table(chain,[('algorithm','Profile'),('depth','Depth'),('transmitted_certificates','Certificates sent'),('tls_certificate_message_bytes','TLS Certificate bytes')])}</section><section><h2>MTC size evidence</h2>{table(mtc,[('algorithm','Profile'),('mtc_profile','MTC mode'),('tree_size','N'),('proof_hashes','Proof hashes'),('tls_certificate_message_bytes','TLS Certificate bytes'),('evidence','Evidence')])}</section></main></body></html>'''
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(html);print(a.output)

if __name__=="__main__": main()
