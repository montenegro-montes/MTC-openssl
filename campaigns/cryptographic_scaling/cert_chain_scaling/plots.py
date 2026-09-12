#!/usr/bin/env python3
import argparse,csv
from pathlib import Path
def rows(path):
 with path.open() as f:return list(csv.DictReader(f))
def main():
 p=argparse.ArgumentParser();p.add_argument("analysis",type=Path);p.add_argument("--measurements",type=Path);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 import matplotlib.pyplot as plt
 if a.output.exists():p.error("output exists")
 a.output.mkdir(parents=True);cert=rows(a.analysis/"certificate_sizes.csv");chain=rows(a.analysis/"chain_sizes.csv");mtc=rows(a.analysis/"mtc_sizes.csv")
 fig,ax=plt.subplots(figsize=(8,4));server=[r for r in cert if r["certificate_position"]=="server" and r["depth"]=="2"];ax.bar([r["algorithm"] for r in server],[float(r["certificate_der_bytes"]) for r in server]);ax.set_ylabel("DER bytes");ax.tick_params(axis="x",rotation=45);fig.tight_layout();fig.savefig(a.output/"certificate-size.pdf");plt.close(fig)
 fig,ax=plt.subplots(figsize=(7,4));
 for alg in sorted({r["algorithm"] for r in chain}):
  g=[r for r in chain if r["algorithm"]==alg];ax.plot([int(r["depth"]) for r in g],[int(r["tls_certificate_message_bytes"]) for r in g],marker="o",label=alg)
 ax.set(xlabel="PKI depth including root",ylabel="TLS Certificate message bytes");ax.legend(fontsize=6,ncol=3);fig.tight_layout();fig.savefig(a.output/"x509-chain-scaling.pdf");plt.close(fig)
 fig,ax=plt.subplots(figsize=(7,4));
 modeled=[r for r in mtc if r["mtc_profile"]=="landmark" and r["evidence"]=="exact serialization model"]
 for alg in sorted({r["algorithm"] for r in modeled}):
  g=[r for r in modeled if r["algorithm"]==alg];ax.plot([int(r["tree_size"]) for r in g],[int(r["tls_certificate_message_bytes"]) for r in g],label=alg)
 for r in chain:
  if r["algorithm"] in {"ecdsa-p256","mldsa65"} and r["depth"] in {"2","5"}:ax.axhline(int(r["tls_certificate_message_bytes"]),linewidth=.6,linestyle="--",alpha=.5)
 ax.set_xscale("log",base=2);ax.set(xlabel="Merkle population N",ylabel="MTC landmark TLS Certificate bytes");ax.legend();fig.tight_layout();fig.savefig(a.output/"mtc-scaling.pdf");plt.close(fig)
 if a.measurements and (a.measurements/"summary.csv").is_file():
  summary=rows(a.measurements/"summary.csv");labels=[r["scenario"] for r in summary]
  for filename,column,ylabel in [("authentication-processing.pdf","authentication_processing_wall_ms_median_of_campaign_medians","Authentication processing wall ms"),("tls-authentication-bytes.pdf","certificate_message_bytes_median_of_campaign_medians","TLS Certificate message bytes")]:
   fig,ax=plt.subplots(figsize=(8,4));ax.bar(labels,[float(r[column]) for r in summary]);ax.set_ylabel(ylabel);ax.tick_params(axis="x",rotation=45);fig.tight_layout();fig.savefig(a.output/filename);plt.close(fig)
 measured=[r for r in mtc if r["evidence"]=="measured fixture"]
 if measured:
  fig,ax=plt.subplots(figsize=(7,4))
  for mode in ["landmark","standalone"]:
   g=[r for r in measured if r["mtc_profile"]==mode and r["algorithm"]=="mldsa65"]
   if g:ax.plot([int(r["tree_size"]) for r in g],[int(r["tls_certificate_message_bytes"]) for r in g],marker="o",label=mode)
  ax.set_xscale("log",base=2);ax.set(xlabel="Merkle population N",ylabel="TLS Certificate message bytes");ax.legend();fig.tight_layout();fig.savefig(a.output/"mtc-standalone-vs-landmark.pdf");plt.close(fig)
 print(a.output)
if __name__=="__main__":main()
