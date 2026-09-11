"""Write exact wire-size bounds for MTP1, MTP2 and PCA1."""
import argparse,csv,math
from pathlib import Path
from core import CACHE_RECORD_BYTES,depth_for


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error("output exists; choose a new file")
    rows=[]
    for n in [16,64,256,1024]:
        d=depth_for(n);baseline=45+32*d;partial=46+math.ceil(d/8);advertisement=38+5*d;net=partial+advertisement;saved=baseline-net
        rows.append({"tree_size":n,"depth":d,"normal_proof_bytes":baseline,"normal_hash_bytes":32*d,"maximum_reusable_proof_bytes":32*d,"minimum_mtp2_bytes":partial,"minimum_selective_pca1_bytes":advertisement,"minimum_net_authentication_bytes":net,"theoretical_net_saving_bytes":saved,"theoretical_net_saving_percent":100*saved/baseline,"cache_records_needed":d,"cache_bytes_needed":d*CACHE_RECORD_BYTES})
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print(a.output)


if __name__=="__main__":main()
