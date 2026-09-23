"""Run one explicitly selected PCMA Stage-A proof/cache simulation."""
import argparse, csv, datetime, hashlib, json, subprocess, time
from pathlib import Path

from cache import NodeCache
from core import CACHE_RECORD_BYTES, NodeKey, decode_advertisement, decode_mtp1, encode_advertisement, encode_mtp2, proof_nodes, verify_mtp1, verify_mtp2
from workloads import generate

FIELDS = ["timestamp_utc","git_commit","implementation_version","protocol_version","tree_size","sequence_position","leaf_id","workload","random_seed","cache_policy","cache_budget_bytes","normal_proof_hashes","reused_hashes","transmitted_hashes","normal_proof_bytes","pcma_proof_bytes","state_advertisement_bytes","net_authentication_bytes","net_bytes_saved","saving_percentage","cached_nodes","cache_bytes","cache_hits","cache_misses","proof_construction_ns","verification_reconstruction_ns"]


def git_commit():
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[3], text=True).strip()


def load_fixture(manifest_path, n):
    manifest = json.loads(manifest_path.read_text()); entry = manifest["sizes"].get(str(n))
    if not entry: raise ValueError(f"tree size {n} absent from fixture manifest")
    directory = Path(entry["directory"])
    credentials = [(directory / f"credential-{i:04d}.bin").read_bytes() for i in range(n)]
    proofs = [decode_mtp1((directory / f"proof-{i:04d}.bin").read_bytes()) for i in range(n)]
    root = bytes.fromhex(entry["tree_root_sha256"])
    if any(p.leaves != n or p.leaf_index != i or p.root != root for i, p in enumerate(proofs)):
        raise ValueError("fixture MTP1 identity/root mismatch")
    for credential, proof in zip(credentials, proofs): verify_mtp1(credential, proof)
    return credentials, proofs, root


def simulate(manifest_path, n, workload, accesses, seed, policy, budget_bytes):
    credentials, proofs, root = load_fixture(manifest_path, n)
    sequence = generate(workload, n, accesses, seed)
    cache = NodeCache(None if policy == "full" else budget_bytes, policy)
    stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(); commit = git_commit(); rows = []
    for t, leaf in enumerate(sequence, 1):
        proof = proofs[leaf]; required = proof_nodes(proof)
        advertisement = encode_advertisement(root, cache.advertised_keys(root))
        advertised_root, entries = decode_advertisement(advertisement)
        if advertised_root != root: raise RuntimeError("advertised root mismatch")
        server_available = {NodeKey(root, level, index) for level, index in entries}
        start = time.perf_counter_ns(); partial, transmitted = encode_mtp2(proof, server_available); construction = time.perf_counter_ns() - start
        cache.account(required)
        start = time.perf_counter_ns(); authenticated = verify_mtp2(credentials[leaf], partial, cache.values(), root); verification = time.perf_counter_ns() - start
        depth = len(proof.siblings)
        cache.update({key:value for key,value in authenticated.items() if key.level < depth})
        normal = 45 + 32 * depth; net = len(partial) + len(advertisement); saved = normal - net
        rows.append({"timestamp_utc":stamp,"git_commit":commit,"implementation_version":"pcma-stage-a-v1","protocol_version":"MTP2+PCA1","tree_size":n,"sequence_position":t,"leaf_id":leaf,"workload":workload,"random_seed":seed,"cache_policy":policy,"cache_budget_bytes":"unbounded" if policy=="full" else budget_bytes,"normal_proof_hashes":depth,"reused_hashes":depth-transmitted,"transmitted_hashes":transmitted,"normal_proof_bytes":normal,"pcma_proof_bytes":len(partial),"state_advertisement_bytes":len(advertisement),"net_authentication_bytes":net,"net_bytes_saved":saved,"saving_percentage":100*saved/normal,"cached_nodes":len(cache.values()),"cache_bytes":cache.bytes,"cache_hits":cache.hits,"cache_misses":cache.misses,"proof_construction_ns":construction,"verification_reconstruction_ns":verification})
    return rows


def write_run(output, config, rows):
    if output.exists(): raise FileExistsError("output exists; choose a new directory")
    output.mkdir(parents=True)
    with (output / "observations.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS); writer.writeheader(); writer.writerows(rows)
    manifest = {"format":"pcma-stage-a-run-v1","created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"configuration":config,"observations":len(rows),"result":"observations.csv","sha256":hashlib.sha256((output/"observations.csv").read_bytes()).hexdigest()}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--fixtures",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--tree-size",type=int,choices=[16,64,256,1024],default=16);p.add_argument("--workload",choices=["uniform","zipf","clustered","targeted"],default="targeted");p.add_argument("--accesses",type=int,default=16);p.add_argument("--seed",type=int,default=20260911);p.add_argument("--cache-policy",choices=["lru","upper-level","full"],default="full");p.add_argument("--cache-kb",type=int,choices=[0,1,2,4,8,16],default=4);a=p.parse_args()
    budget=a.cache_kb*1024;config={"fixtures":str(a.fixtures.resolve()),"tree_size":a.tree_size,"workload":a.workload,"accesses":a.accesses,"seed":a.seed,"cache_policy":a.cache_policy,"cache_budget_bytes":None if a.cache_policy=="full" else budget,"cache_record_bytes":CACHE_RECORD_BYTES}
    rows=simulate(a.fixtures.resolve(),a.tree_size,a.workload,a.accesses,a.seed,a.cache_policy,budget);write_run(a.output.resolve(),config,rows);print(a.output,len(rows),"observations")


if __name__=="__main__": main()
