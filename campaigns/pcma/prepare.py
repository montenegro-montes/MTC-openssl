"""Create an immutable PCMA fixture manifest referencing existing Compact fixtures."""
import argparse, datetime, hashlib, json, os
from pathlib import Path

SIZES = [16, 64, 256, 1024]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True, help="Scaling fixture root containing batchN/compact/FAMILY")
    p.add_argument("--output", type=Path, required=True, help="New manifest directory")
    p.add_argument("--family", choices=["pq", "classic"], default="pq")
    a = p.parse_args(); source = a.source.resolve(); output = a.output.resolve()
    if output.exists(): p.error("output exists; choose a new directory")
    entries = {}
    for n in SIZES:
        directory = source / f"batch{n}" / "compact" / a.family
        files = [directory / "root.signed"] + [directory / f"{kind}-{i:04d}.bin" for i in range(n) for kind in ("credential", "proof")]
        missing = [str(f) for f in files if not f.is_file()]
        if missing: p.error(f"missing Compact fixture: {missing[0]}")
        root = (directory / "proof-0000.bin").read_bytes()[12:44]
        entries[str(n)] = {"directory": str(directory), "tree_root_sha256": root.hex(), "root_signed_sha256": hashlib.sha256(files[0].read_bytes()).hexdigest(), "credentials": n, "proofs": n}
    output.mkdir(parents=True); os.chmod(output, 0o700)
    manifest = {"format": "pcma-fixture-manifest-v1", "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "family": a.family, "source": str(source), "sizes": entries}
    (output / "fixtures.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(output / "fixtures.json")


if __name__ == "__main__": main()
