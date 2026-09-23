#!/usr/bin/env python3
"""Prepare immutable mutual-authentication fixtures; execution is explicit."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
DEFAULT_OUTPUT = Path("artifacts/validation/mutual-auth-manual")
IMAGE = "mt-tls-mtc:local"
OPENSSL = "/opt/openssl/bin/openssl"


def checked(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True)


def openssl(*args):
    return checked(OPENSSL, *args)


def key(path, algorithm, curve=None):
    args = ["genpkey", "-algorithm", algorithm]
    if curve:
        args += ["-pkeyopt", f"ec_paramgen_curve:{curve}"]
    openssl(*args, "-out", path)


def profile_args(profile):
    if profile == "ecdsa-p256":
        return "EC", "P-256", "sha256"
    if profile == "mldsa65":
        return "mldsa65", None, None
    raise ValueError(profile)


def issue_pair(root, profile, role, ca_name, leaf_name, hostname, *, wrong=False):
    algorithm, curve, digest = profile_args(profile)
    prefix = "pq-" if profile == "mldsa65" else ""
    ca_stem = f"{prefix}{role}-ca" if not wrong else "wrong-client-ca"
    leaf_stem = f"{prefix}{role}" if not wrong else "wrong-client"
    ca_key, ca_cert = root / f"{ca_stem}.key", root / f"{ca_stem}.pem"
    leaf_key, leaf_cert = root / f"{leaf_stem}.key", root / f"{leaf_stem}.pem"
    key(ca_key, algorithm, curve)
    digest_arg = [f"-{digest}"] if digest else []
    openssl("req", "-new", "-x509", "-key", ca_key, "-out", ca_cert,
            "-days", "30", "-subj", f"/CN={ca_name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", *digest_arg)
    key(leaf_key, algorithm, curve)
    csr, ext = root / f"{leaf_stem}.csr", root / f"{leaf_stem}.cnf"
    openssl("req", "-new", "-key", leaf_key, "-out", csr,
            "-subj", f"/CN={hostname}", *digest_arg)
    eku = "serverAuth" if role == "server" else "clientAuth"
    ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                   f"extendedKeyUsage={eku}\nsubjectAltName=DNS:{hostname}\n")
    openssl("x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
            "-set_serial", "2", "-days", "30", "-extfile", ext,
            "-out", leaf_cert, *digest_arg)
    csr.unlink(); ext.unlink()


def mtc_domain(root, name):
    sys.path.insert(0, "/repo/src/mtc")
    import prepare
    source = root / ("mtc-client-source" + ("-alt" if name.endswith("alt") else ""))
    target = root / name / "ecdsa-p256"
    source.mkdir(parents=True)
    originals = []
    for index in range(16):
        stem = f"client-{index:04d}"
        leaf_key, leaf_cert = source / f"{stem}.key", source / f"{stem}.pem"
        key(leaf_key, "EC", "P-256")
        openssl("req", "-new", "-x509", "-key", leaf_key, "-out", leaf_cert,
                "-days", "30", "-set_serial", str(index + 1),
                "-subj", f"/CN={stem}",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature",
                "-addext", "extendedKeyUsage=clientAuth", "-sha256")
        originals.append(leaf_cert)
    target.parent.mkdir(parents=True)
    prepare.prepare(target, source, "ecdsa-p256", 16, originals=originals,
                    metadata={"experiment": "mutual-authentication-preflight",
                              "role": "client", "domain": name})


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(output):
    os.umask(0o077)
    output.mkdir(parents=True, exist_ok=False)
    issue_pair(output, "ecdsa-p256", "server", "Mutual Auth Server CA", "server", "server")
    issue_pair(output, "ecdsa-p256", "client", "Mutual Auth Client CA", "client", "client")
    issue_pair(output, "ecdsa-p256", "client", "Wrong Mutual Auth Client CA", "wrong-client", "client", wrong=True)
    issue_pair(output, "mldsa65", "server", "PQC Mutual Auth Server CA", "pq-server", "server")
    issue_pair(output, "mldsa65", "client", "PQC Mutual Auth Client CA", "pq-client", "client")
    mtc_domain(output, "mtc-client-n16")
    mtc_domain(output, "mtc-client-n16-alt")
    files = {str(p.relative_to(output)): digest(p) for p in sorted(output.rglob("*")) if p.is_file()}
    manifest = {
        "schema": 1,
        "purpose": "mutual-authentication functional preflight fixtures",
        "status": "PREPARED_NOT_VALIDATED",
        "image_id": os.environ.get("MTC_IMAGE_ID"),
        "git_commit": os.environ.get("MTC_GIT_COMMIT"),
        "profiles": ["ecdsa-p256", "mldsa65"],
        "mtc_tree_size": 16,
        "independent_untrusted_mtc_domain": True,
        "file_sha256": files,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    if args.inside:
        if not args.execute or output.parent != Path("/output"):
            parser.error("invalid internal execution request")
        if output.exists():
            parser.error(f"output exists and is immutable: {output}")
        generate(output)
        return
    artifacts = (REPO / "artifacts/validation").resolve()
    if not output.is_relative_to(artifacts):
        parser.error("--output must be below artifacts/validation")
    if output.exists():
        parser.error(f"output exists and is immutable: {output}")
    if not args.execute:
        print(json.dumps({"execute": False, "image": args.image, "output": str(output),
                          "profiles": ["ecdsa-p256", "mldsa65"], "mtc_domains": 2}, indent=2))
        return
    image_id = json.loads(checked("docker", "image", "inspect", args.image).stdout)[0]["Id"]
    commit = checked("git", "rev-parse", "HEAD").stdout.strip()
    output.parent.mkdir(parents=True, exist_ok=True)
    relative = Path(__file__).resolve().relative_to(REPO)
    command = ["docker", "run", "--rm", "--network", "none",
               "-e", f"MTC_IMAGE_ID={image_id}", "-e", f"MTC_GIT_COMMIT={commit}",
               "-e", "LD_LIBRARY_PATH=/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib",
               "-v", f"{REPO}:/repo:ro", "-v", f"{output.parent}:/output",
               "--entrypoint", "python3", args.image, f"/repo/{relative}",
               "--inside", "--execute", "--output", f"/output/{output.name}"]
    print("Executing fixture generation in the pinned local image.")
    subprocess.run(command, check=True)


if __name__ == "__main__":
    main()
