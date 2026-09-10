from pathlib import Path
import subprocess
from dotenv import dotenv_values
import os
import csv

# ----------------------------------------------------------
# Load environment variables from .env file
# ----------------------------------------------------------
env = dotenv_values("../config/.env")

# Get directory path names relative to this file rather than the container
WORKDIR = env["WORKDIR"]
PYTHONDIR = str(Path(__file__).resolve().parent.parent)

CHAIN_DIR = Path(env["CHAIN_DIR"].replace(WORKDIR, PYTHONDIR))
CERTS_DIR = Path(env["CERTS_DIR"].replace(WORKDIR, PYTHONDIR))
KEYS_DIR = Path(env["KEYS_DIR"].replace(WORKDIR, PYTHONDIR))

CONTAINER_NAME = env["CONTAINER_NAME"]

# Define the output file
SCRIPT_NAME = Path(__file__).stem
RESULTS_CSV = f"{SCRIPT_NAME}_results.csv"

# ----------------------------------------------------------
# Define the benchmark parameters
# ----------------------------------------------------------
SIG_ALGS = ["EC", "ML-DSA", "SLH-DSAs", "SLH-DSAf"]  # Signature algorithms
CHAINS = [                   # Certificate chains and their security levels
    [1],                     
    [3],
    [5],
    [3, 1],
    [3, 3],
    [5, 1],
    [5, 3],
    [3, 3, 3],
    [5, 3, 1],
    [5, 3, 3],
    [5, 5, 5],               # Root certificate is first in the chain               
]


# ----------------------------------------------------------
# Run the benchmark for defined parameter
# ----------------------------------------------------------
if Path(RESULTS_CSV).exists():
    print(f"{RESULTS_CSV} already exists. Overwrite? [y/N]: ", end="")
    if input().lower() not in ("y", "yes"):
        exit(0)

rows = []
for alg in SIG_ALGS:
    for chain in CHAINS:

        # Convert the chain of security levels to a comma-separated string
        sec_levels = ",".join(map(str, chain))

        print(f"{alg}: {sec_levels}")

        # Generate certificates and keys inside the Docker container
        subprocess.run(
            [
                "docker",
                "exec",
                CONTAINER_NAME,
                "./scripts/generate_certs.sh",
                "--clean",      # Clean previous outputs
                "--sig-alg",    # Signature algorithm
                alg,
                "--sec-levels", # Security levels each certificate in the chain
                sec_levels,
            ],
            check=True,
        )


        # Calculate the sizes of keys, certificates, and the certificate chain
        key_size = sum(f.stat().st_size for f in KEYS_DIR.glob("*.key"))
        cert_size = sum(f.stat().st_size for f in CERTS_DIR.glob("*.crt"))
        chain_size = (CHAIN_DIR / "server-chain.pem").stat().st_size

        rows.append(
            {
                "algorithm": alg,
                "chain": sec_levels,
                "length": len(chain),
                "keys_bytes": key_size,
                "certs_bytes": cert_size,
                "chain_bytes": chain_size,
                "avg_cert_bytes": cert_size / len(chain)
            }
        )

# ----------------------------------------------------------
# Write the benchmark results to a CSV file
# ----------------------------------------------------------
with open(RESULTS_CSV, "w", newline="") as f:

    writer = csv.DictWriter(f, fieldnames=rows[0].keys())

    writer.writeheader()
    writer.writerows(rows)

print(f"Results written to {RESULTS_CSV}")