"""Process client for the external cosigner CLI."""

import json
from pathlib import Path
import subprocess
import sys


class CosignerCLIError(RuntimeError):
    def __init__(self, message, command, returncode=None, stdout="", stderr=""):
        super().__init__(message)
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class CosignerCLIClient:
    def __init__(self, identity, key, ca_id, family, state_path, log=1,
                 python_executable=None, cli_path=None):
        self.identity = identity
        self.key = Path(key)
        self.ca_id = ca_id
        self.family = family
        self.state_path = Path(state_path)
        self.log = log
        self.python_executable = python_executable or sys.executable
        self.cli_path = Path(cli_path) if cli_path is not None else Path(
            __file__).with_name("cosigner_cli.py")

    def _command(self, operation):
        return [
            str(self.python_executable), str(self.cli_path),
            "--identity", self.identity,
            "--key", str(self.key),
            "--ca-id", self.ca_id,
            "--family", self.family,
            "--log", str(self.log),
            "--state", str(self.state_path),
            *operation,
        ]

    def _run(self, operation):
        command = self._command(operation)
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False)
        except OSError as error:
            raise CosignerCLIError(
                "unable to execute external cosigner CLI", command
            ) from error
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise CosignerCLIError(
                f"external cosigner CLI failed with exit code "
                f"{result.returncode}" + (f": {detail}" if detail else ""),
                command, result.returncode,
                result.stdout, result.stderr)
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise CosignerCLIError(
                "external cosigner CLI returned invalid JSON", command,
                result.returncode, result.stdout, result.stderr) from error
        if not isinstance(response, dict):
            raise CosignerCLIError(
                "external cosigner CLI returned an invalid response", command,
                result.returncode, result.stdout, result.stderr)
        return response

    @staticmethod
    def _proof(proof):
        return json.dumps(
            [value.hex() for value in proof], separators=(",", ":"))

    def accept_view(self, tree_size, root_hash, consistency_proof):
        response = self._run([
            "accept-view",
            "--tree-size", str(tree_size),
            "--root-hash", root_hash.hex(),
            "--consistency-proof", self._proof(consistency_proof),
        ])
        try:
            return {
                "tree_size": response["tree_size"],
                "root_hash": bytes.fromhex(response["root_hash"]),
            }
        except (KeyError, TypeError, ValueError) as error:
            raise CosignerCLIError(
                "external cosigner CLI returned an invalid checkpoint",
                self._command([])) from error

    def _signature(self, operation):
        response = self._run(operation)
        try:
            identity = response["identity"]
            signature = bytes.fromhex(response["signature"])
            if not isinstance(identity, str):
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise CosignerCLIError(
                "external cosigner CLI returned an invalid signature",
                self._command(operation)) from error
        return identity, signature

    def cosign_accepted(self, timestamp=0):
        return self._signature([
            "cosign-accepted", "--timestamp", str(timestamp),
        ])

    def cosign_subtree(self, start, end, subtree_hash,
                       subtree_consistency_proof, timestamp=0):
        return self._signature([
            "cosign-subtree",
            "--start", str(start),
            "--end", str(end),
            "--subtree-hash", subtree_hash.hex(),
            "--subtree-consistency-proof",
            self._proof(subtree_consistency_proof),
            "--timestamp", str(timestamp),
        ])
