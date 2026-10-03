"""Deterministic independent mirror for authenticated MTC issuance-log views."""

import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from core import root, verify_consistency
from local_log import LocalLog


MAX_BODY = 1024 * 1024


class MonitorError(RuntimeError):
    pass


def _hex_hash(value):
    if (not isinstance(value,str) or len(value)!=64
            or any(character not in "0123456789abcdef" for character in value)):
        raise MonitorError("invalid hash")
    return bytes.fromhex(value)


class IssuanceLogMonitor:
    """Persist independently reconstructed trees, separated by log number."""

    def __init__(self,root_directory,timeout=2):
        if not isinstance(timeout,(int,float)) or isinstance(timeout,bool) or timeout<=0:
            raise ValueError("invalid timeout")
        self.root=Path(root_directory)
        self.root.mkdir(exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise ValueError("monitor root must be a directory")
        contents=list(self.root.iterdir())
        if not contents:
            (self.root/"logs").mkdir()
        logs=self.root/"logs"
        if (set(path.name for path in self.root.iterdir())!={"logs"}
                or logs.is_symlink() or not logs.is_dir()):
            raise ValueError("invalid monitor layout")
        for path in logs.iterdir():
            if (path.is_symlink() or not path.is_dir() or len(path.name)!=5
                    or not path.name.isdecimal()
                    or not 1<=int(path.name)<=65535
                    or f"{int(path.name):05d}"!=path.name):
                raise ValueError("invalid mirrored log directory")
            LocalLog(path)
        self.timeout=timeout

    @staticmethod
    def _log_number(log_number):
        if type(log_number) is not int or not 1<=log_number<=65535:
            raise ValueError("invalid issuance log number")

    def _log(self,log_number):
        self._log_number(log_number)
        return LocalLog(self.root/"logs"/f"{log_number:05d}")

    @staticmethod
    def _checkpoint(value):
        try:
            if not isinstance(value,dict) or set(value)!={"tree_size","hash"}:
                raise MonitorError("invalid authenticated checkpoint")
            tree_size=value["tree_size"]
            if type(tree_size) is not int or not 0<=tree_size<1<<48:
                raise MonitorError("invalid authenticated checkpoint")
            checkpoint_hash=_hex_hash(value["hash"])
        except MonitorError:
            raise
        return {"tree_size":tree_size,"hash":checkpoint_hash.hex()},checkpoint_hash

    def _get(self,base_url,path,content_type):
        parsed=urlsplit(base_url)
        if (parsed.scheme not in ("http","https") or not parsed.netloc
                or parsed.query or parsed.fragment):
            raise ValueError("invalid log service URL")
        url=base_url.rstrip("/")+path
        try:
            with urlopen(Request(url,method="GET"),timeout=self.timeout) as response:
                if response.status!=200:
                    raise MonitorError("log service returned non-success status")
                actual=response.headers.get("Content-Type","").split(";",1)[0].strip().lower()
                if actual!=content_type:
                    raise MonitorError("log service returned unexpected content type")
                body=response.read(MAX_BODY+1)
        except HTTPError as error:
            raise MonitorError(
                f"log service request failed with status {error.code}") from error
        except (URLError,OSError) as error:
            raise MonitorError("unable to reach log service") from error
        if len(body)>MAX_BODY:
            raise MonitorError("log service response exceeds 1 MiB")
        return body

    def _json(self,base_url,path):
        body=self._get(base_url,path,"application/json")
        try:
            value=json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError,json.JSONDecodeError) as error:
            raise MonitorError("log service returned invalid JSON") from error
        if not isinstance(value,dict):
            raise MonitorError("log service returned invalid JSON response")
        return value

    def state(self,log_number):
        return self._log(log_number).state()

    def entry(self,log_number,index):
        return self._log(log_number).get_entry(index)

    def update(self,log_number,base_url,authenticated_checkpoint):
        """Advance one mirror only after reconstructing the authenticated root."""
        self._log_number(log_number)
        candidate,candidate_root=self._checkpoint(authenticated_checkpoint)
        mirror=self._log(log_number)
        current=mirror.state()
        old_size=current["tree_size"]
        new_size=candidate["tree_size"]
        old_root=bytes.fromhex(current["hash"])

        if new_size<old_size:
            raise MonitorError("authenticated checkpoint rolls back mirror")
        if new_size==old_size:
            if candidate!=current:
                raise MonitorError("same-size authenticated checkpoint conflict")
            return current

        query=urlencode({"old":old_size,"new":new_size})
        response=self._json(base_url,"/proof/consistency?"+query)
        expected={"old_size","new_size","old_hash","new_hash","proof","unsigned"}
        try:
            if set(response)!=expected or response["unsigned"] is not True:
                raise MonitorError("invalid consistency response")
            if (type(response["old_size"]) is not int
                    or type(response["new_size"]) is not int
                    or response["old_size"]!=old_size
                    or response["new_size"]!=new_size):
                raise MonitorError("consistency response sizes do not match request")
            response_old=_hex_hash(response["old_hash"])
            response_new=_hex_hash(response["new_hash"])
            if not isinstance(response["proof"],list):
                raise MonitorError("invalid consistency proof")
            proof=[_hex_hash(value) for value in response["proof"]]
        except (TypeError,MonitorError):
            raise
        if response_old!=old_root or response_new!=candidate_root:
            raise MonitorError("consistency response roots do not match checkpoints")
        if not verify_consistency(
                old_size,new_size,old_root,candidate_root,proof):
            raise MonitorError("invalid consistency proof")

        existing=[mirror.get_entry(index) for index in range(old_size)]
        downloaded=[]
        for index in range(old_size,new_size):
            downloaded.append(self._get(
                base_url,f"/entries/{index}","application/octet-stream"))
        candidate_entries=existing+downloaded
        if root(candidate_entries)!=candidate_root:
            raise MonitorError("downloaded entries do not reconstruct checkpoint")

        # All network data and the complete candidate tree are validated before
        # the first persistent append. LocalLog remains the sole storage codec.
        if mirror.state()!=current:
            raise MonitorError("mirror changed during update")
        for entry in downloaded:
            mirror.append(entry)
        persisted=mirror.state()
        if persisted!=candidate:
            raise MonitorError("persisted mirror differs from checkpoint")
        return persisted
