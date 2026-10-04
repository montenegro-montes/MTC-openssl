"""Cross-language tests for native MCA2/MCP2/MTB2 structural loaders."""

import argparse
from pathlib import Path
import subprocess
import tempfile
import time

import prepare
from config_formats import (
    MAX_UINT48, MCA2Authority, MCP2Checkpoint, MTB2Bundle,
    decode_mcp2, decode_mtb2, encode_mca2, encode_mcp2, encode_mtb2,
)
from core import H, cover, encode_subtree_signature_block, root, uint, vec


SOURCE=Path(__file__).resolve().parent


def authority(log=1,signers=None):
    if signers is None:
        signers=(("32473.1",b"spki-one"),("32473.2",b"spki-two"))
    first=log<<48
    return MCA2Authority("32473.1",tuple(signers),log,first,first+1023)


def checkpoint(size=1,signature_values=None):
    if signature_values is None:
        signature_values=(("32473.1",b"ca"),("32473.2",b"other"))
    intervals=cover(0,size)
    left=H(b"left"+uint(size,6));right=H(b"") if size==1 else H(b"right"+uint(size,6))
    root=left if size==1 else H(b"\x01"+left+right)
    return MCP2Checkpoint(size,123,root,tuple(signature_values),(
        (intervals[0][0],intervals[0][1],left),
        (intervals[1][0],intervals[1][1],right)))


def raw_checkpoint(value,signature_block):
    data=(b"MCP2"+uint(value.tree_size,6)+uint(value.timestamp,8)+value.root_hash+
          uint(len(signature_block),3)+signature_block)
    return data+b"".join(uint(a,6)+uint(b,6)+h for a,b,h in value.subtrees)


def raw_authority(ca_id,signers,log=1,minimum=None,maximum=None):
    if minimum is None:minimum=log<<48
    if maximum is None:maximum=minimum+1023
    data=b"MCA2"+vec(ca_id.encode("ascii"),1)+uint(len(signers),2)
    for identity,spki in signers:
        data+=vec(identity.encode("ascii"),1)+vec(spki,3)
    return data+uint(log,2)+uint(minimum,8)+uint(maximum,8)


def write(directory,name,data):
    path=directory/name;path.write_bytes(data);return path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc",default="cc")
    parser.add_argument("--openssl-prefix",type=Path,default=Path("/opt/homebrew"))
    args=parser.parse_args()
    prepare.OPENSSL=str(args.openssl_prefix/"bin/openssl")
    lib=args.openssl_prefix/"lib"
    if not lib.is_dir():lib=args.openssl_prefix/"lib64"
    with tempfile.TemporaryDirectory(prefix="mtc-config-native-") as temporary:
        directory=Path(temporary);binary=directory/"test_config_formats_native"
        subprocess.run([args.cc,"-Wall","-Wextra","-Werror","-I"+str(args.openssl_prefix/"include"),
            str(SOURCE/"test_config_formats_native.c"),"-L"+str(lib),"-Wl,-rpath,"+str(lib),
            "-lcrypto","-o",str(binary)],check=True)
        def accept(mode,path,*expected):
            subprocess.run([str(binary),mode,str(path),*map(str,expected)],check=True)
        def reject(mode,name,data):
            path=write(directory,name,data);accept("reject-"+mode,path)

        encoded_authorities=[]
        for log in (1,65535):
            data=encode_mca2(authority(log));encoded_authorities.append(data)
            accept("authority",write(directory,f"authority-{log}.mca2",data),log,2,1)
        three=encode_mca2(authority(signers=(("32473.1",b"a"),("32473.2",b"b"),("32473.3",b"c"))))
        accept("authority",write(directory,"authority-three.mca2",three),1,3,1)
        large=encode_mca2(authority(signers=(("32473.1",b"s"*65536),)))
        accept("authority",write(directory,"authority-large.mca2",large),1,1,65536)
        uint64_id=str((1<<64)-1)
        uint64_authority=encode_mca2(MCA2Authority(
            uint64_id,((uint64_id,b"spki"),),1,1<<48,(1<<48)+1023))
        accept("authority",write(directory,"authority-uint64.mca2",uint64_authority),1,1,1)
        normal=encoded_authorities[0]
        reject("authority","authority-log-zero.mca2",normal[:-18]+b"\0\0"+normal[-16:])
        reject("authority","authority-duplicate.mca2",normal.replace(b"32473.2",b"32473.1"))
        reject("authority","authority-huge-count.mca2",
               b"MCA2"+vec(b"1",1)+b"\xff\xff"+b"\0"*18)
        reject("authority","authority-empty-spki.mca2",
               raw_authority("1",(("1",b""),)))
        reject("authority","authority-reversed-range.mca2",
               raw_authority("1",(("1",b"s"),),minimum=2,maximum=1))
        first_signer=vec(b"1",1)+vec(b"s",3)
        broken_second=vec(b"2",1)+uint(30,3)+b"x"+b"\0"*18
        reject("authority","authority-partial-cleanup.mca2",
               b"MCA2"+vec(b"1",1)+uint(2,2)+first_signer+broken_second)
        for label,identity in (("overflow",str(1<<64)),("leading-zero","01"),
                               ("empty-component","1..2"),("trailing","1.")):
            reject("authority",f"authority-id-{label}.mca2",
                   raw_authority(identity,(("1",b"s"),)))
        for label,data in (("wrong",b"BAD2"+normal[4:]),("short",normal[:-1]),("trail",normal+b"\0")):
            reject("authority",f"authority-{label}.mca2",data)

        encoded_checkpoints=[]
        for size in (1,1024,1025,MAX_UINT48):
            data=encode_mcp2(checkpoint(size));encoded_checkpoints.append(data)
            accept("checkpoint",write(directory,f"checkpoint-{size}.mcp2",data),size,2)
        wide=encode_mcp2(checkpoint(1,(("1",b"a"*65528),("2",b""))))
        assert int.from_bytes(wide[50:53],"big")==65536
        accept("checkpoint",write(directory,"checkpoint-wide.mcp2",wide),1,2)
        normal_cp=encoded_checkpoints[0]
        reject("checkpoint","checkpoint-zero.mcp2",normal_cp[:4]+b"\0"*6+normal_cp[10:])
        first=encode_subtree_signature_block((("1",b"a"),))
        second=encode_subtree_signature_block((("2",b"b"),))
        reject("checkpoint","checkpoint-duplicate.mcp2",raw_checkpoint(checkpoint(),first+first))
        reject("checkpoint","checkpoint-order.mcp2",raw_checkpoint(checkpoint(),second+first))
        for label,identity in (("nonminimal",b"\x80\x01"),("unterminated",b"\x81"),
                               ("overflow",bytes([0x82]+[0x80]*8+[0x00]))):
            block=bytes([len(identity)])+identity+b"\0\0"
            reject("checkpoint",f"checkpoint-id-{label}.mcp2",
                   raw_checkpoint(checkpoint(),block))
        interval_offset=53+int.from_bytes(normal_cp[50:53],"big")
        wrong_interval=bytearray(normal_cp);wrong_interval[interval_offset+5]^=1
        reject("checkpoint","checkpoint-interval.mcp2",bytes(wrong_interval))
        wrong_root=bytearray(normal_cp);wrong_root[18]^=1
        reject("checkpoint","checkpoint-root.mcp2",bytes(wrong_root))
        signature_length=int.from_bytes(normal_cp[50:53],"big")
        mismatched=bytearray(normal_cp);mismatched[50:53]=uint(signature_length+1,3)
        reject("checkpoint","checkpoint-signatures-length.mcp2",bytes(mismatched))
        reject("checkpoint","checkpoint-signatures-truncated.mcp2",normal_cp[:52])
        for label,data in (("wrong",b"BAD2"+normal_cp[4:]),("short",normal_cp[:-1]),("trail",normal_cp+b"\0")):
            reject("checkpoint",f"checkpoint-{label}.mcp2",data)

        base=MTB2Bundle(authority(),checkpoint(1025))
        for landmark in (None,1,1<<32,MAX_UINT48):
            data=encode_mtb2(MTB2Bundle(base.authority,base.checkpoint,landmark))
            accept("bundle",write(directory,f"bundle-{landmark}.mtb2",data),"none" if landmark is None else landmark)
        bundle=encode_mtb2(base)
        reject("bundle","bundle-zero.mtb2",bundle[:-1]+b"\x01"+b"\0"*6)
        reject("bundle","bundle-landmark-truncated.mtb2",bundle[:-1]+b"\x01"+b"\0"*5)
        reject("bundle","bundle-kind.mtb2",bundle[:-1]+b"\x02")
        authority_length=int.from_bytes(bundle[4:8],"big")
        checkpoint_length_at=8+authority_length
        checkpoint_at=checkpoint_length_at+4
        bad=bytearray(bundle);bad[8:12]=b"BAD2"
        reject("bundle","bundle-authority.mtb2",bytes(bad))
        bad=bytearray(bundle);bad[checkpoint_at:checkpoint_at+4]=b"BAD2"
        reject("bundle","bundle-checkpoint.mtb2",bytes(bad))
        bad=bytearray(bundle);bad[4:8]=b"\xff"*4
        reject("bundle","bundle-authority-length.mtb2",bytes(bad))
        nested=uint(authority_length+1,4)+bundle[8:8+authority_length]+b"\0"
        reject("bundle","bundle-nested-trailing.mtb2",b"MTB2"+nested+bundle[checkpoint_length_at:])
        reject("bundle","bundle-trailing.mtb2",bundle+b"\0")

        # The deployment adapter authenticates the embedded checkpoint and
        # derives signaling only from the explicit MTB2 signaling kind.
        profile=prepare.crypto_profile("ecdsa-p256")
        keys=[directory/f"adapter-{i}.key" for i in range(2)]
        for key in keys:prepare.keygen(key,"ecdsa-p256")
        public=[prepare.command("pkey","-in",key,"-pubout","-outform","DER")
                for key in keys]
        entries=[b"adapter-entry"]
        timestamp=int(time.time());root_hash=root(entries)
        signature_values=tuple(prepare.checkpoint_signature(
            identity,key,profile["ca_id"],1,root_hash,timestamp,
            "ecdsa-p256") for identity,key in zip(profile["cosigner_ids"],keys))
        adapter_authority=prepare.authority_value_v2(
            profile["ca_id"],profile["cosigner_ids"],public,1)
        adapter_checkpoint=prepare.checkpoint_value_v2(
            entries,timestamp,signature_values)
        for landmark in (None,1,2,1<<32,MAX_UINT48):
            adapter_data=encode_mtb2(MTB2Bundle(
                adapter_authority,adapter_checkpoint,landmark))
            path=write(directory,f"adapter-{landmark}.mtb2",adapter_data)
            if landmark is None:
                signal=request=profile["ca_id"];number=0
            else:
                number=landmark
                signal=f'{profile["ca_id"]}.1.1.{landmark}'
                request=f'{profile["ca_id"]}.2.1.{landmark}'
            accept("trust-config",path,number,signal,request)
        corrupted=list(adapter_checkpoint.signatures)
        identity,signature=corrupted[0]
        corrupted[0]=(identity,signature[:-1]+bytes([signature[-1]^1]))
        corrupt_checkpoint=MCP2Checkpoint(
            adapter_checkpoint.tree_size,adapter_checkpoint.timestamp,
            adapter_checkpoint.root_hash,tuple(corrupted),
            adapter_checkpoint.subtrees)
        corrupt_data=encode_mtb2(MTB2Bundle(
            adapter_authority,corrupt_checkpoint,1))
        assert decode_mtb2(corrupt_data).checkpoint.signatures==tuple(corrupted)
        accept("reject-trust-config",write(
            directory,"adapter-corrupt-signature.mtb2",corrupt_data))

        replacement_key=directory/"adapter-replacement.key"
        prepare.keygen(replacement_key,"ecdsa-p256")
        replacement_public=prepare.command(
            "pkey","-in",replacement_key,"-pubout","-outform","DER")
        mismatched_authority=prepare.authority_value_v2(
            profile["ca_id"],profile["cosigner_ids"],
            [replacement_public,public[1]],1)
        mismatch_data=encode_mtb2(MTB2Bundle(
            mismatched_authority,adapter_checkpoint,1))
        assert decode_mtb2(mismatch_data).authority==mismatched_authority
        accept("reject-trust-config",write(
            directory,"adapter-key-mismatch.mtb2",mismatch_data))
        adapter=encode_mtb2(MTB2Bundle(
            adapter_authority,adapter_checkpoint,1))
        adapter_authority_length=int.from_bytes(adapter[4:8],"big")
        adapter_checkpoint_length_at=8+adapter_authority_length
        adapter_checkpoint_at=adapter_checkpoint_length_at+4
        for label,data in (
                ("authority",adapter[:8]+b"BAD2"+adapter[12:]),
                ("checkpoint",adapter[:adapter_checkpoint_at]+b"BAD2"
                 +adapter[adapter_checkpoint_at+4:]),
                ("landmark-zero",adapter[:-6]+b"\0"*6),
                ("kind",adapter[:-7]+b"\x02")):
            path=write(directory,f"adapter-reject-{label}.mtb2",data)
            accept("reject-trust-config",path)

        # File type is determined exclusively by magic and grammar.
        authority_path=write(directory,"wrong-type-authority.mca2",normal)
        checkpoint_path=write(directory,"wrong-type-checkpoint.mcp2",normal_cp)
        bundle_path=write(directory,"wrong-type-bundle.mtb2",bundle)
        accept("reject-checkpoint",authority_path)
        accept("reject-authority",checkpoint_path)
        accept("reject-checkpoint",bundle_path)

        # The same malformed checkpoint is rejected by both implementations.
        try:decode_mcp2(bytes(wrong_root))
        except ValueError:pass
        else:raise AssertionError("Python accepted native-rejected MCP2")
    print("Native MCA2/MCP2/MTB2 cross-language tests PASS")


if __name__=="__main__":main()
