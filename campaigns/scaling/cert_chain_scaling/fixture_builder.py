#!/usr/bin/env python3
"""Build one immutable X.509 chain. Intended to run inside the lab image."""
import argparse, hashlib, json, os, re, subprocess
from pathlib import Path
from config import PROFILES

OPENSSL = "/opt/openssl/bin/openssl"
def run(*args):
    return subprocess.run([OPENSSL, *map(str, args)], check=True, capture_output=True, text=True).stdout
def run_bytes(*args,input=None):
    return subprocess.run([OPENSSL,*map(str,args)],input=input,check=True,capture_output=True).stdout
def hash_file(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def key(profile, output):
    args = ["genpkey", "-algorithm", profile["algorithm"]]
    if profile.get("curve"): args += ["-pkeyopt", "ec_paramgen_curve:" + profile["curve"]]
    run(*args, "-out", output)
def sign_args(profile): return (["-" + profile["digest"]] if profile.get("digest") else [])
def main():
    p=argparse.ArgumentParser(); p.add_argument("--output",type=Path,required=True);p.add_argument("--profile",choices=PROFILES,required=True);p.add_argument("--depth",type=int,choices=range(2,6),required=True);p.add_argument("--days",type=int,default=30);a=p.parse_args()
    if a.output.exists():p.error("Output exists; fixture directories are immutable")
    if a.days<1:p.error("--days must be positive")
    os.umask(0o077);a.output.mkdir(parents=True);profile=PROFILES[a.profile];serial=1
    root_key=a.output/"root.key";root=a.output/"root.pem";key(profile,root_key)
    run("req","-new","-x509","-key",root_key,"-out",root,"-days",a.days,"-set_serial",serial,"-subj",f"/CN=Certificate Scaling {a.profile} Root", "-addext","basicConstraints=critical,CA:TRUE,pathlen:"+str(a.depth-2),"-addext","keyUsage=critical,keyCertSign,cRLSign",*sign_args(profile))
    issuer_cert,issuer_key=root,root_key;intermediates=[]
    for index in range(1,a.depth-1):
        serial+=1;k=a.output/f"intermediate-{index}.key";csr=a.output/f"intermediate-{index}.csr";cert=a.output/f"intermediate-{index}.pem";ext=a.output/f"intermediate-{index}.cnf";key(profile,k)
        run("req","-new","-key",k,"-out",csr,"-subj",f"/CN=Certificate Scaling {a.profile} Intermediate {index}",*sign_args(profile))
        ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:"+str(a.depth-index-2)+"\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
        run("x509","-req","-in",csr,"-CA",issuer_cert,"-CAkey",issuer_key,"-set_serial",serial,"-days",a.days,"-extfile",ext,"-out",cert,*sign_args(profile));intermediates.append(cert);issuer_cert,issuer_key=cert,k
    serial+=1;server_key=a.output/"server.key";csr=a.output/"server.csr";server=a.output/"server.pem";ext=a.output/"server.cnf";key(profile,server_key)
    run("req","-new","-key",server_key,"-out",csr,"-subj","/CN=server",*sign_args(profile));ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run("x509","-req","-in",csr,"-CA",issuer_cert,"-CAkey",issuer_key,"-set_serial",serial,"-days",a.days,"-extfile",ext,"-out",server,*sign_args(profile))
    chain=[server]+list(reversed(intermediates));(a.output/"server-chain.pem").write_bytes(b"".join(x.read_bytes() for x in chain))
    named_certs=[("root",root),*( (f"intermediate-{i+1}",x) for i,x in enumerate(intermediates)),("server",server)]
    for name,path in named_certs:run("x509","-in",path,"-outform","DER","-out",a.output/(name+".der"))
    named_keys=[("root",root_key),*( (f"intermediate-{i+1}",a.output/f"intermediate-{i+1}.key") for i in range(len(intermediates))),("server",server_key)]
    for name,path in named_keys:
        run("pkey","-in",path,"-outform","DER","-out",a.output/(name+"-private.der"))
        run("pkey","-in",path,"-pubout","-outform","DER","-out",a.output/(name+"-spki.der"))
    untrusted=a.output/"intermediates.pem";untrusted.write_bytes(b"".join(x.read_bytes() for x in reversed(intermediates)))
    args=["verify","-CAfile",root,"-verify_hostname","server"];args += (["-untrusted",untrusted] if intermediates else []);run(*args,server)
    for csr_file in a.output.glob("*.csr"):csr_file.unlink()
    for cnf_file in a.output.glob("*.cnf"):cnf_file.unlink()
    certificate_checks={}
    for name,path in named_certs:
        text=run("x509","-in",path,"-noout","-text")
        algorithms=re.findall(r"Signature Algorithm:\s*([^\n]+)",text)
        cert_spki=run_bytes("pkey","-pubin","-outform","DER",input=run_bytes("x509","-in",path,"-pubkey","-noout"))
        certificate_checks[name]={"signature_algorithms":algorithms,"spki_sha256":hashlib.sha256(cert_spki).hexdigest(),"key_matches_certificate":cert_spki==(a.output/f"{name}-spki.der").read_bytes()}
    files={x.name:hash_file(x) for x in sorted(a.output.iterdir()) if x.is_file()}
    meta={"schema":2,"image_id":os.environ.get("FIXTURE_IMAGE_ID"),"source_commit":os.environ.get("FIXTURE_SOURCE_COMMIT"),"generator_sha256":hash_file(Path(__file__)),"config_sha256":hash_file(Path(__file__).with_name("config.py")),"profile":a.profile,"security_level":profile["level"],"family":profile["family"],"requested_algorithm":profile["algorithm"],"curve":profile.get("curve"),"digest":profile.get("digest"),"depth_including_root":a.depth,"transmitted_certificates":len(chain),"root_transmitted":False,"validity_days":a.days,"openssl":run("version","-a"),"certificate_checks":certificate_checks,"files_sha256":files}
    (a.output/"manifest.json").write_text(json.dumps(meta,indent=2)+"\n")
if __name__=="__main__":main()
