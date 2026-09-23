"""Inspect serialized fixtures, independently of TLS timings."""
import csv,hashlib,json,math,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'src/mtc'))
from core import certificate_parts,from_pem,items,content,root as mtc_root,cover,evaluate
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(path,rows):
 with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def main(result):
 location=json.loads((result/'fixture-location.json').read_text());base=Path(location['host']);rows=[];summaries=[]
 for n in [1,4,16,64,256,1024]:
  for family in ['classic','pq']:
   c=base/f'batch{n}'/'compact'/family;m=base/f'batch{n}'/'mtc'/family
   cm=json.loads((c/'manifest.json').read_text());mm=json.loads((m/'manifest.json').read_text());proof=(c/'proof-0000.bin').read_bytes();cred=(c/'credential-0000.bin').read_bytes();signed=(c/'root.signed').read_bytes()
   assert proof[:4]==b'MTP1' and int.from_bytes(proof[4:8],'big')==n and int.from_bytes(proof[8:12],'big')==0
   siblings=proof[44];assert len(proof)==45+32*siblings and siblings==(n-1).bit_length()
   assert signed[:4]==b'MTR2' and int.from_bytes(signed[4:8],'big')==n and signed[8:40]==proof[12:44]
   entries=[(m/'log'/f'{i:06d}.entry').read_bytes() for i in range(n)];assert len(set(entries))==n
   assert mtc_root(entries).hex()==mm['checkpoint']['hash'];assert mm['subtrees']==[list(x) for x in cover(0,n)]
   server=Path('artifacts/certs')/family/'server.pem';server_der=from_pem(server.read_bytes());server_t=certificate_parts(server_der)[1]
   row={'tree_size':n,'crypto_family':family,'tree_height':siblings,'theoretical_ceil_log2_n':(n-1).bit_length(),'theoretical_full_path_bytes':32*((n-1).bit_length()),'n1_corner_case':int(n==1),'spki_bytes':len(server_t[6][2]),'compact_fixed_fields_bytes':len(cred)-int.from_bytes(cred[4:6],'big')-16,'compact_identity_bytes':int.from_bytes(cred[4:6],'big'),'compact_validity_bytes':16,'compact_credential_bytes':len(cred),'compact_proof_bytes':len(proof),'compact_sibling_hashes':siblings,'compact_inclusion_hash_bytes':32*siblings,'compact_signed_root_bytes':len(signed),'compact_root_signature_bytes':len(signed)-90,'compact_bundle_bytes':(c/'bundle-0000.bin').stat().st_size,'compact_warm_credential_with_spki_bytes':len(server_t[6][2])+(c/'bundle-0000.bin').stat().st_size,'compact_cold_bundle_plus_root_bytes':(c/'bundle-0000.bin').stat().st_size+len(signed),'mtc_log_entry_bytes':len(entries[0]),'mtc_authority_bytes':(m/'authority.bin').stat().st_size,'mtc_predistributed_landmark_bytes':(m/'trust.bin').stat().st_size}
   for mode in ['standalone','landmark']:
    cert=(m/f'{mode}-0000.der').read_bytes();outer,tbs=certificate_parts(cert);p=outer[2][1][1:];offset=2+int.from_bytes(p[:2],'big');start=int.from_bytes(p[offset:offset+6],'big');end=int.from_bytes(p[offset+6:offset+12],'big');offset+=12;path_size=int.from_bytes(p[offset:offset+2],'big');offset+=2;path=p[offset:offset+path_size];offset+=path_size
    assert path_size%32==0 and evaluate(entries[0],0,start,end,[path[i:i+32] for i in range(0,len(path),32)])==mtc_root(entries[start:end])
    assert tbs[4][2]==server_t[4][2] and tbs[5][2]==server_t[5][2] and tbs[6][2]==server_t[6][2]
    row.update({f'mtc_{mode}_certificate_der_bytes':len(cert),f'mtc_{mode}_tbs_bytes':len(outer[0][2]),f'mtc_{mode}_proof_bytes':len(p),f'mtc_{mode}_inclusion_bytes':path_size,f'mtc_{mode}_sibling_hashes':path_size//32,f'mtc_{mode}_signature_vector_bytes':len(p)-offset,f'mtc_{mode}_subtree_signature_bytes':mm['sizes'][mode]['mtc_signature_bytes'],f'mtc_{mode}_cosignature_bytes':mm['sizes'][mode]['mtc_cosignature_bytes']})
   trust=(m/'trust.bin').read_bytes();pos=row['mtc_authority_bytes']+4;sigpos=pos+46;row['mtc_checkpoint_bytes']=48+int.from_bytes(trust[sigpos:sigpos+2],'big');row['mtc_landmark_incremental_bytes']=len(trust)-row['mtc_authority_bytes']
   rows.append(row);summaries.append({'tree_size':n,'tree_height':siblings,'crypto_family':family,'number_of_log_entries':n,'server_leaf_index':0,'compact_root':proof[12:44].hex(),'compact_signed_root_sha256':sha(c/'root.signed'),'mtc_checkpoint_hash':mm['checkpoint']['hash'],'mtc_trust_sha256':sha(m/'trust.bin'),'compact_ca_spki_sha256':cm['authority_spki_sha256'],'mtc_ca_spki_sha256':mm['ca_spki_sha256'],'cosigner_spki_sha256':mm['cosigner_spki_sha256'],'server_key_sha256':sha(Path('artifacts/certs')/family/'server.key'),'server_certificate_sha256':sha(server),'mtc_subtrees':json.dumps(mm['subtrees']),'fixture_directory':str(c.parent.parent)})
 write(result/'structural-sizes.csv',rows);write(result/'fixtures-summary.csv',summaries)
 inventory={str(p):sha(p) for p in base.rglob('*') if p.is_file()};(result/'scaling-fixture-sha256.json').write_text(json.dumps(inventory,indent=2))
 # Protect completed new fixture objects against accidental edits; later Docker mounts are read-only too.
 for p in base.rglob('*'):
  if p.is_file():p.chmod(0o400)
 print('Serialized fixtures validated:',len(rows),'family/size combinations;',len(inventory),'files')
if __name__=='__main__':main(Path(sys.argv[1]))
