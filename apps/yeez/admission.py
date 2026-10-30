#!/usr/bin/env python3
"""Actual SDK declarations: redirects accept, raw and unmapped calls reject."""
import hashlib,json,os,resource,subprocess
from pathlib import Path
H=Path(__file__).resolve().parent;R=H.parents[1];B=R/'build/yeez/admission';B.mkdir(parents=True,exist_ok=True)
S=Path(os.environ.get('SGX_SDK',R/'deps/sgxsdk'))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
flags=['-O2','-fno-builtin','-fno-common','-nostdinc',*['-I'+str(p) for p in (H,S/'include',S/'include/tlibc')]]
header='#include <string.h>\n#include <sgx_trts.h>\n#include <sgx_tcrypto.h>\n#include <sgx_dh.h>\n'
cases={
 'read_rand': 'sgx_read_rand(p,n)',
 'encrypt': 'sgx_rijndael128GCM_encrypt(p,p,n,p,p,12,p,n,p)',
 'decrypt': 'sgx_rijndael128GCM_decrypt(p,p,n,p,p,12,p,n,p)',
 'cmac': 'sgx_rijndael128_cmac_msg(p,p,n,p)',
 'sha256': 'sgx_sha256_msg(p,n,p)',
 'memset_s': 'memset_s(p,n,0,n)',
 'dh_init': 'sgx_dh_init_session(SGX_DH_SESSION_INITIATOR,p)',
 'dh_msg1': 'sgx_dh_initiator_proc_msg1(p,p,p)',
 'dh_msg3': 'sgx_dh_initiator_proc_msg3(p,p,p,p)',
}
rows=[]
for name,call in cases.items():
 src=B/(name+'.c');src.write_text(header+'int probe(void*p,unsigned n){return '+call+';}\n')
 for profile in ('RADIX_ONLY','MAC27'):
  for mode in ('raw','redirected','unmapped'):
   key=profile+'-'+name+'-'+mode;obj=B/(key+'.o')
   env={k:v for k,v in os.environ.items() if not k.startswith('ENCBOUND_')}
   env.update(ENCBOUND_PROFILE=profile)
   if mode=='redirected':env['ENCBOUND_ADMITTED']=str(H/'admitted-services.txt')
   extra=[] if mode=='raw' else ['-include',str(H/'services.h')]
   command=[R/'tools/with-integration-defaults.sh',R/'tools/encbound-cc.sh',src,obj,*flags,*extra]
   p=subprocess.run(list(map(str,command)),env=env,capture_output=True,text=True,timeout=60)
   text=p.stdout+p.stderr;(B/(key+'.log')).write_text(text)
   assert (p.returncode==0)==(mode=='redirected'),(key,text[-3000:])
   if mode!='redirected':assert 'unsupported external function reference:' in text,(key,text)
   else:
    symbols=subprocess.check_output(['nm','-u',obj],text=True)
    assert 'encbound_yeez_'+name in symbols,(key,symbols)
   rows.append(dict(profile=profile,service=name,mode=mode,returncode=p.returncode,
       log_sha256=hashlib.sha256((B/(key+'.log')).read_bytes()).hexdigest()))
(B/'results.json').write_text(json.dumps(dict(rows=rows,scope='native compiler admission only'),indent=2)+'\n')
print('YEEZ SDK SERVICE ADMISSION PASS',len(rows))
