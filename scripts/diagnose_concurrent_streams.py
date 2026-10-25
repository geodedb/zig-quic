import json,os,pathlib,subprocess,time,sys
out=pathlib.Path('progress-diagnostics');out.mkdir(exist_ok=True)
print(json.dumps({'cpu_affinity':sorted(os.sched_getaffinity(0)),'cpu_count':os.cpu_count()}),flush=True)
certs=pathlib.Path('tests/certs');certs.mkdir(exist_ok=True)
subprocess.run(['openssl','ecparam','-genkey','-name','prime256v1','-out',str(certs/'key.pem')],check=True)
subprocess.run(['openssl','req','-new','-x509','-key',str(certs/'key.pem'),'-out',str(certs/'cert.pem'),'-days','1','-subj','/CN=localhost/O=Test/C=US','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],check=True)
rows=[]
for name,args in [('full-j2',['-j2']),('full-j1',['-j1']),('isolated-j1',['-j1','-Dtest-filter=high_parallel_stream_progress'])]:
 log=out/(name+'.log');start=time.monotonic();cmd=['zig','build','test',*args,'--summary','all'];print(json.dumps({'phase':name,'event':'start','command':cmd}),flush=True)
 with log.open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
 row={'phase':name,'exit':r.returncode,'seconds':round(time.monotonic()-start,2)};rows.append(row);(out/'results.json').write_text(json.dumps(rows,indent=2));print(json.dumps(row),flush=True)
 for line in log.read_text(errors='replace').splitlines():
  if any(x in line for x in ['high-parallel client','high-parallel stream','expected successes','got      successes','Build Summary:']):print(line,flush=True)
sys.exit(any(x['exit'] for x in rows))
