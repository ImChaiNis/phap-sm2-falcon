#!/usr/bin/env python3
"""Five sequential fresh JVMs, real CA-signature verification; build tools/pom.xml first."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--java',default='java')
    a=p.parse_args(); root=Path(__file__).resolve().parents[1]
    jar=root/'tools/target/phap-tools.jar'
    assert jar.is_file(), 'Build tools/pom.xml first'
    assert not a.output.exists(), 'Never overwrite a raw run'
    a.output.mkdir(parents=True)
    manifest={'design':{'forks':5,'phases':4,'warmupPerPhase':500,'measuredPerPhase':1000,'signaturePool':32},'jarSha256':hashlib.sha256(jar.read_bytes()).hexdigest(),'commands':[],'sourceSha256':{}}
    sources=list((root/'tools/src').rglob('*.kt'))+list((root/'app/src/main/java/com/example/v2v0614/protocol').glob('*.kt'))+list((root/'experiments').glob('*.py'))+[root/'tools/pom.xml']
    for source in sorted(sources): manifest['sourceSha256'][str(source.relative_to(root))]=hashlib.sha256(source.read_bytes()).hexdigest()
    try:
        for fork in range(1,6):
            cmd=[a.java,'-Xms512m','-Xmx512m','-XX:+UseG1GC','-cp',str(jar),'com.example.phap.experiments.CredentialVerificationBenchmark',str(a.output/f'fork-{fork}'),str(fork),'500','1000']
            print(f'Running credential-verification fork {fork}/5',flush=True)
            start=time.monotonic()
            with (a.output/f'fork-{fork}.log').open('w') as log: result=subprocess.run(cmd,cwd=root,stdout=log,stderr=subprocess.STDOUT)
            manifest['commands'].append({'command':cmd,'returncode':result.returncode,'wallSeconds':time.monotonic()-start})
            if result.returncode: raise RuntimeError(f'Fork {fork} failed; partial records retained')
    finally:
        (a.output/'run_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('All credential-verification forks completed.',flush=True)
if __name__=='__main__': main()
