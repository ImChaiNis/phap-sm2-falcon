#!/usr/bin/env python3
"""Strictly validate four CA-verification phases in five 500/1000 JVM forks; no sample exclusions."""
import argparse,csv,hashlib,json
from pathlib import Path
from summarize import summarize_phase,FORKS,demand
PHASES=tuple(f'credential/{alg}-verify/D{size}' for size in (128,1025) for alg in ('SM2','Falcon'))
FIELDS=('fork','phase','iteration','body_bytes','signature_index','elapsed_ns','ok','detail')

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('root',type=Path); root=p.parse_args().root
    by_phase={phase:{} for phase in PHASES}; failed=[]
    for fork in FORKS:
        directory=root/f'fork-{fork}'; meta=json.loads((directory/'metadata.json').read_text())
        demand(meta['fork']==fork and meta['warmupPerPhase']==500 and meta['measuredPerPhase']==1000,'Wrong repetition design')
        demand(meta['signaturePoolSize']==32 and meta['completedAllPhases'],'Incomplete fork')
        demand(set(meta['phaseOrder'])==set(PHASES),'Unexpected phase order')
        for item in meta['fixtures']:
            path=directory/item['relativeDirectory']; body=(path/'body.bin').read_bytes()
            demand(len(body)==item['bodyBytes'] and hashlib.sha256(body).hexdigest()==item['bodySha256'],'Body mismatch')
            demand(item['fixtureSuite']==(2 if len(body)==128 else 3),'Unexpected representative suite')
            size=64 if 'SM2' in item['phase'] else 666
            demand(item['signatureBytes']==[size] and len(item['signatureSha256'])==32,'Wrong signature sizes/count')
            for index,sha in enumerate(item['signatureSha256']):
                signature=(path/f'signature-{index:02d}.bin').read_bytes()
                demand(len(signature)==size and hashlib.sha256(signature).hexdigest()==sha,'Signature binary mismatch')
        public=directory/'public-fixtures'
        demand((public/'ca-sm2-public.bin').stat().st_size==65,'SM2 public-key size')
        demand((public/'ca-falcon-public.bin').stat().st_size==897,'Falcon public-key size')
        groups={phase:[] for phase in PHASES}
        with (directory/'timings.csv').open(newline='') as f:
            reader=csv.DictReader(f); demand(tuple(reader.fieldnames)==FIELDS,'CSV schema')
            for row in reader:
                demand(row['phase'] in groups and int(row['fork'])==fork and row['ok'] in ('true','false'),'CSV fields')
                size=int(row['phase'].rsplit('D',1)[1]); index=int(row['signature_index']); iteration=int(row['iteration']); elapsed=int(row['elapsed_ns'])
                demand(int(row['body_bytes'])==size and index==iteration%32 and elapsed>=0,'Timing row mismatch')
                parsed={'fork':fork,'phase':row['phase'],'iteration':iteration,'elapsed_ns':elapsed,'ack_elapsed_ns':0,'ok':row['ok']=='true','detail':row['detail']}
                groups[row['phase']].append(parsed)
                if not parsed['ok']: failed.append(parsed)
        for phase,rows in groups.items():
            demand(len(rows)==1000 and sorted(r['iteration'] for r in rows)==list(range(1000)),'Missing/extra observations')
            by_phase[phase][fork]=rows
        demand(sum(not r['ok'] for rows in groups.values() for r in rows)==meta['failedMeasuredRows'],'Failure count mismatch')
    phases={phase:summarize_phase(by_phase[phase]) for phase in PHASES}
    result={'classification':'Desktop real-cryptography CA verification; no representative-terminal timing claim','validation':{'forks':5,'phases_per_fork':4,'warmup_per_phase':500,'samples_per_phase':1000,'total_measured_rows':20000,'failed_rows':len(failed),'all_expected_rows_present':True,'public_binary_hashes_and_sizes_consistent':True},'scope':'One production CryptoProvider verification of the canonical 128B suite2 or 1025B suite3 credential body; excludes key generation/signing/setup and credential parsing/policy/transport/ledger. CA SM2 signer identity is included by the provider.','statistics':'Pooled median/p95 (linear interpolation type7); no row exclusions; 95% Student-t interval over five fork means, df4, t2.776445','phases':phases,'failed_observations':failed}
    (root/'summary.json').write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    columns=['phase','n','successes','failures','mean_ms','mean_ci95_low_ms','mean_ci95_high_ms','median_ms','p95_ms','min_ms','max_ms']
    with (root/'summary.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=columns); writer.writeheader()
        for phase,stats in phases.items(): writer.writerow({'phase':phase,**{key:stats[key] for key in columns[1:]}})
    print(f'Validated 20000 credential-verification observations; {len(failed)} failures; all signed fixture hashes/lengths match.')
if __name__=='__main__': main()
