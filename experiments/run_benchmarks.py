#!/usr/bin/env python3
"""Run fresh JVMs sequentially. Build tools/pom.xml first; no external services."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java', default='java')
    parser.add_argument('--forks', type=int, default=5)
    parser.add_argument('--warmup', type=int, default=500)
    parser.add_argument('--samples', type=int, default=1000)
    parser.add_argument('--functional-repetitions', type=int, default=100)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    jar = root / 'tools/target/phap-tools.jar'
    assert jar.is_file(), 'Build tools/pom.xml before running'
    assert not args.output.exists(), 'Use a new output directory; never overwrite raw runs'
    args.output.mkdir(parents=True)
    command = [args.java, '-Xms512m', '-Xmx512m', '-XX:+UseG1GC', '-cp', str(jar),
               'com.example.phap.experiments.BenchmarkMainKt']
    manifest = {'driverArguments': vars(args).copy(), 'commands': [],
                'jarSha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
                'sourceSha256': {}}
    manifest['driverArguments']['output'] = str(args.output)
    sources = sorted(list((root/'app/src/main/java/com/example/v2v0614/protocol').glob('*.kt'))
                     + list((root/'tools/src').rglob('*.kt'))
                     + list((root/'experiments').glob('*.py')) + [root/'tools/pom.xml'])
    for source in sources:
        manifest['sourceSha256'][str(source.relative_to(root))] = hashlib.sha256(source.read_bytes()).hexdigest()
    try:
        for fork in range(1, args.forks+1):
            target = args.output / f'fork-{fork}'
            cmd = command + ['benchmark', str(target), str(fork), str(args.warmup), str(args.samples)]
            print(f'Running fork {fork}/{args.forks}', flush=True)
            start = time.monotonic()
            with (args.output/f'fork-{fork}.log').open('w') as log:
                result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=root)
            manifest['commands'].append({'command': cmd, 'returncode': result.returncode,
                                         'wallSeconds': time.monotonic()-start})
            if result.returncode:
                raise RuntimeError(f'Fork {fork} failed; preserve its log and partial data')
        # Deliberate fault/clock inputs run after all timed forks, never alongside them.
        cmd = command + ['functional', str(args.output/'functional'), str(args.functional_repetitions)]
        with (args.output/'functional.log').open('w') as log:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=root)
        manifest['commands'].append({'command': cmd, 'returncode': result.returncode})
        if result.returncode:
            raise RuntimeError('Functional experiment failed; all rows retained')
    finally:
        (args.output/'run_manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('All measured forks and controlled functional trials completed.', flush=True)


if __name__ == '__main__':
    main()
