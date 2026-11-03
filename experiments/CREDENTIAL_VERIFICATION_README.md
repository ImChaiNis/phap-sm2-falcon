# Separate credential-body signature verification benchmark

This supplemental track measures production `CryptoProvider` SM2/Falcon verification calls over real canonical credential bodies, independently of the original fourteen-phase benchmark. It does not change `BenchmarkMain`, the original aggregation script, comparison profiles, or production protocol.

Build once before any timing, from the project root:

```sh
mvn -B -ntp -f tools/pom.xml package
```

Run five fresh JVMs **sequentially**, using a new output root each time. Do not run compilation or other CPU-intensive work concurrently:

```sh
mkdir experiments/results/credential-new-run
for fork in 1 2 3 4 5; do
  java -Xms512m -Xmx512m -XX:+UseG1GC -cp tools/target/phap-tools.jar \
    com.example.phap.experiments.CredentialVerificationBenchmark \
    "experiments/results/credential-new-run/fork-$fork" "$fork" 500 1000 || break
done
```

The CLI is `OUTPUT FORK [WARMUP SAMPLES]`; defaults are 500 warmup and 1000 measured calls per phase. Each output fork directory must not exist. The four phases are:

| Phase | Body |
| --- | --- |
| `credential/SM2-verify/D128` | Actual suite-2 PHAP body, 128 bytes |
| `credential/Falcon-verify/D128` | Same 128-byte body |
| `credential/SM2-verify/D1025` | Actual suite-3 Falcon-message body, 1025 bytes |
| `credential/Falcon-verify/D1025` | Same 1025-byte body |

Each fresh JVM generates one authority/endpoint key set. Before timing, it generates and verifies a pool of 32 genuine signatures for each phase over its exact body. The per-phase loop cycles through this pool. Cryptographic randomness uses real `SecureRandom`; only phase ordering uses a recorded deterministic seed. Pool generation and initial correctness checks are outside all timers. Every measured call's returned Boolean is retained. Failed measured calls remain in CSV; the fork completes its phases and then exits nonzero. Warmup failure stops the fork. All outliers remain.

`timings.csv` records `fork,phase,iteration,body_bytes,signature_index,elapsed_ns,ok,detail`. `metadata.json` records runtime/OS, actual JVM flags, warmup/sample counts, order, empirical clock-call probe, fixture hashes, phase GC/JIT counters, failure/completion flags, and timing scope. `public-fixtures/` contains the exact bodies, all 128 signatures, authority public keys, and the SM2 authority signer identity; it contains **no private key material**. Signature index matches `signature-00.bin` through `signature-31.bin` in each phase's directory.

Five successful forks yield 5000 measured calls per phase and 20,000 rows overall. This CSV schema is separate from `experiments/summarize.py`; use a separate aggregator, retaining every row. Report pooled median/p95, and calculate mean uncertainty over the five JVM fork means rather than treating all calls as independent devices.

These are single-host provider API verification costs. A call includes key decoding, signer initialization, hashing, SM2 identity processing or Falcon padded-format validation. It excludes credential parsing, credential digest calculation, policy/replay checks, transfer/reconstruction, chain operations, and setup. It is not full certificate acceptance time, a separately controlled arithmetic benchmark, or a representative renewable-energy terminal result. The 128-byte credential body is distinct from the 223-byte signed application input in the original provider benchmark. The 1025-byte body additionally carries the endpoint Falcon key, and retains the SM2 endpoint key and both authority signature types.
