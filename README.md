# PHAP: SM2–Falcon protocol simulation and reproducible experiments

This repository contains the revised partially hybrid authentication implementation, its Android integration source, and the source and complete results of **desktop protocol-simulation experiments using real cryptographic operations**. In the partial profile an independent authority signs a credential body with SM2 and Falcon-512; endpoints sign application messages with SM2. Falcon protects the credential body under the stated assumptions. It does not protect those application messages after recovery of an endpoint SM2 key.

The simulation models the sender, credential acquisition/cache, and receiver in software. It executes genuine SM2/SM3 and Falcon signing/verification through Bouncy Castle, rather than replacing cryptography with simulated delays. Transfer comparisons use established TCP loopback connections between two threads in one JVM. Recorded milliseconds are measured execution times on the named host, not estimates for a renewable-energy terminal, radio link, or an MMS deployment.

## Build and rerun

The Maven project pins Kotlin 1.9.22, Bouncy Castle 1.86, Gson 2.13.2 and JUnit 4.13.2. A JDK and Maven are needed; Android SDK is not needed for the protocol/experiment build.

```sh
mvn -B -ntp -f tools/pom.xml package
python3 experiments/run_benchmarks.py --output experiments/results/new-run
python3 experiments/summarize.py experiments/results/new-run
```

For the plot, install the pinned optional plotting package and pass `--plot`:

```sh
python3 -m pip install -r experiments/plot-requirements.txt
python3 experiments/summarize.py experiments/results/new-run --plot
```

Run sequentially without other builds/benchmarks. A new output directory is required. The driver runs five fresh JVMs, 500 warm-up and 1000 measured iterations in each of fourteen phases per fork, then the separate controlled functional trials. Command-line options are documented in [experiments/README.md](experiments/README.md). The prebuilt execution artifact is [dist/phap-tools.jar](dist/phap-tools.jar); its SHA-256 is recorded in the result manifest. Android build/provisioning instructions are in [docs/ANDROID_USAGE.md](docs/ANDROID_USAGE.md).

## Recorded run: 2 November 2026

Host: Apple M3 MacBook Air, four performance plus four efficiency cores, 16 GiB RAM, macOS 26.6.2, Oracle Java 23 (`23+37-2369`), 512 MiB heap and G1 GC. Host/runtime details and uncontrolled affinity/frequency/power/thermal settings are recorded with the data. Ubuntu was not the execution OS of this dataset.

All 36 Maven tests passed. All 70,000 recorded timing observations passed their authentication/correctness check. All 1500 controlled functional trials (15 conditions × 100 trials) matched their declared expectations. These counts describe the controlled experiment, not field reliability or a cryptographic security proof.

For a 128-byte application payload, the comparison TCP adapter produced the following median payload-ready to authenticated-delivery times. Cold means the receiver credential cache is empty; the JVM, connection and endpoint objects already exist.

| Configuration | Credential bytes | Fragments at 256-byte budget | Cold median (ms) | Warm median (ms) |
|---|---:|---:|---:|---:|
| SM2-only | 200 | 1 | 2.826 | 1.786 |
| PHAP, SM2 messages | 866 | 4 | 2.865 | 1.761 |
| Falcon messages | 1763 | 7 | 1.454 | 0.332 |
| SM2 + Falcon messages | 1763 | 7 | 3.215 | 2.079 |

Falcon-message signing was faster on this provider/host combination. These results do not establish a latency advantage for partial migration. PHAP uses smaller message/credential encodings. Both alternatives retain the SM2 endpoint key and dual authority signatures in the common credential format; “Falcon messages” does not mean a wholly Falcon-only PKI.

Only production PHAP suite 2 is accepted by the Android protocol parser. The three other configurations are isolated experiment helpers. Production-core measurements use the actual bounded `Sender`, `Receiver`, and `WireCodec`; their receiver path differs from the four-profile transport adapter, so subtracting the two tracks does not isolate network cost.

## Data, boundaries, and provenance

- [summary.csv](experiments/results/run-20261102/summary.csv) and [summary.json](experiments/results/run-20261102/summary.json) contain pooled medians/p95s and mean intervals using five fork means, not 5000 independent replications.
- Each `fork-N/` contains every raw timing row, actual JVM/GC/JIT metadata, encoded size records, and real signed public fixture dumps.
- [functional_trials.csv](experiments/results/run-20261102/functional/functional_trials.csv) retains every initiated trial, deliberate fault positions, offered fragments, receiver outcomes, and separate initial/control deliveries.
- [PUBLICATION_MANIFEST.json](PUBLICATION_MANIFEST.json) records file hashes, input archive identity, and transformations for this public distribution. Measurement CSV and binary fixture/JAR bytes are unchanged from the execution archive. Local project paths in ancillary logs/manifests are replaced with portable labels. The original archive result hash list is retained under `docs/` and the public result hash list validates this derivative.

Provider timers include actual API initialization/decoding/hashing costs. Delivery timing starts before message signing and stops after receiver authentication/replay update, before the return acknowledgment. It excludes key generation, authority issuance, provisioning, initial TCP setup and sender-side pre-serialization of credential fragments. The two threads use a common `System.nanoTime()` origin. Every observation is retained, including outliers and failures.

The experiment uses volatile sequence/replay stores. It does not measure Android SharedPreferences commit or AndroidKeyStore cost, JSON/Base64/OkHttp relay overhead, real MMS/TLS, constrained-terminal performance, energy, peak memory, or actual link loss. Controlled missing fragments and clock advances are deliberate test inputs, not observed network impairments. Historical phone plots are not reproduced or used to support these results.

## Licensing and key material

No license grant for the authors' original project code or data is inferred by this distribution; an author-selected license has not been supplied. Third-party components retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No operational or generated experiment private signing keys are exported. Source known-answer tests deliberately contain public standard test vectors and test signer IDs.
