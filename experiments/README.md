# Desktop protocol-simulation experiments

This directory contains the experiment driver and aggregation script for the revised implementation. These are desktop protocol-simulation experiments executing real cryptographic operations; simulation does not mean replacing the cryptography with synthetic delays. The measurements concern a desktop JVM and a TCP loopback test adapter. They do not establish performance on an Android phone or a renewable-energy terminal, and they do not reproduce the historical phone plots.

## Build and reproduce

Run these commands from the project root with Maven, Python 3, and Java available. The Maven project pins Kotlin 1.9.22, Bouncy Castle 1.86, Gson 2.13.2, and JUnit 4.13.2. Building also runs the protocol, provisioning, and experiment tests included by `tools/pom.xml`.

```sh
mvn -B -ntp -f tools/pom.xml package
python3 experiments/run_benchmarks.py --output experiments/results/new-run
python3 experiments/summarize.py experiments/results/new-run
```

Use a new output directory for every run. The driver refuses to overwrite an existing directory. It launches five fresh JVMs **sequentially**, each with `-Xms512m -Xmx512m -XX:+UseG1GC`, then runs the functional trials after all timed JVMs have exited. `--java /absolute/path/to/java` selects a specific executable; the actual runtime properties are recorded inside every fork. Do not run builds or other CPU-intensive tests alongside the timed forks.

To create the optional scientific plot, use a Python environment with matplotlib:

```sh
python3 experiments/summarize.py experiments/results/new-run --plot
```

The driver exposes `--forks`, `--warmup`, `--samples`, and `--functional-repetitions` for diagnostic runs. The publication aggregation script validates five forks and 1000 measured iterations per phase, rejecting missing or extra measured rows. The intended design also requires 500 warm-up iterations per phase, recorded in each fork metadata file. Its output should not be used unchanged for a different sampling design. The aggregator validates measured row counts; warm-up counts must also be checked in each fork's `metadata.json`.

For functional checks alone, without a timing run:

```sh
java -Xms512m -Xmx512m -XX:+UseG1GC -cp tools/target/phap-tools.jar \
  com.example.phap.experiments.BenchmarkMainKt functional experiments/results/functional-only 100
```

## Three measurement tracks

Every timed JVM executes fourteen phases. Each phase performs 500 unrecorded warm-up iterations immediately before its 1000 recorded iterations. The default complete timing design therefore generates 70,000 measured rows, subject to successful execution; this is a design count, not a statement that a particular run completed.

| Track | Phases per fork | What is executed |
| --- | ---: | --- |
| Provider calls | 4 | SM2 signing, SM2 verification, Falcon signing, Falcon verification through the production `CryptoProvider` |
| TCP loopback comparison | 8 | Four experimental configurations, each with a cold and warm credential cache |
| Production PHAP core | 2 | The actual `Sender`, `Receiver`, and `WireCodec`, with a cold and warm cache, without a transport |

The production PHAP parser continues to accept only its specified version and suite. `ComparisonProfiles.kt` supplies a separate experiment-only implementation for SM2-only, PHAP, Falcon-message, and dual-message configurations. The Falcon-message configuration retains the SM2 endpoint key and both authority signatures in its credential, but uses Falcon alone for application-message signatures. The dual-message configuration requires both endpoint signatures over the same signed input. These comparison configurations are not newly supported Android protocol profiles and do not extend the PHAP security proof.

Within a fork all four configurations share the same generated authority and endpoint key material and the same 128-byte deterministic application payload. Key material is regenerated in every fresh JVM. Real `SecureRandom` supplies cryptographic randomness; the experiment-order seed does not seed keys or signatures. Credential issuance, key generation, and preparation of the serialized credential-fragment records occur outside the trial timers. The phase order is shuffled independently for each fork with seed `20261029 + fork`, which is recorded with the resulting order. This randomizes order across forks; it does not eliminate JIT, GC, host load, or thermal effects.

### Provider calls

Provider phases use a pool of 32 actual 223-byte PHAP signed inputs, corresponding to a 128-byte application payload. Verification signatures are prepared outside the verification timers. Signing observations end before an additional correctness verification; that verification is outside the signing timer. The provider calls include the implementation's key decoding, signer initialization, SM2 identity processing, hashing, and Falcon padded-format conversion as applicable. They are API-call costs, not isolated arithmetic-operation costs. Only valid-input provider timings are measured; rejection behavior is exercised separately by functional trials.

### Production PHAP core

The core timer begins before `Sender.createMessage` and ends after the receiver's delivery result. It includes endpoint SM2 signing, canonical message encoding and decoding, receiver checks, and volatile sequence/replay-state operations. In cold trials, the application message arrives first and is buffered; the timer also includes decoding and processing all four credential fragments, reconstruction, credential verification, and delivery of the buffered message. Credential-cache and incomplete-context clearing take place before the timer. The replay store remains in place and sequence numbers continue increasing.

Warm trials preload the verified credential before the phase's trials. Their timer includes the message path and current cache-policy checks but excludes credential transfer and initial authority verification. The core track has no socket, Android UI, or network relay.

### TCP loopback comparison

Each comparison phase uses one established TCP connection to `127.0.0.1` and a receiving thread in the same JVM. TCP_NODELAY is enabled. The receiver sends a ready signal before every trial, outside the timer. For cold trials the receiver clears its credential cache before that signal; for warm trials it preloads and verifies the credential before any trial timing. The volatile replay store remains active and every sent message uses a fresh increasing sequence number.

`System.nanoTime()` supplies a common monotonic clock for both threads. The start is immediately before preparing and signing the application message. The receiver stop is taken after the authentication result and before writing the acknowledgment. Thus `elapsed_ns` measures payload readiness to authenticated delivery and excludes acknowledgment traversal. `ack_elapsed_ns` separately records the interval until the sender reads the acknowledgment. Neither field is an inter-device one-way measurement, and no clock synchronization between devices is involved.

The binary test adapter sends the application message first, followed by all credential fragments for cold trials. It sends a single message for warm trials. A four-byte record count and four-byte length prefix per record are additional test framing, reported separately from canonical protocol bytes in `sizes.json`. Credential reconstruction checks index coverage, distinct indices, declared lengths, and digest binding before authority and message verification. There is no deliberate transport impairment, retransmission scheduler, or forwarding stage in this experiment. Only one trial is outstanding at a time; the workload is not a throughput, saturation, or fixed-rate traffic experiment.

Cold observations include endpoint signing, message serialization, socket transfer, reconstruction and hashing, authority verification, message verification, policy checks, and replay update. Warm observations begin with an already verified still-valid credential. Both exclude key generation, authority issuance, provisioning, initial connection establishment, TLS, MMS, radio links, and remote revocation retrieval. Serialized credential fragments are prepared outside the timer, so sender-side credential fragmentation is also excluded. The test uses in-memory sequence and replay stores; it excludes Android SharedPreferences commits, AndroidKeyStore operations, JSON/Base64 framing, OkHttp, and the Python WebSocket relay used by the application.

## Clock, runtime, and statistical records

Each fork records actual JVM/runtime/OS properties, heap arguments, available processors, collectors, start/end timestamps, phase order, and phase-boundary GC counts, GC time, and total JIT compilation time. These counters include the phase's warm-up and measurement work; they do not identify a particular sample as affected by GC. The clock probe collects 10,000 back-to-back `System.nanoTime()` differences and records the minimum positive and median pair differences. This empirical call-pair probe does not establish an absolute nanosecond clock resolution or accuracy.

There is no CPU affinity pinning, frequency lock, power-mode control, or thermal control. Fresh JVM forks are repeated executions on one host, not independent devices or links. Any separately supplied host configuration should describe the machine actually used and avoid equating it with a constrained target terminal.

`summarize.py` retains every measured row, including failed observations and large GC/scheduling delays. It computes pooled medians and 95th percentiles with linear interpolation (type 7). The mean's two-sided 95% Student-t interval uses the five JVM fork means, with four degrees of freedom and critical value 2.776445. It does not treat the 5000 within-phase messages as independent experimental replications. The interval describes between-fork variation on this host and does not quantify variation over terminals or networks. Plot bars are medians and separate diamonds are 95th percentiles, not confidence bounds.

A failed measured observation remains in `timings.csv`; the JVM fails after completing its recorded phases. A warm-up failure stops that fork. The parent driver retains logs and writes its run manifest on exit, including failures. The strict aggregator rejects incomplete runs instead of silently reducing the sample population.

## Controlled functional trials

After timing, `FunctionalTrials.kt` runs 100 trials for each of fifteen conditions by default. Each trial initializes a fresh production receiver and fresh sequence/replay stores. One honest credential/key set is shared within the functional run, with new genuine application signatures per trial. Trial order, fragment permutations, duplicate placement, and altered byte locations use a recorded deterministic seed; cryptographic randomness remains real.

The conditions are ordered cold acquisition, reordered fragments with duplicates, warm-cache delivery, a missing fragment reaching its timeout, duplicate arrival near the original deadline followed by late recovery, corrupted fragment content, conflicting duplicate content, altered SM2 authority signature, altered Falcon authority signature, modified buffered application payload, warm-message replay, credential expiry, revocation after cache population, incorrect destination, and an application message older than the freshness limit.

Authority-signature faults use a recomputed credential digest and a genuinely signed message bound to that digest, so they exercise authority verification rather than only a digest mismatch. The expiry case signs a fresh timestamp after expiry, isolating certificate validity from message freshness. Some cases send a later valid control message to verify recovery or that a rejected message did not consume replay state.

These experiments deliberately advance controlled wall and monotonic clocks. A 5000 ms timeout input is not an observed 5000 ms network delay. Offered fragment records include duplicates and deliberate recovery sends, and are not IP packet counts. An expectation-pass ratio is the number of trials satisfying their declared acceptance, rejection, cache, and timeout assertions divided by all initiated trials in that condition. It is not a field delivery probability, an authentication-success estimate for random networks, or a cryptographic forgery-probability estimate. Initial and later control deliveries have separate counters. The CSV and JSON state the exact denominator definitions and retain failed initiated trials.

## Outputs and provenance

Each `fork-N/` contains `timings.csv`, `metadata.json`, `sizes.json`, and `public-fixtures/` with actual signed credential bodies, credentials, sample messages, fragment records, and authority public keys. No private key material is exported. The public fixture signatures are generated cryptographically, unlike the older supplementary synthetic byte-accounting script. `sizes.json` includes canonical sizes and separate loopback framing sizes.

The parent produces one log per fork, a functional log, and `run_manifest.json` containing the invoked commands, return codes, JAR SHA-256, and SHA-256 values of the protocol/experiment Kotlin sources, Python scripts, and Maven configuration selected by the driver. The manifest is an experiment provenance record, not a cryptographic validation certificate or a complete archive manifest. The functional directory includes per-trial CSV rows, condition summaries, the genuine credential, and public fixture metadata. Aggregation adds `summary.csv`, `summary.json`, and, optionally, `loopback_latency.png`.

The experiment supports a reproducible desktop comparison and checks of the revised protocol code. It leaves representative terminal hardware, memory and energy use, real MMS integration, real link behavior and failure modes, Android persistence costs, deployed credential policy, and operator approval to separate evaluation. Repository publication provides the source and recorded dataset; no DOI is implied.

## Recorded run: 2026-11-02

`results/run-20261102/` contains the completed run. All 70,000 measured timing rows passed their checks, and all 1500 controlled functional trials met their declared expectations. The Maven suite passed 36 tests (zero failures/errors/skips). PHAP loopback cold/warm medians were 2.864542/1.761167 ms; Falcon-message medians were 1.453625/0.332375 ms. See `summary.csv`, `summary.json`, `host.json`, and the complete raw per-fork files for distributions, uncertainty, and scope. These results do not establish a latency advantage for partial migration on this host.
