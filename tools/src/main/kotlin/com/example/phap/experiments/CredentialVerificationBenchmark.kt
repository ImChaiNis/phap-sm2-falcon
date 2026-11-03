package com.example.phap.experiments

import com.example.v2v0614.protocol.CryptoProvider
import com.google.gson.GsonBuilder
import java.io.BufferedWriter
import java.lang.management.ManagementFactory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.time.Instant
import java.util.Collections
import java.util.Random

/**
 * Separate provider-call benchmark for CA signatures over actual credential bodies.
 * This does not alter the original fourteen-phase experiment or production PHAP.
 */
object CredentialVerificationBenchmark {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size in 2..4) { "OUTPUT FORK [WARMUP SAMPLES]" }
        val output = Paths.get(args[0])
        val fork = args[1].toInt()
        val warmup = args.getOrNull(2)?.toInt() ?: 500
        val samples = args.getOrNull(3)?.toInt() ?: 1000
        require(fork > 0 && warmup >= 0 && samples > 0)
        CredentialVerificationRun(output, fork, warmup, samples).run()
    }
}

private data class CredentialVerificationPhase(
    val name: String,
    val suite: Int,
    val algorithm: String,
    val body: ByteArray,
    val signatures: List<ByteArray>
)

private class CredentialVerificationRun(
    private val directory: Path,
    private val fork: Int,
    private val warmup: Int,
    private val samples: Int
) {
    private val crypto = CryptoProvider()
    private val gson = GsonBuilder().setPrettyPrinting().create()
    private val poolSize = 32

    fun run() {
        require(!Files.exists(directory)) { "Refusing to overwrite: $directory" }
        Files.createDirectories(directory)
        val startedUtc = Instant.now().toString()
        // All key generation, signing and fixture writes precede all phase timers.
        val keys = CompareKeyMaterial.generate(crypto)
        val now = System.currentTimeMillis()
        val fixtures = listOf(2, 3).map { ProfileFixture(it, crypto, keys, now) }
        val phases = fixtures.flatMap { fixture ->
            val body = fixture.bodyBytes
            listOf("SM2", "Falcon").map { algorithm ->
                val signatures = (0 until poolSize).map {
                    if (algorithm == "SM2") crypto.sm2Sign(keys.authoritySm2.privateKey, keys.authoritySignerId, body)
                    else crypto.falconSign(keys.authorityFalcon.privateKey, body)
                }
                CredentialVerificationPhase("credential/$algorithm-verify/D${body.size}", fixture.suite, algorithm, body, signatures)
            }
        }.toMutableList()
        fun verify(phase: CredentialVerificationPhase, signature: ByteArray): Boolean =
            if (phase.algorithm == "SM2")
                crypto.sm2Verify(keys.authoritySm2.publicKey, keys.authoritySignerId, phase.body, signature)
            else crypto.falconVerify(keys.authorityFalcon.publicKey, phase.body, signature)
        // Prove every pool entry is valid before using it as a timing observation.
        phases.forEach { phase -> phase.signatures.forEach { check(verify(phase, it)) { "Invalid setup signature: ${phase.name}" } } }
        val public = directory.resolve("public-fixtures")
        Files.createDirectories(public)
        Files.write(public.resolve("ca-sm2-public.bin"), keys.authoritySm2.publicKey)
        Files.write(public.resolve("ca-falcon-public.bin"), keys.authorityFalcon.publicKey)
        Files.write(public.resolve("ca-sm2-signer-id.bin"), keys.authoritySignerId)
        val fixtureMetadata = phases.map { phase ->
            val subdirectory = public.resolve("D${phase.body.size}-${phase.algorithm}")
            Files.createDirectories(subdirectory)
            Files.write(subdirectory.resolve("body.bin"), phase.body)
            phase.signatures.forEachIndexed { index, signature ->
                Files.write(subdirectory.resolve("signature-${index.toString().padStart(2, '0')}.bin"), signature)
            }
            mapOf("phase" to phase.name, "fixtureSuite" to phase.suite, "bodyBytes" to phase.body.size,
                "bodySha256" to sha256(phase.body), "signatureBytes" to phase.signatures.map { it.size }.distinct(),
                "poolSize" to poolSize, "relativeDirectory" to "public-fixtures/D${phase.body.size}-${phase.algorithm}",
                "signatureSha256" to phase.signatures.map(::sha256))
        }
        val seed = 20261103L + fork
        Collections.shuffle(phases, Random(seed))
        val metadata = linkedMapOf<String, Any?>(
            "classification" to "Single-host desktop JVM provider verification of real CA-signed canonical credential bodies; not terminal measurements",
            "fork" to fork, "startedUtc" to startedUtc, "timingStartedUtc" to Instant.now().toString(),
            "warmupPerPhase" to warmup, "measuredPerPhase" to samples, "signaturePoolSize" to poolSize,
            "phaseOrderSeed" to seed, "phaseOrder" to phases.map { it.name }, "fixtures" to fixtureMetadata,
            "java" to listOf("java.version", "java.runtime.version", "java.vendor", "java.vm.name", "java.vm.version",
                "os.name", "os.version", "os.arch").associateWith { System.getProperty(it) },
            "jvmArguments" to ManagementFactory.getRuntimeMXBean().inputArguments,
            "availableProcessors" to Runtime.getRuntime().availableProcessors(),
            "maxHeapBytes" to Runtime.getRuntime().maxMemory(),
            "garbageCollectors" to ManagementFactory.getGarbageCollectorMXBeans().map { it.name },
            "clockProbe" to clockProbe(),
            "timingScope" to "One production CryptoProvider verification call, including key decoding, signer initialization, hashing and signature-format checks; excludes setup key generation/signing/validation, fixture writes, credential parsing, digest, policy, network and ledger operations",
            "randomness" to "Fresh per-JVM keys and real SecureRandom signatures; order seed does not seed cryptography",
            "warmupFailurePolicy" to "Stop fork immediately; metadata and prior measured rows retained",
            "measurementFailurePolicy" to "Retain every failed row and complete all phases before nonzero exit",
            "outlierPolicy" to "Retain all observations; no GC, scheduling or other outlier removal",
            "counterScope" to "Phase counters include both warmup and measured iterations; they do not identify per-observation GC effects"
        )
        val phaseMetadata = mutableListOf<Map<String, Any?>>()
        var failures = 0
        var completed = false
        var failureDetail: String? = null
        try {
            Files.newBufferedWriter(directory.resolve("timings.csv")).use { csv ->
                csv.write("fork,phase,iteration,body_bytes,signature_index,elapsed_ns,ok,detail\n")
                for (phase in phases) {
                    println("fork=$fork phase=${phase.name}")
                    val before = counters()
                    val wallStart = System.nanoTime()
                    for (iteration in -warmup until samples) {
                        val index = Math.floorMod(iteration, poolSize)
                        val signature = phase.signatures[index]
                        var detail = ""
                        val start = System.nanoTime()
                        val accepted = try { verify(phase, signature) } catch (error: Exception) {
                            detail = error.javaClass.simpleName
                            false
                        }
                        val elapsed = System.nanoTime() - start
                        if (!accepted && detail.isEmpty()) detail = "Verification returned false"
                        if (iteration < 0) {
                            check(accepted) { "Warmup verification failed: ${phase.name} $detail" }
                        } else {
                            if (!accepted) failures++
                            writeObservation(csv, phase, iteration, index, elapsed, accepted, detail)
                        }
                    }
                    csv.flush()
                    phaseMetadata += mapOf("phase" to phase.name, "phaseWallNanos" to System.nanoTime() - wallStart,
                        "before" to before, "after" to counters())
                }
            }
            completed = true
        } catch (error: Throwable) {
            failureDetail = error.javaClass.simpleName + ": " + (error.message ?: "").take(300)
            throw error
        } finally {
            metadata["phases"] = phaseMetadata
            metadata["failedMeasuredRows"] = failures
            metadata["completedAllPhases"] = completed
            metadata["fatalFailure"] = failureDetail
            metadata["endedUtc"] = Instant.now().toString()
            Files.write(directory.resolve("metadata.json"), gson.toJson(metadata).toByteArray(Charsets.UTF_8))
        }
        check(failures == 0) { "$failures failed observations retained in timings.csv" }
    }

    private fun writeObservation(csv: BufferedWriter, phase: CredentialVerificationPhase, iteration: Int,
                                 index: Int, elapsed: Long, accepted: Boolean, detail: String) {
        fun quoted(value: String) = "\"" + value.replace("\"", "\"\"") + "\""
        csv.write("$fork,${quoted(phase.name)},$iteration,${phase.body.size},$index,$elapsed,$accepted,${quoted(detail)}\n")
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun counters(): Map<String, Any?> = mapOf(
        "gc" to ManagementFactory.getGarbageCollectorMXBeans().associate {
            it.name to mapOf("count" to it.collectionCount, "millis" to it.collectionTime)
        }, "jitCompilationMillis" to ManagementFactory.getCompilationMXBean()?.totalCompilationTime
    )

    private fun clockProbe(): Map<String, Long> {
        val pairs = LongArray(10000) { val start = System.nanoTime(); System.nanoTime() - start }.sorted()
        return mapOf("minPositivePairNanos" to (pairs.firstOrNull { it > 0 } ?: 0),
            "medianPairNanos" to pairs[pairs.size / 2])
    }
}
