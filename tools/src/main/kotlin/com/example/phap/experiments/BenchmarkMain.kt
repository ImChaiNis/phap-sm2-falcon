package com.example.phap.experiments

import com.example.v2v0614.protocol.*
import com.google.gson.GsonBuilder
import java.io.*
import java.lang.management.ManagementFactory
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Collections
import java.util.Random
import kotlin.concurrent.thread

/** Desktop experiment adapter, deliberately outside the Android production code. */
private data class Observation(val elapsed: Long, val ack: Long = 0, val ok: Boolean = true, val detail: String = "")
private data class Phase(val name: String, val run: () -> Unit)

fun main(args: Array<String>) {
    require(args.size >= 2) { "benchmark OUTPUT FORK [WARMUP SAMPLES] | functional OUTPUT [REPETITIONS]" }
    if (args[0] == "functional") {
        val result = FunctionalTrials.run(Paths.get(args[1]), args.getOrNull(2)?.toInt() ?: 100)
        println("Functional trials: ${result.expectationsPassed}/${result.totalTrials}")
        check(result.expectationsFailed == 0)
        return
    }
    require(args[0] == "benchmark" && args.size >= 3)
    Experiment(Paths.get(args[1]), args[2].toInt(), args.getOrNull(3)?.toInt() ?: 500,
        args.getOrNull(4)?.toInt() ?: 1000).run()
}

private class Experiment(val directory: Path, val fork: Int, val warmup: Int, val samples: Int) {
    private val crypto = CryptoProvider()
    private val keys = CompareKeyMaterial.generate(crypto)
    private val fixtures = (1..4).associateWith { ProfileFixture(it, crypto, keys, System.currentTimeMillis()) }
    private val payload = ByteArray(128) { (it * 17 + 5).toByte() }
    private val gson = GsonBuilder().setPrettyPrinting().create()
    private val phaseMetadata = mutableListOf<Map<String, Any?>>()
    private lateinit var csv: BufferedWriter
    private var failures = 0

    fun run() {
        require(warmup >= 0 && samples > 0)
        Files.createDirectories(directory)
        dumpPublicFixtures()
        val phases = mutableListOf<Phase>()
        for (name in listOf("SM2-sign", "SM2-verify", "Falcon-sign", "Falcon-verify"))
            phases += Phase("provider/$name") { provider(name) }
        for (suite in 1..4) for (cold in listOf(true, false)) {
            val name = "loopback/${fixtures.getValue(suite).profileName}/${if (cold) "cold" else "warm"}"
            phases += Phase(name) { network(fixtures.getValue(suite), cold, name) }
        }
        for (cold in listOf(true, false)) {
            val name = "production-core/PHAP/${if (cold) "cold" else "warm"}"
            phases += Phase(name) { production(cold, name) }
        }
        Collections.shuffle(phases, Random(20261029L + fork))
        val metadata = linkedMapOf<String, Any?>(
            "fork" to fork, "startedUtc" to java.time.Instant.now().toString(),
            "warmupPerPhase" to warmup, "measuredPerPhase" to samples,
            "phaseOrderSeed" to 20261029L + fork, "phaseOrder" to phases.map { it.name },
            "java" to listOf("java.version", "java.runtime.version", "java.vendor", "java.vm.name", "java.vm.version",
                "os.name", "os.version", "os.arch").associateWith { System.getProperty(it) },
            "jvmArguments" to ManagementFactory.getRuntimeMXBean().inputArguments,
            "availableProcessors" to Runtime.getRuntime().availableProcessors(),
            "maxHeapBytes" to Runtime.getRuntime().maxMemory(),
            "garbageCollectors" to ManagementFactory.getGarbageCollectorMXBeans().map { it.name },
            "clockProbe" to clockProbe(), "payloadBytes" to payload.size,
            "scope" to "Common-JVM monotonic clock; persistent binary TCP loopback; volatile sequence/replay stores; no Android persistence, radio, TLS or MMS",
            "cryptographicRandomness" to "Real SecureRandom, never seeded by the experiment-order seed")
        csv = Files.newBufferedWriter(directory.resolve("timings.csv"))
        csv.use {
            it.write("fork,phase,iteration,elapsed_ns,ack_elapsed_ns,ok,detail\n")
            for (phase in phases) {
                val before = counters()
                val start = System.nanoTime()
                println("fork=$fork phase=${phase.name}")
                phase.run()
                csv.flush()
                phaseMetadata += mapOf("phase" to phase.name, "phaseWallNanos" to System.nanoTime()-start,
                    "before" to before, "after" to counters())
            }
        }
        metadata["phases"] = phaseMetadata
        metadata["failures"] = failures
        metadata["endedUtc"] = java.time.Instant.now().toString()
        Files.write(directory.resolve("metadata.json"), gson.toJson(metadata).toByteArray())
        check(failures == 0) { "$failures failed measurements retained in timings.csv" }
    }

    private fun record(name: String, iteration: Int, result: Observation) {
        if (iteration < 0) { check(result.ok) { "Warmup failed: $name ${result.detail}" }; return }
        if (!result.ok) failures++
        fun quote(value: String) = "\""+value.replace("\"","\"\"")+"\""
        csv.write("$fork,${quote(name)},$iteration,${result.elapsed},${result.ack},${result.ok},${quote(result.detail)}\n")
    }

    private fun provider(operation: String) {
        val fixture = fixtures.getValue(2)
        val inputs = (1..32).map { fixture.signedMessageInput(payload,it.toLong(),System.currentTimeMillis()) }
        val falcon = operation.startsWith("Falcon")
        val pk = if (falcon) keys.endpointFalcon.publicKey else keys.endpointSm2.publicKey
        val sk = if (falcon) keys.endpointFalcon.privateKey else keys.endpointSm2.privateKey
        val id = Hex.id(keys.subjectId)
        fun sign(input: ByteArray) = if (falcon) crypto.falconSign(sk,input) else crypto.sm2Sign(sk,id,input)
        fun verify(input: ByteArray, signature: ByteArray) = if (falcon) crypto.falconVerify(pk,input,signature) else crypto.sm2Verify(pk,id,input,signature)
        val signatures = inputs.map(::sign)
        for (i in -warmup until samples) {
            val index = Math.floorMod(i,inputs.size)
            val input = inputs[index]
            val start = System.nanoTime()
            val result = if (operation.endsWith("sign")) {
                val signature = sign(input)
                val end = System.nanoTime()
                Observation(end-start,ok=verify(input,signature)) // verification is outside the signing timer
            } else {
                val accepted = verify(input,signatures[index])
                Observation(System.nanoTime()-start,ok=accepted)
            }
            record("provider/$operation",i,result)
        }
    }

    private fun production(cold: Boolean, name: String) {
        val fixture = fixtures.getValue(2)
        val anchor = TrustAnchor(keys.issuerId,keys.authoritySignerId,keys.authoritySm2.publicKey,keys.authorityFalcon.publicKey)
        val policy = SnapshotPolicy(setOf(keys.subjectId),emptySet(),fixture.notAfterMillis)
        val sender = Sender(fixture.credentialBytes,keys.endpointSm2.privateKey,crypto,InMemorySequenceStore())
        val fragments = sender.fragments().map(WireCodec::encodeFragment)
        val receiver = Receiver(keys.destinationId,listOf(anchor),crypto,InMemoryReplayStore(),policy)
        if (!cold) fragments.forEach { receiver.receiveFragment(WireCodec.decodeFragment(it)) }
        for (i in -warmup until samples) {
            if (cold) { receiver.clearCredentialCache(); receiver.discardIncomplete() } // untimed state reset
            val start = System.nanoTime()
            val packet = sender.createMessage(keys.destinationId,payload,System.currentTimeMillis())
            var deliveries = receiver.receive(WireCodec.decodeMessage(WireCodec.encodeMessage(packet))).deliveries.size
            if (cold) for (fragment in fragments) deliveries += receiver.receiveFragment(WireCodec.decodeFragment(fragment)).deliveries.size
            val end = System.nanoTime()
            record(name,i,Observation(end-start,ok=deliveries == 1,detail=if (deliveries == 1) "" else "deliveries=$deliveries"))
        }
    }

    private fun network(fixture: ProfileFixture, cold: Boolean, name: String) {
        val fragments = fixture.fragments().map(WireCodec::encodeFragment)
        val server = ServerSocket(0,1,InetAddress.getByName("127.0.0.1"))
        var workerFailure: Throwable? = null
        val worker = thread(name="phap-loopback-receiver") {
            try {
                server.accept().use { peer ->
                    peer.tcpNoDelay = true; peer.soTimeout = 10000
                    val input = DataInputStream(BufferedInputStream(peer.getInputStream()))
                    val output = DataOutputStream(BufferedOutputStream(peer.getOutputStream()))
                    val replay = InMemoryReplayStore()
                    var cached: VerifiedComparisonCredential? = if (cold) null else
                        fixture.verifyCredential(fixture.credentialBytes,System.currentTimeMillis(),fixture.credentialDigest)
                    output.writeBoolean(true); output.flush() // preload complete, outside all trial timers
                    repeat(warmup + samples) {
                        check(input.readByte().toInt() == 7)
                        if (cold) cached = null
                        output.writeBoolean(true); output.flush() // untimed ready barrier
                        var detail = ""; var accepted = false
                        try {
                            val count = input.readInt(); require(count == if (cold) fragments.size+1 else 1)
                            val message = input.frame()
                            if (cold) {
                                val parsed = fixture.parseMessage(message)
                                val parts = (1 until count).map { WireCodec.decodeFragment(input.frame()) }
                                require(parts.size <= 32 && parts.map { it.index }.distinct().size == parts.size)
                                require(parts.all { it.credentialDigest == parsed.credentialDigest && it.count == parts.size && it.totalLength == fixture.credentialSize })
                                val encoded = parts.sortedBy { it.index }.fold(ByteArrayOutputStream()) { out, part -> out.apply { write(part.bytes) } }.toByteArray()
                                require(parts.map { it.index }.sorted() == (1..parts.size).toList() && encoded.size == fixture.credentialSize)
                                cached = fixture.verifyCredential(encoded,System.currentTimeMillis(),parsed.credentialDigest)
                            }
                            accepted = fixture.verifyMessage(message,checkNotNull(cached),System.currentTimeMillis(),replay)
                            if (!accepted) detail = "Authentication rejected"
                        } catch (error: Exception) { detail = error.javaClass.simpleName+":"+(error.message ?: "").take(150) }
                        val stop = System.nanoTime() // stop before sending acknowledgement
                        output.writeLong(stop); output.writeBoolean(accepted); output.writeUTF(detail); output.flush()
                    }
                }
            } catch (error: Throwable) { workerFailure = error }
        }
        try {
            Socket("127.0.0.1",server.localPort).use { peer ->
                peer.tcpNoDelay = true; peer.soTimeout = 10000
                val input = DataInputStream(BufferedInputStream(peer.getInputStream()))
                val output = DataOutputStream(BufferedOutputStream(peer.getOutputStream()))
                check(input.readBoolean())
                var sequence = 0L
                for (i in -warmup until samples) {
                    sequence++
                    output.writeByte(7); output.flush(); check(input.readBoolean())
                    val start = System.nanoTime() // application payload ready; signing is timed
                    val message = fixture.prepareMessage(payload,sequence,System.currentTimeMillis())
                    output.writeInt(if (cold) fragments.size+1 else 1)
                    output.frame(message)
                    if (cold) fragments.forEach { output.frame(it) }
                    output.flush()
                    val stop = input.readLong(); val accepted = input.readBoolean(); val detail = input.readUTF()
                    val ack = System.nanoTime()
                    record(name,i,Observation(stop-start,ack-start,accepted,detail))
                }
            }
        } finally { server.close(); worker.join(10000) }
        check(!worker.isAlive) { "Receiver thread did not exit" }
        workerFailure?.let { throw IllegalStateException("Receiver worker failed",it) }
    }

    private fun DataOutputStream.frame(value: ByteArray) { writeInt(value.size); write(value) }
    private fun DataInputStream.frame(): ByteArray { val size=readInt(); require(size in 1..100000); return ByteArray(size).also { readFully(it) } }
    private fun counters(): Map<String, Any?> = mapOf(
        "gc" to ManagementFactory.getGarbageCollectorMXBeans().associate { it.name to mapOf("count" to it.collectionCount,"millis" to it.collectionTime) },
        "jitCompilationMillis" to ManagementFactory.getCompilationMXBean()?.totalCompilationTime)
    private fun clockProbe(): Map<String, Long> {
        val steps = LongArray(10000) { val a=System.nanoTime(); System.nanoTime()-a }.sorted()
        return mapOf("minPositivePairNanos" to (steps.firstOrNull { it>0 } ?: 0),"medianPairNanos" to steps[steps.size/2])
    }
    private fun dumpPublicFixtures() {
        val public = directory.resolve("public-fixtures"); Files.createDirectories(public)
        Files.write(public.resolve("ca-sm2-public.bin"),keys.authoritySm2.publicKey)
        Files.write(public.resolve("ca-falcon-public.bin"),keys.authorityFalcon.publicKey)
        val sizes = fixtures.values.map { f ->
            val p=public.resolve("suite-${f.suite}"); Files.createDirectories(p)
            Files.write(p.resolve("body.bin"),f.bodyBytes); Files.write(p.resolve("credential.bin"),f.credentialBytes)
            Files.write(p.resolve("message-128.bin"),f.prepareMessage(payload,1,System.currentTimeMillis()))
            f.fragments().forEach { Files.write(p.resolve("fragment-${it.index}.bin"),WireCodec.encodeFragment(it)) }
            val messageBytes=92+payload.size+f.messageSignatureSize
            val credentialFragmentWireBytes=f.credentialSize+44*f.fragments().size
            mapOf("suite" to f.suite,"profile" to f.profileName,"bodyBytes" to f.bodySize,"credentialBytes" to f.credentialSize,
                "messageSignatureBytes" to f.messageSignatureSize,"signedInputBytes" to f.signedMessageInput(payload,1,System.currentTimeMillis()).size,
                "fragmentPayloadBytes" to f.fragmentPayloads().map { it.size },"fragments" to f.fragments().size,
                "messageWireBytes" to messageBytes,"credentialFragmentWireBytes" to credentialFragmentWireBytes,
                "coldCanonicalBytes" to messageBytes+credentialFragmentWireBytes,"warmCanonicalBytes" to messageBytes,
                "coldTestFramingBytes" to 4+4*(1+f.fragments().size),"warmTestFramingBytes" to 8)
        }
        Files.write(directory.resolve("sizes.json"),gson.toJson(sizes).toByteArray())
    }
}
