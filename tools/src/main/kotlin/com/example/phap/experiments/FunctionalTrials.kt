package com.example.phap.experiments

import com.example.v2v0614.protocol.*
import com.google.gson.GsonBuilder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.Random

/**
 * Repeated, real-cryptography functional trials of the production PHAP engine.
 *
 * These are controlled scheduling/fault-injection experiments, NOT observed
 * packet loss, radio reception rates, device latency or a forgery-probability
 * estimate. Clock advances below are deliberate test inputs, not measured time.
 * Per-run honest key material/credential is reused; receivers, sequence/replay
 * stores and application signatures are fresh in each trial. The seed controls
 * trial order and fault positions only; cryptographic randomness remains real.
 */
object FunctionalTrials {
    enum class Condition {
        COLD_ORDERED,
        COLD_REORDERED_DUPLICATES,
        WARM_CACHED,
        MISSING_FRAGMENT_TIMEOUT,
        DUPLICATE_DEADLINE_AND_LATE_RECOVERY,
        CORRUPTED_FRAGMENT,
        CONFLICTING_DUPLICATE,
        INVALID_SM2_AUTHORITY_SIGNATURE,
        INVALID_FALCON_AUTHORITY_SIGNATURE,
        MODIFIED_BUFFERED_PAYLOAD,
        WARM_MESSAGE_REPLAY,
        EXPIRED_CREDENTIAL,
        REVOKED_CREDENTIAL,
        INCORRECT_DESTINATION,
        STALE_APPLICATION_MESSAGE
    }

    data class Row(
        val trialOrdinal: Int,
        val condition: String,
        val repetition: Int,
        val faultSeed: Long,
        val expectedInitialDeliveries: Int,
        val initialPhaseDeliveries: Int,
        val expectedControlDeliveries: Int,
        val controlPhaseDeliveries: Int,
        val fragmentIndicesPlanned: Int,
        val fragmentOffers: Int,
        val distinctFragmentIndicesOffered: Int,
        val fragmentOfferOrder: String,
        val applicationPacketOffers: Int,
        val rejectedReceiverCalls: Int,
        val cachedBeforeInitialMessage: Boolean,
        val cachedAfterInitialPhase: Boolean,
        val cachedAtEnd: Boolean,
        val incompleteContextsAtEnd: Int,
        val expiredContextCount: Int,
        val injectedFaultLocation: String,
        val expectationsPassed: Boolean,
        val failure: String,
        val receiverStatuses: String
    )

    data class ConditionSummary(
        val condition: String,
        val initiatedTrials: Int,
        val expectationsPassed: Int,
        val expectationsFailed: Int,
        val initialMessageOffers: Int,
        val expectedInitialDeliveries: Int,
        val actualInitialDeliveries: Int,
        val expectedControlDeliveries: Int,
        val actualControlDeliveries: Int,
        val fragmentOffers: Int,
        val sumPerTrialDistinctFragmentIndicesOffered: Int,
        val finalCachedCredentials: Int,
        val expiredContexts: Int
    )

    data class Summary(
        val classification: String,
        val scope: String,
        val randomness: String,
        val clock: String,
        val denominatorDefinitions: Map<String, String>,
        val seed: Long,
        val trialsPerCondition: Int,
        val totalTrials: Int,
        val expectationsPassed: Int,
        val expectationsFailed: Int,
        val credentialBytes: Int,
        val fragmentPayloadBytes: Int,
        val plannedFragmentsPerCredential: Int,
        val messagePayloadBytes: Int,
        val credentialDigest: String,
        val conditions: List<ConditionSummary>
    )

    private class ControlledClock(var wall: Long, var monotonic: Long = 0L) : ProtocolClock {
        override fun wallTimeMillis() = wall
        override fun monotonicTimeMillis() = monotonic
    }

    private data class Fixture(
        val crypto: CryptoProvider,
        val anchor: TrustAnchor,
        val endpoint: CryptoKeyPair,
        val credential: Credential,
        val encodedCredential: ByteArray,
        val now: Long,
        val subjectId: String,
        val receiverId: String,
        val otherId: String
    )

    /** Each row represents one independently initialized receiver/state trial. */
    fun run(outputDirectory: Path, trialsPerCondition: Int = 100, seed: Long = 20261029L): Summary {
        require(trialsPerCondition in 1..10000)
        Files.createDirectories(outputDirectory)
        val fixture = fixture()
        val jobs = mutableListOf<Pair<Condition, Int>>()
        Condition.values().forEach { condition -> (1..trialsPerCondition).forEach { jobs += condition to it } }
        Collections.shuffle(jobs, Random(seed))
        val rows = jobs.mapIndexed { index, (condition, repetition) ->
            val faultSeed = seed xor (repetition.toLong() shl 32) xor condition.name.hashCode().toLong()
            try {
                trial(fixture, condition, repetition, index + 1, faultSeed)
            } catch (error: Exception) {
                // A setup failure is retained as a failed initiated trial rather
                // than disappearing from the denominator or output file.
                Row(index+1, condition.name, repetition, faultSeed, expectedInitial(condition), 0,
                    expectedControl(condition), 0, 4, 0, 0, "", 0, 0, false, false, false, 0, 0,
                    "setup", false, "SETUP_FAILURE: ${error.javaClass.simpleName}: ${(error.message ?: "").take(300)}", "")
            }
        }
        val byCondition = Condition.values().map { condition ->
            val selected = rows.filter { it.condition == condition.name }
            ConditionSummary(
                condition.name, selected.size, selected.count { it.expectationsPassed }, selected.count { !it.expectationsPassed },
                selected.count { it.applicationPacketOffers > 0 }, selected.sumOf { it.expectedInitialDeliveries }, selected.sumOf { it.initialPhaseDeliveries },
                selected.sumOf { it.expectedControlDeliveries }, selected.sumOf { it.controlPhaseDeliveries },
                selected.sumOf { it.fragmentOffers }, selected.sumOf { it.distinctFragmentIndicesOffered },
                selected.count { it.cachedAtEnd }, selected.sumOf { it.expiredContextCount }
            )
        }
        val summary = Summary(
            "Repeated real-signature functional checks with controlled fault injection; not field/network statistics",
            "Production CryptoProvider/CredentialAuthority/Sender/Receiver/WireCodec; one honest per-run credential and key set; fresh receiver, sequence/replay stores and SM2 signatures in every trial",
            "Seed controls condition order, permutations, duplicate placement and altered byte positions; SecureRandom used for all cryptographic operations and not seeded from the experiment seed",
            "Production validity/freshness checks use a controlled wall-clock fixture; timeout experiments advance a controlled monotonic clock. These advances are test inputs and are not latency observations.",
            linkedMapOf(
                "initiatedTrials" to "All initialized trials in a condition; no failed expectation is removed",
                "initialPhaseDeliveries" to "Application messages authenticated during the first phase; excludes any later valid control message",
                "controlPhaseDeliveries" to "Additional valid control messages authenticated after the injected fault/recovery, or zero for replay controls",
                "fragmentOffers" to "Calls that supplied a fragment record to the production receiver, including duplicates, altered fragments and deliberate recovery sends; not IP packet transmissions",
                "distinctFragmentIndicesOffered" to "Distinct fragment index values offered within a trial, not independently cryptographically authenticated fragments or a reception probability",
                "expectationsPassed" to "Trials whose declared accept/reject/cache/timeout conditions all matched; not an authentication-success rate for a random network"
            ),
            seed, trialsPerCondition, rows.size, rows.count { it.expectationsPassed }, rows.count { !it.expectationsPassed },
            fixture.encodedCredential.size, 256, 4, 128, Hex.encode(fixture.crypto.digest(fixture.encodedCredential)), byCondition
        )
        writeCsv(outputDirectory.resolve("functional_trials.csv"), rows)
        val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
        Files.write(outputDirectory.resolve("functional_summary.json"), (gson.toJson(summary) + "\n").toByteArray(StandardCharsets.UTF_8))
        Files.write(outputDirectory.resolve("functional_credential.bin"), fixture.encodedCredential)
        val publicFixture = linkedMapOf(
            "classification" to "Public fixture only; no private keys",
            "issuerId" to fixture.anchor.issuerId,
            "authoritySm2SignerIdHex" to Hex.encode(fixture.anchor.sm2SignerId),
            "authoritySm2PublicKeyHex" to Hex.encode(fixture.anchor.sm2PublicKey),
            "authorityFalconPublicKeyHex" to Hex.encode(fixture.anchor.falconPublicKey),
            "endpointId" to fixture.subjectId,
            "endpointSm2PublicKeyHex" to Hex.encode(fixture.endpoint.publicKey),
            "controlledWallStartMillis" to fixture.now,
            "credentialDigest" to summary.credentialDigest
        )
        Files.write(outputDirectory.resolve("functional_public_fixture.json"), (gson.toJson(publicFixture) + "\n").toByteArray(StandardCharsets.UTF_8))
        return summary
    }

    private fun fixture(): Fixture {
        val crypto = CryptoProvider()
        val authoritySm2 = crypto.generateSm2KeyPair()
        val authorityFalcon = crypto.generateFalconKeyPair()
        val endpoint = crypto.generateSm2KeyPair()
        val issuer = "11".repeat(16)
        val subject = "22".repeat(16)
        val receiverId = "33".repeat(16)
        val signerId = "PHAP functional-trial authority".toByteArray(StandardCharsets.US_ASCII)
        val now = System.currentTimeMillis()
        val body = CredentialBody(issuer, subject, 1L, now - 1000L, now + 60000L, endpoint.publicKey)
        val credential = CredentialAuthority.issue(body, authoritySm2.privateKey, authorityFalcon.privateKey, signerId, crypto)
        val encoded = WireCodec.encodeCredential(credential)
        check(encoded.size == 866)
        return Fixture(crypto, TrustAnchor(issuer, signerId, authoritySm2.publicKey, authorityFalcon.publicKey),
            endpoint, credential, encoded, now, subject, receiverId, "44".repeat(16))
    }

    private fun expectedInitial(condition: Condition): Int =
        if (condition in setOf(Condition.COLD_ORDERED, Condition.COLD_REORDERED_DUPLICATES,
                Condition.WARM_CACHED, Condition.WARM_MESSAGE_REPLAY)) 1 else 0

    private fun expectedControl(condition: Condition): Int =
        if (condition in setOf(Condition.DUPLICATE_DEADLINE_AND_LATE_RECOVERY,
                Condition.CONFLICTING_DUPLICATE, Condition.MODIFIED_BUFFERED_PAYLOAD,
                Condition.STALE_APPLICATION_MESSAGE)) 1 else 0

    private fun trial(f: Fixture, condition: Condition, repetition: Int, ordinal: Int, faultSeed: Long): Row {
        val random = Random(faultSeed)
        val clock = ControlledClock(f.now)
        val trace = mutableListOf<String>()
        val offers = mutableListOf<Int>()
        val indices = mutableSetOf<Int>()
        var packetOffers = 0
        var rejected = 0
        var initialDeliveries = 0
        var controlDeliveries = 0
        val expectedInitial = expectedInitial(condition)
        val expectedControl = expectedControl(condition)
        var cachedBefore = false
        var cachedAfterInitial = false
        var expired = 0
        var location = "none"
        var passed = false
        var failure = ""
        var revocationActive = false
        val policy = object : ProtocolPolicy {
            override fun credentialAllowed(body: CredentialBody, nowMillis: Long) =
                body.subjectId == f.subjectId && !revocationActive
            override fun messageAllowed(body: CredentialBody, envelope: MessageEnvelope) =
                envelope.senderId == f.subjectId && envelope.destinationId == f.receiverId
        }
        val receiver = Receiver(f.receiverId, listOf(f.anchor), f.crypto, InMemoryReplayStore(), policy, clock = clock)
        var encoded = f.encodedCredential
        if (condition == Condition.INVALID_SM2_AUTHORITY_SIGNATURE) {
            val position = random.nextInt(64)
            val modified = f.credential.sm2Signature.copyOf().also { it[position] = (it[position].toInt() xor 1).toByte() }
            encoded = WireCodec.encodeCredential(f.credential.copy(sm2Signature = modified))
            location = "SM2 authority signature byte $position; digest recomputed"
        }
        if (condition == Condition.INVALID_FALCON_AUTHORITY_SIGNATURE) {
            val position = 41 + random.nextInt(500)
            val modified = f.credential.falconSignature.copyOf().also { it[position] = (it[position].toInt() xor 1).toByte() }
            encoded = WireCodec.encodeCredential(f.credential.copy(falconSignature = modified))
            location = "Falcon authority signature byte $position; digest recomputed"
        }
        // For authority-signature faults the fixture deliberately signs a message
        // bound to the altered credential digest, isolating certificate verification.
        val sender = Sender(encoded, f.endpoint.privateKey, f.crypto, InMemorySequenceStore())
        val fragments = sender.fragments()
        val digest = sender.credentialDigest
        val payload = ByteArray(128).also { random.nextBytes(it) }
        val initial = sender.createMessage(if (condition == Condition.INCORRECT_DESTINATION) f.otherId else f.receiverId, payload, f.now)

        fun observe(result: ReceiveResult): Int {
            trace += result.status.name + ":" + result.reason.take(120)
            if (result.status == ReceiveStatus.REJECTED) rejected++
            return result.deliveries.size
        }
        fun fragment(part: CredentialFragment): Int {
            offers += part.index; indices += part.index
            // Exercise the production wire decoder as well as receiver state.
            val decoded = WireCodec.decodeFragment(WireCodec.encodeFragment(part))
            return observe(receiver.receiveFragment(decoded))
        }
        fun message(packet: MessagePacket): Int {
            packetOffers++
            val decoded = WireCodec.decodeMessage(WireCodec.encodeMessage(packet))
            return observe(receiver.receive(decoded))
        }
        fun prepareWarmCache() {
            fragments.forEach { check(fragment(it) == 0) }
            check(receiver.hasCachedCredential(digest)) { "Warm-up credential did not verify" }
            cachedBefore = true
        }
        fun checkInitial(expectedCache: Boolean) {
            cachedAfterInitial = receiver.hasCachedCredential(digest)
            check(cachedAfterInitial == expectedCache) { "Initial credential-cache state differed from expectation" }
            check(initialDeliveries == expectedInitial) { "Initial authenticated deliveries $initialDeliveries, expected $expectedInitial" }
        }
        try {
            when (condition) {
                Condition.COLD_ORDERED -> {
                    initialDeliveries += message(initial)
                    fragments.forEach { initialDeliveries += fragment(it) }
                    checkInitial(true)
                }
                Condition.COLD_REORDERED_DUPLICATES -> {
                    initialDeliveries += message(initial)
                    val shuffled = fragments.shuffled(random)
                    shuffled.forEachIndexed { index, part ->
                        initialDeliveries += fragment(part)
                        if (index < shuffled.lastIndex && (index == 0 || random.nextBoolean())) {
                            initialDeliveries += fragment(part)
                            initialDeliveries += fragment(part)
                        }
                    }
                    checkInitial(true)
                }
                Condition.WARM_CACHED -> {
                    prepareWarmCache(); initialDeliveries += message(initial); checkInitial(true)
                }
                Condition.MISSING_FRAGMENT_TIMEOUT -> {
                    initialDeliveries += message(initial)
                    val omitted = random.nextInt(4)
                    location = "Omitted fragment ${omitted+1}; controlled timeout at 5000 ms"
                    fragments.filterIndexed { index, _ -> index != omitted }.shuffled(random).forEach { initialDeliveries += fragment(it) }
                    check(receiver.missingFragments(digest) == listOf(omitted+1))
                    clock.monotonic = 5000L
                    expired += receiver.expireIncomplete()
                    check(expired == 1 && receiver.incompleteContextCount == 0)
                    checkInitial(false)
                }
                Condition.DUPLICATE_DEADLINE_AND_LATE_RECOVERY -> {
                    initialDeliveries += message(initial)
                    val first = fragments[random.nextInt(4)]
                    location = "Duplicate fragment ${first.index} at 4999 ms; original deadline 5000 ms"
                    initialDeliveries += fragment(first)
                    clock.monotonic = 4999L; clock.wall = f.now + 4999L
                    initialDeliveries += fragment(first)
                    clock.monotonic = 5000L; clock.wall = f.now + 5000L
                    expired += receiver.expireIncomplete()
                    check(expired == 1 && receiver.incompleteContextCount == 0)
                    checkInitial(false)
                    var lateBufferedDeliveries = 0
                    fragments.shuffled(random).forEach { lateBufferedDeliveries += fragment(it) }
                    check(lateBufferedDeliveries == 0 && receiver.hasCachedCredential(digest)) { "Timed-out buffer was revived" }
                    controlDeliveries += message(sender.createMessage(f.receiverId, byteArrayOf(1,2,3), clock.wall))
                }
                Condition.CORRUPTED_FRAGMENT -> {
                    initialDeliveries += message(initial)
                    val partIndex = random.nextInt(4)
                    val byteIndex = random.nextInt(fragments[partIndex].bytes.size)
                    location = "Fragment ${partIndex+1}, byte $byteIndex; declared digest unchanged"
                    fragments.mapIndexed { index, part ->
                        if (index == partIndex) part.copy(bytes = part.bytes.copyOf().also { it[byteIndex] = (it[byteIndex].toInt() xor 1).toByte() }) else part
                    }.shuffled(random).forEach { initialDeliveries += fragment(it) }
                    checkInitial(false); check(receiver.incompleteContextCount == 0 && rejected > 0)
                }
                Condition.CONFLICTING_DUPLICATE -> {
                    initialDeliveries += message(initial)
                    val first = fragments[random.nextInt(4)]
                    val byteIndex = random.nextInt(first.bytes.size)
                    location = "Conflicting duplicate fragment ${first.index}, byte $byteIndex"
                    initialDeliveries += fragment(first)
                    initialDeliveries += fragment(first.copy(bytes = first.bytes.copyOf().also { it[byteIndex] = (it[byteIndex].toInt() xor 1).toByte() }))
                    check(receiver.incompleteContextCount == 0 && rejected > 0)
                    checkInitial(false)
                    var revived = 0
                    fragments.shuffled(random).forEach { revived += fragment(it) }
                    check(revived == 0 && receiver.hasCachedCredential(digest)) { "Discarded buffer was revived" }
                    controlDeliveries += message(sender.createMessage(f.receiverId, byteArrayOf(4,5), clock.wall))
                }
                Condition.INVALID_SM2_AUTHORITY_SIGNATURE, Condition.INVALID_FALCON_AUTHORITY_SIGNATURE -> {
                    initialDeliveries += message(initial)
                    fragments.shuffled(random).forEach { initialDeliveries += fragment(it) }
                    checkInitial(false); check(receiver.incompleteContextCount == 0 && rejected > 0)
                }
                Condition.MODIFIED_BUFFERED_PAYLOAD -> {
                    val position = random.nextInt(payload.size)
                    location = "Application payload byte $position, original signature retained"
                    val alteredPayload = payload.copyOf().also { it[position] = (it[position].toInt() xor 1).toByte() }
                    initialDeliveries += message(initial.copy(envelope = initial.envelope.copy(payload = alteredPayload)))
                    fragments.shuffled(random).forEach { initialDeliveries += fragment(it) }
                    checkInitial(true); check(rejected > 0)
                    // A failed signature must not consume the genuine message's sequence.
                    controlDeliveries += message(initial)
                }
                Condition.WARM_MESSAGE_REPLAY -> {
                    prepareWarmCache(); initialDeliveries += message(initial); checkInitial(true)
                    val beforeRejected = rejected
                    controlDeliveries += message(initial)
                    check(rejected == beforeRejected + 1) { "Repeated message was not rejected" }
                }
                Condition.EXPIRED_CREDENTIAL -> {
                    prepareWarmCache()
                    clock.wall = f.credential.body.notAfterMillis + 1L
                    location = "Controlled wall clock one millisecond after credential expiry; genuinely signed fresh timestamp"
                    // Isolate credential expiry from message freshness: the fixture
                    // still holds the honest endpoint key and signs a fresh time.
                    val afterExpiry = initial.envelope.copy(timestampMillis = clock.wall)
                    val signedAfterExpiry = initial.copy(envelope = afterExpiry,
                        sm2Signature = f.crypto.sm2Sign(f.endpoint.privateKey, Hex.id(f.subjectId),
                            WireCodec.messageSignedBytes(afterExpiry, digest)))
                    initialDeliveries += message(signedAfterExpiry)
                    // Cache eviction leaves the digest unknown: an arriving
                    // message may safely wait for a credential. Re-offer that
                    // credential to exercise the explicit expiry rejection.
                    fragments.forEach { initialDeliveries += fragment(it) }
                    checkInitial(false); check(rejected > 0)
                }
                Condition.REVOKED_CREDENTIAL -> {
                    prepareWarmCache(); revocationActive = true
                    location = "Credential policy changed to revoked after cache population"
                    initialDeliveries += message(initial)
                    fragments.forEach { initialDeliveries += fragment(it) }
                    checkInitial(false); check(rejected > 0)
                }
                Condition.INCORRECT_DESTINATION -> {
                    prepareWarmCache(); location = "Genuinely signed message addressed to another receiver"
                    initialDeliveries += message(initial)
                    checkInitial(true); check(rejected > 0)
                }
                Condition.STALE_APPLICATION_MESSAGE -> {
                    prepareWarmCache()
                    clock.wall = f.now + 10001L
                    location = "Controlled message age 10001 ms, limit 10000 ms; credential still valid"
                    initialDeliveries += message(initial)
                    checkInitial(true); check(rejected > 0)
                    controlDeliveries += message(sender.createMessage(f.receiverId, byteArrayOf(6,7), clock.wall))
                }
            }
            check(controlDeliveries == expectedControl) { "Control authenticated deliveries $controlDeliveries, expected $expectedControl" }
            check(receiver.incompleteContextCount == 0) { "Completed/rejected/expired trial retained a reconstruction context" }
            passed = true
        } catch (error: Exception) {
            failure = error.javaClass.simpleName + ": " + (error.message ?: "").take(300)
        }
        return Row(ordinal, condition.name, repetition, faultSeed, expectedInitial, initialDeliveries,
            expectedControl, controlDeliveries, 4, offers.size, indices.size, offers.joinToString(";"), packetOffers,
            rejected, cachedBefore, cachedAfterInitial, receiver.hasCachedCredential(digest), receiver.incompleteContextCount,
            expired, location, passed, failure, trace.joinToString(" | "))
    }

    private fun writeCsv(path: Path, rows: List<Row>) {
        fun cell(value: Any?): String = "\"" + (value?.toString() ?: "").replace("\"", "\"\"") + "\""
        val header = listOf("trial_ordinal", "condition", "repetition", "fault_seed", "expected_initial_deliveries",
            "initial_phase_deliveries", "expected_control_deliveries", "control_phase_deliveries", "fragment_indices_planned",
            "fragment_offers", "distinct_fragment_indices_offered", "fragment_offer_order", "application_packet_offers",
            "rejected_receiver_calls", "cached_before_initial_message", "cached_after_initial_phase", "cached_at_end",
            "incomplete_contexts_at_end", "expired_context_count", "injected_fault_location", "expectations_passed", "failure", "receiver_statuses")
        Files.newBufferedWriter(path, StandardCharsets.UTF_8).use { output ->
            output.append(header.joinToString(",") { cell(it) }).append('\n')
            rows.forEach { r ->
                val values = listOf(r.trialOrdinal,r.condition,r.repetition,r.faultSeed,r.expectedInitialDeliveries,r.initialPhaseDeliveries,
                    r.expectedControlDeliveries,r.controlPhaseDeliveries,r.fragmentIndicesPlanned,r.fragmentOffers,r.distinctFragmentIndicesOffered,
                    r.fragmentOfferOrder,r.applicationPacketOffers,r.rejectedReceiverCalls,r.cachedBeforeInitialMessage,r.cachedAfterInitialPhase,
                    r.cachedAtEnd,r.incompleteContextsAtEnd,r.expiredContextCount,r.injectedFaultLocation,r.expectationsPassed,r.failure,r.receiverStatuses)
                output.append(values.joinToString(",") { cell(it) }).append('\n')
            }
        }
    }
}
