package com.example.v2v0614.protocol

import java.io.ByteArrayOutputStream
import java.security.MessageDigest

private fun CredentialBody.snapshot() = copy(sm2PublicKey = sm2PublicKey.copyOf())
private fun Credential.snapshot() = copy(body = body.snapshot(), sm2Signature = sm2Signature.copyOf(), falconSignature = falconSignature.copyOf())
private fun MessageEnvelope.snapshot() = copy(payload = payload.copyOf())
private fun MessagePacket.snapshot() = copy(envelope = envelope.snapshot(), sm2Signature = sm2Signature.copyOf(), fragment = fragment?.copy(bytes = fragment.bytes.copyOf()))

/** Run on the authority only. Issuance authorization and proof of possession precede this call. */
object CredentialAuthority {
    fun issue(
        body: CredentialBody,
        issuerSm2Private: ByteArray,
        issuerFalconPrivate: ByteArray,
        authoritySm2Id: ByteArray,
        crypto: CryptoProvider
    ): Credential {
        require(authoritySm2Id.isNotEmpty() && authoritySm2Id.size <= 8191)
        require(crypto.validateSm2PublicKey(body.sm2PublicKey)) { "Invalid endpoint SM2 key" }
        val immutableBody = body.snapshot()
        val encoded = WireCodec.encodeBody(immutableBody)
        return Credential(
            immutableBody,
            crypto.sm2Sign(issuerSm2Private, authoritySm2Id, encoded),
            crypto.falconSign(issuerFalconPrivate, encoded)
        ).also { WireCodec.encodeCredential(it) }
    }
}

/** Verifies only pinned issuer keys; a key received inside a peer message is never a trust anchor. */
class CredentialVerifier(anchors: List<TrustAnchor>, private val crypto: CryptoProvider, private val policy: ProtocolPolicy) {
    private val trusted: Map<String, TrustAnchor>
    init {
        require(anchors.map { it.issuerId }.distinct().size == anchors.size) { "Duplicate issuer identity" }
        trusted = anchors.associate { anchor ->
            Hex.id(anchor.issuerId)
            require(anchor.sm2SignerId.isNotEmpty() && anchor.sm2SignerId.size <= 8191)
            require(crypto.validateSm2PublicKey(anchor.sm2PublicKey)) { "Invalid authority SM2 key" }
            require(crypto.validateFalconPublicKey(anchor.falconPublicKey)) { "Invalid authority Falcon key" }
            anchor.issuerId to anchor.copy(
                sm2SignerId = anchor.sm2SignerId.copyOf(),
                sm2PublicKey = anchor.sm2PublicKey.copyOf(),
                falconPublicKey = anchor.falconPublicKey.copyOf()
            )
        }
    }

    fun verify(credentialBytes: ByteArray, nowMillis: Long): Credential {
        require(nowMillis >= 0)
        val credential = WireCodec.decodeCredential(credentialBytes.copyOf())
        val body = credential.body
        val anchor = trusted[body.issuerId] ?: throw SecurityException("Unknown issuer")
        require(body.notBeforeMillis <= nowMillis && nowMillis <= body.notAfterMillis) { "Credential outside validity interval" }
        require(crypto.validateSm2PublicKey(body.sm2PublicKey)) { "Invalid endpoint key" }
        check(policy.credentialAllowed(body.snapshot(), nowMillis)) { "Credential policy or revocation check rejected" }
        val signed = WireCodec.encodeBody(body)
        check(crypto.sm2Verify(anchor.sm2PublicKey, anchor.sm2SignerId, signed, credential.sm2Signature)) { "SM2 authority signature rejected" }
        check(crypto.falconVerify(anchor.falconPublicKey, signed, credential.falconSignature)) { "Falcon authority signature rejected" }
        return credential.snapshot()
    }
}

/** Endpoint credentials are provisioned by the authority; no Falcon signing key is held here. */
class Sender(
    credentialBytes: ByteArray,
    sm2PrivateKey: ByteArray,
    private val crypto: CryptoProvider,
    private val sequenceStore: SequenceStore,
    private val fragmentPayloadBytes: Int = 256
) {
    private val encodedCredential = credentialBytes.copyOf()
    private val credential = WireCodec.decodeCredential(encodedCredential)
    private val privateKey = sm2PrivateKey.copyOf()
    val credentialDigest = Hex.encode(crypto.digest(encodedCredential))
    val subjectId: String get() = credential.body.subjectId

    init {
        require(fragmentPayloadBytes in 1..65535)
        require(MessageDigest.isEqual(crypto.sm2PublicKey(privateKey), credential.body.sm2PublicKey)) { "Private key does not match credential" }
    }

    fun fragments(): List<CredentialFragment> {
        val count = (encodedCredential.size + fragmentPayloadBytes - 1) / fragmentPayloadBytes
        return (1..count).map { index ->
            val offset = (index - 1) * fragmentPayloadBytes
            CredentialFragment(credentialDigest, index, count, encodedCredential.size,
                encodedCredential.copyOfRange(offset, minOf(offset + fragmentPayloadBytes, encodedCredential.size)))
        }
    }

    @Synchronized fun createMessage(destinationId: String, payload: ByteArray, nowMillis: Long, fragmentIndex: Int? = null): MessagePacket {
        Hex.id(destinationId)
        require(payload.size <= 64 * 1024) { "Payload exceeds reference implementation limit" }
        require(nowMillis >= credential.body.notBeforeMillis && nowMillis <= credential.body.notAfterMillis) { "Sender credential is not currently valid" }
        val sequence = sequenceStore.next(credentialDigest)
        check(sequence > 0) { "Sequence store returned an invalid reservation" }
        val envelope = MessageEnvelope(subjectId, destinationId, sequence, nowMillis, payload.copyOf())
        val signature = crypto.sm2Sign(privateKey, Hex.id(subjectId), WireCodec.messageSignedBytes(envelope, credentialDigest))
        val fragment = fragmentIndex?.let { index -> fragments().firstOrNull { it.index == index } ?: throw IllegalArgumentException("Invalid fragment index") }
        return MessagePacket(envelope, credentialDigest, signature, fragment)
    }
}

/**
 * Bounded receiver with a fail-closed policy. Calls are serialized to make authentication and
 * replay-state commits atomic. Replay state is deliberately external to the credential cache.
 * The replay store enforces increasing sequence numbers; a delayed lower sequence is discarded.
 */
class Receiver(
    private val localId: String,
    trustAnchors: List<TrustAnchor>,
    private val crypto: CryptoProvider,
    private val replayStore: ReplayStore,
    private val policy: ProtocolPolicy,
    private val limits: ProtocolLimits = ProtocolLimits(),
    private val clock: ProtocolClock = SystemProtocolClock
) {
    private val verifier = CredentialVerifier(trustAnchors, crypto, policy)
    private val cache = LinkedHashMap<String, Credential>()
    private class Context(val createdMillis: Long) {
        var count: Int? = null
        var total: Int? = null
        val parts = mutableMapOf<Int, ByteArray>()
        val packets = LinkedHashMap<String, MessagePacket>()
        var bufferedBytes = 0
    }
    private val contexts = LinkedHashMap<String, Context>()

    init { Hex.id(localId) }
    val cachedCredentialCount: Int @Synchronized get() = cache.size
    val incompleteContextCount: Int @Synchronized get() = contexts.size

    @Synchronized fun clearCredentialCache() { cache.clear() }
    @Synchronized fun discardIncomplete() { contexts.clear() }
    @Synchronized fun hasCachedCredential(credentialDigest: String): Boolean {
        Hex.digest(credentialDigest)
        return validCached(credentialDigest, clock.wallTimeMillis()) != null
    }
    @Synchronized fun missingFragments(credentialDigest: String): List<Int> {
        expireIncomplete()
        val context = contexts[credentialDigest] ?: return emptyList()
        val count = context.count ?: return emptyList()
        return (1..count).filter { it !in context.parts }
    }

    @Synchronized fun expireIncomplete(): Int {
        val now = clock.monotonicTimeMillis()
        val expired = contexts.filterValues { context ->
            val elapsed = now - context.createdMillis
            now < context.createdMillis || elapsed < 0 || elapsed >= limits.reconstructionTimeoutMillis
        }.keys.toList()
        expired.forEach(contexts::remove)
        return expired.size
    }

    @Synchronized fun receive(packet: MessagePacket): ReceiveResult = rejectErrors {
        expireIncomplete()
        val now = clock.wallTimeMillis()
        purgeInvalidCache(now)
        validateMessageStructure(packet)
        val immutable = packet.snapshot()
        require(now >= 0)
        require(fresh(immutable.envelope.timestampMillis, now)) { "Message is stale or too far in the future" }
        val cached = validCached(immutable.credentialDigest, now)
        if (cached != null) return@rejectErrors authenticate(immutable, cached, now)

        val context = context(immutable.credentialDigest)
        val packetKey = Hex.encode(crypto.digest(WireCodec.encodeMessage(immutable)))
        if (!context.packets.containsKey(packetKey)) {
            val length = 156L + immutable.envelope.payload.size
            require(context.packets.size < limits.maxBufferedMessagesPerContext) { "Message buffer count limit reached" }
            require(context.bufferedBytes.toLong() + length <= limits.maxBufferedBytesPerContext) { "Message buffer byte limit reached" }
            context.packets[packetKey] = immutable.copy(fragment = null)
            context.bufferedBytes += length.toInt()
        }
        if (immutable.fragment != null) collect(immutable.fragment, context) else pending("Awaiting credential fragments")
    }

    @Synchronized fun receiveFragment(fragment: CredentialFragment): ReceiveResult = rejectErrors {
        expireIncomplete()
        val now = clock.wallTimeMillis()
        purgeInvalidCache(now)
        validateFragment(fragment)
        if (validCached(fragment.credentialDigest, now) != null) return@rejectErrors pending("Credential already verified")
        collect(fragment.copy(bytes = fragment.bytes.copyOf()), context(fragment.credentialDigest))
    }

    private fun context(digest: String): Context {
        Hex.digest(digest)
        return contexts[digest] ?: run {
            require(contexts.size < limits.maxContexts) { "Reconstruction context limit reached" }
            Context(clock.monotonicTimeMillis()).also { contexts[digest] = it }
        }
    }

    private fun validateMessageStructure(packet: MessagePacket) {
        Hex.digest(packet.credentialDigest)
        Hex.id(packet.envelope.senderId)
        Hex.id(packet.envelope.destinationId)
        require(packet.envelope.destinationId == localId) { "Incorrect destination" }
        require(packet.envelope.sequence > 0 && packet.envelope.timestampMillis >= 0)
        require(packet.envelope.payload.size <= limits.maxPayloadBytes && packet.sm2Signature.size == 64)
        packet.fragment?.let {
            require(it.credentialDigest == packet.credentialDigest) { "Fragment belongs to another credential" }
            validateFragment(it)
        }
    }

    private fun validateFragment(fragment: CredentialFragment) {
        Hex.digest(fragment.credentialDigest)
        require(fragment.totalLength == PhapProfile.CREDENTIAL_BYTES && fragment.totalLength <= limits.maxCredentialBytes) { "Unsupported credential length" }
        val expectedCount = (fragment.totalLength.toLong() + limits.fragmentPayloadBytes - 1) / limits.fragmentPayloadBytes
        require(fragment.count.toLong() == expectedCount && fragment.count in 1..limits.maxFragments) { "Inconsistent fragment count" }
        require(fragment.index in 1..fragment.count)
        val expectedLength = if (fragment.index == fragment.count) fragment.totalLength - (fragment.count - 1) * limits.fragmentPayloadBytes else limits.fragmentPayloadBytes
        require(fragment.bytes.size == expectedLength) { "Inconsistent fragment payload length" }
    }

    private fun collect(fragment: CredentialFragment, context: Context): ReceiveResult {
        val digest = fragment.credentialDigest
        try {
            validateFragment(fragment)
            require(context.count == null || context.count == fragment.count) { "Conflicting fragment count" }
            require(context.total == null || context.total == fragment.totalLength) { "Conflicting credential length" }
            context.count = fragment.count
            context.total = fragment.totalLength
            val prior = context.parts[fragment.index]
            require(prior == null || MessageDigest.isEqual(prior, fragment.bytes)) { "Conflicting duplicate fragment" }
            if (prior == null) context.parts[fragment.index] = fragment.bytes.copyOf()
            if (context.parts.size != fragment.count) return pending("Credential reconstruction incomplete")

            val reconstructed = ByteArrayOutputStream(fragment.totalLength)
            for (index in 1..fragment.count) reconstructed.write(context.parts[index] ?: throw IllegalArgumentException("Missing fragment"))
            val encoded = reconstructed.toByteArray()
            require(encoded.size == fragment.totalLength && Hex.encode(crypto.digest(encoded)) == digest) { "Credential digest mismatch" }
            val now = clock.wallTimeMillis()
            val credential = verifier.verify(encoded, now)
            if (cache.size >= limits.maxCachedCredentials) cache.remove(cache.keys.first())
            cache[digest] = credential.snapshot()
            contexts.remove(digest)

            val delivered = mutableListOf<AuthenticatedMessage>()
            var rejected = 0
            // Strict monotonic replay state must not turn fragment arrival order into message rejection.
            for (packet in context.packets.values.sortedBy { it.envelope.sequence }) {
                val result = authenticate(packet, credential, clock.wallTimeMillis())
                delivered += result.deliveries
                if (result.status == ReceiveStatus.REJECTED) rejected++
            }
            return if (delivered.isNotEmpty()) ReceiveResult(ReceiveStatus.ACCEPTED, delivered, "Credential verified; $rejected buffered messages rejected")
            else if (rejected > 0) ReceiveResult(ReceiveStatus.REJECTED, reason = "Credential verified; all buffered messages rejected")
            else pending("Credential verified and cached")
        } catch (error: Exception) {
            contexts.remove(digest)
            throw error
        }
    }

    private fun purgeInvalidCache(now: Long) {
        val invalid = cache.filterValues { credential ->
            val body = credential.body
            try { now < 0 || now < body.notBeforeMillis || now > body.notAfterMillis || !policy.credentialAllowed(body.snapshot(), now) }
            catch (_: Exception) { true }
        }.keys.toList()
        invalid.forEach(cache::remove)
    }

    private fun validCached(digest: String, now: Long): Credential? {
        val credential = cache[digest] ?: return null
        val body = credential.body
        val valid = try { now >= 0 && now >= body.notBeforeMillis && now <= body.notAfterMillis && policy.credentialAllowed(body.snapshot(), now) } catch (_: Exception) { false }
        if (!valid) { cache.remove(digest); return null }
        return credential
    }

    private fun authenticate(packet: MessagePacket, credential: Credential, now: Long): ReceiveResult = rejectErrors {
        val body = credential.body
        require(packet.envelope.senderId == body.subjectId) { "Sender identity does not match credential" }
        require(packet.envelope.destinationId == localId && fresh(packet.envelope.timestampMillis, now)) { "Destination or freshness rejected" }
        require(now >= body.notBeforeMillis && now <= body.notAfterMillis && policy.credentialAllowed(body.snapshot(), now)) { "Credential no longer valid under policy" }
        val message = WireCodec.messageSignedBytes(packet.envelope, packet.credentialDigest)
        check(crypto.sm2Verify(body.sm2PublicKey, Hex.id(body.subjectId), message, packet.sm2Signature)) { "Message signature rejected" }
        check(policy.messageAllowed(body.snapshot(), packet.envelope.snapshot())) { "Application authorization rejected" }
        // Commit only after all cryptographic, identity, timing and authorization checks have succeeded.
        check(replayStore.accept(packet.credentialDigest, packet.envelope.sequence)) { "Replay or non-increasing sequence rejected" }
        ReceiveResult(ReceiveStatus.ACCEPTED, listOf(AuthenticatedMessage(packet.envelope.snapshot(), packet.credentialDigest)), "Authenticated")
    }

    private fun fresh(timestamp: Long, now: Long): Boolean {
        if (timestamp < 0 || now < 0) return false
        val lower = if (now < limits.messageMaxAgeMillis) 0L else now - limits.messageMaxAgeMillis
        val upper = if (Long.MAX_VALUE - now < limits.clockSkewMillis) Long.MAX_VALUE else now + limits.clockSkewMillis
        return timestamp in lower..upper
    }

    private fun pending(reason: String) = ReceiveResult(ReceiveStatus.PENDING, reason = reason)
    private inline fun rejectErrors(action: () -> ReceiveResult): ReceiveResult = try { action() }
    catch (error: Exception) { ReceiveResult(ReceiveStatus.REJECTED, reason = error.message ?: error.javaClass.simpleName) }
}
