package com.example.phap.experiments

import com.example.v2v0614.protocol.CredentialFragment
import com.example.v2v0614.protocol.CredentialBody
import com.example.v2v0614.protocol.CryptoKeyPair
import com.example.v2v0614.protocol.CryptoProvider
import com.example.v2v0614.protocol.Hex
import com.example.v2v0614.protocol.MessageEnvelope
import com.example.v2v0614.protocol.ReplayStore
import com.example.v2v0614.protocol.SnapshotPolicy
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

/**
 * Experimental comparison fixtures only. Production PHAP continues to accept
 * version 1 / suite 2; this module does not modify its negotiation or parsers.
 * Never serialize this key material: it includes private keys for fixture setup.
 */
class CompareKeyMaterial(
    @Transient val authoritySm2: CryptoKeyPair,
    @Transient val authorityFalcon: CryptoKeyPair,
    @Transient val endpointSm2: CryptoKeyPair,
    @Transient val endpointFalcon: CryptoKeyPair,
    val issuerId: String = "11".repeat(16),
    val subjectId: String = "22".repeat(16),
    val destinationId: String = "33".repeat(16),
    val authoritySignerId: ByteArray = "PHAP-EXPERIMENT-CA".toByteArray(Charsets.US_ASCII)
) {
    companion object {
        fun generate(crypto: CryptoProvider): CompareKeyMaterial = CompareKeyMaterial(
            crypto.generateSm2KeyPair(), crypto.generateFalconKeyPair(),
            crypto.generateSm2KeyPair(), crypto.generateFalconKeyPair()
        )
    }
}

class VerifiedComparisonCredential internal constructor(
    val suite: Int,
    val issuerId: String,
    val subjectId: String,
    val serial: Long,
    val notBeforeMillis: Long,
    val notAfterMillis: Long,
    val credentialDigest: String,
    internal val sm2PublicKey: ByteArray,
    internal val falconPublicKey: ByteArray,
    internal val policyBody: CredentialBody
)

data class ParsedComparisonMessage(
    val suite: Int,
    val credentialDigest: String,
    val envelope: MessageEnvelope,
    val sm2Signature: ByteArray,
    val falconSignature: ByteArray,
    val signedInput: ByteArray
)

/**
 * Actual signed credentials and messages for the four reference encodings.
 * Creation/key generation is fixture setup and must remain outside timed trials.
 * For a fair within-fork comparison, share one CompareKeyMaterial across suites.
 * All methods use byte-array messages, actual SM2 identities, and padded Falcon.
 */
class ProfileFixture(
    val suite: Int,
    @Transient private val crypto: CryptoProvider,
    @Transient private val keys: CompareKeyMaterial,
    nowMillis: Long,
    private val credentialLifetimeMillis: Long = 3_600_000L,
    private val messageMaxAgeMillis: Long = 10_000L,
    private val clockSkewMillis: Long = 2_000L
) {
    val profileName: String get() = when (suite) {
        1 -> "SM2-only"
        2 -> "PHAP"
        3 -> "Falcon-message"
        4 -> "Dual-message"
        else -> error("Unsupported comparison suite")
    }
    val bodySize: Int get() = canonicalBody.size
    val credentialSize: Int get() = canonicalCredential.size
    val messageSignatureSize: Int get() = sm2MessageBytes + falconMessageBytes
    val bodyBytes: ByteArray get() = canonicalBody.copyOf()
    val credentialBytes: ByteArray get() = canonicalCredential.copyOf()
    val authoritySm2Signature: ByteArray get() = caSm2Signature.copyOf()
    val authorityFalconSignature: ByteArray get() = caFalconSignature.copyOf()
    val credentialDigest: String
    val subjectId: String get() = keys.subjectId
    val destinationId: String get() = keys.destinationId
    val notBeforeMillis: Long
    val notAfterMillis: Long
    private val sm2MessageBytes: Int get() = if (suite == 3) 0 else 64
    private val falconMessageBytes: Int get() = if (suite >= 3) 666 else 0
    private val endpointFalconBytes: Int get() = if (suite >= 3) 897 else 0
    private val authorityFalconBytes: Int get() = if (suite == 1) 0 else 666
    private val canonicalBody: ByteArray
    private val caSm2Signature: ByteArray
    private val caFalconSignature: ByteArray
    private val canonicalCredential: ByteArray
    private val policy: SnapshotPolicy

    init {
        require(suite in 1..4 && nowMillis >= 0)
        require(credentialLifetimeMillis > 0 && messageMaxAgeMillis >= 0 && clockSkewMillis >= 0)
        Hex.id(keys.issuerId); Hex.id(keys.subjectId); Hex.id(keys.destinationId)
        require(keys.authoritySignerId.size in 1..8191)
        require(crypto.validateSm2PublicKey(keys.authoritySm2.publicKey))
        require(crypto.validateFalconPublicKey(keys.authorityFalcon.publicKey))
        require(crypto.validateSm2PublicKey(keys.endpointSm2.publicKey))
        require(crypto.validateFalconPublicKey(keys.endpointFalcon.publicKey))
        notBeforeMillis = maxOf(0L, nowMillis - minOf(nowMillis, 1_000L))
        notAfterMillis = Math.addExact(nowMillis, credentialLifetimeMillis)
        // Fixed, provisioned benchmark policy: this subject authorized, no revoked
        // credentials, and status fresh for the fixture lifetime. This is not a
        // remote revocation service or an operator-policy implementation.
        policy = SnapshotPolicy(setOf(keys.subjectId), emptySet(), notAfterMillis)
        canonicalBody = encode { out ->
            out.writeByte(VERSION); out.writeShort(suite)
            out.write(Hex.id(keys.issuerId)); out.write(Hex.id(keys.subjectId))
            out.writeLong(1L); out.writeLong(notBeforeMillis); out.writeLong(notAfterMillis)
            out.sized16(keys.endpointSm2.publicKey)
            out.sized16(if (suite >= 3) keys.endpointFalcon.publicKey else byteArrayOf())
        }
        check(canonicalBody.size == if (suite >= 3) 1025 else 128)
        caSm2Signature = crypto.sm2Sign(keys.authoritySm2.privateKey, keys.authoritySignerId, canonicalBody)
        caFalconSignature = if (suite == 1) byteArrayOf() else crypto.falconSign(keys.authorityFalcon.privateKey, canonicalBody)
        canonicalCredential = encode { out ->
            out.writeInt(canonicalBody.size); out.write(canonicalBody)
            out.sized16(caSm2Signature); out.sized16(caFalconSignature)
        }
        check(canonicalCredential.size == when(suite) { 1 -> 200; 2 -> 866; else -> 1763 })
        credentialDigest = Hex.encode(crypto.digest(canonicalCredential))
    }

    fun fragments(fragmentPayloadBytes: Int = 256): List<CredentialFragment> {
        require(fragmentPayloadBytes in 1..65535)
        val count = (canonicalCredential.size + fragmentPayloadBytes - 1) / fragmentPayloadBytes
        return (1..count).map { index ->
            val start = (index - 1) * fragmentPayloadBytes
            CredentialFragment(credentialDigest, index, count, canonicalCredential.size,
                canonicalCredential.copyOfRange(start, minOf(start + fragmentPayloadBytes, canonicalCredential.size)))
        }
    }

    fun fragmentPayloads(fragmentPayloadBytes: Int = 256): List<ByteArray> =
        fragments(fragmentPayloadBytes).map { it.bytes }

    fun signedMessageInput(payload: ByteArray, sequence: Long, timestampMillis: Long,
                           destinationId: String = keys.destinationId): ByteArray = signedInput(
        MessageEnvelope(keys.subjectId, destinationId, sequence, timestampMillis, payload), credentialDigest
    )

    fun prepareMessage(payload: ByteArray, sequence: Long, timestampMillis: Long,
                       destinationId: String = keys.destinationId): ByteArray {
        require(payload.size <= MAX_PAYLOAD_BYTES && sequence > 0 && timestampMillis >= 0)
        val envelope = MessageEnvelope(keys.subjectId, destinationId, sequence, timestampMillis, payload.copyOf())
        val signed = signedInput(envelope, credentialDigest)
        val sm2 = if (sm2MessageBytes == 0) byteArrayOf() else
            crypto.sm2Sign(keys.endpointSm2.privateKey, Hex.id(keys.subjectId), signed)
        val falcon = if (falconMessageBytes == 0) byteArrayOf() else
            crypto.falconSign(keys.endpointFalcon.privateKey, signed)
        return encode { out ->
            out.writeByte(2); out.writeByte(VERSION); out.writeShort(suite)
            out.write(Hex.digest(credentialDigest)); out.envelopeHeader(envelope)
            out.writeShort(sm2.size); out.writeShort(falcon.size)
            out.write(envelope.payload); out.write(sm2); out.write(falcon)
        }.also { check(it.size == 92 + payload.size + messageSignatureSize) }
    }

    /** Full canonical parse, digest, validity/authorization and authority verification. */
    fun verifyCredential(encoded: ByteArray, nowMillis: Long,
                         expectedDigest: String? = null): VerifiedComparisonCredential {
        require(nowMillis >= 0 && encoded.size == credentialSize) { "Incorrect comparison credential length" }
        val digest = Hex.encode(crypto.digest(encoded))
        if (expectedDigest != null) require(digest == expectedDigest.also { Hex.digest(it) }) { "Credential digest mismatch" }
        val stream = input(encoded)
        val length = stream.readInt()
        require(length == bodySize)
        val body = stream.fixed(length)
        val sm2 = stream.sized16(64)
        val falcon = stream.sized16(authorityFalconBytes)
        stream.end()
        val bodyStream = input(body)
        require(bodyStream.readUnsignedByte() == VERSION && bodyStream.readUnsignedShort() == suite) { "Suite mismatch" }
        val issuer = Hex.encode(bodyStream.fixed(16)); val subject = Hex.encode(bodyStream.fixed(16))
        val serial = bodyStream.nonnegativeLong()
        val start = bodyStream.nonnegativeLong(); val end = bodyStream.nonnegativeLong()
        val sm2Key = bodyStream.sized16(65); val falconKey = bodyStream.sized16(endpointFalconBytes)
        bodyStream.end()
        require(issuer == keys.issuerId && subject == keys.subjectId && serial > 0) { "Issuer/subject authorization rejected" }
        require(end > start && nowMillis in start..end) { "Credential expired/not yet valid" }
        val policyBody = CredentialBody(issuer,subject,serial,start,end,sm2Key.copyOf(),VERSION,suite)
        require(policy.credentialAllowed(policyBody,nowMillis)) { "Credential policy rejected" }
        require(crypto.validateSm2PublicKey(sm2Key)) { "Invalid endpoint SM2 key" }
        if (suite >= 3) require(crypto.validateFalconPublicKey(falconKey)) { "Invalid endpoint Falcon key" }
        require(crypto.sm2Verify(keys.authoritySm2.publicKey, keys.authoritySignerId, body, sm2)) { "Authority SM2 signature rejected" }
        if (suite != 1) require(crypto.falconVerify(keys.authorityFalcon.publicKey, body, falcon)) { "Authority Falcon signature rejected" }
        return VerifiedComparisonCredential(suite,issuer,subject,serial,start,end,digest,sm2Key.copyOf(),falconKey.copyOf(),policyBody)
    }

    fun parseMessage(encoded: ByteArray): ParsedComparisonMessage {
        require(encoded.size in (92 + messageSignatureSize)..(92 + MAX_PAYLOAD_BYTES + messageSignatureSize))
        val stream = input(encoded)
        require(stream.readUnsignedByte() == 2 && stream.readUnsignedByte() == VERSION && stream.readUnsignedShort() == suite) { "Message suite mismatch" }
        val digest = Hex.encode(stream.fixed(32))
        val sender = Hex.encode(stream.fixed(16)); val destination = Hex.encode(stream.fixed(16))
        val sequence = stream.nonnegativeLong(); val timestamp = stream.nonnegativeLong()
        val payloadSize = stream.readInt()
        require(sequence > 0 && payloadSize in 0..MAX_PAYLOAD_BYTES)
        require(stream.readUnsignedShort() == sm2MessageBytes && stream.readUnsignedShort() == falconMessageBytes)
        require(stream.available().toLong() == payloadSize.toLong() + messageSignatureSize.toLong())
        val payload = stream.fixed(payloadSize)
        val sm2 = stream.fixed(sm2MessageBytes); val falcon = stream.fixed(falconMessageBytes)
        stream.end()
        val envelope = MessageEnvelope(sender,destination,sequence,timestamp,payload)
        return ParsedComparisonMessage(suite,digest,envelope,sm2,falcon,signedInput(envelope,digest))
    }

    /** Cached-key path; replay commits only after every authenticity and policy check. */
    fun verifyMessage(encoded: ByteArray, verified: VerifiedComparisonCredential,
                      nowMillis: Long, replayStore: ReplayStore): Boolean = try {
        val packet = parseMessage(encoded)
        require(verified.suite == suite && packet.credentialDigest == verified.credentialDigest)
        require(verified.issuerId == keys.issuerId && verified.subjectId == keys.subjectId)
        require(nowMillis >= 0 && nowMillis in verified.notBeforeMillis..verified.notAfterMillis)
        require(policy.credentialAllowed(verified.policyBody,nowMillis))
        require(packet.envelope.senderId == verified.subjectId && packet.envelope.destinationId == keys.destinationId)
        val lower = if (nowMillis < messageMaxAgeMillis) 0L else nowMillis - messageMaxAgeMillis
        val upper = if (Long.MAX_VALUE - nowMillis < clockSkewMillis) Long.MAX_VALUE else nowMillis + clockSkewMillis
        require(packet.envelope.timestampMillis in lower..upper)
        if (sm2MessageBytes > 0) require(crypto.sm2Verify(verified.sm2PublicKey, Hex.id(verified.subjectId), packet.signedInput, packet.sm2Signature))
        if (falconMessageBytes > 0) require(crypto.falconVerify(verified.falconPublicKey, packet.signedInput, packet.falconSignature))
        require(policy.messageAllowed(verified.policyBody,packet.envelope))
        replayStore.accept(verified.credentialDigest, packet.envelope.sequence)
    } catch (_: Exception) { false }

    private fun signedInput(envelope: MessageEnvelope, digest: String): ByteArray = encode { out ->
        out.write("GRID-MSG".toByteArray(Charsets.US_ASCII)); out.writeByte(VERSION); out.writeShort(suite)
        out.write(Hex.digest(digest)); out.envelopeHeader(envelope); out.write(envelope.payload)
    }

    private fun DataOutputStream.envelopeHeader(envelope: MessageEnvelope) {
        require(envelope.sequence > 0 && envelope.timestampMillis >= 0 && envelope.payload.size <= MAX_PAYLOAD_BYTES)
        write(Hex.id(envelope.senderId)); write(Hex.id(envelope.destinationId))
        writeLong(envelope.sequence); writeLong(envelope.timestampMillis); writeInt(envelope.payload.size)
    }
    private fun DataOutputStream.sized16(value: ByteArray) { require(value.size <= 65535); writeShort(value.size); write(value) }
    private fun DataInputStream.fixed(length: Int): ByteArray {
        require(length >= 0 && length <= available()); return ByteArray(length).also { readFully(it) }
    }
    private fun DataInputStream.sized16(expected: Int): ByteArray { require(readUnsignedShort() == expected); return fixed(expected) }
    private fun DataInputStream.nonnegativeLong(): Long = readLong().also { require(it >= 0) }
    private fun DataInputStream.end() { require(available() == 0) { "Noncanonical trailing bytes" } }
    private fun input(bytes: ByteArray) = DataInputStream(ByteArrayInputStream(bytes))
    private fun encode(write: (DataOutputStream) -> Unit): ByteArray {
        val out = ByteArrayOutputStream(); DataOutputStream(out).use(write); return out.toByteArray()
    }

    companion object { const val VERSION = 1; const val MAX_PAYLOAD_BYTES = 64 * 1024 }
}
