package com.example.v2v0614.protocol

/** Local experimental wire identifiers; not MMS/X.509 algorithm registrations. */
object PhapProfile {
    const val VERSION = 1
    const val SUITE = 2
    const val BODY_BYTES = 128
    const val CREDENTIAL_BYTES = 866
    const val SM2_SIGNATURE_BYTES = 64
    const val FALCON_SIGNATURE_BYTES = 666
    const val DIGEST_BYTES = 32
    const val ID_BYTES = 16
}

object Hex {
    fun encode(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    fun decode(value: String): ByteArray {
        require(value.length % 2 == 0 && value.all { it in '0'..'9' || it in 'a'..'f' }) { "Expected canonical lowercase hex" }
        return ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    fun id(value: String): ByteArray = decode(value).also { require(it.size == PhapProfile.ID_BYTES) { "Identity must contain 16 bytes" } }
    fun digest(value: String): ByteArray = decode(value).also { require(it.size == PhapProfile.DIGEST_BYTES) { "Digest must contain 32 bytes" } }
}

data class CredentialBody(
    val issuerId: String,
    val subjectId: String,
    val serial: Long,
    val notBeforeMillis: Long,
    val notAfterMillis: Long,
    val sm2PublicKey: ByteArray,
    val version: Int = PhapProfile.VERSION,
    val suite: Int = PhapProfile.SUITE
)

data class Credential(val body: CredentialBody, val sm2Signature: ByteArray, val falconSignature: ByteArray)

data class TrustAnchor(
    val issuerId: String,
    val sm2SignerId: ByteArray,
    val sm2PublicKey: ByteArray,
    val falconPublicKey: ByteArray
)

data class MessageEnvelope(
    val senderId: String,
    val destinationId: String,
    val sequence: Long,
    val timestampMillis: Long,
    val payload: ByteArray
)

data class CredentialFragment(
    val credentialDigest: String,
    val index: Int,
    val count: Int,
    val totalLength: Int,
    val bytes: ByteArray
)

data class MessagePacket(
    val envelope: MessageEnvelope,
    val credentialDigest: String,
    val sm2Signature: ByteArray,
    val fragment: CredentialFragment? = null
)

data class AuthenticatedMessage(val envelope: MessageEnvelope, val credentialDigest: String)
enum class ReceiveStatus { PENDING, ACCEPTED, REJECTED }
data class ReceiveResult(val status: ReceiveStatus, val deliveries: List<AuthenticatedMessage> = emptyList(), val reason: String = "")

/** Implementations must reserve/increment durably before returning. Never reset under an existing credential. */
interface SequenceStore { fun next(credentialDigest: String): Long }

/** Atomic durable compare-and-set; false means already used or out of strict monotonic order. */
interface ReplayStore { fun accept(credentialDigest: String, sequence: Long): Boolean }

/** Volatile stores are for tests and short-lived command-line trials, not restart-safe deployments. */
class InMemorySequenceStore : SequenceStore {
    private val values = mutableMapOf<String, Long>()
    @Synchronized override fun next(credentialDigest: String): Long {
        val old = values[credentialDigest] ?: 0L
        check(old < Long.MAX_VALUE) { "Sequence exhausted; renew the credential" }
        return (old + 1L).also { values[credentialDigest] = it }
    }
}

class InMemoryReplayStore : ReplayStore {
    private val values = mutableMapOf<String, Long>()
    @Synchronized override fun accept(credentialDigest: String, sequence: Long): Boolean {
        if (sequence <= (values[credentialDigest] ?: 0L)) return false
        values[credentialDigest] = sequence
        return true
    }
}

interface ProtocolPolicy {
    /** Must include authenticated revocation freshness and operator enrollment/algorithm policy. */
    fun credentialAllowed(body: CredentialBody, nowMillis: Long): Boolean
    /** Application authorization; protocol independently checks certified sender and local destination. */
    fun messageAllowed(body: CredentialBody, envelope: MessageEnvelope): Boolean
}

/** Explicit offline policy snapshot provisioned with the trust anchors, not accepted from peer traffic. */
class SnapshotPolicy(
    allowedSubjects: Set<String>,
    revokedCredentials: Set<String>,
    private val statusValidUntilMillis: Long
) : ProtocolPolicy {
    private val allowed = allowedSubjects.toSet().also { it.forEach(Hex::id) }
    private val revoked = revokedCredentials.toSet()
    override fun credentialAllowed(body: CredentialBody, nowMillis: Long): Boolean =
        nowMillis <= statusValidUntilMillis && body.subjectId in allowed && "${body.issuerId}:${body.serial}" !in revoked
    override fun messageAllowed(body: CredentialBody, envelope: MessageEnvelope): Boolean = body.subjectId in allowed
}

interface ProtocolClock {
    fun wallTimeMillis(): Long
    fun monotonicTimeMillis(): Long
}

object SystemProtocolClock : ProtocolClock {
    override fun wallTimeMillis(): Long = System.currentTimeMillis()
    override fun monotonicTimeMillis(): Long = System.nanoTime() / 1_000_000L
}

data class ProtocolLimits(
    val fragmentPayloadBytes: Int = 256,
    val maxCredentialBytes: Int = 4096,
    val maxFragments: Int = 32,
    val maxContexts: Int = 8,
    val maxBufferedMessagesPerContext: Int = 32,
    val maxBufferedBytesPerContext: Int = 128 * 1024,
    val maxPayloadBytes: Int = 64 * 1024,
    val reconstructionTimeoutMillis: Long = 5000L,
    val messageMaxAgeMillis: Long = 10000L,
    val clockSkewMillis: Long = 2000L,
    val maxCachedCredentials: Int = 64
) {
    init {
        require(fragmentPayloadBytes in 1..65535 && maxCredentialBytes >= PhapProfile.CREDENTIAL_BYTES)
        require(maxFragments in 1..65535 && maxContexts > 0 && maxBufferedMessagesPerContext > 0)
        require(maxBufferedBytesPerContext > 0 && maxPayloadBytes in 0..(16 * 1024 * 1024))
        require(reconstructionTimeoutMillis > 0 && messageMaxAgeMillis >= 0 && clockSkewMillis >= 0)
        require(maxCachedCredentials > 0)
    }
}
