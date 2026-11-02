package com.example.v2v0614.provisioning

import com.example.v2v0614.protocol.*
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.bouncycastle.util.encoders.Base64

data class AnchorBundle(
    val anchors: List<TrustAnchor>, val allowedSubjects: Set<String>,
    val revokedCredentials: Set<String>, val statusValidUntilMillis: Long
) {
    fun policy() = SnapshotPolicy(allowedSubjects, revokedCredentials, statusValidUntilMillis)
}
data class EnrollmentRequest(val subjectId: String, val publicKey: ByteArray, val proof: ByteArray)
data class CredentialBundle(val subjectId: String, val credential: ByteArray)

/** Provision these files over a trusted management path, never from peer WebSocket traffic. */
object BundleCodec {
    const val MAX_BUNDLE_CHARS = 256 * 1024
    private fun parse(text: String): JsonObject {
        require(text.length <= MAX_BUNDLE_CHARS) { "Oversized provisioning file" }
        val value = JsonParser.parseString(text)
        require(value.isJsonObject) { "Expected a JSON object" }
        return value.asJsonObject
    }
    private fun JsonObject.string(name: String): String {
        val v = get(name) ?: throw IllegalArgumentException("Missing $name")
        require(v.isJsonPrimitive && v.asJsonPrimitive.isString) { "Expected string $name" }
        return v.asString
    }
    private fun JsonObject.number(name: String): Long {
        val v = get(name) ?: throw IllegalArgumentException("Missing $name")
        require(v.isJsonPrimitive && v.asJsonPrimitive.isNumber && v.asString.matches(Regex("0|[1-9][0-9]*"))) { "Invalid $name" }
        return v.asString.toLong()
    }
    private fun JsonObject.array(name: String): JsonArray = getAsJsonArray(name) ?: throw IllegalArgumentException("Missing $name")
    fun b64(bytes: ByteArray): String = Base64.toBase64String(bytes)
    fun unb64(text: String, maxBytes: Int): ByteArray {
        require(text.length <= ((maxBytes + 2) / 3) * 4)
        val bytes = Base64.decode(text)
        require(bytes.size <= maxBytes && b64(bytes) == text) { "Noncanonical Base64" }
        return bytes
    }
    fun enrollmentSignedBytes(subjectId: String, publicKey: ByteArray): ByteArray =
        "PHAP-ENROLLMENT-1".toByteArray(Charsets.US_ASCII) + Hex.id(subjectId) + publicKey.also { require(it.size == 65) }

    fun enrollment(subjectId: String, keys: CryptoKeyPair, crypto: CryptoProvider): String {
        val proof = crypto.sm2Sign(keys.privateKey, Hex.id(subjectId), enrollmentSignedBytes(subjectId, keys.publicKey))
        return JsonObject().apply {
            addProperty("format", "PHAP-ENROLLMENT-1"); addProperty("subjectId", subjectId)
            addProperty("sm2PublicKey", Hex.encode(keys.publicKey)); addProperty("proofOfPossession", b64(proof))
        }.toString()
    }
    fun readEnrollment(text: String, crypto: CryptoProvider): EnrollmentRequest {
        val j = parse(text); require(j.string("format") == "PHAP-ENROLLMENT-1")
        val id = j.string("subjectId").also(Hex::id)
        val key = Hex.decode(j.string("sm2PublicKey"))
        require(crypto.validateSm2PublicKey(key)) { "Invalid enrollment SM2 key" }
        val proof = unb64(j.string("proofOfPossession"), 64)
        require(proof.size == 64 && crypto.sm2Verify(key, Hex.id(id), enrollmentSignedBytes(id, key), proof)) { "Enrollment proof rejected" }
        return EnrollmentRequest(id, key, proof)
    }
    fun credential(subjectId: String, encoded: ByteArray): String {
        require(WireCodec.decodeCredential(encoded).body.subjectId == subjectId)
        return JsonObject().apply {
            addProperty("format", "PHAP-CREDENTIAL-1"); addProperty("subjectId", subjectId); addProperty("credential", b64(encoded))
        }.toString()
    }
    fun readCredential(text: String): CredentialBundle {
        val j = parse(text); require(j.string("format") == "PHAP-CREDENTIAL-1")
        val id = j.string("subjectId").also(Hex::id)
        val bytes = unb64(j.string("credential"), PhapProfile.CREDENTIAL_BYTES)
        require(WireCodec.decodeCredential(bytes).body.subjectId == id) { "Credential identity mismatch" }
        return CredentialBundle(id, bytes)
    }
    fun readAnchors(text: String, crypto: CryptoProvider, now: Long): AnchorBundle {
        val j = parse(text); require(j.string("format") == "PHAP-ANCHORS-1")
        val entries = j.array("anchors"); require(entries.size() in 1..8)
        val anchors = entries.map { item ->
            val a = item.asJsonObject
            val id = a.string("issuerId").also(Hex::id)
            val sm2Id = Hex.decode(a.string("sm2SignerId")); require(sm2Id.size in 1..8191)
            val sm2 = Hex.decode(a.string("sm2PublicKey")); val falcon = Hex.decode(a.string("falconPublicKey"))
            require(crypto.validateSm2PublicKey(sm2) && crypto.validateFalconPublicKey(falcon)) { "Invalid authority public keys" }
            TrustAnchor(id, sm2Id, sm2, falcon)
        }
        require(anchors.map { it.issuerId }.distinct().size == anchors.size) { "Duplicate authority ID" }
        val ids = j.array("allowedSubjects"); require(ids.size() <= 1024)
        val allowed = ids.map { require(it.isJsonPrimitive && it.asJsonPrimitive.isString); it.asString.also(Hex::id) }.toSet()
        require(allowed.size == ids.size())
        val revocations = j.array("revokedCredentials"); require(revocations.size() <= 4096)
        val revoked = revocations.map {
            val value = it.asString; val parts = value.split(':'); require(parts.size == 2)
            Hex.id(parts[0]); require(parts[1].toLong() > 0 && parts[1].toLong().toString() == parts[1]); value
        }.toSet()
        require(revoked.size == revocations.size())
        val until = j.number("statusValidUntilMillis")
        require(now >= 0 && until > now) { "Policy/revocation status expired" }
        return AnchorBundle(anchors, allowed, revoked, until)
    }
    fun anchors(bundle: AnchorBundle): String = JsonObject().apply {
        addProperty("format", "PHAP-ANCHORS-1"); addProperty("statusValidUntilMillis", bundle.statusValidUntilMillis)
        add("allowedSubjects", JsonArray().apply { bundle.allowedSubjects.sorted().forEach { add(it) } })
        add("revokedCredentials", JsonArray().apply { bundle.revokedCredentials.sorted().forEach { add(it) } })
        add("anchors", JsonArray().apply { bundle.anchors.forEach { a -> add(JsonObject().apply {
            addProperty("issuerId", a.issuerId); addProperty("sm2SignerId", Hex.encode(a.sm2SignerId))
            addProperty("sm2PublicKey", Hex.encode(a.sm2PublicKey)); addProperty("falconPublicKey", Hex.encode(a.falconPublicKey))
        }) } })
    }.toString()
}
