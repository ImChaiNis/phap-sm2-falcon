package com.example.v2v0614.protocol

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/** Fixed-order unsigned network-byte-order encodings from the manuscript's reference profile.
 * uint64 fields are restricted to [0, Long.MAX_VALUE] in this implementation.
 */
object WireCodec {
    private fun bytes(write: (DataOutputStream) -> Unit): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use(write)
        return out.toByteArray()
    }
    private fun input(value: ByteArray) = DataInputStream(ByteArrayInputStream(value))
    private fun DataInputStream.fixed(length: Int): ByteArray {
        require(length >= 0 && length <= available()) { "Truncated field" }
        return ByteArray(length).also { readFully(it) }
    }
    private fun DataInputStream.nonnegativeLong(): Long = readLong().also { require(it >= 0) { "Unsupported unsigned integer" } }
    private fun DataInputStream.end() = require(available() == 0) { "Trailing bytes are not canonical" }
    private fun DataOutputStream.sized16(value: ByteArray) {
        require(value.size <= 65535)
        writeShort(value.size)
        write(value)
    }
    private fun DataInputStream.sized16(expected: Int): ByteArray {
        require(readUnsignedShort() == expected) { "Unexpected field length" }
        return fixed(expected)
    }

    fun encodeBody(body: CredentialBody): ByteArray {
        require(body.version == PhapProfile.VERSION && body.suite == PhapProfile.SUITE) { "Unsupported credential profile" }
        require(body.serial > 0 && body.notBeforeMillis >= 0 && body.notAfterMillis > body.notBeforeMillis)
        require(body.sm2PublicKey.size == 65 && body.sm2PublicKey[0] == 4.toByte()) { "Expected uncompressed SM2 key" }
        return bytes { out ->
            out.writeByte(body.version)
            out.writeShort(body.suite)
            out.write(Hex.id(body.issuerId))
            out.write(Hex.id(body.subjectId))
            out.writeLong(body.serial)
            out.writeLong(body.notBeforeMillis)
            out.writeLong(body.notAfterMillis)
            out.sized16(body.sm2PublicKey)
            out.sized16(byteArrayOf()) // The endpoint Falcon-key field is empty in PHAP.
        }.also { check(it.size == PhapProfile.BODY_BYTES) }
    }

    fun decodeBody(encoded: ByteArray): CredentialBody {
        require(encoded.size == PhapProfile.BODY_BYTES) { "Incorrect PHAP body length" }
        return input(encoded).use { stream ->
            val version = stream.readUnsignedByte()
            val suite = stream.readUnsignedShort()
            require(version == PhapProfile.VERSION && suite == PhapProfile.SUITE) { "Credential downgrade or unsupported profile" }
            val issuer = Hex.encode(stream.fixed(16))
            val subject = Hex.encode(stream.fixed(16))
            val serial = stream.nonnegativeLong()
            val start = stream.nonnegativeLong()
            val end = stream.nonnegativeLong()
            val key = stream.sized16(65)
            stream.sized16(0)
            stream.end()
            CredentialBody(issuer, subject, serial, start, end, key, version, suite).also { encodeBody(it) }
        }
    }

    fun encodeCredential(credential: Credential): ByteArray {
        val body = encodeBody(credential.body)
        require(credential.sm2Signature.size == 64 && credential.falconSignature.size == 666) { "Both authority signatures are required" }
        return bytes { out ->
            out.writeInt(body.size)
            out.write(body)
            out.sized16(credential.sm2Signature)
            out.sized16(credential.falconSignature)
        }.also { check(it.size == PhapProfile.CREDENTIAL_BYTES) }
    }

    fun decodeCredential(encoded: ByteArray): Credential {
        require(encoded.size == PhapProfile.CREDENTIAL_BYTES) { "Incorrect PHAP credential length" }
        return input(encoded).use { stream ->
            require(stream.readInt() == PhapProfile.BODY_BYTES)
            val body = decodeBody(stream.fixed(PhapProfile.BODY_BYTES))
            val sm2 = stream.sized16(64)
            val falcon = stream.sized16(666)
            stream.end()
            Credential(body, sm2, falcon)
        }
    }

    private fun DataOutputStream.envelope(envelope: MessageEnvelope) {
        write(Hex.id(envelope.senderId))
        write(Hex.id(envelope.destinationId))
        require(envelope.sequence > 0 && envelope.timestampMillis >= 0)
        writeLong(envelope.sequence)
        writeLong(envelope.timestampMillis)
        writeInt(envelope.payload.size)
    }

    /** Exact canonical W = Enc(GRID-MSG, version, suite, rho, A). */
    fun messageSignedBytes(envelope: MessageEnvelope, credentialDigest: String): ByteArray = bytes { out ->
        out.write("GRID-MSG".toByteArray(Charsets.US_ASCII))
        out.writeByte(PhapProfile.VERSION)
        out.writeShort(PhapProfile.SUITE)
        out.write(Hex.digest(credentialDigest))
        out.envelope(envelope)
        out.write(envelope.payload)
    }

    /** 92-byte record header followed by payload and the 64-byte SM2 signature.
     * Optional credential fragments are encoded separately by the transport adapter.
     */
    fun encodeMessage(packet: MessagePacket): ByteArray {
        require(packet.sm2Signature.size == 64)
        return bytes { out ->
            out.writeByte(2)
            out.writeByte(PhapProfile.VERSION)
            out.writeShort(PhapProfile.SUITE)
            out.write(Hex.digest(packet.credentialDigest))
            out.envelope(packet.envelope)
            out.writeShort(64)
            out.writeShort(0) // No endpoint Falcon signature in the partial profile.
            out.write(packet.envelope.payload)
            out.write(packet.sm2Signature)
        }
    }

    fun decodeMessage(encoded: ByteArray, maxPayloadBytes: Int = 64 * 1024): MessagePacket {
        require(maxPayloadBytes >= 0 && encoded.size.toLong() <= 156L + maxPayloadBytes) { "Oversized message" }
        require(encoded.size >= 156) { "Truncated message" }
        return input(encoded).use { stream ->
            require(stream.readUnsignedByte() == 2 && stream.readUnsignedByte() == PhapProfile.VERSION)
            require(stream.readUnsignedShort() == PhapProfile.SUITE) { "Message downgrade or unsupported suite" }
            val digest = Hex.encode(stream.fixed(32))
            val sender = Hex.encode(stream.fixed(16))
            val destination = Hex.encode(stream.fixed(16))
            val sequence = stream.nonnegativeLong()
            val time = stream.nonnegativeLong()
            val payloadLength = stream.readInt()
            require(payloadLength in 0..maxPayloadBytes && sequence > 0)
            require(stream.readUnsignedShort() == 64 && stream.readUnsignedShort() == 0)
            require(stream.available().toLong() == payloadLength.toLong() + 64L) { "Inconsistent message length" }
            val payload = stream.fixed(payloadLength)
            val signature = stream.fixed(64)
            stream.end()
            MessagePacket(MessageEnvelope(sender, destination, sequence, time, payload), digest, signature)
        }
    }

    fun encodeFragment(fragment: CredentialFragment): ByteArray {
        require(fragment.index in 1..fragment.count && fragment.count <= 65535 && fragment.totalLength > 0)
        require(fragment.bytes.size in 1..65535)
        return bytes { out ->
            out.writeByte(1)
            out.writeByte(PhapProfile.VERSION)
            out.write(Hex.digest(fragment.credentialDigest))
            out.writeShort(fragment.index)
            out.writeShort(fragment.count)
            out.writeInt(fragment.totalLength)
            out.writeShort(fragment.bytes.size)
            out.write(fragment.bytes)
        }
    }

    fun decodeFragment(encoded: ByteArray, maxCredentialBytes: Int = 4096, maxFragmentBytes: Int = 256): CredentialFragment {
        require(maxCredentialBytes > 0 && maxFragmentBytes in 1..65535)
        require(encoded.size in 45..(44 + maxFragmentBytes)) { "Invalid fragment record length" }
        return input(encoded).use { stream ->
            require(stream.readUnsignedByte() == 1 && stream.readUnsignedByte() == PhapProfile.VERSION)
            val digest = Hex.encode(stream.fixed(32))
            val index = stream.readUnsignedShort()
            val count = stream.readUnsignedShort()
            val total = stream.readInt()
            val length = stream.readUnsignedShort()
            require(index in 1..count && total in 1..maxCredentialBytes && length in 1..maxFragmentBytes)
            require(length == stream.available())
            CredentialFragment(digest, index, count, total, stream.fixed(length))
        }
    }
}
