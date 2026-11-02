package com.example.v2v0614.protocol

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.asn1.gm.GMNamedCurves
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithID
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.PlainDSAEncoding
import org.bouncycastle.crypto.signers.SM2Signer
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator
import org.bouncycastle.pqc.crypto.falcon.FalconParameters
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters
import org.bouncycastle.pqc.crypto.falcon.FalconSigner
import org.bouncycastle.util.BigIntegers

/** Raw protocol encodings, not X.509/PKCS#8 objects. Never log privateKey. */
data class CryptoKeyPair(val publicKey: ByteArray, val privateKey: ByteArray)

/**
 * Real cryptographic primitives, provided by Bouncy Castle's lightweight API.
 *
 * SM2 uses sm2p256v1 + SM3 and an explicitly supplied signer identity in Z_A.
 * Signatures are raw r || s (64 bytes); public keys are uncompressed SEC1 (65).
 * Falcon uses degree 512; standard public/private encodings include their
 * 0x09/0x59 headers. The adapter below changes compressed *encoding* to the
 * reference PADDED format, not the signature arithmetic: it checks the codec,
 * retries oversized signatures and requires exactly 666 bytes with zero pad.
 *
 * Every operation creates a fresh signer, so instances can be shared by callers.
 * The JVM provider does not claim to be a certified cryptographic module.
 */
class CryptoProvider(private val random: SecureRandom = SecureRandom()) {
    private val curve = GMNamedCurves.getByName("sm2p256v1")
    private val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h)

    fun generateSm2KeyPair(): CryptoKeyPair {
        val generator = ECKeyPairGenerator()
        generator.init(ECKeyGenerationParameters(domain, random))
        // Generic EC generators may return n-1, which SM2 must exclude because
        // its signing equation uses (1+d)^-1 modulo n.
        while (true) {
            val pair = generator.generateKeyPair()
            val secret = pair.private as ECPrivateKeyParameters
            if (secret.d < domain.n.subtract(BigInteger.ONE)) {
                return CryptoKeyPair(
                    (pair.public as ECPublicKeyParameters).q.getEncoded(false),
                    BigIntegers.asUnsignedByteArray(SM2_PRIVATE_BYTES, secret.d)
                )
            }
        }
    }

    fun sm2PublicKey(privateKey: ByteArray): ByteArray =
        domain.g.multiply(sm2Private(privateKey).d).normalize().getEncoded(false)

    fun validateSm2PublicKey(publicKey: ByteArray): Boolean = try {
        sm2Public(publicKey)
        true
    } catch (_: Exception) {
        false
    }

    fun validateFalconPublicKey(publicKey: ByteArray): Boolean = try {
        falconPublic(publicKey)
        true
    } catch (_: Exception) {
        false
    }

    fun sm2Sign(privateKey: ByteArray, signerId: ByteArray, message: ByteArray): ByteArray {
        requireSignerId(signerId)
        val key = sm2Private(privateKey)
        val signer = SM2Signer(PlainDSAEncoding.INSTANCE)
        signer.init(true, ParametersWithID(ParametersWithRandom(key, random), signerId.copyOf()))
        signer.update(message, 0, message.size)
        return signer.generateSignature().also { check(it.size == SM2_SIGNATURE_BYTES) }
    }

    fun sm2Verify(
        publicKey: ByteArray,
        signerId: ByteArray,
        message: ByteArray,
        signature: ByteArray
    ): Boolean = try {
        requireSignerId(signerId)
        if (signature.size != SM2_SIGNATURE_BYTES) {
            false
        } else {
            val r = BigInteger(1, signature.copyOfRange(0, 32))
            val s = BigInteger(1, signature.copyOfRange(32, 64))
            if (r.signum() <= 0 || s.signum() <= 0 || r >= domain.n || s >= domain.n) {
                false
            } else {
                val signer = SM2Signer(PlainDSAEncoding.INSTANCE)
                signer.init(false, ParametersWithID(sm2Public(publicKey), signerId.copyOf()))
                signer.update(message, 0, message.size)
                signer.verifySignature(signature)
            }
        }
    } catch (_: Exception) {
        false
    }

    fun generateFalconKeyPair(): CryptoKeyPair {
        val generator = FalconKeyPairGenerator()
        generator.init(FalconKeyGenerationParameters(random, FalconParameters.falcon_512))
        val pair = generator.generateKeyPair()
        val public = (pair.public as FalconPublicKeyParameters).h
        val private = (pair.private as FalconPrivateKeyParameters).encoded
        check(public.size == FALCON_PUBLIC_BYTES - 1)
        check(private.size == FALCON_PRIVATE_BYTES - 1)
        return CryptoKeyPair(byteArrayOf(0x09) + public, byteArrayOf(0x59) + private)
    }

    fun falconSign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val key = falconPrivate(privateKey)
        val signer = FalconSigner()
        signer.init(true, ParametersWithRandom(key, random))
        repeat(MAX_PADDED_SIGN_ATTEMPTS) {
            // BC returns the reference compressed header + nonce + coefficients.
            val compressed = signer.generateSignature(message)
            if (compressed.size <= FALCON_SIGNATURE_BYTES &&
                compressedLength(compressed) == compressed.size
            ) {
                return compressed.copyOf(FALCON_SIGNATURE_BYTES)
            }
        }
        throw IllegalStateException("Falcon padded-signature size retry limit exceeded")
    }

    fun falconVerify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        if (signature.size != FALCON_SIGNATURE_BYTES) {
            false
        } else {
            val key = falconPublic(publicKey)
            val used = compressedLength(signature)
            if (used == null || (used until signature.size).any { signature[it] != 0.toByte() }) {
                false
            } else {
                val signer = FalconSigner()
                signer.init(false, key)
                signer.verifySignature(message, signature.copyOf(used))
            }
        }
    } catch (_: Exception) {
        false
    }

    fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun requireSignerId(id: ByteArray) {
        require(id.isNotEmpty() && id.size < 8192) { "SM2 signer identity must contain 1..8191 bytes" }
    }

    private fun sm2Private(encoded: ByteArray): ECPrivateKeyParameters {
        require(encoded.size == SM2_PRIVATE_BYTES) { "SM2 private key must be 32 bytes" }
        val d = BigInteger(1, encoded)
        require(d.signum() > 0 && d < domain.n.subtract(BigInteger.ONE)) { "SM2 private scalar out of range" }
        return ECPrivateKeyParameters(d, domain)
    }

    private fun sm2Public(encoded: ByteArray): ECPublicKeyParameters {
        require(encoded.size == SM2_PUBLIC_BYTES && encoded[0] == 0x04.toByte()) {
            "SM2 public key must be an uncompressed 65-byte point"
        }
        // BC validates canonical field coordinates, curve membership and infinity.
        val point = domain.curve.decodePoint(encoded).normalize()
        require(!point.isInfinity && point.isValid) { "Invalid SM2 public point" }
        return ECPublicKeyParameters(point, domain)
    }

    private fun falconPrivate(encoded: ByteArray): FalconPrivateKeyParameters {
        require(encoded.size == FALCON_PRIVATE_BYTES && encoded[0] == 0x59.toByte()) {
            "Falcon-512 private key must be a standard 1281-byte encoding"
        }
        return FalconPrivateKeyParameters(
            FalconParameters.falcon_512,
            encoded.copyOfRange(1, 385),
            encoded.copyOfRange(385, 769),
            encoded.copyOfRange(769, 1281),
            ByteArray(0)
        )
    }

    private fun falconPublic(encoded: ByteArray): FalconPublicKeyParameters {
        require(encoded.size == FALCON_PUBLIC_BYTES && encoded[0] == 0x09.toByte()) {
            "Falcon-512 public key must be a standard 897-byte encoding"
        }
        // The 512 public coefficients are unsigned 14-bit values strictly below q.
        val bits = BitReader(encoded, 8)
        repeat(512) { require(bits.read(14) < 12289) { "Noncanonical Falcon public key" } }
        return FalconPublicKeyParameters(FalconParameters.falcon_512, encoded.copyOfRange(1, encoded.size))
    }

    /**
     * Locate the exact end of the Falcon compressed coefficient encoding.
     * Each of 512 coefficients is sign || magnitude-low-7 || unary-high.
     * Reject truncated/unbounded unary, values outside +/-2047, negative zero,
     * and nonzero unused bits. Extra whole bytes are checked by the caller.
     * This is serialization validation; BC performs all Falcon arithmetic.
     */
    private fun compressedLength(signature: ByteArray): Int? = try {
        if (signature.size < FALCON_PREFIX_BYTES || signature[0] != 0x39.toByte()) {
            null
        } else {
            val bits = BitReader(signature, FALCON_PREFIX_BYTES * 8)
            repeat(512) {
                val sign = bits.read(1)
                var magnitude = bits.read(7)
                while (bits.read(1) == 0) {
                    magnitude += 128
                    require(magnitude <= 2047) { "Oversized Falcon coefficient" }
                }
                require(sign == 0 || magnitude != 0) { "Negative zero Falcon coefficient" }
            }
            while (bits.position % 8 != 0) {
                require(bits.read(1) == 0) { "Nonzero unused Falcon encoding bits" }
            }
            bits.position / 8
        }
    } catch (_: IllegalArgumentException) {
        null
    }

    private class BitReader(private val bytes: ByteArray, var position: Int) {
        fun read(count: Int): Int {
            require(count in 1..14 && position + count <= bytes.size * 8) { "Truncated Falcon encoding" }
            var value = 0
            repeat(count) {
                value = (value shl 1) or ((bytes[position ushr 3].toInt() ushr (7 - (position and 7))) and 1)
                position++
            }
            return value
        }
    }

    companion object {
        const val SM2_PRIVATE_BYTES = 32
        const val SM2_PUBLIC_BYTES = 65
        const val SM2_SIGNATURE_BYTES = 64
        const val FALCON_PRIVATE_BYTES = 1281
        const val FALCON_PUBLIC_BYTES = 897
        const val FALCON_SIGNATURE_BYTES = 666
        private const val FALCON_PREFIX_BYTES = 41
        private const val MAX_PADDED_SIGN_ATTEMPTS = 128
    }
}
