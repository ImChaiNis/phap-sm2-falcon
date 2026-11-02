package com.example.v2v0614.protocol

import org.bouncycastle.asn1.gm.GMNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithID
import org.bouncycastle.crypto.signers.PlainDSAEncoding
import org.bouncycastle.crypto.signers.SM2Signer
import org.bouncycastle.pqc.crypto.falcon.FalconParameters
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters
import org.bouncycastle.pqc.crypto.falcon.FalconSigner
import org.junit.Assert.*
import org.junit.Test

class CryptoProviderTest {
    private val crypto = CryptoProvider()
    private val identity = ByteArray(16) { (it + 1).toByte() }
    private val message = byteArrayOf(0x00, 0x7f, 0xff.toByte(), 0x00) + "binary credential".toByteArray()

    @Test fun sm2BindsBinaryMessageIdentityAndPublicKey() {
        val key = crypto.generateSm2KeyPair()
        assertEquals(65, key.publicKey.size)
        assertEquals(32, key.privateKey.size)
        assertArrayEquals(key.publicKey, crypto.sm2PublicKey(key.privateKey))
        assertTrue(crypto.validateSm2PublicKey(key.publicKey))
        val signature = crypto.sm2Sign(key.privateKey, identity, message)
        assertEquals(64, signature.size)
        assertTrue(crypto.sm2Verify(key.publicKey, identity, message, signature))
        assertFalse(crypto.sm2Verify(key.publicKey, identity + 0x00, message, signature))
        assertFalse(crypto.sm2Verify(key.publicKey, identity, message + 0x00, signature))
        assertFalse(crypto.sm2Verify(crypto.generateSm2KeyPair().publicKey, identity, message, signature))
        val altered = signature.copyOf().also { it[33] = (it[33].toInt() xor 1).toByte() }
        assertFalse(crypto.sm2Verify(key.publicKey, identity, message, altered))

        // Independent BC signer invocation checks that the wrapper emits the
        // standard SM2 identity-bound raw signature rather than a private format.
        val c = GMNamedCurves.getByName("sm2p256v1")
        val domain = ECDomainParameters(c.curve, c.g, c.n, c.h)
        val verifier = SM2Signer(PlainDSAEncoding.INSTANCE)
        verifier.init(false, ParametersWithID(ECPublicKeyParameters(c.curve.decodePoint(key.publicKey), domain), identity))
        verifier.update(message, 0, message.size)
        assertTrue(verifier.verifySignature(signature))
    }

    @Test fun sm2RejectsMalformedInputsInsteadOfThrowing() {
        val key = crypto.generateSm2KeyPair()
        val sig = crypto.sm2Sign(key.privateKey, identity, message)
        assertFalse(crypto.sm2Verify(key.publicKey, identity, message, ByteArray(64)))
        assertFalse(crypto.sm2Verify(key.publicKey, identity, message, ByteArray(65)))
        assertFalse(crypto.sm2Verify(key.publicKey.copyOf(64), identity, message, sig))
        assertFalse(crypto.sm2Verify(ByteArray(65).also { it[0] = 4 }, identity, message, sig))
        assertFalse(crypto.validateSm2PublicKey(ByteArray(65).also { it[0] = 4 }))
        assertFalse(crypto.sm2Verify(key.publicKey, ByteArray(0), message, sig))
        assertFalse(crypto.sm2Verify(key.publicKey, ByteArray(8192), message, sig))
        assertThrows(IllegalArgumentException::class.java) { crypto.sm2Sign(ByteArray(32), identity, message) }
    }

    @Test fun falconPaddedSignatureIsFixedLengthAndAuthenticates() {
        val key = crypto.generateFalconKeyPair()
        assertEquals(897, key.publicKey.size)
        assertEquals(1281, key.privateKey.size)
        assertEquals(0x09, key.publicKey[0].toInt())
        assertEquals(0x59, key.privateKey[0].toInt())
        assertTrue(crypto.validateFalconPublicKey(key.publicKey))
        assertFalse(crypto.validateFalconPublicKey(key.publicKey.copyOf().also { it[0] = 8 }))
        val signature = crypto.falconSign(key.privateKey, message)
        assertEquals(666, signature.size)
        assertEquals(0x39, signature[0].toInt())
        assertTrue(crypto.falconVerify(key.publicKey, message, signature))
        assertFalse(crypto.falconVerify(key.publicKey, message + 0, signature))
        assertFalse(crypto.falconVerify(crypto.generateFalconKeyPair().publicKey, message, signature))
        val alteredNonce = signature.copyOf().also { it[3] = (it[3].toInt() xor 1).toByte() }
        assertFalse(crypto.falconVerify(key.publicKey, message, alteredNonce))
        // A nonzero trailing padding byte must never be silently discarded.
        val alteredPad = signature.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFalse(crypto.falconVerify(key.publicKey, message, alteredPad))
        assertFalse(crypto.falconVerify(key.publicKey, message, signature.copyOf(665)))
        assertFalse(crypto.falconVerify(key.publicKey, message, signature.copyOf(667)))
        assertFalse(crypto.falconVerify(key.publicKey.copyOf().also { it[0] = 8 }, message, signature))
        assertFalse(crypto.falconVerify(ByteArray(897).also { it[0] = 9 }, message, ByteArray(666)))

        // BC accepts only the exact compressed encoding, while the protocol
        // accepts only PADDED. Finding a BC-verifiable prefix proves the wrapper
        // emits an ordinary Falcon signature beneath the fixed-length padding.
        val verifier = FalconSigner()
        verifier.init(false, FalconPublicKeyParameters(FalconParameters.falcon_512, key.publicKey.copyOfRange(1, 897)))
        val verifiedPrefix = (41..666).any { used ->
            try { verifier.verifySignature(message, signature.copyOf(used)) } catch (_: Exception) { false }
        }
        assertTrue(verifiedPrefix)
    }

    @Test fun falconRejectsMalformedCoefficientEncoding() {
        val key = crypto.generateFalconKeyPair()
        val negativeZero = ByteArray(666)
        negativeZero[0] = 0x39
        negativeZero[41] = 0x80.toByte() // sign=1, magnitude low=0
        negativeZero[42] = 0x80.toByte() // unary terminator=1 => negative zero
        assertFalse(crypto.falconVerify(key.publicKey, message, negativeZero))
        val truncatedUnary = ByteArray(666).also { it[0] = 0x39 }
        assertFalse(crypto.falconVerify(key.publicKey, message, truncatedUnary))
    }

    @Test fun digestUsesSha256() {
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".chunked(2)
            .map { it.toInt(16).toByte() }.toByteArray()
        assertArrayEquals(expected, crypto.digest("abc".toByteArray()))
    }

    @Test fun sm2VerifiesPublishedStandardCurveExample() {
        // BC's primary SM2SignerTest.doSignerTestFpStandardSM3 known answer:
        // github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/crypto/test/SM2SignerTest.java
        // Expected signature is fixed externally; this is not a self-sign roundtrip.
        val public = crypto.sm2PublicKey(hex(
            "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC"))
        val signature = hex(
            "05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA" +
            "E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993")
        assertTrue(crypto.sm2Verify(public, "sm2test@example.com".toByteArray(), "hi chappy".toByteArray(), signature))
        assertFalse(crypto.sm2Verify(public, "sm2tess@example.com".toByteArray(), "hi chappy".toByteArray(), signature))
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
