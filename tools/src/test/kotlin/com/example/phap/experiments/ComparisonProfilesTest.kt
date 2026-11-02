package com.example.phap.experiments

import com.example.v2v0614.protocol.*
import org.junit.Assert.*
import org.junit.Test

class ComparisonProfilesTest {
    companion object {
        private val crypto = CryptoProvider()
        private val keys by lazy { CompareKeyMaterial.generate(crypto) }
        private const val NOW = 1_800_000_000_000L
    }
    private fun fixture(suite: Int) = ProfileFixture(suite,crypto,keys,NOW)
    private fun rejected(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } }

    @Test fun actualCredentialAndMessageEncodingsHaveTheSpecifiedSizes() {
        for (suite in 1..4) {
            val fixture = fixture(suite)
            assertEquals(if (suite >= 3) 1025 else 128,fixture.bodySize)
            assertEquals(listOf(200,866,1763,1763)[suite-1],fixture.credentialSize)
            assertEquals(listOf(64,64,666,730)[suite-1],fixture.messageSignatureSize)
            assertEquals(listOf(1,4,7,7)[suite-1],fixture.fragments().size)
            assertArrayEquals(fixture.credentialBytes,fixture.fragmentPayloads().fold(byteArrayOf()) { all,part -> all+part })
            val message = fixture.prepareMessage(ByteArray(128) { it.toByte() },1,NOW)
            assertEquals(92+128+fixture.messageSignatureSize,message.size)
            assertEquals(223,fixture.parseMessage(message).signedInput.size)
            fixture.verifyCredential(fixture.credentialBytes,NOW,fixture.credentialDigest)
        }
    }

    @Test fun allProfilesActuallyVerifyAndRejectReplayAndTampering() {
        for (suite in 1..4) {
            val fixture = fixture(suite)
            val credential = fixture.verifyCredential(fixture.credentialBytes,NOW)
            val message = fixture.prepareMessage("real cryptography".toByteArray(),1,NOW)
            val replay = InMemoryReplayStore()
            val altered = message.copyOf().also { it[92] = (it[92].toInt() xor 1).toByte() }
            assertFalse(fixture.verifyMessage(altered,credential,NOW,replay))
            assertTrue(fixture.verifyMessage(message,credential,NOW,replay))
            assertFalse(fixture.verifyMessage(message,credential,NOW,replay))
            assertTrue(fixture.verifyMessage(fixture.prepareMessage(byteArrayOf(3),2,NOW),credential,NOW,replay))
        }
    }

    @Test fun everyRequiredAuthorityComponentIsVerified() {
        for (suite in 1..4) {
            val fixture = fixture(suite)
            val sm2 = fixture.credentialBytes.also { it[4+fixture.bodySize+2] = (it[4+fixture.bodySize+2].toInt() xor 1).toByte() }
            rejected { fixture.verifyCredential(sm2,NOW) }
            if (suite != 1) {
                val falcon = fixture.credentialBytes.also { it[4+fixture.bodySize+2+64+2+90] = (it[4+fixture.bodySize+2+64+2+90].toInt() xor 1).toByte() }
                rejected { fixture.verifyCredential(falcon,NOW) }
            }
            val body = fixture.credentialBytes.also { it[4+3+16+16+7] = 9 }
            rejected { fixture.verifyCredential(body,NOW) }
            rejected { fixture.verifyCredential(fixture.credentialBytes,NOW,"00".repeat(32)) }
        }
    }

    @Test fun bothMessageComponentsMustVerifyInTheDualProfile() {
        val fixture = fixture(4)
        val verified = fixture.verifyCredential(fixture.credentialBytes,NOW)
        val message = fixture.prepareMessage(byteArrayOf(1,2),1,NOW)
        for (offset in listOf(92+2,92+2+64+80)) {
            val modified = message.copyOf().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            assertFalse(fixture.verifyMessage(modified,verified,NOW,InMemoryReplayStore()))
        }
        assertTrue(fixture.verifyMessage(message,verified,NOW,InMemoryReplayStore()))
    }

    @Test fun freshnessDestinationSuiteAndUnknownAuthorityAreRejected() {
        for (suite in 1..4) {
            val fixture = fixture(suite); val verified = fixture.verifyCredential(fixture.credentialBytes,NOW)
            assertFalse(fixture.verifyMessage(fixture.prepareMessage(byteArrayOf(1),1,NOW,"44".repeat(16)),verified,NOW,InMemoryReplayStore()))
            assertFalse(fixture.verifyMessage(fixture.prepareMessage(byteArrayOf(1),1,NOW-10001),verified,NOW,InMemoryReplayStore()))
            assertFalse(fixture.verifyMessage(fixture.prepareMessage(byteArrayOf(1),1,NOW+2001),verified,NOW,InMemoryReplayStore()))
            val foreign = ProfileFixture(suite,crypto,CompareKeyMaterial.generate(crypto),NOW)
            rejected { foreign.verifyCredential(fixture.credentialBytes,NOW) }
            rejected { fixture.verifyCredential(fixture.credentialBytes,NOW+3_600_001) }
            val downgraded = fixture.credentialBytes.also { it[6] = if (suite == 1) 2 else 1 }
            rejected { fixture.verifyCredential(downgraded,NOW) }
        }
    }

    @Test fun partialProfileInteroperatesWithTheProductionCoreInBothDirections() {
        val fixture = fixture(2)
        val bytes = fixture.credentialBytes
        val policy = SnapshotPolicy(setOf(keys.subjectId),emptySet(),NOW+3_600_000)
        val anchor = TrustAnchor(keys.issuerId,keys.authoritySignerId,keys.authoritySm2.publicKey,keys.authorityFalcon.publicKey)
        val decoded = WireCodec.decodeCredential(bytes)
        assertArrayEquals(fixture.bodyBytes,WireCodec.encodeBody(decoded.body))
        CredentialVerifier(listOf(anchor),crypto,policy).verify(bytes,NOW)
        val receiver = Receiver(keys.destinationId,listOf(anchor),crypto,InMemoryReplayStore(),policy,
            clock=object:ProtocolClock {
                override fun wallTimeMillis()=NOW
                override fun monotonicTimeMillis()=0L
            })
        fixture.fragments().forEach { receiver.receiveFragment(it) }
        assertEquals(ReceiveStatus.ACCEPTED,receiver.receive(WireCodec.decodeMessage(fixture.prepareMessage(byteArrayOf(7),1,NOW))).status)
        val sender = Sender(bytes,keys.endpointSm2.privateKey,crypto,InMemorySequenceStore())
        val productionMessage = WireCodec.encodeMessage(sender.createMessage(keys.destinationId,byteArrayOf(8),NOW))
        assertTrue(fixture.verifyMessage(productionMessage,fixture.verifyCredential(bytes,NOW),NOW,InMemoryReplayStore()))
        for (suite in listOf(1,3,4)) rejected { WireCodec.decodeCredential(fixture(suite).credentialBytes) }
    }
}
