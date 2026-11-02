package com.example.v2v0614.protocol

import org.junit.Assert.*
import org.junit.Test

class ProtocolEngineTest {
    companion object {
        private val crypto = CryptoProvider()
        private val caSm2 by lazy { crypto.generateSm2KeyPair() }
        private val caFalcon by lazy { crypto.generateFalconKeyPair() }
        private val endpoint by lazy { crypto.generateSm2KeyPair() }
        private val issuer = "01".repeat(16)
        private val subject = "02".repeat(16)
        private val receiverId = "03".repeat(16)
        private val otherId = "04".repeat(16)
        private val caIdentity = "PHAP experimental authority".toByteArray()
        private const val NOW = 1_700_000_000_000L
    }
    private class Clock(var wall: Long = NOW, var monotonic: Long = 0) : ProtocolClock {
        override fun wallTimeMillis() = wall
        override fun monotonicTimeMillis() = monotonic
    }
    private fun body(serial: Long = 1, start: Long = NOW - 1000, end: Long = NOW + 60000) =
        CredentialBody(issuer, subject, serial, start, end, endpoint.publicKey.copyOf())
    private fun credential(serial: Long = 1): Credential = CredentialAuthority.issue(body(serial), caSm2.privateKey, caFalcon.privateKey, caIdentity, crypto)
    private fun encoded(serial: Long = 1) = WireCodec.encodeCredential(credential(serial))
    private fun anchor() = TrustAnchor(issuer, caIdentity.copyOf(), caSm2.publicKey.copyOf(), caFalcon.publicKey.copyOf())
    private fun policy(allowed: Set<String> = setOf(subject), revoked: Set<String> = emptySet(), statusEnd: Long = NOW + 60000) =
        SnapshotPolicy(allowed, revoked, statusEnd)
    private fun sender(bytes: ByteArray = encoded(), sequences: SequenceStore = InMemorySequenceStore()) = Sender(bytes, endpoint.privateKey, crypto, sequences)
    private fun receiver(
        policy: ProtocolPolicy = policy(), limits: ProtocolLimits = ProtocolLimits(),
        clock: Clock = Clock(), replay: ReplayStore = InMemoryReplayStore()
    ) = Receiver(receiverId, listOf(anchor()), crypto, replay, policy, limits, clock)
    private fun cache(sender: Sender, receiver: Receiver) {
        sender.fragments().forEach { assertNotEquals(ReceiveStatus.REJECTED, receiver.receiveFragment(it).status) }
        assertEquals(1, receiver.cachedCredentialCount)
        assertTrue(receiver.hasCachedCredential(sender.credentialDigest))
    }
    private fun expectFailure(action: () -> Unit) {
        try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } catch (_: IllegalStateException) { } catch (_: SecurityException) { }
    }

    @Test fun exactEncodingSizesAndRoundTrip() {
        val credential = credential()
        val encodedBody = WireCodec.encodeBody(credential.body)
        val bytes = WireCodec.encodeCredential(credential)
        assertEquals(128, encodedBody.size)
        assertEquals(866, bytes.size)
        assertArrayEquals(bytes, WireCodec.encodeCredential(WireCodec.decodeCredential(bytes)))
        val sender = sender(bytes)
        val message = sender.createMessage(receiverId, byteArrayOf(1, 2, 3), NOW)
        assertEquals(92 + 3 + 64, WireCodec.encodeMessage(message).size)
        assertArrayEquals(WireCodec.encodeMessage(message), WireCodec.encodeMessage(WireCodec.decodeMessage(WireCodec.encodeMessage(message))))
        val fragments = sender.fragments()
        assertEquals(listOf(256, 256, 256, 98), fragments.map { it.bytes.size })
        fragments.forEach { assertArrayEquals(WireCodec.encodeFragment(it), WireCodec.encodeFragment(WireCodec.decodeFragment(WireCodec.encodeFragment(it)))) }
    }

    @Test fun coldReconstructionAndIndividualVerificationSurviveFragmentReordering() {
        val sender = sender()
        val receiver = receiver()
        val first = sender.createMessage(receiverId, "first".toByteArray(), NOW)
        val second = sender.createMessage(receiverId, "second".toByteArray(), NOW)
        assertEquals(ReceiveStatus.PENDING, receiver.receive(second).status)
        assertEquals(ReceiveStatus.PENDING, receiver.receive(first).status)
        val fragments = sender.fragments()
        for (index in listOf(3, 1, 1, 0)) {
            val result = receiver.receiveFragment(fragments[index])
            assertEquals(ReceiveStatus.PENDING, result.status)
            assertTrue(result.deliveries.isEmpty())
        }
        val result = receiver.receiveFragment(fragments[2])
        assertEquals(ReceiveStatus.ACCEPTED, result.status)
        assertEquals(listOf(1L, 2L), result.deliveries.map { it.envelope.sequence })
        assertEquals(listOf("first", "second"), result.deliveries.map { String(it.envelope.payload) })
        assertEquals(0, receiver.incompleteContextCount)
    }

    @Test fun alteredBufferedMessageDoesNotAuthenticateBecauseCredentialWasValid() {
        val sender = sender()
        val receiver = receiver()
        val legitimate = sender.createMessage(receiverId, "original".toByteArray(), NOW)
        val tampered = legitimate.copy(envelope = legitimate.envelope.copy(payload = "modified".toByteArray()))
        assertEquals(ReceiveStatus.PENDING, receiver.receive(tampered).status)
        val results = sender.fragments().map { receiver.receiveFragment(it) }
        assertEquals(ReceiveStatus.REJECTED, results.last().status)
        assertTrue(results.flatMap { it.deliveries }.isEmpty())
        // Rejected signatures must not reserve replay state.
        assertEquals(ReceiveStatus.ACCEPTED, receiver.receive(legitimate).status)
    }

    @Test fun warmMessageMutationReplayAndDestinationAreRejected() {
        val sender = sender()
        val receiver = receiver()
        cache(sender, receiver)
        val message = sender.createMessage(receiverId, "load".toByteArray(), NOW)
        val signature = message.sm2Signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(message.copy(sm2Signature = signature)).status)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(message.copy(envelope = message.envelope.copy(destinationId = otherId))).status)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(message.copy(envelope = message.envelope.copy(senderId = otherId))).status)
        assertEquals(ReceiveStatus.ACCEPTED, receiver.receive(message).status)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(message).status)
    }

    @Test fun eachAuthoritySignatureIsRequiredAndNewBodyCannotBeSubstituted() {
        val original = credential()
        val verifier = CredentialVerifier(listOf(anchor()), crypto, policy())
        val badSm2 = original.sm2Signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val badFalcon = original.falconSignature.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() }
        expectFailure { verifier.verify(WireCodec.encodeCredential(original.copy(sm2Signature = badSm2)), NOW) }
        expectFailure { verifier.verify(WireCodec.encodeCredential(original.copy(falconSignature = badFalcon)), NOW) }
        expectFailure { verifier.verify(WireCodec.encodeCredential(original.copy(body = original.body.copy(serial = 2))), NOW) }
        expectFailure { WireCodec.encodeCredential(original.copy(sm2Signature = byteArrayOf())) }
        expectFailure { WireCodec.encodeCredential(original.copy(falconSignature = byteArrayOf())) }
    }

    @Test fun poisonedReconstructionNeverPopulatesCredentialCache() {
        val sender = sender()
        val receiver = receiver()
        val fragments = sender.fragments().toMutableList()
        fragments[1] = fragments[1].copy(bytes = fragments[1].bytes.copyOf().also { it[9] = (it[9].toInt() xor 1).toByte() })
        val last = fragments.map { receiver.receiveFragment(it) }.last()
        assertEquals(ReceiveStatus.REJECTED, last.status)
        assertEquals(0, receiver.cachedCredentialCount)
        assertEquals(0, receiver.incompleteContextCount)
        cache(sender, receiver)
    }

    @Test fun changedDigestCannotTransferSignatureBetweenGenuineCredentials() {
        val firstSender = sender(encoded(1))
        val secondSender = sender(encoded(2))
        val receiver = receiver()
        cache(firstSender, receiver)
        secondSender.fragments().forEach { receiver.receiveFragment(it) }
        val first = firstSender.createMessage(receiverId, byteArrayOf(4), NOW)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(first.copy(credentialDigest = secondSender.credentialDigest)).status)
        assertEquals(ReceiveStatus.ACCEPTED, receiver.receive(first).status)
    }

    @Test fun conflictingDuplicateClearsUntrustedContextWithoutDelivery() {
        val sender = sender()
        val receiver = receiver()
        val packet = sender.createMessage(receiverId, byteArrayOf(5), NOW)
        receiver.receive(packet)
        val first = sender.fragments().first()
        receiver.receiveFragment(first)
        val conflict = first.copy(bytes = first.bytes.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() })
        assertEquals(ReceiveStatus.REJECTED, receiver.receiveFragment(conflict).status)
        assertEquals(0, receiver.incompleteContextCount)
        assertEquals(0, receiver.cachedCredentialCount)
        val after = sender.fragments().map { receiver.receiveFragment(it) }.last()
        assertTrue(after.deliveries.isEmpty()) // The discarded buffer must not later be delivered.
    }

    @Test fun duplicatesDoNotExtendDeadlineAndMissingFragmentsAreReported() {
        val clock = Clock()
        val sender = sender()
        val receiver = receiver(clock = clock)
        receiver.receiveFragment(sender.fragments()[0])
        assertEquals(listOf(2, 3, 4), receiver.missingFragments(sender.credentialDigest))
        clock.monotonic = 4999
        receiver.receiveFragment(sender.fragments()[0])
        clock.monotonic = 5000
        assertEquals(1, receiver.expireIncomplete())
        assertEquals(0, receiver.incompleteContextCount)
        assertEquals(0, receiver.cachedCredentialCount)
    }

    @Test fun reconstructionCountIndexAndLengthAreCheckedBeforeAllocation() {
        val sender = sender()
        val receiver = receiver()
        val fragment = sender.fragments().first()
        for (bad in listOf(fragment.copy(count = 65535), fragment.copy(index = 0), fragment.copy(totalLength = Int.MAX_VALUE), fragment.copy(bytes = byteArrayOf(1)))) {
            assertEquals(ReceiveStatus.REJECTED, receiver.receiveFragment(bad).status)
            assertEquals(0, receiver.incompleteContextCount)
        }
    }

    @Test fun memoryLimitsBoundUnknownCredentialTrafficAndBuffers() {
        val sender = sender()
        val receiver = receiver(limits = ProtocolLimits(maxContexts = 1, maxBufferedMessagesPerContext = 1))
        val first = sender.createMessage(receiverId, byteArrayOf(1), NOW)
        val second = sender.createMessage(receiverId, byteArrayOf(2), NOW)
        assertEquals(ReceiveStatus.PENDING, receiver.receive(first).status)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(second).status)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(first.copy(credentialDigest = "ff".repeat(32))).status)
        assertEquals(1, receiver.incompleteContextCount)
        assertEquals(0, receiver.cachedCredentialCount)
    }

    @Test fun expiryRevocationStatusFreshnessAndAuthorizationAreRecheckedOnCacheUse() {
        val clock = Clock()
        val sender = sender()
        var revoked = false
        var permitted = true
        var statusFresh = true
        val dynamic = object : ProtocolPolicy {
            override fun credentialAllowed(body: CredentialBody, nowMillis: Long) = !revoked && statusFresh
            override fun messageAllowed(body: CredentialBody, envelope: MessageEnvelope) = permitted
        }
        val receiver = receiver(policy = dynamic, clock = clock)
        cache(sender, receiver)
        val message = sender.createMessage(receiverId, byteArrayOf(6), NOW)
        permitted = false
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(message).status)
        permitted = true
        assertEquals(ReceiveStatus.ACCEPTED, receiver.receive(message).status)
        revoked = true
        assertNotEquals(ReceiveStatus.ACCEPTED, receiver.receive(sender.createMessage(receiverId, byteArrayOf(7), NOW)).status)
        assertEquals(0, receiver.cachedCredentialCount)
        revoked = false
        assertFalse(receiver.hasCachedCredential(sender.credentialDigest))
        statusFresh = false
        sender.fragments().forEach { assertNotEquals(ReceiveStatus.ACCEPTED, receiver.receiveFragment(it).status) }
        assertEquals(0, receiver.cachedCredentialCount)
        statusFresh = true
        cache(sender, receiver)
        clock.wall = NOW + 60001
        assertNotEquals(ReceiveStatus.ACCEPTED, receiver.receive(message).status)
        assertEquals(0, receiver.cachedCredentialCount)
    }

    @Test fun untrustedIssuerUnapprovedSubjectAndStalePolicyCannotBeImported() {
        val bytes = encoded()
        expectFailure { CredentialVerifier(emptyList(), crypto, policy()).verify(bytes, NOW) }
        expectFailure { CredentialVerifier(listOf(anchor()), crypto, policy(allowed = emptySet())).verify(bytes, NOW) }
        expectFailure { CredentialVerifier(listOf(anchor()), crypto, policy(revoked = setOf("$issuer:1"))).verify(bytes, NOW) }
        expectFailure { CredentialVerifier(listOf(anchor()), crypto, policy(statusEnd = NOW - 1)).verify(bytes, NOW) }
        expectFailure { CredentialVerifier(listOf(anchor(), anchor()), crypto, policy()) }
    }

    @Test fun replayStateSurvivesCacheEvictionAndReceiverRestart() {
        val sender = sender()
        val replay = InMemoryReplayStore()
        val receiver = receiver(replay = replay)
        cache(sender, receiver)
        val first = sender.createMessage(receiverId, byteArrayOf(1), NOW)
        assertEquals(ReceiveStatus.ACCEPTED, receiver.receive(first).status)
        receiver.clearCredentialCache()
        cache(sender, receiver)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(first).status)
        val restarted = receiver(replay = replay)
        cache(sender, restarted)
        assertEquals(ReceiveStatus.REJECTED, restarted.receive(first).status)
        assertEquals(ReceiveStatus.ACCEPTED, restarted.receive(sender.createMessage(receiverId, byteArrayOf(2), NOW)).status)
    }

    @Test fun futureOverflowAndStaleMessagesDoNotAdvanceReplayState() {
        val clock = Clock()
        val sender = sender()
        val receiver = receiver(clock = clock)
        cache(sender, receiver)
        val packet = sender.createMessage(receiverId, byteArrayOf(1), NOW)
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(packet.copy(envelope = packet.envelope.copy(timestampMillis = Long.MAX_VALUE))).status)
        clock.wall = NOW + 10001
        assertEquals(ReceiveStatus.REJECTED, receiver.receive(packet).status)
        clock.wall = NOW
        assertEquals(ReceiveStatus.ACCEPTED, receiver.receive(packet).status)
    }

    @Test fun bufferedAndTrustAnchorArraysAreDefensivelyCopied() {
        val sender = sender()
        val copiedAnchor = anchor()
        val receiver = Receiver(receiverId, listOf(copiedAnchor), crypto, InMemoryReplayStore(), policy(), clock = Clock())
        copiedAnchor.sm2PublicKey.fill(0)
        copiedAnchor.falconPublicKey.fill(0)
        val packet = sender.createMessage(receiverId, "safe".toByteArray(), NOW)
        receiver.receive(packet)
        packet.envelope.payload.fill(0)
        packet.sm2Signature.fill(0)
        val result = sender.fragments().map { receiver.receiveFragment(it) }.last()
        assertEquals(ReceiveStatus.ACCEPTED, result.status)
        assertEquals("safe", String(result.deliveries.single().envelope.payload))
    }

    @Test fun parserRejectsDowngradeOversizeTrailingAndNegativeUnsignedFields() {
        val sender = sender()
        val packet = sender.createMessage(receiverId, byteArrayOf(1), NOW)
        val encoded = WireCodec.encodeMessage(packet)
        expectFailure { WireCodec.decodeMessage(encoded.copyOf().also { it[3] = 1 }) }
        expectFailure { WireCodec.decodeMessage(encoded + byteArrayOf(0)) }
        expectFailure { WireCodec.decodeMessage(encoded, maxPayloadBytes = 0) }
        expectFailure { WireCodec.decodeMessage(encoded.copyOf().also { it[68] = 0x80.toByte() }) }
        expectFailure { WireCodec.decodeCredential(encoded) }
        expectFailure { Sender(encoded(), crypto.generateSm2KeyPair().privateKey, crypto, InMemorySequenceStore()) }
    }
}
