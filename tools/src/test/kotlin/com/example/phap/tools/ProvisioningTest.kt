package com.example.phap.tools

import com.example.v2v0614.protocol.*
import com.example.v2v0614.provisioning.*
import com.google.gson.JsonParser
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class ProvisioningTest {
    private val crypto = CryptoProvider()
    private fun reject(action: () -> Unit) { try { action(); fail("Expected rejection") } catch (_: IllegalArgumentException) { } catch (_: IllegalStateException) { } }

    @Test fun enrollmentProofBindsIdentityAndKey() {
        val id = "ab".repeat(16)
        val keys = crypto.generateSm2KeyPair()
        val text = BundleCodec.enrollment(id, keys, crypto)
        assertArrayEquals(keys.publicKey, BundleCodec.readEnrollment(text, crypto).publicKey)
        val modified = JsonParser.parseString(text).asJsonObject
        modified.addProperty("subjectId", "cd".repeat(16))
        reject { BundleCodec.readEnrollment(modified.toString(), crypto) }
        modified.addProperty("subjectId", id)
        modified.addProperty("sm2PublicKey", Hex.encode(crypto.generateSm2KeyPair().publicKey))
        reject { BundleCodec.readEnrollment(modified.toString(), crypto) }
    }

    @Test fun offlineIssuanceChecksApprovalIssuesDualCredentialAndExportsRevocation() {
        val dir = Files.createTempDirectory("phap-authority-test-")
        try {
            val issuer = "01".repeat(16); val subject = "02".repeat(16)
            val state = dir.resolve("ca-private.json"); val request = dir.resolve("request.json")
            val credentialFile = dir.resolve("credential.json"); val anchorsFile = dir.resolve("anchors.json")
            runCommand(arrayOf("new-ca","--state",state.toString(),"--issuer-id",issuer,"--sm2-id","aabbcc"))
            val endpoint = crypto.generateSm2KeyPair()
            Files.write(request, BundleCodec.enrollment(subject, endpoint, crypto).toByteArray())
            fun issue(approved: String) = runCommand(arrayOf("issue","--state",state.toString(),"--request",request.toString(),"--subject-id",approved,"--out",credentialFile.toString(),"--anchors",anchorsFile.toString()))
            reject { issue("03".repeat(16)) }
            assertFalse(Files.exists(credentialFile))
            issue(subject)
            val encoded = BundleCodec.readCredential(String(Files.readAllBytes(credentialFile))).credential
            val anchors = BundleCodec.readAnchors(String(Files.readAllBytes(anchorsFile)), crypto, System.currentTimeMillis())
            val credential = CredentialVerifier(anchors.anchors, crypto, anchors.policy()).verify(encoded, System.currentTimeMillis())
            assertEquals(866, encoded.size); assertEquals(subject, credential.body.subjectId)
            assertArrayEquals(endpoint.publicKey, credential.body.sm2PublicKey)
            assertFalse(String(Files.readAllBytes(anchorsFile)).contains("PrivateKey"))
            assertEquals(2L, JsonParser.parseString(String(Files.readAllBytes(state))).asJsonObject["nextSerial"].asLong)
            runCommand(arrayOf("revoke","--state",state.toString(),"--serial","1","--out",anchorsFile.toString()))
            val revoked = BundleCodec.readAnchors(String(Files.readAllBytes(anchorsFile)), crypto, System.currentTimeMillis())
            reject { CredentialVerifier(revoked.anchors, crypto, revoked.policy()).verify(encoded, System.currentTimeMillis()) }
            reject { runCommand(arrayOf("new-ca","--state",state.toString(),"--issuer-id",issuer,"--sm2-id","aabbcc")) }
        } finally { dir.toFile().deleteRecursively() }
    }
}
