package com.example.phap.tools

import com.example.v2v0614.protocol.CryptoProvider
import com.example.v2v0614.provisioning.BundleCodec
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Operator-supplied output aliases must never overwrite the CA's private state. */
class CaPathRegressionTest {
    @Rule @JvmField val temporary = TemporaryFolder()
    private val issuer = "a1".repeat(16)
    private val subject = "b2".repeat(16)

    private fun newAuthority(root: Path): Path {
        val state = root.resolve("authority-private.json")
        runCommand(arrayOf("new-ca", "--state", state.toString(), "--issuer-id", issuer,
            "--sm2-id", "746573742d6361"))
        return state
    }

    private fun hash(path: Path): ByteArray = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))

    private fun rejectAndPreserve(state: Path, args: Array<String>) {
        val before = hash(state)
        var rejected = false
        try {
            runCommand(args)
        } catch (_: Exception) {
            rejected = true
        }
        assertTrue("An authority-state output alias must be rejected", rejected)
        assertArrayEquals("Rejecting an output alias must preserve private authority state", before, hash(state))
    }

    @Test fun anchorExportRejectsDotAndDotDotAuthorityAliases() {
        val root = temporary.root.toPath()
        val state = newAuthority(root)
        Files.createDirectory(root.resolve("sub"))
        for (alias in listOf(root.resolve("./authority-private.json"), root.resolve("sub/../authority-private.json"))) {
            rejectAndPreserve(state, arrayOf("anchors", "--state", state.toString(), "--out", alias.toString()))
        }
    }

    @Test fun anchorExportRejectsSymlinkAndHardlinkAuthorityAliases() {
        val root = temporary.root.toPath()
        val state = newAuthority(root)
        val symlink = root.resolve("authority-symlink.json")
        Files.createSymbolicLink(symlink, state)
        val hardlink = root.resolve("authority-hardlink.json")
        Files.createLink(hardlink, state)
        val parentAlias = root.resolve("directory-alias")
        Files.createSymbolicLink(parentAlias, root)
        try {
            for (alias in listOf(symlink, hardlink, parentAlias.resolve(state.fileName))) {
                rejectAndPreserve(state, arrayOf("anchors", "--state", state.toString(), "--out", alias.toString()))
            }
        } finally {
            // TemporaryFolder's recursive cleanup predates NIO and may follow
            // directory symlinks; remove this self-alias before its cleanup.
            Files.deleteIfExists(parentAlias)
        }
        // Aliasing the --state side must produce the same protection.
        rejectAndPreserve(state, arrayOf("anchors", "--state", hardlink.toString(), "--out", state.toString()))
    }

    @Test fun issuanceRejectsEitherOutputAliasingPrivateAuthorityState() {
        val root = temporary.root.toPath()
        val state = newAuthority(root)
        val crypto = CryptoProvider()
        val request = root.resolve("request.json")
        Files.write(request, BundleCodec.enrollment(subject, crypto.generateSm2KeyPair(), crypto).toByteArray())
        val requestBefore = hash(request)
        val sub = Files.createDirectory(root.resolve("sub"))
        val aliases = listOf(root.resolve("./authority-private.json"), sub.resolve("../authority-private.json"))
        for ((index, alias) in aliases.withIndex()) {
            for (field in listOf("out", "anchors")) {
                val credentialOutput = if (field == "out") alias else root.resolve("credential-$index.json")
                val anchorOutput = if (field == "anchors") alias else root.resolve("anchors-$index.json")
                rejectAndPreserve(state, arrayOf("issue", "--state", state.toString(),
                    "--request", request.toString(), "--subject-id", subject,
                    "--out", credentialOutput.toString(), "--anchors", anchorOutput.toString()))
                assertArrayEquals(requestBefore, hash(request))
            }
        }
    }

    @Test fun newAuthorityRefusesExistingAuthorityThroughAliases() {
        val root = temporary.root.toPath()
        val state = newAuthority(root)
        Files.createDirectory(root.resolve("sub"))
        val alias = root.resolve("private-link.json")
        Files.createSymbolicLink(alias, state)
        for (target in listOf(root.resolve("./authority-private.json"), root.resolve("sub/../authority-private.json"), alias)) {
            rejectAndPreserve(state, arrayOf("new-ca", "--state", target.toString(), "--issuer-id", issuer,
                "--sm2-id", "746573742d6361"))
        }
    }
}
