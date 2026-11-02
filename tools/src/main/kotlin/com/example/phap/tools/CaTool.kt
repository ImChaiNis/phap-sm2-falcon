package com.example.phap.tools

import com.example.v2v0614.protocol.*
import com.example.v2v0614.provisioning.*
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.system.exitProcess

private val crypto = CryptoProvider()
/** Canonicalize before locking or comparing: lexical aliases must not bypass state protection. */
private fun canonicalTarget(path: Path): Path {
    val absolute = path.toAbsolutePath().normalize()
    if (Files.exists(absolute)) return absolute.toRealPath()
    var existing = absolute.parent ?: throw IllegalArgumentException("Invalid file path")
    while (!Files.exists(existing)) existing = existing.parent ?: throw IllegalArgumentException("Invalid parent path")
    return existing.toRealPath().resolve(existing.relativize(absolute)).normalize()
}
private fun distinctFiles(vararg paths: Path) {
    for (i in paths.indices) for (j in i+1 until paths.size) {
        require(paths[i] != paths[j] && !(Files.exists(paths[i]) && Files.exists(paths[j]) && Files.isSameFile(paths[i], paths[j]))) {
            "Authority state, input, and output files must be distinct (including aliases)"
        }
    }
}
private fun privateFile(path: Path) {
    try { Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")) }
    catch (_: UnsupportedOperationException) { /* Use the operating system's private account ACLs. */ }
}
private fun writeAtomic(path: Path, text: String) {
    val parent = path.toAbsolutePath().parent
    Files.createDirectories(parent)
    val temp = Files.createTempFile(parent, ".phap-", ".tmp")
    try {
        privateFile(temp)
        Files.write(temp, text.toByteArray(Charsets.UTF_8))
        try { Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING) }
        catch (_: java.nio.file.AtomicMoveNotSupportedException) { Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING) }
    } finally { Files.deleteIfExists(temp) }
}
private fun readObject(path: Path): JsonObject {
    require(Files.size(path) <= 2 * 1024 * 1024) { "Oversized authority state" }
    return JsonParser.parseString(String(Files.readAllBytes(path), Charsets.UTF_8)).asJsonObject
}
private fun withLock(path: Path, action: () -> Unit) {
    val lockPath = path.toAbsolutePath().resolveSibling(path.fileName.toString() + ".lock")
    Files.createDirectories(lockPath.parent)
    FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
        privateFile(lockPath)
        channel.lock().use {
            // Atomic replacement would fork two hard-linked authority-state names.
            // Keep a single state name on POSIX filesystems; symlinks are canonicalized above.
            if (Files.exists(path) && Files.getFileStore(path).supportsFileAttributeView("unix")) {
                require((Files.getAttribute(path, "unix:nlink") as Number).toLong() == 1L) { "Authority state must not have hard-link aliases" }
            }
            action()
        }
    }
}
private fun anchor(state: JsonObject) = TrustAnchor(
    state["issuerId"].asString, Hex.decode(state["sm2SignerId"].asString),
    Hex.decode(state["sm2PublicKey"].asString), Hex.decode(state["falconPublicKey"].asString)
)
private fun publicBundle(state: JsonObject, seconds: Long): AnchorBundle {
    require(seconds in 60..86400) { "Policy lifetime must be 60..86400 seconds" }
    val until = Math.addExact(System.currentTimeMillis(), Math.multiplyExact(seconds, 1000L))
    val allowed = state.getAsJsonObject("subjects").keySet().toSet()
    val revoked = state.getAsJsonArray("revokedCredentials").map { it.asString }.toSet()
    return AnchorBundle(listOf(anchor(state)), allowed, revoked, until)
}
private fun checkState(state: JsonObject) {
    require(state["format"].asString == "PHAP-CA-PRIVATE-1")
    Hex.id(state["issuerId"].asString)
    require(state.getAsJsonObject("subjects").size() <= 1024)
    require(state.getAsJsonArray("revokedCredentials").size() <= 4096)
    require(state["nextSerial"].asLong > 0)
    val a = anchor(state)
    require(crypto.validateSm2PublicKey(a.sm2PublicKey) && crypto.validateFalconPublicKey(a.falconPublicKey))
    require(crypto.sm2PublicKey(Hex.decode(state["sm2PrivateKey"].asString)).contentEquals(a.sm2PublicKey))
}

/** Offline authority only. Never copy the authority state file to an endpoint. */
fun main(args: Array<String>) {
    try { runCommand(args) }
    catch (e: Exception) { System.err.println("PHAP: ${e.message ?: e.javaClass.simpleName}"); exitProcess(1) }
}

fun runCommand(args: Array<String>) {
    require(args.isNotEmpty()) { "Commands: new-ca, issue, anchors, revoke, demo" }
    val command = args[0]
    val options = mutableMapOf<String, String>()
    var i = 1
    while (i < args.size) {
        require(args[i].startsWith("--") && i + 1 < args.size)
        require(options.put(args[i].substring(2), args[i+1]) == null) { "Duplicate option" }
        i += 2
    }
    fun required(name: String) = options[name] ?: throw IllegalArgumentException("Missing --$name")
    fun path(name: String) = canonicalTarget(Paths.get(required(name)))
    fun seconds(name: String, default: Long) = options[name]?.toLong() ?: default
    val allowedOptions = when(command) {
        "new-ca" -> setOf("state", "issuer-id", "sm2-id")
        "issue" -> setOf("state", "request", "subject-id", "out", "anchors", "valid-seconds", "policy-seconds")
        "anchors" -> setOf("state", "out", "policy-seconds")
        "revoke" -> setOf("state", "serial", "out", "policy-seconds")
        "demo" -> setOf("out")
        else -> throw IllegalArgumentException("Unknown command")
    }
    require(options.keys.all { it in allowedOptions }) { "Unknown option" }
    when (command) {
        "new-ca" -> {
            val destination = path("state")
            val issuer = required("issuer-id").also(Hex::id)
            val id = Hex.decode(required("sm2-id")); require(id.size in 1..8191)
            withLock(destination) {
                require(!Files.exists(destination)) { "Authority state already exists; refusing replacement" }
                val sm2 = crypto.generateSm2KeyPair(); val falcon = crypto.generateFalconKeyPair()
                val state = JsonObject().apply {
                    addProperty("format", "PHAP-CA-PRIVATE-1"); addProperty("issuerId", issuer)
                    addProperty("sm2SignerId", Hex.encode(id))
                    addProperty("sm2PublicKey", Hex.encode(sm2.publicKey)); addProperty("sm2PrivateKey", Hex.encode(sm2.privateKey))
                    addProperty("falconPublicKey", Hex.encode(falcon.publicKey)); addProperty("falconPrivateKey", Hex.encode(falcon.privateKey))
                    addProperty("nextSerial", 1L); add("subjects", JsonObject()); add("issuedSerials", JsonArray()); add("revokedCredentials", JsonArray())
                }
                writeAtomic(destination, state.toString())
                println("Authority created. Public-key fingerprint SHA-256: ${Hex.encode(crypto.digest(sm2.publicKey + falcon.publicKey))}")
            }
        }
        "issue" -> {
            val statePath = path("state")
            val requestPath = path("request"); require(Files.size(requestPath) <= BundleCodec.MAX_BUNDLE_CHARS)
            val approved = required("subject-id").also(Hex::id)
            val request = BundleCodec.readEnrollment(String(Files.readAllBytes(requestPath), Charsets.UTF_8), crypto)
            require(request.subjectId == approved) { "Enrollment subject differs from operator-approved identity" }
            val output = path("out"); val anchorsOutput = path("anchors")
            require(!Files.exists(output)) { "Credential output already exists" }
            distinctFiles(statePath, requestPath, output, anchorsOutput)
            val validity = seconds("valid-seconds", 3600); require(validity in 60..31536000)
            withLock(statePath) {
                val state = readObject(statePath); checkState(state)
                val subjects = state.getAsJsonObject("subjects")
                if (subjects.has(approved)) require(subjects[approved].asString == Hex.encode(request.publicKey)) { "Identity is already bound to another key; enroll a fresh identity" }
                require(subjects.has(approved) || subjects.size() < 1024)
                val serial = state["nextSerial"].asLong
                val now = System.currentTimeMillis()
                val body = CredentialBody(state["issuerId"].asString, approved, serial, maxOf(0, now-5000), Math.addExact(now, Math.multiplyExact(validity, 1000L)), request.publicKey)
                val credential = CredentialAuthority.issue(body, Hex.decode(state["sm2PrivateKey"].asString), Hex.decode(state["falconPrivateKey"].asString), Hex.decode(state["sm2SignerId"].asString), crypto)
                val encoded = WireCodec.encodeCredential(credential)
                subjects.addProperty(approved, Hex.encode(request.publicKey)); state.addProperty("nextSerial", Math.addExact(serial, 1))
                state.getAsJsonArray("issuedSerials").add(serial)
                val bundle = publicBundle(state, seconds("policy-seconds", 3600))
                // Commit the serial before publishing, so a crash cannot cause serial reuse.
                writeAtomic(statePath, state.toString())
                writeAtomic(output, BundleCodec.credential(approved, encoded))
                writeAtomic(anchorsOutput, BundleCodec.anchors(bundle))
                println("Issued serial $serial: body=${body.let { WireCodec.encodeBody(it).size }} B, credential=${encoded.size} B, digest=${Hex.encode(crypto.digest(encoded))}")
            }
        }
        "anchors", "revoke" -> {
            val statePath = path("state"); val output = path("out")
            distinctFiles(statePath, output)
            withLock(statePath) {
                val state = readObject(statePath); checkState(state)
                if (command == "revoke") {
                    val serial = required("serial").toLong()
                    require(state.getAsJsonArray("issuedSerials").any { it.asLong == serial }) { "Serial was not issued by this authority" }
                    val entry = "${state["issuerId"].asString}:$serial"
                    val revoked = state.getAsJsonArray("revokedCredentials")
                    if (revoked.none { it.asString == entry }) { require(revoked.size() < 4096); revoked.add(entry) }
                    writeAtomic(statePath, state.toString())
                }
                writeAtomic(output, BundleCodec.anchors(publicBundle(state, seconds("policy-seconds", 3600))))
                println("Public trust/policy snapshot written; distribute by a trusted management path.")
            }
        }
        "demo" -> {
            val out = path("out"); require(!Files.exists(out)) { "Demo output must be a new directory" }; Files.createDirectories(out)
            val issuer = "01".repeat(16); val subject = "02".repeat(16); val receiverId = "03".repeat(16)
            val caSm2 = crypto.generateSm2KeyPair(); val caFalcon = crypto.generateFalconKeyPair(); val endpoint = crypto.generateSm2KeyPair()
            val now = System.currentTimeMillis(); val caId = "PHAP-CLI-DEMO".toByteArray()
            val credential = CredentialAuthority.issue(CredentialBody(issuer,subject,1,now-1000,now+60000,endpoint.publicKey),caSm2.privateKey,caFalcon.privateKey,caId,crypto)
            val encoded = WireCodec.encodeCredential(credential)
            val bundle = AnchorBundle(listOf(TrustAnchor(issuer,caId,caSm2.publicKey,caFalcon.publicKey)),setOf(subject,receiverId),emptySet(),now+60000)
            val sender = Sender(encoded,endpoint.privateKey,crypto,InMemorySequenceStore())
            val receiver = Receiver(receiverId,bundle.anchors,crypto,InMemoryReplayStore(),bundle.policy())
            val pending = sender.createMessage(receiverId,"cold message".toByteArray(),now)
            check(receiver.receive(pending).status == ReceiveStatus.PENDING)
            val cold = sender.fragments().reversed().map { receiver.receiveFragment(it) }.flatMap { it.deliveries }
            check(cold.size == 1)
            val warmPacket = sender.createMessage(receiverId,"warm message".toByteArray(),System.currentTimeMillis())
            val warm = receiver.receive(warmPacket); check(warm.deliveries.size == 1)
            val replay = receiver.receive(warmPacket); check(replay.status == ReceiveStatus.REJECTED)
            writeAtomic(out.resolve("enrollment.json"), BundleCodec.enrollment(subject,endpoint,crypto))
            writeAtomic(out.resolve("credential.json"),BundleCodec.credential(subject,encoded))
            writeAtomic(out.resolve("anchors.json"),BundleCodec.anchors(bundle))
            val report = JsonObject().apply {
                addProperty("kind","local JVM functional demonstration; no terminal/network latency measurement")
                addProperty("bodyBytes",128); addProperty("credentialBytes",encoded.size); addProperty("fragmentCount",sender.fragments().size)
                addProperty("coldDeliveries",cold.size); addProperty("warmDeliveries",warm.deliveries.size); addProperty("replayRejected",replay.status == ReceiveStatus.REJECTED)
            }
            writeAtomic(out.resolve("result.json"),report.toString()); println(report)
        }
    }
}
