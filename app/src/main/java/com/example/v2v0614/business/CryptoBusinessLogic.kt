package com.example.v2v0614.business

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.example.v2v0614.protocol.*
import com.example.v2v0614.provisioning.*
import android.os.SystemClock
import org.json.JSONObject
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Android application adapter. Authority private keys never enter this class or the phone. */
class CryptoBusinessLogic(context: Context) {
    private val crypto = CryptoProvider()
    private val settings = context.getSharedPreferences("phap_public_configuration", Context.MODE_PRIVATE)
    private val privatePrefs = context.getSharedPreferences("phap_endpoint_identity", Context.MODE_PRIVATE)
    private val durablePrefs = context.getSharedPreferences("phap_durable_state", Context.MODE_PRIVATE)
    private val endpointStore = EndpointStore(privatePrefs, durablePrefs, crypto)
    private val durable = DurableProtocolStore(durablePrefs)
    private var receiver: Receiver? = null
    private var sender: Sender? = null
    private var anchors: AnchorBundle? = null
    private var ownCredential: Credential? = null
    private var local: EndpointMaterial? = null
    private var peer = settings.getString("peerId", "") ?: ""
    private var credentialBytes: ByteArray? = null
    var startupError: String? = null
        private set

    init {
        try {
            local = endpointStore.load()
            local?.let { durable.bind(it.subjectId, it.bootstrap) }
            settings.getString("credential", null)?.let { credentialBytes = b64decode(it, 4096) }
            settings.getString("anchors", null)?.let { anchors = parseAnchors(it) }
            rebuild()
        } catch (e: Exception) {
            startupError = "初始化失败：${e.message}。过期配置请重新导入；持久状态/密钥丢失时须轮换身份并重新签发。"
        }
    }

    val subjectId: String get() = local?.subjectId ?: ""
    val peerId: String get() = peer
    val ownedCredentialDigest: String get() = sender?.credentialDigest ?: ""
    val ready: Boolean get() {
        val body = ownCredential?.body ?: return false
        val now = System.currentTimeMillis()
        return sender != null && receiver != null && startupError == null &&
            now in body.notBeforeMillis..body.notAfterMillis && policy().credentialAllowed(body, now)
    }
    val credentialSize: Int get() = credentialBytes?.size ?: 0
    val cachedCredentialCount: Int get() = receiver?.cachedCredentialCount ?: 0
    val anchorSummary: String get() = (anchors?.anchors ?: emptyList()).joinToString("\n") {
        "CA ${it.issuerId} · 指纹 ${Hex.encode(crypto.digest(it.sm2PublicKey + it.falconPublicKey))}"
    }

    /** Explicit operator enrollment/rotation: new random identity prevents identity reuse after state loss. */
    @Synchronized fun createEndpoint(): String {
        val fresh = endpointStore.create()
        local = fresh
        durable.bind(fresh.subjectId, fresh.bootstrap)
        credentialBytes = null
        ownCredential = null
        check(settings.edit().remove("credential").commit()) { "Cannot persist credential reset" }
        startupError = null
        receiver = null
        sender = null
        return fresh.subjectId
    }

    @Synchronized fun enrollmentRequest(): String {
        val material = local ?: error("请先新建终端身份")
        endpointStore.checkState(material)
        return BundleCodec.enrollment(material.subjectId, CryptoKeyPair(material.publicKey, material.privateKey), crypto)
    }

    @Synchronized fun importAnchors(document: String) {
        val parsed = parseAnchors(document)
        check(settings.edit().putString("anchors", document).commit()) { "Cannot persist trust anchors" }
        anchors = parsed
        startupError = null
        rebuild()
    }

    @Synchronized fun importCredential(document: String) {
        val material = local ?: error("先在本机生成终端密钥并由 CA 签发")
        endpointStore.checkState(material)
        require(anchors != null) { "请先通过可信渠道导入 CA 信任锚及状态快照" }
        val bundle = BundleCodec.readCredential(document)
        require(bundle.subjectId == material.subjectId) { "凭证不属于本机身份" }
        val bytes = bundle.credential
        val validated = CredentialVerifier(anchors!!.anchors, crypto, policy()).verify(bytes, System.currentTimeMillis())
        require(validated.body.subjectId == material.subjectId && validated.body.sm2PublicKey.contentEquals(material.publicKey)) {
            "凭证中的身份/公钥与本机密钥不匹配"
        }
        check(settings.edit().putString("credential", b64(bytes)).commit()) { "Cannot persist credential" }
        credentialBytes = bytes.copyOf()
        startupError = null
        rebuild()
    }

    @Synchronized fun configurePeer(value: String) {
        Hex.id(value)
        require(value != subjectId) { "对端身份必须与本机不同" }
        anchors?.let { require(value in it.allowedSubjects) { "对端不在 CA 授权名单中" } }
        check(settings.edit().putString("peerId", value).commit()) { "Cannot persist peer authorization" }
        peer = value
        rebuild()
    }

    @Synchronized fun createMessage(payload: ByteArray, includeFirstFragment: Boolean): MessagePacket {
        ensureReady()
        return sender!!.createMessage(peer, payload, System.currentTimeMillis(), if (includeFirstFragment) 1 else null)
    }

    @Synchronized fun fragments(): List<CredentialFragment> { ensureReady(); return sender!!.fragments() }
    @Synchronized fun receive(packet: MessagePacket): ReceiveResult { ensureReady(); return receiver!!.receive(packet) }
    @Synchronized fun receiveFragment(fragment: CredentialFragment): ReceiveResult { ensureReady(); return receiver!!.receiveFragment(fragment) }
    @Synchronized fun hasCachedCredential(digest: String): Boolean { ensureReady(); return receiver!!.hasCachedCredential(digest) }
    @Synchronized fun missingFragments(digest: String): List<Int> { ensureReady(); Hex.digest(digest); return receiver!!.missingFragments(digest) }
    @Synchronized fun expireIncomplete(): Int = receiver?.expireIncomplete() ?: 0

    private fun ensureReady() {
        check(ready) { startupError ?: "请完成终端注册、信任锚、CA 凭证和对端身份配置" }
        endpointStore.checkState(local!!)
        // The signed local credential was verified at import/rebuild; warm operations only recheck policy/time.
        val body = ownCredential!!.body
        val now = System.currentTimeMillis()
        check(now in body.notBeforeMillis..body.notAfterMillis && policy().credentialAllowed(body, now)) { "本机凭证或撤销状态已过期" }
    }

    private fun rebuild() {
        sender = null
        receiver = null
        ownCredential = null
        val material = local ?: return
        endpointStore.checkState(material)
        if (anchors == null || credentialBytes == null || peer.isEmpty()) return
        Hex.id(peer)
        require(peer in anchors!!.allowedSubjects) { "对端不在 CA 授权名单中" }
        val currentPolicy = policy()
        val credential = CredentialVerifier(anchors!!.anchors, crypto, currentPolicy)
            .verify(credentialBytes!!, System.currentTimeMillis())
        require(credential.body.subjectId == material.subjectId && credential.body.sm2PublicKey.contentEquals(material.publicKey))
        ownCredential = credential
        sender = Sender(credentialBytes!!, material.privateKey, crypto, durable)
        receiver = Receiver(material.subjectId, anchors!!.anchors, crypto, durable, currentPolicy,
            clock = object : ProtocolClock {
                override fun wallTimeMillis() = System.currentTimeMillis()
                override fun monotonicTimeMillis() = SystemClock.elapsedRealtime()
            })
    }

    private fun policy(): ProtocolPolicy {
        val localId = subjectId
        val peerId = peer
        val snapshot = anchors?.policy()
        return object : ProtocolPolicy {
            override fun credentialAllowed(body: CredentialBody, nowMillis: Long): Boolean =
                snapshot?.credentialAllowed(body, nowMillis) == true && (body.subjectId == localId || body.subjectId == peerId)
            override fun messageAllowed(body: CredentialBody, envelope: MessageEnvelope): Boolean =
                snapshot?.messageAllowed(body, envelope) == true && body.subjectId == peerId &&
                    envelope.senderId == peerId && envelope.destinationId == localId
        }
    }

    private fun parseAnchors(document: String): AnchorBundle =
        BundleCodec.readAnchors(document, crypto, System.currentTimeMillis())

    companion object {
        fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
        fun b64decode(value: String, maxBytes: Int): ByteArray {
            require(value.length <= ((maxBytes + 2) / 3) * 4) { "编码长度超限" }
            return Base64.decode(value, Base64.NO_WRAP).also { require(it.size <= maxBytes && b64(it) == value) { "Base64 编码不规范" } }
        }
    }
}

internal data class EndpointMaterial(val subjectId: String, val publicKey: ByteArray, val privateKey: ByteArray, val bootstrap: String)

/** Private SM2 scalar is encrypted using an app-specific AndroidKeyStore AES-GCM key. */
internal class EndpointStore(private val prefs: SharedPreferences, private val state: SharedPreferences, private val crypto: CryptoProvider) {
    fun load(): EndpointMaterial? {
        val encoded = prefs.getString("encryptedIdentity", null) ?: return null
        val blob = CryptoBusinessLogic.b64decode(encoded, 4096)
        require(blob.size > 28)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        cipher.updateAAD("PHAP-ENDPOINT-1".toByteArray(Charsets.US_ASCII))
        val json = JSONObject(String(cipher.doFinal(blob.copyOfRange(12, blob.size)), Charsets.UTF_8))
        val material = EndpointMaterial(json.getString("subjectId"), Hex.decode(json.getString("publicKey")),
            Hex.decode(json.getString("privateKey")), json.getString("bootstrap"))
        Hex.id(material.subjectId)
        checkState(material)
        val challenge = "PHAP-KEY-CHECK".toByteArray(Charsets.US_ASCII)
        val signature = crypto.sm2Sign(material.privateKey, Hex.id(material.subjectId), challenge)
        check(crypto.sm2Verify(material.publicKey, Hex.id(material.subjectId), challenge, signature)) { "本机密钥不一致" }
        return material
    }

    fun create(): EndpointMaterial {
        val pair = crypto.generateSm2KeyPair()
        val random = SecureRandom()
        val material = EndpointMaterial(Hex.encode(ByteArray(16).also { random.nextBytes(it) }), pair.publicKey, pair.privateKey,
            Hex.encode(ByteArray(32).also { random.nextBytes(it) }))
        synchronized(DurableStateLock.lock) {
            check(state.edit().clear().putString("owner", material.subjectId).putString("bootstrap", material.bootstrap).commit()) { "Cannot initialize durable state" }
        }
        val json = JSONObject().put("subjectId", material.subjectId).put("publicKey", Hex.encode(material.publicKey))
            .put("privateKey", Hex.encode(material.privateKey)).put("bootstrap", material.bootstrap)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(true))
        cipher.updateAAD("PHAP-ENDPOINT-1".toByteArray(Charsets.US_ASCII))
        val blob = cipher.iv + cipher.doFinal(json.toString().toByteArray(Charsets.UTF_8))
        check(prefs.edit().putString("encryptedIdentity", CryptoBusinessLogic.b64(blob)).commit()) { "Cannot persist endpoint identity" }
        return material
    }

    fun checkState(material: EndpointMaterial) {
        check(state.getString("owner", null) == material.subjectId && state.getString("bootstrap", null) == material.bootstrap) {
            "持久序列/重放状态丢失；必须轮换身份并重新签发"
        }
    }

    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        (store.getKey("phap_endpoint_wrapping_v1", null) as? SecretKey)?.let { return it }
        check(create) { "AndroidKeyStore 密钥丢失" }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder("phap_endpoint_wrapping_v1", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }
}

/** Synchronous commits reserve sequence numbers and record replays before returning to the core. */
internal class DurableProtocolStore(private val prefs: SharedPreferences) : SequenceStore, ReplayStore {
    private var expectedOwner: String? = null
    private var expectedBootstrap: String? = null
    fun bind(owner: String, bootstrap: String) = synchronized(DurableStateLock.lock) {
        check(prefs.getString("owner", null) == owner && prefs.getString("bootstrap", null) == bootstrap) { "持久状态初始化不一致" }
        expectedOwner = owner
        expectedBootstrap = bootstrap
    }
    private fun checkBound() {
        check(expectedOwner != null && expectedBootstrap != null && prefs.getString("owner", null) == expectedOwner &&
            prefs.getString("bootstrap", null) == expectedBootstrap) { "持久状态缺失或已被新身份替换" }
    }
    override fun next(credentialDigest: String): Long = synchronized(DurableStateLock.lock) {
        checkBound()
        Hex.digest(credentialDigest)
        val key = "sequence.$credentialDigest"
        val old = prefs.getLong(key, 0L)
        check(old in 0 until Long.MAX_VALUE) { "序列号已耗尽或损坏，请更新凭证" }
        val next = old + 1
        check(prefs.edit().putLong(key, next).commit()) { "序列号持久化失败" }
        next
    }
    override fun accept(credentialDigest: String, sequence: Long): Boolean = synchronized(DurableStateLock.lock) {
        checkBound()
        Hex.digest(credentialDigest)
        val key = "replay.$credentialDigest"
        val old = prefs.getLong(key, 0L)
        check(old >= 0) { "重放状态损坏" }
        if (sequence <= old) false
        else {
            check(prefs.edit().putLong(key, sequence).commit()) { "重放状态持久化失败" }
            true
        }
    }
}

/** Shared across activity/ViewModel instances in the app single process. */
internal object DurableStateLock { val lock = Any() }
