package com.example.v2v0614.ui.viewmodel

import android.app.Application
import android.net.Uri
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.v2v0614.business.CryptoBusinessLogic
import com.example.v2v0614.network.WebSocketManager
import com.example.v2v0614.protocol.*
import com.example.v2v0614.provisioning.BundleCodec
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.util.ArrayDeque

data class PhapUiState(
    val subjectId: String = "", val peerId: String = "", val ready: Boolean = false,
    val busy: Boolean = false, val sending: Boolean = false, val receiving: Boolean = false,
    val credentialBytes: Int = 0, val cachedCredentials: Int = 0, val anchorSummary: String = "",
    val inputRecords: Long = 0, val authenticatedMessages: Long = 0,
    val rejectedRecords: Long = 0, val pendingRecords: Long = 0,
    val pendingCredentialDigest: String = "",
    val recoveryRequestsSent: Long = 0, val recoveryResponsesSent: Long = 0,
    val recoveryRecordsReceived: Long = 0, val recoveryRecordsRejected: Long = 0,
    val sentMessages: Long = 0, val notifications: List<String> = emptyList()
)

/** Single serial receive consumer; UI progress counts authenticated deliveries, never pre-verification input. */
class V2VCommunicationViewModel(application: Application) : AndroidViewModel(application) {
    val network = WebSocketManager()
    private val business = CryptoBusinessLogic(application)
    private val mutex = Mutex()
    private val _state = MutableStateFlow(PhapUiState())
    val state: StateFlow<PhapUiState> = _state.asStateFlow()
    private var sendJob: Job? = null
    private val events = ArrayDeque<String>()
    private var resumeAttempts = 0
    private data class RecoveryBudget(var count: Int = 0, var lastMillis: Long = -1L)
    private val requestBudgets = mutableMapOf<String, RecoveryBudget>()
    private val responseBudgets = mutableMapOf<String, RecoveryBudget>()

    init {
        refresh()
        business.startupError?.let(::notice)
        viewModelScope.launch(Dispatchers.IO) {
            network.incoming.collect { record ->
                mutex.withLock { processRecord(record) }
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(1000)
                mutex.withLock {
                    val expired = business.expireIncomplete()
                    if (expired > 0) notice("$expired 个凭证重建上下文超时，已丢弃暂存消息")
                    refresh()
                }
            }
        }
    }

    fun connect(url: String) = action {
        network.connect(url.trim())
        resumeAttempts = 0
        notice("连接 WebSocket 研究原型；链路建立不等于应用认证完成")
    }
    fun disconnect() { sendJob?.cancel(); network.disconnect(); _state.update { it.copy(sending = false) } }
    fun createEndpoint() = action {
        check(!_state.value.receiving && !_state.value.sending) { "请先停止收发再轮换身份" }
        val id = business.createEndpoint()
        _state.update { it.copy(pendingCredentialDigest = "") }
        resumeAttempts = 0
        notice("已生成新终端身份 $id。请导出注册请求，由独立 CA 签发后导入凭证。")
    }
    fun configurePeer(peerId: String) = action {
        check(!_state.value.receiving && !_state.value.sending) { "请先停止收发再修改授权对端" }
        business.configurePeer(peerId.trim())
        _state.update { it.copy(pendingCredentialDigest = "") }
        notice("已设置授权对端；必须同时列入 CA 状态文件的 allowedSubjects")
    }
    fun importAnchors(uri: Uri) = action {
        check(!_state.value.receiving && !_state.value.sending) { "请先停止收发再更新信任配置" }
        business.importAnchors(readDocument(uri))
        _state.update { it.copy(pendingCredentialDigest = "") }
        notice("已导入 CA 信任锚、授权名单和撤销状态快照")
    }
    fun importCredential(uri: Uri) = action {
        check(!_state.value.receiving && !_state.value.sending) { "请先停止收发再更新本机凭证" }
        business.importCredential(readDocument(uri))
        _state.update { it.copy(pendingCredentialDigest = "") }
        resumeAttempts = 0
        notice("本机凭证通过两种 CA 签名、身份、公钥和状态检查")
    }
    fun exportEnrollment(uri: Uri) = action {
        writeDocument(uri, business.enrollmentRequest())
        notice("已导出含 SM2 私钥持有证明的公开注册请求；未导出私钥")
    }
    fun exportEvents(uri: Uri) = action {
        val header = JSONObject().put("format", "PHAP-LOCAL-EVENTS-1")
            .put("clock", "elapsedRealtimeNanos for local processing only")
            .put("scope", "bounded local event log; no one-way network latency or remote clock comparison")
            .put("retainedEvents", events.size).toString()
        writeDocument(uri, (listOf(header) + events.toList()).joinToString("\n", postfix = "\n"))
        notice("已导出最近 ${events.size} 条本地处理事件，非端到端网络时延")
    }
    fun setReceiving(enabled: Boolean) = action {
        check(!enabled || business.ready) { "请先完成终端身份、信任锚、本机凭证和授权对端配置" }
        _state.update { it.copy(receiving = enabled) }
        notice(if (enabled) "已开始验证接收；已有缓存与重放状态继续保留" else "已停止接收；没有重置重放状态")
    }

    fun startSending(payload: String, countText: String, withCredential: Boolean) {
        if (_state.value.sending) return
        val count = countText.toIntOrNull()
        if (count == null || count !in 1..1000) { notice("消息条数须为 1–1000"); return }
        val bytes = payload.toByteArray(Charsets.UTF_8)
        if (bytes.size > 64 * 1024) { notice("消息载荷超过 64 KiB"); return }
        _state.update { it.copy(sending = true) }
        sendJob = viewModelScope.launch(Dispatchers.IO) {
            try {
                for (index in 0 until count) {
                    ensureActive()
                    mutex.withLock {
                        val cold = index == 0 && withCredential
                        val packet = business.createMessage(bytes, cold)
                        network.sendMessage(encodePacket(packet))
                        if (cold) business.fragments().drop(1).forEach { network.sendMessage(encodeFragment(it)) }
                        _state.update { it.copy(sentMessages = it.sentMessages + 1) }
                        record("send", "MESSAGE_QUEUED", 0L, JSONObject().put("sequence", packet.envelope.sequence)
                            .put("credentialDigest", packet.credentialDigest).put("payloadBytes", bytes.size))
                    }
                    if (index + 1 < count) delay(1000)
                }
                notice("消息已提交发送队列；远端认证结果由远端单独记录")
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) { notice("发送失败：${e.message}") }
            finally { _state.update { it.copy(sending = false) }; refresh() }
        }
    }
    fun stopSending() { sendJob?.cancel(); _state.update { it.copy(sending = false) }; notice("已停止发送") }
    fun resendCredential() = action {
        check(resumeAttempts < 3) { "本次凭证恢复重试已达 3 次；请排查连接并重新配置会话" }
        business.fragments().forEach { network.sendMessage(encodeFragment(it)) }
        resumeAttempts++
        notice("已重发完整凭证分片（本次恢复 $resumeAttempts/3）；未清除重放状态")
    }
    /** Unsigned control metadata only requests bounded retransmission of a public credential. */
    fun requestMissingFragments() = action {
        check(business.ready && _state.value.receiving) { "请先启用认证接收" }
        val digest = _state.value.pendingCredentialDigest.also { Hex.digest(it) }
        val missing = business.missingFragments(digest).ifEmpty { (1..4).toList() }
        require(missing.isNotEmpty() && missing.size <= 4 && missing.all { it in 1..4 })
        consumeRecoveryBudget(requestBudgets, digest)
        val request = JSONObject().put("type", "phap-fragment-request").put("requesterId", business.subjectId)
            .put("destinationId", business.peerId).put("credentialDigest", digest)
            .put("missing", JSONArray().also { array -> missing.forEach { array.put(it) } })
        network.sendMessage(request.toString())
        _state.update { it.copy(recoveryRequestsSent = it.recoveryRequestsSent + 1) }
        record("phap-fragment-request", "UNAUTHENTICATED_REQUEST_SENT", 0L,
            JSONObject().put("credentialDigest", digest).put("missing", request.getJSONArray("missing")))
        notice("已请求公开凭证缺片 ${missing.joinToString()}。若上下文已超时，仅重新缓存证书；原暂存消息不会恢复。")
    }

    private fun consumeRecoveryBudget(budgets: MutableMap<String, RecoveryBudget>, digest: String) {
        val now = SystemClock.elapsedRealtime()
        val budget = budgets[digest] ?: run {
            check(budgets.size < 64) { "本视图恢复控制状态已达上限" }
            RecoveryBudget().also { budgets[digest] = it }
        }
        check(budget.count < 3) { "本凭证在本视图中的恢复次数已达 3 次" }
        check(budget.lastMillis < 0 || now - budget.lastMillis >= 1000L) { "恢复操作至少间隔 1 秒" }
        budget.count++
        budget.lastMillis = now
    }

    private fun respondToFragmentRequest(json: JSONObject) {
        val requester = json.getString("requesterId").also { Hex.id(it) }
        val destination = json.getString("destinationId").also { Hex.id(it) }
        val digest = json.getString("credentialDigest").also { Hex.digest(it) }
        require(destination == business.subjectId && requester == business.peerId) { "恢复请求身份与配置不符" }
        require(digest == business.ownedCredentialDigest) { "仅响应本机当前公开凭证的恢复请求" }
        val array = json.getJSONArray("missing")
        require(array.length() in 1..4) { "恢复请求片数超限" }
        val missing = (0 until array.length()).map { index ->
            val value = array.getInt(index)
            require(array.get(index) is Number && array.get(index).toString() == value.toString() && value in 1..4) { "非法缺片索引" }
            value
        }
        require(missing.distinct().size == missing.size) { "重复缺片索引" }
        val fragments = business.fragments().associateBy { it.index }
        require(missing.all { it in fragments })
        consumeRecoveryBudget(responseBudgets, digest)
        missing.sorted().forEach { network.sendMessage(encodeFragment(fragments.getValue(it))) }
        _state.update { it.copy(recoveryResponsesSent = it.recoveryResponsesSent + 1) }
        notice("按未认证控制请求重发 ${missing.size} 片公开凭证；该请求不代表消息认证成功。")
    }

    fun clearNotifications() { _state.update { it.copy(notifications = emptyList()) } }

    private fun processRecord(recordText: String) {
        val started = SystemClock.elapsedRealtimeNanos()
        val wall = System.currentTimeMillis()
        var control = false
        var countedInput = false
        try {
            val json = JSONObject(recordText)
            val type = json.getString("type")
            control = type == "phap-fragment-request"
            // Recovery can serve the configured peer while application-message reception is disabled.
            if (!_state.value.receiving && !control) return
            if (control) _state.update { it.copy(recoveryRecordsReceived = it.recoveryRecordsReceived + 1) }
            else {
                _state.update { it.copy(inputRecords = it.inputRecords + 1) }
                countedInput = true
            }
            check(business.ready) { "本机凭证/撤销状态过期或配置不完整" }
            val metadata = JSONObject().put("wallStartMillis", wall).put("inputChars", recordText.length)
            if (control) {
                respondToFragmentRequest(json)
                record(type, "UNAUTHENTICATED_RECOVERY_RESPONSE", SystemClock.elapsedRealtimeNanos() - started,
                    metadata.put("credentialDigest", json.getString("credentialDigest")).put("deliveries", 0))
                return
            }
            var claimedDigest: String? = null
            val result = when (type) {
                "phap-message" -> {
                    var packet = WireCodec.decodeMessage(BundleCodec.unb64(json.getString("message"), 64 * 1024 + 156))
                    if (json.has("fragment")) packet = packet.copy(fragment = WireCodec.decodeFragment(BundleCodec.unb64(json.getString("fragment"), 300)))
                    metadata.put("claimedSequence", packet.envelope.sequence).put("credentialDigest", packet.credentialDigest)
                        .put("payloadBytes", packet.envelope.payload.size)
                    packet.fragment?.let { metadata.put("fragmentIndex", it.index).put("fragmentCount", it.count) }
                    if (packet.envelope.senderId == business.peerId) claimedDigest = packet.credentialDigest
                    business.receive(packet)
                }
                "phap-fragment" -> {
                    val fragment = WireCodec.decodeFragment(BundleCodec.unb64(json.getString("fragment"), 300))
                    metadata.put("credentialDigest", fragment.credentialDigest).put("fragmentIndex", fragment.index).put("fragmentCount", fragment.count)
                    claimedDigest = fragment.credentialDigest
                    business.receiveFragment(fragment)
                }
                else -> error("不支持的传输记录类型")
            }
            when (result.status) {
                ReceiveStatus.PENDING -> _state.update { it.copy(pendingRecords = it.pendingRecords + 1,
                    pendingCredentialDigest = claimedDigest ?: it.pendingCredentialDigest) }
                ReceiveStatus.REJECTED -> _state.update { it.copy(rejectedRecords = it.rejectedRecords + 1) }
                ReceiveStatus.ACCEPTED -> {
                    if (result.deliveries.any { it.credentialDigest == _state.value.pendingCredentialDigest }) {
                        _state.update { it.copy(pendingCredentialDigest = "") }
                    }
                }
            }
            val waiting = _state.value.pendingCredentialDigest
            if (waiting.isNotEmpty() && business.hasCachedCredential(waiting)) {
                _state.update { it.copy(pendingCredentialDigest = "") }
            }
            _state.update { it.copy(authenticatedMessages = it.authenticatedMessages + result.deliveries.size) }
            val elapsed = SystemClock.elapsedRealtimeNanos() - started
            record(type, result.status.name, elapsed, metadata.put("deliveries", result.deliveries.size).put("reason", result.reason.take(256)))
            result.deliveries.forEach {
                notice("已认证消息 #${it.envelope.sequence}：${String(it.envelope.payload, Charsets.UTF_8).take(120)}")
            }
            if (result.deliveries.isEmpty()) notice("${result.status}: ${result.reason}")
        } catch (e: Exception) {
            if (control) _state.update { it.copy(recoveryRecordsRejected = it.recoveryRecordsRejected + 1) }
            else {
                if (!_state.value.receiving) return
                _state.update { it.copy(inputRecords = it.inputRecords + if (countedInput) 0 else 1,
                    rejectedRecords = it.rejectedRecords + 1) }
            }
            record(if (control) "phap-fragment-request" else "input", if (control) "CONTROL_REJECTED" else "REJECTED",
                SystemClock.elapsedRealtimeNanos() - started,
                JSONObject().put("wallStartMillis", wall).put("reason", (e.message ?: "Invalid record").take(256)).put("deliveries", 0))
            notice("拒收：${e.message}")
        }
        refresh()
    }

    private fun action(block: suspend () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            mutex.withLock {
                _state.update { it.copy(busy = true) }
                try { block() }
                catch (e: CancellationException) { throw e }
                catch (e: Exception) { notice("操作失败：${e.message}") }
                finally { _state.update { it.copy(busy = false) }; refresh() }
            }
        }
    }
    private fun refresh() { _state.update { it.copy(subjectId = business.subjectId, peerId = business.peerId,
        ready = business.ready, credentialBytes = business.credentialSize, cachedCredentials = business.cachedCredentialCount,
        anchorSummary = business.anchorSummary) } }
    private fun notice(message: String) { _state.update { it.copy(notifications = (listOf(message.take(512)) + it.notifications).take(150)) } }
    private fun record(kind: String, status: String, nanos: Long, fields: JSONObject) {
        fields.put("kind", kind).put("status", status).put("localProcessingNanos", nanos)
        fields.put("observedWallMillis", System.currentTimeMillis()).put("localMonotonicEndNanos", SystemClock.elapsedRealtimeNanos())
        if (events.size >= 5000) events.removeFirst()
        events.addLast(fields.toString())
    }
    private fun encodePacket(packet: MessagePacket): String = JSONObject().put("type", "phap-message")
        .put("message", BundleCodec.b64(WireCodec.encodeMessage(packet))).also { json ->
            packet.fragment?.let { json.put("fragment", BundleCodec.b64(WireCodec.encodeFragment(it))) }
        }.toString()
    private fun encodeFragment(fragment: CredentialFragment): String = JSONObject().put("type", "phap-fragment")
        .put("fragment", BundleCodec.b64(WireCodec.encodeFragment(fragment))).toString()
    private fun readDocument(uri: Uri): String = getApplication<Application>().contentResolver.openInputStream(uri)?.use { input ->
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            require(output.size() + count <= BundleCodec.MAX_BUNDLE_CHARS) { "配置文件超限" }
            output.write(buffer, 0, count)
        }
        String(output.toByteArray(), Charsets.UTF_8)
    } ?: error("无法读取文件")
    private fun writeDocument(uri: Uri, text: String) {
        getApplication<Application>().contentResolver.openOutputStream(uri, "wt")?.bufferedWriter(Charsets.UTF_8)?.use { it.write(text) }
            ?: error("无法写入文件")
    }
    override fun onCleared() { sendJob?.cancel(); network.shutdown(); super.onCleared() }
}
