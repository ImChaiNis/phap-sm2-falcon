package com.example.v2v0614.network

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** Bounded event queue: input records are never conflated into a StateFlow "last item". */
class WebSocketManager {
    private val generation = AtomicLong()
    private val incomingQueue = Channel<String>(32)
    val incoming: Flow<String> = incomingQueue.receiveAsFlow()
    private val _connectionStatus = MutableStateFlow<ConnectionStatus>(ConnectionStatus.Disconnected)
    val connectionStatus: StateFlow<ConnectionStatus> = _connectionStatus
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error
    private var socket: WebSocket? = null
    private val client = OkHttpClient.Builder().readTimeout(0, TimeUnit.MILLISECONDS)
        .pingInterval(30, TimeUnit.SECONDS).build()

    @Synchronized fun connect(url: String) {
        require(url.startsWith("wss://") || url.startsWith("ws://")) { "请输入 ws:// 或 wss:// 地址" }
        disconnect()
        val token = generation.incrementAndGet()
        _connectionStatus.value = ConnectionStatus.Connecting
        _error.value = null
        socket = client.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                if (token != generation.get()) { webSocket.close(1000, "Superseded"); return }
                _connectionStatus.value = ConnectionStatus.Connected
            }
            override fun onMessage(webSocket: WebSocket, text: String) {
                if (token != generation.get()) return
                if (text.length > MAX_RECORD_CHARS || !incomingQueue.trySend(text).isSuccess) {
                    _error.value = "接收记录超限或队列已满；连接已关闭，请恢复凭证传输"
                    _connectionStatus.value = ConnectionStatus.Error
                    webSocket.close(1009, "Input limit exceeded")
                }
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (token != generation.get()) return
                _connectionStatus.value = ConnectionStatus.Error
                _error.value = t.message ?: "连接失败"
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (token != generation.get()) return
                _connectionStatus.value = ConnectionStatus.Disconnected
            }
        })
    }

    @Synchronized fun sendMessage(message: String) {
        require(message.length <= MAX_RECORD_CHARS) { "发送记录超限" }
        check(_connectionStatus.value is ConnectionStatus.Connected) { "WebSocket 尚未连接" }
        val current = socket ?: error("WebSocket 尚未连接")
        check(current.queueSize() <= 512 * 1024) { "发送队列已满，请稍后恢复传输" }
        check(current.send(message)) { "发送失败，连接已关闭" }
    }

    @Synchronized fun disconnect() {
        generation.incrementAndGet()
        socket?.close(1000, "Operator disconnect")
        socket = null
        while (incomingQueue.tryReceive().isSuccess) { /* discard old-connection records */ }
        _connectionStatus.value = ConnectionStatus.Disconnected
    }

    fun shutdown() { disconnect(); incomingQueue.close(); client.dispatcher.executorService.shutdown(); client.connectionPool.evictAll() }
    companion object { const val MAX_RECORD_CHARS = 128 * 1024 }
}
