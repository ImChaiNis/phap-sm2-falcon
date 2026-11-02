package com.example.v2v0614.data.repository

import com.example.v2v0614.network.WebSocketManager

/** Compatibility facade; one serial consumer must own the incoming event stream. */
class MessageRepository(private val webSocketManager: WebSocketManager) {
    val connectionStatus = webSocketManager.connectionStatus
    val messages = webSocketManager.incoming
    fun connect(url: String) = webSocketManager.connect(url)
    fun disconnect() = webSocketManager.disconnect()
    fun sendMessage(message: String) = webSocketManager.sendMessage(message)
}
