package com.example.v2v0614.network

sealed class ConnectionStatus {
    object Connected : ConnectionStatus()
    object Disconnected : ConnectionStatus()
    object Connecting : ConnectionStatus()
    object Error : ConnectionStatus()
} 