package com.example.v2v0614.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.v2v0614.network.ConnectionStatus
import com.example.v2v0614.ui.viewmodel.V2VCommunicationViewModel

@Composable
fun TestScreen(model: V2VCommunicationViewModel = viewModel()) {
    val state by model.state.collectAsState()
    val connection by model.network.connectionStatus.collectAsState()
    val connectionError by model.network.error.collectAsState()
    var url by rememberSaveable { mutableStateOf("ws://192.168.1.100:8080") }
    var peer by rememberSaveable { mutableStateOf("") }
    var payload by rememberSaveable { mutableStateOf("DRET measurement") }
    var count by rememberSaveable { mutableStateOf("10") }
    var withCredential by rememberSaveable { mutableStateOf(true) }
    val anchors = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(model::importAnchors) }
    val credential = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(model::importCredential) }
    val enrollment = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri -> uri?.let(model::exportEnrollment) }
    val events = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-ndjson")) { uri -> uri?.let(model::exportEvents) }

    LaunchedEffect(state.peerId) { peer = state.peerId }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("GCC–DRET 部分混合认证原型", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text("CA 双签凭证，终端 SM2 消息签名。当前传输使用 WebSocket 研究适配器；尚未集成 MMS。",
            style = MaterialTheme.typography.bodySmall)

        Section("1. 本机注册与 CA 配置") {
            Text(if (state.subjectId.isEmpty()) "本机尚无终端身份" else "本机身份：${state.subjectId}")
            Text("私钥仅保存在本机加密存储；轮换身份后需由 CA 重新签发。", style = MaterialTheme.typography.bodySmall)
            Button(onClick = model::createEndpoint, enabled = !state.busy && !state.sending && !state.receiving) {
                Text(if (state.subjectId.isEmpty()) "新建终端身份" else "轮换终端身份（重新注册）")
            }
            OutlinedButton(onClick = { enrollment.launch("enrollment-${state.subjectId}.json") },
                enabled = state.subjectId.isNotEmpty() && !state.busy) { Text("导出公开注册请求") }
            OutlinedButton(onClick = { anchors.launch(arrayOf("*/*")) }, enabled = !state.busy && !state.sending && !state.receiving) {
                Text("导入 CA 信任锚与状态快照")
            }
            if (state.anchorSummary.isNotEmpty()) Text(state.anchorSummary, style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { credential.launch(arrayOf("*/*")) },
                enabled = state.subjectId.isNotEmpty() && !state.busy && !state.sending && !state.receiving) { Text("导入 CA 签发的本机凭证") }
            OutlinedTextField(value = peer, onValueChange = { peer = it }, modifier = Modifier.fillMaxWidth(),
                label = { Text("授权对端身份（32 位小写十六进制）") }, singleLine = true,
                enabled = !state.sending && !state.receiving)
            OutlinedButton(onClick = { model.configurePeer(peer) }, enabled = !state.busy && !state.sending && !state.receiving) { Text("保存授权对端") }
            Text("本机凭证 ${state.credentialBytes} 字节 · 已验证远端缓存 ${state.cachedCredentials} 项")
            Text(if (state.ready) "配置可用" else "请完成注册、凭证和状态配置；过期状态须更新")
        }

        Section("2. 连接中转服务") {
            OutlinedTextField(value = url, onValueChange = { url = it }, modifier = Modifier.fillMaxWidth(),
                label = { Text("WebSocket 地址（ws:// 或 wss://）") }, singleLine = true)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.connect(url) }, enabled = !state.busy && connection !is ConnectionStatus.Connecting) { Text("连接") }
                OutlinedButton(onClick = model::disconnect) { Text("断开") }
            }
            Text(when (connection) {
                is ConnectionStatus.Connected -> "已连接"
                is ConnectionStatus.Connecting -> "连接中"
                is ConnectionStatus.Error -> "连接失败"
                is ConnectionStatus.Disconnected -> "未连接"
            })
            connectionError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        }

        Section("3. 发送与认证接收") {
            OutlinedTextField(value = payload, onValueChange = { payload = it }, modifier = Modifier.fillMaxWidth(),
                label = { Text("应用消息内容") }, minLines = 2)
            OutlinedTextField(value = count, onValueChange = { count = it }, label = { Text("条数（1–1000，每秒一条）") }, singleLine = true)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = withCredential, onCheckedChange = { withCredential = it }, enabled = !state.sending)
                Text("发送本轮凭证分片（256 字节片载荷）")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.startSending(payload, count, withCredential) },
                    enabled = state.ready && !state.sending && !state.busy && connection is ConnectionStatus.Connected) { Text("发送") }
                OutlinedButton(onClick = model::stopSending, enabled = state.sending) { Text("停止") }
            }
            OutlinedButton(onClick = model::requestMissingFragments,
                enabled = state.ready && state.receiving && !state.busy && state.pendingCredentialDigest.isNotEmpty() && connection is ConnectionStatus.Connected) {
                Text("请求缺片 / 恢复凭证获取（最多 3 次）")
            }
            Text("恢复控制请求未认证，仅触发有界的公开凭证分片重发，不计为认证消息。", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = model::resendCredential,
                enabled = state.ready && !state.busy && connection is ConnectionStatus.Connected) { Text("恢复传输：重发凭证（最多 3 次）") }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(checked = state.receiving, onCheckedChange = model::setReceiving,
                    enabled = !state.busy && (state.ready || state.receiving))
                Spacer(Modifier.width(8.dp))
                Text("启用认证接收")
            }
            Text("恢复请求发送 ${state.recoveryRequestsSent} 次 · 响应 ${state.recoveryResponsesSent} 次 · 控制输入 ${state.recoveryRecordsReceived} 次 · 控制拒绝 ${state.recoveryRecordsRejected} 次")
            Text("发送队列提交 ${state.sentMessages} 条 · 应用/凭证输入记录 ${state.inputRecords} 条")
            Text("已认证交付 ${state.authenticatedMessages} 条 · 待凭证记录 ${state.pendingRecords} 条 · 拒收记录 ${state.rejectedRecords} 条")
            Text("记录计数与认证消息计数的单位不同；待凭证消息只有逐条验签通过后才计入交付。",
                style = MaterialTheme.typography.bodySmall)
        }

        Section("4. 本地事件记录") {
            Text("导出的是本机接收处理耗时和事件结果，不代表两台设备间的单向网络时延。最多保留最近 5000 条事件。",
                style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { events.launch("phap-local-events.jsonl") }, enabled = !state.busy) { Text("导出事件") }
                OutlinedButton(onClick = model::clearNotifications) { Text("清空显示") }
            }
            state.notifications.take(80).forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
    }
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            content()
        }
    }
}
