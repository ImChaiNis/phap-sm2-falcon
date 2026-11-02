package com.example.v2v0614.data

/**
 * SPDU验证结果
 */
data class SpduVerificationResult(
    val success: Boolean,
    val message: String,
    val bsm: String? = null,
    val certificateParts: MutableList<String> = mutableListOf(),
    val fullCertificate: String? = null,
    val sm2PublicKey: String? = null,
    val falconPublicKey: String? = null,
    val isPending: Boolean = false,  // 是否为待验证状态
    val verifiedBsms: List<String> = emptyList()  // 已验证的BSM列表
)

/**
 * SPDU验证状态管理器
 */
class SpduVerificationState {
    val certificateParts: MutableList<String> = mutableListOf()
    var fullCertificate: String? = null
    var sm2PublicKey: String? = null
    var falconPublicKey: String? = null
    
    // 暂存的BSM（SPDU_1-5，等待凭证验证后重新验证）
    val pendingBsms: MutableMap<Int, String> = mutableMapOf()
    
    // 已验证并接收的BSM
    val verifiedBsms: MutableMap<Int, String> = mutableMapOf()
    
    /**
     * 重置验证状态
     */
    fun reset() {
        certificateParts.clear()
        fullCertificate = null
        sm2PublicKey = null
        falconPublicKey = null
        pendingBsms.clear()
        verifiedBsms.clear()
    }
    
    /**
     * 检查是否已收集完整的凭证
     */
    fun hasCompleteCertificate(): Boolean {
        return certificateParts.size == 5 && fullCertificate != null
    }
    
    /**
     * 检查是否已提取公钥
     */
    fun hasPublicKeys(): Boolean {
        return sm2PublicKey != null && falconPublicKey != null
    }
    
    /**
     * 获取已接收的BSM数量
     */
    fun getReceivedBsmCount(): Int {
        return verifiedBsms.size
    }
    
    /**
     * 获取暂存的BSM数量
     */
    fun getPendingBsmCount(): Int {
        return pendingBsms.size
    }
} 