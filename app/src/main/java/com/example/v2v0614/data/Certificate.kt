package com.example.v2v0614.data

/**
 * 凭证数据结构
 * 基于新的业务逻辑6月21日文档定义
 */
data class Certificate(
    val version: Int = 4,                    // 凭证格式版本
    val type: Int = 0,                       // 隐式或显式类型
    val issuer: String = "C",                // 发行者标识
    val id: String = "S",                    // 持有者标识（假名）
    val verifyKeyIndicator: String,          // 公钥指示器
    val pqSignature: String = "",            // 后量子签名
    val ecdsaSignature: String = ""          // ECDSA签名
) {
    /**
     * 将凭证转换为字符串格式，用于签名
     * 格式: version|type|issuer|id|verifyKeyIndicator
     */
    fun toSignableString(): String {
        return "$version|$type|$issuer|$id|$verifyKeyIndicator"
    }
    
    /**
     * 将凭证转换为完整的字符串表示
     */
    fun toFullString(): String {
        return "${toSignableString()}|$pqSignature|$ecdsaSignature"
    }
}

/**
 * 密钥对数据结构
 */
data class KeyPair(
    val publicKey: String,
    val privateKey: String
)

/**
 * 完整的密钥组数据结构
 * 包含SM2和Falcon两种算法的密钥对
 */
data class KeyGroup(
    val sm2KeyPair: KeyPair,
    val falconKeyPair: KeyPair
) {
    /**
     * 获取公钥组
     */
    fun getPublicKeys(): Pair<String, String> {
        return Pair(sm2KeyPair.publicKey, falconKeyPair.publicKey)
    }
    
    /**
     * 获取私钥组
     */
    fun getPrivateKeys(): Pair<String, String> {
        return Pair(sm2KeyPair.privateKey, falconKeyPair.privateKey)
    }
}

/**
 * 凭证组数据结构
 * 包含SM2和Falcon两种算法的凭证
 */
data class CertificateGroup(
    val sm2Certificate: Certificate,
    val falconCertificate: Certificate
) {
    /**
     * 将凭证组转换为字符串格式
     * 格式: SM2凭证||Falcon凭证
     */
    fun toCombinedString(): String {
        return "${sm2Certificate.toFullString()}||${falconCertificate.toFullString()}"
    }
} 