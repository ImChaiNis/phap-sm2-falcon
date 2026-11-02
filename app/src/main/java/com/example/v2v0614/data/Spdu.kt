package com.example.v2v0614.data

/**
 * SPDU (协议信息单元) 数据结构
 * 基于新的业务逻辑6月21日文档定义
 */
data class Spdu(
    val index: Int,                    // 序号标记 (1-10)
    val bsm: String,                   // 16字节随机字符串
    val sm2Signature: String,          // SM2签名
    val falconSignature: String? = null, // Falcon签名 (可选)
    val hash: String? = null,          // 哈希值 (可选)
    val certificatePart: String? = null // 凭证部分 (可选)
) {
    /**
     * 将SPDU转换为字符串格式
     */
    fun toSpduString(): String {
        return when (index) {
            1 -> "$bsm|$sm2Signature|$certificatePart"
            in 2..4 -> "$bsm|$sm2Signature|$hash|$certificatePart"
            5 -> "$bsm|$sm2Signature|$hash|$certificatePart"
            in 6..10 -> {
                val signatures = if (falconSignature != null) {
                    "$sm2Signature,$falconSignature"
                } else {
                    sm2Signature
                }
                "$bsm|$signatures|$hash"
            }
            else -> throw IllegalArgumentException("无效的SPDU索引: $index")
        }
    }
    
    /**
     * 获取SPDU的完整描述
     */
    fun getDescription(): String {
        return when (index) {
            1 -> "SPDU_1: (BSM_1, sig_1^c, C_1)"
            in 2..4 -> "SPDU_$index: (BSM_$index, sig_${index}^c, h^c, C_$index)"
            5 -> "SPDU_5: (BSM_5, sig_5^c, h, C_5)"
            in 6..10 -> "SPDU_$index: (BSM_$index, sig_$index, h)"
            else -> "无效SPDU"
        }
    }
}

/**
 * SPDU生成结果
 */
data class SpduResult(
    val index: Int,
    val spdu: Spdu,
    val description: String
) 