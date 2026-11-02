# SM2–Falcon PHAP：GCC–DRET 研究原型

本工程实现部分混合认证：独立 CA 对同一证书体执行 SM2 与 Falcon 双签；终端仅使用 SM2 签署应用消息。实际量子恢复终端 SM2 私钥后，应用消息仍可被伪造。

实现包括真实密码运算、规范字节编码、有界分片重建、证书缓存、身份/目的/新鲜度检查和持久化防重放状态。当前传输适配器使用 WebSocket 中转，尚未接入 MMS。旧 C++ 演示不参与构建；公开复现包仅包含修订后的实现。

## 构建与本地验证

Android 构建需要 Android SDK 34 和 JDK 17 或以上。项目统一为 AGP 8.7.2、Kotlin 1.9.22、Compose Compiler 1.5.8；使用固定版本 Bouncy Castle 1.86 和 Gson 2.13.2。终端不再依赖旧 JNI、NDK 或 CMake。

```sh
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
```

无 Android SDK 时，可以使用 JDK 和 Maven 构建同一协议核心及离线 CA 工具：

```sh
mvn -f tools/pom.xml test package
java -jar tools/target/phap-tools.jar demo --out .phap-local/demo
```

交付包中的 `dist/phap-tools.jar` 可直接运行。`demo` 必须使用不存在的新输出目录；它用真实签名验证冷/热缓存交付及重放拒绝，并导出功能结果。它不测手机或受限终端性能，也不包含网络单向时延。

## 两台终端的注册与配置

1. 在每台手机中点击“新建终端身份”，导出各自的公开注册请求。私钥以 AndroidKeyStore AES-GCM 加密后保存在应用私有存储中，公开请求包含 SM2 私钥持有证明。
2. 在 CA 电脑新建私有状态。下面的发行者标识和 SM2 signer ID 是示例管理标识，密钥由安全随机源生成；`ca-private.json` 只保存在 CA 电脑。

```sh
java -jar dist/phap-tools.jar new-ca \
  --state .phap-local/ca-private.json \
  --issuer-id 01010101010101010101010101010101 \
  --sm2-id 504841502d4341
```

3. 运营人员核对终端身份与实际设备后，分别签发。`--subject-id` 必须填入该手机导出的 32 位小写十六进制身份，表示操作者批准该绑定；PoP 本身不代替设备身份审核。

```sh
java -jar dist/phap-tools.jar issue \
  --state .phap-local/ca-private.json \
  --request enrollment-A.json --subject-id '<替换为A的32位身份>' \
  --out credential-A.json --anchors anchors.json \
  --valid-seconds 3600 --policy-seconds 3600

java -jar dist/phap-tools.jar issue \
  --state .phap-local/ca-private.json \
  --request enrollment-B.json --subject-id '<替换为B的32位身份>' \
  --out credential-B.json --anchors anchors.json \
  --valid-seconds 3600 --policy-seconds 3600
```

签发第二台后，最新 `anchors.json` 的授权名单包含两台身份。通过可信管理渠道将该最新文件导入两台手机；分别导入自己的 `credential-A.json` 或 `credential-B.json`，并将授权对端设置为另一台手机的身份。核对界面显示的 CA 公钥指纹。终端不接收或导入 CA 私钥。

CA 工具验证请求 PoP、阻止同一身份悄悄换成另一公钥，并在发布凭证前持久化串行号。现有凭证输出不会被覆盖。CA 状态文件按私有文件权限创建；Windows 需放在仅管理员账户可访问的目录中。

## 通信、缓存与恢复

在同一可达网络的电脑上启动原有中转服务：

```sh
python3 -m pip install -r requirements.txt
python3 test_server.py
```

使用服务打印的地址连接两台手机，开启认证接收。第一次发送保留“发送本轮凭证分片”：首条消息携带第一片，其余片独立发送。接收端重建完整证书、检查摘要和两种 CA 签名后，再逐条验证暂存消息。

随后取消发送凭证分片即可检查热缓存消息。停止/重启接收不会清除缓存或重放状态；进程重启会重新获取证书，已持久化的防重放状态继续有效。连接中断后可通过“恢复传输”重发凭证，最多 3 次；分片不完整超过 5 秒会清理上下文与暂存消息。

接收端也可点击“请求缺片”。恢复控制只提供未认证的传输提示，发送方仅响应配置对端针对本机当前凭证摘要的 1–4 个唯一片索引；请求和响应分别最多 3 次、至少间隔 1 秒。控制记录不更新应用重放状态、不产生认证交付。上下文超时后重新取得证书不会复活已丢弃的消息，需要发送带新序列和时间的新消息。

默认应用消息有效年龄为 10 秒，允许未来时钟偏差为 2 秒；测试时需协调设备墙钟。分片载荷 256 字节；凭证体 128 字节、完整凭证 866 字节，分为 256/256/256/98 字节四片。SM2 原始签名为 64 字节，Falcon-512 padded CA 签名为 666 字节。

授权与撤销状态过期时拒绝继续认证，使用 CA 电脑更新并重新导入：

```sh
java -jar dist/phap-tools.jar anchors \
  --state .phap-local/ca-private.json --out anchors.json --policy-seconds 3600

java -jar dist/phap-tools.jar revoke \
  --state .phap-local/ca-private.json --serial 1 --out anchors.json --policy-seconds 3600
```

状态快照通过可信管理渠道分发，不能从对端消息中自动学习信任锚。重新安装、密钥或持久状态丢失后应生成新身份并重新签发。应用禁止备份密钥、序列号与重放状态；不会在旧身份下静默重置已检测到的持久状态损坏。

## 事件与实验边界

界面区分输入记录、待凭证记录、拒收记录和已经认证的应用消息，计数单位不同。可导出最近 5000 条 JSONL 本地事件，包含单调时钟处理耗时、所声明的序列/摘要、分片元数据和验证结果，不导出私钥或消息载荷。

`localProcessingNanos` 是本机从解析输入到完成处理的耗时，包含该次需要的重建/验签等工作，不是两台手机之间的单向时延，也不是独立的 Falcon 微基准。冷/热认证结果仍需在实际目标设备和指定网络上测量。本工程没有恢复或重造旧论文图表，没有建立公开数据仓库。

实现对应关系和本轮验证范围见 [IMPLEMENTATION.md](IMPLEMENTATION.md)。

主要密码接口来源：[Bouncy Castle 官方下载](https://www.bouncycastle.org/download/bouncy-castle-java/)、[SM2 API](https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/signers/SM2Signer.html)、[Falcon 参考 API 与 padded 格式](https://falcon-sign.info/impl/falcon.h.html)。本实现采用 Falcon v1.2 研究格式，不宣称未来 FN-DSA/FIPS 206 的格式或模块认证。

## 2026-11-02 实测与论文实验补充

新增独立的四配置比较与生产核心异常试验，生产APK仍只接受PHAP suite 2。36项JVM测试通过；五个JVM共70,000条计时记录和1500次受控异常试验全部通过检查。详见 [实验验证记录](EXPERIMENTS_20261102.md) 与 [复现方法](experiments/README.md)。桌面回环数据不能代替真机/受限终端、MMS或实际网络测试。
