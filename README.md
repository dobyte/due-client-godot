# due-client-godot

due 游戏服务器框架的 Godot 客户端 SDK，使用 GDScript 编写，基于 Godot 4（最新稳定版）的 `WebSocketPeer` 实现。

## 1. 特性

- 💡 **简单**：仅暴露必要的调用接口。
- 🚀 **轻量**：无第三方依赖，仅依赖 Godot 内置的网络与密码学类（`WebSocketPeer`、`StreamPeerBuffer`、`Crypto`、`AESContext` 等）。
- 🧊 **标准**：完整实现 due 二进制协议（心跳、握手、消息打包/解包、序列号、路由）。
- ⚖️ **可靠**：支持大端/小端字节序、1/2/4 字节路由与序列号、消息体大小限制。
- 🔄 **同步请求**：内置请求/响应模型，通过 GDScript 协程 `await` 等待服务器响应并支持超时。
- 💓 **心跳**：自动发送心跳并接收服务器附带的时间戳。
- 🔌 **断线重连**：支持连接状态监听与自动重连，可配置重连间隔与最大次数。
- 🔐 **会话安全**：支持 due 会话安全（security），握手协商会话密钥并对业务消息加解密。

## 2. 目录结构

```
due-client-godot/
├── addons/
│   └── due_client/
│       ├── due_packer.gd      # 打包/解包器
│       ├── due_client.gd      # 客户端
│       └── security/          # 会话安全模块
│           ├── due_crypto.gd            # 密码学工具
│           ├── due_hkdf.gd              # HKDF-SHA256
│           ├── due_x25519.gd            # X25519 密钥交换
│           ├── due_aead.gd              # AES-256-GCM
│           ├── due_session.gd           # 会话加解密与重放窗口
│           ├── due_handshake.gd         # 客户端握手
│           ├── due_verifier.gd          # 服务端签名验证器
│           └── due_security_options.gd  # 会话安全配置
├── test/
│   ├── test_packer.gd           # DuePacker 单元测试
│   ├── test_client.gd           # DueClient 集成测试（本地 mock 服务器）
│   ├── test_security.gd         # 安全模块单元测试（含握手）
│   ├── test_client_security.gd  # DueClient 安全模式集成测试
│   ├── security_test_server.gd  # 测试用握手服务端
│   └── security_test_util.gd    # 测试工具
├── project.godot              # 最小 Godot 项目配置（用于运行测试）
└── README.md
```

## 3. 安装

将 `addons/due_client` 目录复制到你的 Godot 项目中即可。

## 4. 快速开始

```gdscript
extends Node

func _ready() -> void:
    # 打包器配置需与服务器保持一致
    var packer := DuePacker.new({
        "byte_order": "big",
        "seq_bytes": 0,     # 需要同步请求时，客户端与服务器需同时开启 seq
        "route_bytes": 4,
        "buffer_bytes": 5000,
    })

    var client := DueClient.new({
        "url": "ws://127.0.0.1:3553",
        "heartbeat": 10000,
        "auto_reconnect": true,          # 开启自动重连
        "reconnect_interval": 3000,      # 重连间隔（毫秒）
        "reconnect_max_attempts": 0,     # 0 表示无限重连
        "packer": packer,
    })
    add_child(client)  # 必须加入场景树，才能轮询网络数据

    client.connected.connect(_on_connected)
    client.disconnected.connect(_on_disconnected)
    client.received.connect(_on_received)
    client.heartbeat.connect(_on_heartbeat)
    client.error.connect(_on_error)
    client.state_changed.connect(_on_state_changed)

    client.connect_server()


func _on_connected(client: DueClient) -> void:
    var buffer := JSON.stringify({ "message": "hello server" }).to_utf8_buffer()

    # 异步消息
    client.send({ "route": 1, "buffer": buffer })

    # 同步请求（seq_bytes > 0 时可用）
    _do_request(client, buffer)


func _do_request(client: DueClient, buffer: PackedByteArray) -> void:
    var result: Dictionary = await client.request(1, buffer, 2000)
    if result.get("ok"):
        print("response: ", result["message"]["buffer"].get_string_from_utf8())
    else:
        print("request error: ", result.get("error"))


func _on_received(message: Dictionary) -> void:
    print("receive route=", message["route"], " data=", message["buffer"].get_string_from_utf8())


func _on_heartbeat(millisecond: int) -> void:
    if millisecond > 0:
        print("server heartbeat timestamp: ", millisecond)


func _on_disconnected() -> void:
    print("disconnected")


func _on_state_changed(state: int) -> void:
    match state:
        DueClient.State.DISCONNECTED:
            print("状态：未连接")
        DueClient.State.CONNECTING:
            print("状态：连接中")
        DueClient.State.CONNECTED:
            print("状态：已连接")
        DueClient.State.RECONNECTING:
            print("状态：等待重连")


func _on_error(message: String) -> void:
    print("client error: ", message)
```

### 4.1 启用会话安全

服务端启用会话安全后（`gate.WithSessionSecurity(...)`），客户端需要配置服务端公钥：

```gdscript
var client := DueClient.new({
    "url": "ws://127.0.0.1:3553",
    "heartbeat": 10000,
    "packer": DuePacker.new({ "byte_order": "big", "seq_bytes": 2, "route_bytes": 2 }),
    "security": DueSecurityOptions.new({
        # 服务端公钥：可以是 PEM 文件路径，也可以是 PEM 内容
        "verifier": DueVerifier.ecdsa("keys/gate.pub.pem"),
        # 握手超时时间（毫秒），默认为 5000
        "handshake_timeout": 5000,
    }),
})
add_child(client)

# 握手完成后才会触发 connected，此时可以正常收发消息
client.connected.connect(_on_connected)
client.connect_server()
```

> 注意：
> * 握手使用 X25519 协商临时密钥，通过 HKDF-SHA256 派生双向密钥；客户端会用配置的公钥校验服务端 ServerHello 签名。
> * 内置 AEAD 套件为 AES-256-GCM（套件编号 1）；客户端默认只提供该套件，需要与服务端启用的套件有交集。
> * 只有握手成功后才会触发 `connected`；握手完成前调用 `send` 会返回 `false`。
> * 心跳帧保持明文，不参与会话加密；每条连接都会重新握手，断线重连无需额外处理。
> * 握手失败或超时会触发 `error` 并断开连接。

## 5. API 参考

### DuePacker

打包/解包器。

构造参数（`DuePacker.new(opts: Dictionary)`）：

| 参数 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `byte_order` | `String` | `"big"` | 字节序，可选 `"big"` / `"little"` |
| `seq_bytes` | `int` | `2` | 序列号字节长度，可选 `0` / `1` / `2` / `4`；`0` 表示不开启序列号编码 |
| `route_bytes` | `int` | `2` | 路由字节长度，可选 `1` / `2` / `4` |
| `buffer_bytes` | `int` | `5000` | 消息体最大字节长度 |

方法：

| 方法 | 说明 |
| --- | --- |
| `pack_heartbeat() -> PackedByteArray` | 打包心跳包 |
| `pack_handshake(payload: PackedByteArray) -> PackedByteArray` | 打包握手帧，出错时返回空 `PackedByteArray` |
| `pack_message(message: Dictionary) -> PackedByteArray` | 打包消息，出错时返回空 `PackedByteArray` |
| `unpack(data: PackedByteArray) -> Dictionary` | 解包数据，见下方说明 |

`unpack` 返回结构：

- 心跳帧：`{ "is_heartbeat": true, "is_handshake": false, "millisecond": int }`
- 握手帧：`{ "is_heartbeat": false, "is_handshake": true, "payload": PackedByteArray }`
- 消息帧：`{ "is_heartbeat": false, "is_handshake": false, "message": { "seq", "route", "buffer" } }`

### DueClient

客户端。

连接状态（`State` 枚举）：

| 值 | 说明 |
| --- | --- |
| `DISCONNECTED` | 未连接 |
| `CONNECTING` | 连接中 |
| `CONNECTED` | 已连接 |
| `RECONNECTING` | 等待重连 |

构造参数（`DueClient.new(opts: Dictionary)`）：

| 参数 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `url` | `String` | `""` | 服务器地址，如 `ws://127.0.0.1:3553` |
| `heartbeat` | `int` | `0` | 心跳间隔（毫秒），大于 `0` 时开启心跳 |
| `auto_reconnect` | `bool` | `false` | 是否自动重连 |
| `reconnect_interval` | `int` | `3000` | 重连间隔（毫秒） |
| `reconnect_max_attempts` | `int` | `0` | 最大重连次数，`0` 表示无限重连 |
| `packer` | `DuePacker` | `DuePacker.new({})` | 打包器实例 |
| `security` | `DueSecurityOptions` / `Dictionary` | `null` | 会话安全配置；为 `null` 时不启用安全模式 |

信号：

| 信号 | 参数 | 说明 |
| --- | --- | --- |
| `connected` | 无 | 连接建立 |
| `disconnected` | 无 | 连接断开 |
| `received` | `message: Dictionary` | 收到消息 |
| `heartbeat` | `millisecond: int` | 收到服务器心跳附带的时间戳 |
| `error` | `message: String` | 连接错误 |
| `state_changed` | `state: int` | 连接状态变化，参数为 `State` 枚举值 |

方法：

| 方法 | 说明 |
| --- | --- |
| `connect_server() -> bool` | 连接服务器，成功返回 `true` |
| `disconnect_server()` | 断开连接 |
| `is_open() -> bool` | 是否已连接 |
| `is_connecting() -> bool` | 是否正在连接 |
| `get_state() -> int` | 获取当前连接状态（`State` 枚举值） |
| `send(message: Dictionary) -> bool` | 发送异步消息 |
| `request(route: int, buffer: PackedByteArray, timeout: int = 0) -> Dictionary` | 发送同步请求（协程，可 `await`） |

> 注意：`connect_server` / `disconnect_server` 之所以不使用 `connect` / `disconnect`，是因为 `connect` 是 Godot 内置方法，不能覆盖。

`request` 返回结构：

- 成功：`{ "ok": true, "message": { "seq": int, "route": int, "buffer": PackedByteArray } }`
- 失败：`{ "ok": false, "error": String }`

### 安全模块

#### DueSecurityOptions

会话安全配置。

支持两种构造方式：

```gdscript
# 直接传入验证器
var security := DueSecurityOptions.new(DueVerifier.ecdsa("keys/gate.pub.pem"))

# 字典形式
var security := DueSecurityOptions.new({
    "verifier": DueVerifier.ecdsa("keys/gate.pub.pem"),
    "handshake_timeout": 5000,
})
```

| 属性 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `verifier` | `Callable` | 无 | 服务端签名验证器，通常由 `DueVerifier` 创建 |
| `suites` | `Array` | `[1]` | 客户端支持的 AEAD 套件编号，`1` 为 AES-256-GCM |
| `handshake_timeout` | `int` | `5000` | 握手超时时间（毫秒），小于等于 `0` 表示不启用超时 |

#### DueVerifier

服务端签名验证器工厂，返回 `Callable(data, signature) -> bool`。

| 方法 | 说明 |
| --- | --- |
| `ecdsa(public_key, hash = "sha256", delimiter = " ") -> Callable` | ECDSA 验签；`public_key` 可以是 PEM 文件路径或内容，`delimiter` 需与服务端一致 |
| `rsa(public_key, hash = "sha256", pss = false) -> Callable` | RSA 验签（PKCS#1 v1.5） |

> 注意：Godot 仅支持 RSA PKCS#1 v1.5，`pss = true` 时返回始终失败的验证器；
> 如需自定义验签逻辑，也可以直接传入任意 `Callable(data, signature) -> bool`。
> 公钥文件兼容 due 的 `ECDSA PUBLIC KEY` PEM 标签，可直接使用网关的 `key.pub.pem`。

#### DueSession

握手协商出的 AEAD 会话，业务消息的加解密由客户端内部完成，通常无需直接使用。

| 成员 | 说明 |
| --- | --- |
| `Direction.CLIENT_TO_SERVER` / `Direction.SERVER_TO_CLIENT` | 消息传输方向 |
| `seal_message(plaintext, direction, route, seq) -> PackedByteArray` | 加密载荷，返回 `epoch(1) \| counter(8) \| ciphertext \| tag` |
| `open_message(sealed_data, direction, route, seq) -> PackedByteArray` | 校验并解密载荷，失败时返回空数组 |
| `get_epoch() -> int` / `get_overhead() -> int` | 密钥世代 / 信封开销（25 字节） |

#### 其他

| 类型 | 说明 |
| --- | --- |
| `DueHandshakeClient` | 客户端握手状态机，`hello()` 生成 ClientHello，`handle(frame)` 处理 ServerHello |
| `DueAesGcm` | AES-256-GCM 加解密器，`seal` / `open` / `open_checked` |
| `DueX25519` | X25519 密钥交换，`generate_private_key` / `get_public_key` / `compute_shared_key` |
| `DueHkdf` | HKDF-SHA256 密钥派生 |
| `DueCrypto` | 随机数、SHA256、HMAC-SHA256、定长时间比较等工具 |

## 6. 运行测试

单元测试（`DuePacker`）：

```bash
godot --headless --script res://test/test_packer.gd
```

覆盖心跳打包、消息打包（大端/小端）、打包/解包往返、心跳时间戳解包、越界与无效数据等场景。

集成测试（`DueClient`，内置本地 mock WebSocket 服务器）：

```bash
godot --headless --script res://test/test_client.gd
```

覆盖连接建立、消息收发、同步请求/响应、心跳、断线自动重连等场景。

安全模块单元测试（X25519、HKDF、AES-GCM、会话、验签与握手）：

```bash
godot --headless --script res://test/test_security.gd
```

覆盖 X25519（RFC 7748）与 HKDF（RFC 5869）标准向量、AES-256-GCM（NIST 向量）、
会话加解密、AAD 绑定、重放窗口、ECDSA 验签以及完整握手流程。

安全模式集成测试（`DueClient` 握手 + 加密收发 + 重连重握手）：

```bash
godot --headless --script res://test/test_client_security.gd
```

覆盖握手完成前发送被拒绝、握手后加密收发、安全模式同步请求/响应、心跳明文、断线重连后重新握手等场景。

> 集成测试的协议参数与 `due-benchmark/cluster/ws/client/etc/etc.toml` 的 `[packet]` 保持一致
> （`byteOrder=big`、`routeBytes=4`、`seqBytes=4`、`bufferBytes=5000`）；
> 安全测试使用与该 benchmark 相同的示例 ECDSA 密钥（`hash=SHA256`、`delimiter=空格`）。

## License

[MIT](https://tldrlegal.com/license/mit-license)
