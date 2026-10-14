# due-client-godot

due 游戏服务器框架的 Godot 客户端 SDK，使用 GDScript 编写，基于 Godot 4（最新稳定版）的 `WebSocketPeer` 实现。

## 1. 特性

- 💡 **简单**：仅暴露必要的调用接口。
- 🚀 **轻量**：无第三方依赖，仅依赖 Godot 内置的 `WebSocketPeer` 与 `StreamPeerBuffer`。
- 🧊 **标准**：完整实现 due 二进制协议（心跳、消息打包/解包、序列号、路由）。
- ⚖️ **可靠**：支持大端/小端字节序、1/2/4 字节路由与序列号、消息体大小限制。
- 🔄 **同步请求**：内置请求/响应模型，通过 GDScript 协程 `await` 等待服务器响应并支持超时。
- 💓 **心跳**：自动发送心跳并接收服务器附带的时间戳。
- 🔌 **断线重连**：支持连接状态监听与自动重连，可配置重连间隔与最大次数。

## 2. 目录结构

```
due-client-godot/
├── addons/
│   └── due_client/
│       ├── due_packer.gd      # 打包/解包器
│       └── due_client.gd      # 客户端
├── test/
│   ├── test_packer.gd         # DuePacker 单元测试
│   └── test_client.gd         # DueClient 集成测试（本地 mock 服务器）
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
| `pack_message(message: Dictionary) -> PackedByteArray` | 打包消息，出错时返回空 `PackedByteArray` |
| `unpack(data: PackedByteArray) -> Dictionary` | 解包数据，返回 `{ "is_heartbeat": bool, "millisecond": int, "message": Dictionary }` |

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

## License

[MIT](https://tldrlegal.com/license/mit-license)
