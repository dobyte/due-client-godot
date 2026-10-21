class_name DueClient
extends Node
## due 客户端，基于 WebSocketPeer 实现，用于与 due 游戏服务器网关通信。
##
## 使用前需要将客户端节点加入场景树（add_child），否则无法轮询网络数据。
## 示例：
##     var client := DueClient.new({
##         "url": "ws://127.0.0.1:3553",
##         "heartbeat": 10000,
##         "auto_reconnect": true,
##         "reconnect_interval": 3000,
##         "reconnect_max_attempts": 0,
##         "packer": DuePacker.new({ "byte_order": "big", "seq_bytes": 0, "route_bytes": 4 }),
##         # 可选：启用会话安全
##         "security": DueSecurityOptions.new({
##             "verifier": DueVerifier.ecdsa("keys/gate.pub.pem"),
##         }),
##     })
##     add_child(client)
##     client.connected.connect(_on_connected)
##     client.received.connect(_on_received)
##     client.state_changed.connect(_on_state_changed)
##     client.connect_server()

const DuePackerScript := preload("res://addons/due_client/due_packer.gd")
const DueSecurityOptionsScript := preload("res://addons/due_client/security/due_security_options.gd")
const DueHandshakeScript := preload("res://addons/due_client/security/due_handshake.gd")
const DueSessionScript := preload("res://addons/due_client/security/due_session.gd")

## 连接状态
enum State {
	DISCONNECTED,   # 未连接
	CONNECTING,     # 连接中
	CONNECTED,      # 已连接
	RECONNECTING,   # 等待重连
}

## 连接建立
signal connected
## 连接断开
signal disconnected
## 收到消息，参数为 { "seq": int, "route": int, "buffer": PackedByteArray }
signal received(message: Dictionary)
## 收到服务器心跳附带的时间戳（毫秒）
signal heartbeat(millisecond: int)
## 连接错误，参数为错误描述
signal error(message: String)
## 连接状态变化，参数为 State 枚举值
signal state_changed(state: int)


## 内部请求/响应等待器，供 request 的 await 使用
class _Deferred extends RefCounted:
	signal done(result: Dictionary)


## 服务器地址，如 ws://127.0.0.1:3553
var url: String = ""
## 心跳间隔（毫秒），大于 0 时开启心跳
var heartbeat_interval: int = 0
## 打包器
var packer: DuePackerScript
## 会话安全配置；为 null 时表示不启用安全模式
var security: DueSecurityOptionsScript

## 是否自动重连，默认为 false
var auto_reconnect: bool = false
## 重连间隔（毫秒），默认 3000
var reconnect_interval: int = 3000
## 最大重连次数，0 表示无限重连，默认 0
var reconnect_max_attempts: int = 0

var _socket: WebSocketPeer
var _heartbeat_timer: Timer
var _reconnect_timer: Timer
var _handshake_timer: Timer
var _state: int = State.DISCONNECTED
var _reconnect_attempts: int = 0
var _manual_close: bool = false
## 连接是否已就绪（安全模式下为握手完成）
var _established: bool = false
## 握手状态
var _handshake: DueHandshakeScript
## 会话密钥
var _session: DueSessionScript
## route -> { "seq": int, "callbacks": { seq: _Deferred } }
var _waitgroup: Dictionary = {}


func _init(opts: Dictionary = {}) -> void:
	url = opts.get("url", "")
	heartbeat_interval = opts.get("heartbeat", 0)
	auto_reconnect = opts.get("auto_reconnect", false)
	reconnect_interval = opts.get("reconnect_interval", 3000)
	reconnect_max_attempts = opts.get("reconnect_max_attempts", 0)
	packer = opts.get("packer")
	if packer == null:
		packer = DuePackerScript.new({})
	security = _normalize_security(opts.get("security"))


func _ready() -> void:
	_heartbeat_timer = Timer.new()
	_heartbeat_timer.name = "DueHeartbeatTimer"
	_heartbeat_timer.one_shot = false
	add_child(_heartbeat_timer)
	_heartbeat_timer.timeout.connect(_on_heartbeat_timeout)

	_reconnect_timer = Timer.new()
	_reconnect_timer.name = "DueReconnectTimer"
	_reconnect_timer.one_shot = true
	add_child(_reconnect_timer)
	_reconnect_timer.timeout.connect(_on_reconnect_timeout)

	_handshake_timer = Timer.new()
	_handshake_timer.name = "DueHandshakeTimer"
	_handshake_timer.one_shot = true
	add_child(_handshake_timer)
	_handshake_timer.timeout.connect(_on_handshake_timeout)


func _exit_tree() -> void:
	_stop_heartbeat()
	_stop_reconnect()
	_stop_handshake_timer()


func _process(_delta: float) -> void:
	if _socket == null:
		return

	_socket.poll()
	var ws_state := _socket.get_ready_state()

	if ws_state == WebSocketPeer.STATE_OPEN:
		if not _established:
			_established = true
			_reconnect_attempts = 0
			if security != null:
				_start_handshake()
			else:
				_on_established()
	elif ws_state == WebSocketPeer.STATE_CLOSED:
		if _state == State.CONNECTED:
			_established = false
			_stop_heartbeat()
			_clear_waitgroup()
			_clear_security()
			_set_state(State.DISCONNECTED)
			disconnected.emit()
			_maybe_reconnect()
		elif _state == State.CONNECTING:
			_established = false
			_stop_handshake_timer()
			_clear_security()
			_set_state(State.DISCONNECTED)
			if not _manual_close:
				error.emit("connection closed before open")
			_maybe_reconnect()

	while _socket.get_available_packet_count() > 0:
		var packet: Variant = _socket.get_packet()
		if packet is PackedByteArray:
			_handle_binary(packet)


## 连接服务器，成功返回 true
func connect_server() -> bool:
	_manual_close = false
	_cleanup()
	_set_state(State.CONNECTING)

	_socket = WebSocketPeer.new()
	var err: Error = _socket.connect_to_url(url)
	if err != OK:
		push_error("due-client: 连接失败，错误码 %d" % err)
		error.emit("connect failed: %d" % err)
		_set_state(State.DISCONNECTED)
		return false

	return true


## 断开与服务器的连接，不会触发自动重连
func disconnect_server() -> void:
	var was_open: bool = _state == State.CONNECTED or _state == State.CONNECTING
	_manual_close = true
	_cleanup()
	_set_state(State.DISCONNECTED)
	if was_open:
		disconnected.emit()


## 获取当前连接状态（State 枚举值）
func get_state() -> int:
	return _state


## 是否已连接
func is_open() -> bool:
	return _state == State.CONNECTED


## 是否正在连接
func is_connecting() -> bool:
	return _state == State.CONNECTING


## 发送异步消息
## message 结构：{ "seq": int, "route": int, "buffer": PackedByteArray }
## 安全模式下会对 buffer 加密，握手完成前发送会返回 false
func send(message: Dictionary) -> bool:
	if not is_open():
		return false

	if security != null:
		if _session == null:
			push_warning("due-client: security session is not established")
			return false
		var sealed := _session.seal_message(
			message.get("buffer", PackedByteArray()),
			DueSessionScript.Direction.CLIENT_TO_SERVER,
			message.get("route", 0),
			message.get("seq", 0)
		)
		if sealed.is_empty():
			return false
		message = message.duplicate()
		message["buffer"] = sealed

	var data := packer.pack_message(message)
	if data.is_empty():
		return false
	return _socket.send(data) == OK


## 发送同步请求（C/S 模型），需要客户端和服务器同时开启 seq 配置。
## 返回结构：
##   成功：{ "ok": true, "message": { "seq", "route", "buffer" } }
##   失败：{ "ok": false, "error": String }
func request(route: int, buffer: PackedByteArray = PackedByteArray(), timeout: int = 0) -> Dictionary:
	if not is_open():
		push_error("due-client: client not connected")
		return { "ok": false, "error": "client not connected" }

	var seq := _next_seq(route)
	var group: Dictionary = _waitgroup[route]
	var deferred := _Deferred.new()
	group["callbacks"][seq] = deferred

	if not send({ "seq": seq, "route": route, "buffer": buffer }):
		group["callbacks"].erase(seq)
		push_error("due-client: send message failed")
		return { "ok": false, "error": "send message failed" }

	if timeout > 0 and get_tree() != null:
		var timer := get_tree().create_timer(timeout / 1000.0)
		timer.timeout.connect(_on_request_timeout.bind(route, seq, deferred))

	var awaited: Variant = await deferred.done
	return awaited if not (awaited is Array) else awaited[0]


func _next_seq(route: int) -> int:
	var group: Dictionary = _waitgroup.get(route, {})
	if group.is_empty():
		group = { "seq": 0, "callbacks": {} }
		_waitgroup[route] = group
	group["seq"] = group.get("seq", 0) + 1
	return group["seq"]


func _on_request_timeout(route: int, seq: int, deferred) -> void:
	var group: Dictionary = _waitgroup.get(route, {})
	if group.is_empty():
		return
	var callbacks: Dictionary = group.get("callbacks", {})
	if callbacks.has(seq) and callbacks[seq] == deferred:
		callbacks.erase(seq)
		deferred.done.emit({ "ok": false, "error": "request timeout" })


func _handle_binary(data: PackedByteArray) -> void:
	if data.is_empty():
		return
	var packet: Dictionary = packer.unpack(data)
	if packet.is_empty():
		return

	if packet.get("is_handshake", false):
		_handle_handshake(packet.get("payload", PackedByteArray()))
		return

	if packet.get("is_heartbeat", false):
		heartbeat.emit(packet.get("millisecond", 0))
		return

	var message: Dictionary = packet.get("message", {})
	if security != null:
		if _session == null:
			push_error("due-client: security session is not established")
			return
		var sealed_buffer: PackedByteArray = message.get("buffer", PackedByteArray())
		var route: int = message.get("route", 0)
		var seq: int = message.get("seq", 0)
		var plaintext := _session.open_message(
			sealed_buffer, DueSessionScript.Direction.SERVER_TO_CLIENT, route, seq
		)
		# 解密成功时明文长度必然等于密文长度减去信封开销
		if plaintext.size() != sealed_buffer.size() - _session.get_overhead():
			error.emit("decrypt message failed")
			return
		message["buffer"] = plaintext

	if not _invoke(message):
		received.emit(message)


func _invoke(message: Dictionary) -> bool:
	var seq: int = message.get("seq", 0)
	if seq == 0:
		return false
	var route: int = message.get("route", 0)
	var group: Dictionary = _waitgroup.get(route, {})
	if group.is_empty():
		return false
	var callbacks: Dictionary = group.get("callbacks", {})
	var deferred = callbacks.get(seq)
	if deferred == null:
		return false
	callbacks.erase(seq)
	deferred.done.emit({ "ok": true, "message": message })
	return true


func _set_state(new_state: int) -> void:
	if _state == new_state:
		return
	_state = new_state
	state_changed.emit(new_state)


func _cleanup() -> void:
	_stop_heartbeat()
	_stop_reconnect()
	_clear_waitgroup()
	_clear_security()
	_established = false
	if _socket != null:
		var ws_state := _socket.get_ready_state()
		if ws_state == WebSocketPeer.STATE_OPEN or ws_state == WebSocketPeer.STATE_CONNECTING:
			_socket.close()


## 连接就绪：启动心跳并触发连接回调；安全模式下在握手完成后调用
func _on_established() -> void:
	_start_heartbeat()
	_set_state(State.CONNECTED)
	connected.emit()


## 发起会话安全握手
func _start_handshake() -> void:
	if not security.verifier.is_valid():
		_fail_handshake("invalid server verifier")
		return

	_handshake = DueHandshakeScript.new(security.verifier, security.suites)
	var hello := _handshake.hello()
	_start_handshake_timer()

	if hello.is_empty() or not _send_raw(packer.pack_handshake(hello)):
		_fail_handshake("send client hello failed")


## 处理服务端握手帧
func _handle_handshake(payload: PackedByteArray) -> void:
	if _handshake == null:
		push_error("due-client: unexpected handshake frame")
		return

	var result := _handshake.handle(payload)
	if not result.get("ok", false):
		_fail_handshake(result.get("error", "handshake failed"))
		return

	# 先发布会话，再回发 Finished：服务端确认后可能立即下发加密消息
	_session = result["session"]
	_handshake = null
	_stop_handshake_timer()

	if not _send_raw(packer.pack_handshake(result["finished"])):
		_session = null
		_fail_handshake("send finished frame failed")
		return

	_on_established()


## 握手失败：通知错误并断开连接
func _fail_handshake(message: String) -> void:
	push_error("due-client: " + message)
	error.emit(message)
	disconnect_server()


## 启动握手超时定时器
func _start_handshake_timer() -> void:
	if _handshake_timer == null or security.handshake_timeout <= 0:
		return
	_handshake_timer.wait_time = security.handshake_timeout / 1000.0
	_handshake_timer.start()


## 停止握手超时定时器
func _stop_handshake_timer() -> void:
	if _handshake_timer != null:
		_handshake_timer.stop()


## 握手超时：断开连接
func _on_handshake_timeout() -> void:
	if _session != null:
		return
	_fail_handshake("security handshake timed out")


## 清理握手状态与会话密钥
func _clear_security() -> void:
	_stop_handshake_timer()
	_handshake = null
	_session = null


## 直接发送已打包的数据
func _send_raw(data: PackedByteArray) -> bool:
	if data.is_empty() or _socket == null:
		return false
	return _socket.send(data) == OK


## 归一化安全配置，允许直接传入字典
static func _normalize_security(value: Variant) -> DueSecurityOptionsScript:
	if value == null:
		return null
	if value is DueSecurityOptionsScript:
		return value
	if value is Dictionary:
		return DueSecurityOptionsScript.new(value)
	push_error("due-client: invalid security options")
	return null


func _maybe_reconnect() -> void:
	if _manual_close or not auto_reconnect:
		return
	if reconnect_max_attempts > 0 and _reconnect_attempts >= reconnect_max_attempts:
		return
	_reconnect_attempts += 1
	_set_state(State.RECONNECTING)
	_start_reconnect()


func _start_reconnect() -> void:
	if _reconnect_timer == null:
		return
	_reconnect_timer.wait_time = reconnect_interval / 1000.0
	_reconnect_timer.start()


func _stop_reconnect() -> void:
	if _reconnect_timer != null:
		_reconnect_timer.stop()


func _on_reconnect_timeout() -> void:
	connect_server()


func _start_heartbeat() -> void:
	if heartbeat_interval > 0 and _heartbeat_timer != null:
		_heartbeat_timer.wait_time = heartbeat_interval / 1000.0
		_heartbeat_timer.start()


func _stop_heartbeat() -> void:
	if _heartbeat_timer != null:
		_heartbeat_timer.stop()


func _on_heartbeat_timeout() -> void:
	if is_open():
		_socket.send(packer.pack_heartbeat())


func _clear_waitgroup() -> void:
	for group in _waitgroup.values():
		var callbacks: Dictionary = group.get("callbacks", {})
		for deferred in callbacks.values():
			deferred.done.emit({ "ok": false, "error": "connection closed" })
	_waitgroup.clear()
