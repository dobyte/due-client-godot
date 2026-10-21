extends SceneTree
## DueClient 安全模式集成测试：本地 mock WebSocket 服务器完成握手并加解密消息。
##
## 运行方式（在项目根目录执行）：
##     godot --headless --script res://test/test_client_security.gd

const DueClientScript := preload("res://addons/due_client/due_client.gd")
const DuePackerScript := preload("res://addons/due_client/due_packer.gd")
const DueSecurityOptionsScript := preload("res://addons/due_client/security/due_security_options.gd")
const DueVerifierScript := preload("res://addons/due_client/security/due_verifier.gd")
const DueSessionScript := preload("res://addons/due_client/security/due_session.gd")
const TestUtil := preload("res://test/security_test_util.gd")
const TestServerScript := preload("res://test/security_test_server.gd")

## 测试用 P-256 私钥，与 due-benchmark/cluster/ws/gate/resource/key.pem 一致
const PRIVATE_KEY := """-----BEGIN ECDSA PRIVATE KEY-----
MHcCAQEEIBBzcsY8yb1Xtjfaqx54SUj/euyRIY1JwXpJaqWuV0omoAoGCCqGSM49
AwEHoUQDQgAE0KDj25at5TKOdvPmtF0gd2ImGa2a9w7NTi2ywa98NQKNtjT1eGRK
rzo6HWxeLAj42zQ7RJZ6Zwb/BeBHbcONzg==
-----END ECDSA PRIVATE KEY-----"""

## 与私钥配对的公钥，与 due-benchmark/cluster/ws/client/resource/key.pub.pem 一致
const PUBLIC_KEY := """-----BEGIN ECDSA PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0KDj25at5TKOdvPmtF0gd2ImGa2a
9w7NTi2ywa98NQKNtjT1eGRKrzo6HWxeLAj42zQ7RJZ6Zwb/BeBHbcONzg==
-----END ECDSA PUBLIC KEY-----"""

const PORT := 9081
## 与 due-benchmark/cluster/ws/client 的 etc.toml [packet] 配置一致
const PACKET_OPTIONS := { "byte_order": "big", "route_bytes": 4, "seq_bytes": 4, "buffer_bytes": 5000 }

var _server := TCPServer.new()
var _server_peer: WebSocketPeer = null
var _server_packer = DuePackerScript.new(PACKET_OPTIONS)
var _server_handshake = null
var _server_session: DueSessionScript = null

var _client: DueClientScript
var _client_packer = DuePackerScript.new(PACKET_OPTIONS)

var _passed := 0
var _failed := 0
var _server_messages: Array = []
var _server_heartbeats := 0
var _client_received: Array = []
var _client_errors: Array = []


func _init() -> void:
	var err: Error = _server.listen(PORT)
	if err != OK:
		printerr("mock 服务器启动失败：%d" % err)
		quit(1)
		return

	_client = DueClientScript.new({
		"url": "ws://127.0.0.1:%d" % PORT,
		"heartbeat": 100,
		"auto_reconnect": true,
		"reconnect_interval": 200,
		"reconnect_max_attempts": 0,
		"packer": _client_packer,
		"security": DueSecurityOptionsScript.new({
			"verifier": DueVerifierScript.ecdsa(PUBLIC_KEY),
		}),
	})
	root.add_child(_client)
	_client.received.connect(func(message: Dictionary) -> void: _client_received.append(message))
	_client.error.connect(func(message: String) -> void: _client_errors.append(message))

	_server_loop()
	_run_tests()


func _server_loop() -> void:
	while true:
		_poll_server()
		await create_timer(0.02).timeout


func _run_tests() -> void:
	print("=== DueClient 安全模式集成测试 ===")

	await _test_connect()
	await _test_send_to_server()
	await _test_receive_from_server()
	await _test_request_response()
	await _test_heartbeat()
	await _test_reconnect()

	_print_summary()
	quit(0 if _failed == 0 else 1)


func _test_connect() -> void:
	_client.connect_server()

	# 握手完成前不允许发送业务消息
	var early := _client.send({ "route": 1, "buffer": PackedByteArray([1]) })
	_assert(not early, "握手完成前发送被拒绝")

	var ok: bool = await _await_condition(15.0, func() -> bool: return _client.is_open())
	_assert(ok, "握手完成后连接建立")
	_assert(_server_handshake != null and _server_session != null, "服务端完成握手")


func _test_send_to_server() -> void:
	_server_messages.clear()
	var buffer := PackedByteArray([1, 2, 3])
	_client.send({ "route": 1, "buffer": buffer })
	var ok: bool = await _await_condition(3.0, func() -> bool: return _server_messages.size() > 0)
	var matched: bool = ok and _server_messages[0]["route"] == 1 and _server_messages[0]["buffer"] == buffer
	_assert(matched, "客户端加密发送，服务端解密成功")


func _test_receive_from_server() -> void:
	_client_received.clear()
	var buffer := PackedByteArray([9, 8, 7])
	_server_send_encrypted({ "route": 2, "seq": 0, "buffer": buffer })
	var ok: bool = await _await_condition(3.0, func() -> bool: return _client_received.size() > 0)
	var matched: bool = ok and _client_received[0]["route"] == 2 and _client_received[0]["buffer"] == buffer
	_assert(matched, "服务端加密推送，客户端解密成功")


func _test_request_response() -> void:
	var buffer := PackedByteArray([4, 5, 6])
	var result: Dictionary = await _client.request(1, buffer, 2000)
	var matched: bool = result.get("ok") and result["message"]["route"] == 1 and result["message"]["buffer"] == buffer
	_assert(matched, "安全模式同步请求/响应")


func _test_heartbeat() -> void:
	_server_heartbeats = 0
	var ok: bool = await _await_condition(2.0, func() -> bool: return _server_heartbeats > 0)
	_assert(ok, "心跳保持明文")


func _test_reconnect() -> void:
	if _server_peer == null:
		_assert(false, "服务器断开后客户端断开（无连接）")
		_assert(false, "重连后重新握手")
		return

	_client_received.clear()
	_server_peer.close()
	var disconnected: bool = await _await_condition(3.0, func() -> bool: return not _client.is_open())
	_assert(disconnected, "服务器断开后客户端断开")

	var reconnected: bool = await _await_condition(15.0, func() -> bool: return _client.is_open())
	_assert(reconnected, "重连后重新握手")

	if reconnected:
		_server_messages.clear()
		var buffer := PackedByteArray([7, 7, 7])
		_client.send({ "route": 3, "buffer": buffer })
		var ok: bool = await _await_condition(3.0, func() -> bool: return _server_messages.size() > 0)
		var matched: bool = ok and _server_messages[0]["buffer"] == buffer
		_assert(matched, "重连后新会话可正常通信")


func _poll_server() -> void:
	if _server.is_connection_available():
		var stream := _server.take_connection()
		if _server_peer != null and _server_peer.get_ready_state() == WebSocketPeer.STATE_OPEN:
			_server_peer.close()
		_server_peer = WebSocketPeer.new()
		_server_peer.accept_stream(stream)
		# 每条连接都需要重新握手
		_server_handshake = null
		_server_session = null

	if _server_peer != null:
		_server_peer.poll()
		while _server_peer.get_available_packet_count() > 0:
			var packet: Variant = _server_peer.get_packet()
			if packet is PackedByteArray:
				_on_server_packet(packet)


func _on_server_packet(data: PackedByteArray) -> void:
	var packet: Dictionary = _server_packer.unpack(data)
	if packet.is_empty():
		return

	if packet.get("is_handshake", false):
		_handle_handshake(packet.get("payload", PackedByteArray()))
		return

	if packet.get("is_heartbeat", false):
		_server_heartbeats += 1
		return

	if _server_session == null:
		return

	var message: Dictionary = packet["message"]
	var sealed_buffer: PackedByteArray = message.get("buffer", PackedByteArray())
	var route: int = message.get("route", 0)
	var seq: int = message.get("seq", 0)
	var plaintext := _server_session.open_message(
		sealed_buffer, DueSessionScript.Direction.CLIENT_TO_SERVER, route, seq
	)
	if plaintext.size() != sealed_buffer.size() - _server_session.get_overhead():
		printerr("mock 服务器解密失败")
		return

	_server_messages.append({ "route": route, "seq": seq, "buffer": plaintext })

	# 请求（seq > 0）时回显响应
	if seq > 0:
		_server_send_encrypted({ "route": route, "seq": seq, "buffer": plaintext })


func _handle_handshake(payload: PackedByteArray) -> void:
	if _server_handshake == null:
		_server_handshake = TestServerScript.new(_create_signer())
		var frame: PackedByteArray = _server_handshake.accept(payload)
		_server_send_raw(_server_packer.pack_handshake(frame))
	else:
		_server_session = _server_handshake.confirm(payload)


func _server_send_raw(data: PackedByteArray) -> void:
	if _server_peer != null and _server_peer.get_ready_state() == WebSocketPeer.STATE_OPEN:
		_server_peer.send(data)


func _server_send_encrypted(message: Dictionary) -> void:
	if _server_session == null:
		return
	var sealed := _server_session.seal_message(
		message.get("buffer", PackedByteArray()),
		DueSessionScript.Direction.SERVER_TO_CLIENT,
		message.get("route", 0),
		message.get("seq", 0)
	)
	_server_send_raw(_server_packer.pack_message({
		"route": message.get("route", 0),
		"seq": message.get("seq", 0),
		"buffer": sealed,
	}))


func _create_signer() -> CryptoKey:
	return TestUtil.load_private_key(PRIVATE_KEY)


func _await_condition(timeout_sec: float, condition: Callable) -> bool:
	var elapsed := 0.0
	var step := 0.05
	while elapsed < timeout_sec:
		if condition.call():
			return true
		await create_timer(step).timeout
		elapsed += step
	return condition.call()


func _assert(condition: bool, name: String) -> void:
	if condition:
		_passed += 1
		print("  [PASS] " + name)
	else:
		_failed += 1
		printerr("  [FAIL] " + name)


func _print_summary() -> void:
	if not _client_errors.is_empty():
		print("客户端错误：", _client_errors)
	print("")
	print("测试完成：%d 通过，%d 失败" % [_passed, _failed])
