extends SceneTree
## DueClient 集成测试，使用本地 mock WebSocket 服务器。
##
## 运行方式（在项目根目录执行）：
##     godot --headless --script res://test/test_client.gd

const DueClientScript := preload("res://addons/due_client/due_client.gd")
const DuePackerScript := preload("res://addons/due_client/due_packer.gd")

const PORT := 9080
## 与 due-benchmark/cluster/ws/client 的 etc.toml [packet] 配置一致
const PACKET_OPTIONS := { "byte_order": "big", "route_bytes": 4, "seq_bytes": 4, "buffer_bytes": 5000 }

var _server := TCPServer.new()
var _server_peer: WebSocketPeer = null
var _server_packer = DuePackerScript.new(PACKET_OPTIONS)

var _client
var _client_packer = DuePackerScript.new(PACKET_OPTIONS)

var _passed := 0
var _failed := 0

# 服务器收到的消息与心跳次数
var _server_messages: Array = []
var _server_heartbeats: int = 0

# 客户端收到的消息
var _client_received: Array = []


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
	})
	root.add_child(_client)
	_client.received.connect(func(message: Dictionary) -> void: _client_received.append(message))

	_server_loop()
	_run_tests()


func _server_loop() -> void:
	while true:
		_poll_server()
		await create_timer(0.02).timeout


func _run_tests() -> void:
	print("=== DueClient 集成测试 ===")

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
	var ok: bool = await _await_condition(3.0, func() -> bool: return _client.is_open())
	_assert(ok, "连接建立")


func _test_send_to_server() -> void:
	_server_messages.clear()
	var buffer := PackedByteArray([1, 2, 3])
	_client.send({ "route": 1, "buffer": buffer })
	var ok: bool = await _await_condition(3.0, func() -> bool: return _server_messages.size() > 0)
	var matched: bool = ok and _server_messages[0]["route"] == 1 and _server_messages[0]["buffer"] == buffer
	_assert(matched, "客户端发送消息到服务器")


func _test_receive_from_server() -> void:
	_client_received.clear()
	var buffer := PackedByteArray([9, 8, 7])
	_server_send({ "route": 2, "buffer": buffer })
	var ok: bool = await _await_condition(3.0, func() -> bool: return _client_received.size() > 0)
	var matched: bool = ok and _client_received[0]["route"] == 2 and _client_received[0]["buffer"] == buffer
	_assert(matched, "服务器推送消息到客户端")


func _test_request_response() -> void:
	var buffer := PackedByteArray([4, 5, 6])
	var result: Dictionary = await _client.request(1, buffer, 2000)
	var matched: bool = result.get("ok") and result["message"]["route"] == 1 and result["message"]["buffer"] == buffer
	_assert(matched, "同步请求/响应")


func _test_heartbeat() -> void:
	_server_heartbeats = 0
	var ok: bool = await _await_condition(2.0, func() -> bool: return _server_heartbeats > 0)
	_assert(ok, "客户端心跳")


func _test_reconnect() -> void:
	if _server_peer == null:
		_assert(false, "服务器断开后客户端断开（无连接）")
		_assert(false, "客户端自动重连（无连接）")
		return
	_server_peer.close()
	var disconnected: bool = await _await_condition(3.0, func() -> bool: return not _client.is_open())
	_assert(disconnected, "服务器断开后客户端断开")
	var reconnected: bool = await _await_condition(5.0, func() -> bool: return _client.is_open())
	_assert(reconnected, "客户端自动重连")


func _poll_server() -> void:
	if _server.is_connection_available():
		var stream := _server.take_connection()
		if _server_peer != null and _server_peer.get_ready_state() == WebSocketPeer.STATE_OPEN:
			_server_peer.close()
		_server_peer = WebSocketPeer.new()
		_server_peer.accept_stream(stream)

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
	if packet.get("is_heartbeat", false):
		_server_heartbeats += 1
		return

	var message: Dictionary = packet["message"]
	_server_messages.append(message)
	# 请求（seq > 0）时回显响应
	if message.get("seq", 0) > 0:
		_server_send({ "seq": message["seq"], "route": message["route"], "buffer": message["buffer"] })


func _server_send(message: Dictionary) -> void:
	if _server_peer != null and _server_peer.get_ready_state() == WebSocketPeer.STATE_OPEN:
		_server_peer.send(_server_packer.pack_message(message))


func _await_condition(timeout_sec: float, condition: Callable) -> bool:
	var t := 0.0
	var step := 0.05
	while t < timeout_sec:
		if condition.call():
			return true
		await create_timer(step).timeout
		t += step
	return condition.call()


func _assert(condition: bool, name: String) -> void:
	if condition:
		_passed += 1
		print("  [PASS] " + name)
	else:
		_failed += 1
		printerr("  [FAIL] " + name)


func _print_summary() -> void:
	print("")
	print("测试完成：%d 通过，%d 失败" % [_passed, _failed])
