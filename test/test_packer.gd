extends SceneTree
## DuePacker 单元测试。
##
## 运行方式（在项目根目录执行）：
##     godot --headless --script res://test/test_packer.gd

const DuePackerScript := preload("res://addons/due_client/due_packer.gd")

var _passed := 0
var _failed := 0


func _init() -> void:
	print("=== DuePacker 单元测试 ===")

	_test_pack_heartbeat_big_endian()
	_test_pack_heartbeat_little_endian()
	_test_pack_message_big_endian()
	_test_pack_message_little_endian()
	_test_roundtrip_route4_seq0()
	_test_roundtrip_route1_seq1()
	_test_unpack_heartbeat()
	_test_unpack_heartbeat_with_timestamp()
	_test_route_overflow()
	_test_seq_overflow()
	_test_buffer_too_large()
	_test_unpack_invalid()

	_print_summary()
	quit(0 if _failed == 0 else 1)


func _test_pack_heartbeat_big_endian() -> void:
	var packer := DuePackerScript.new({ "byte_order": "big" })
	# size = 1（仅 header），header = 0x80
	_assert_eq(packer.pack_heartbeat(), PackedByteArray([0, 0, 0, 1, 0x80]), "心跳打包（大端）")


func _test_pack_heartbeat_little_endian() -> void:
	var packer := DuePackerScript.new({ "byte_order": "little" })
	_assert_eq(packer.pack_heartbeat(), PackedByteArray([1, 0, 0, 0, 0x80]), "心跳打包（小端）")


func _test_pack_message_big_endian() -> void:
	var packer := DuePackerScript.new({ "byte_order": "big", "seq_bytes": 2, "route_bytes": 2 })
	var data := packer.pack_message({
		"seq": 10,
		"route": 1,
		"buffer": PackedByteArray([1, 2, 3]),
	})
	# size = 1 + 2 + 2 + 3 = 8
	_assert_eq(data, PackedByteArray([0, 0, 0, 8, 0, 0, 1, 0, 10, 1, 2, 3]), "消息打包（大端）")


func _test_pack_message_little_endian() -> void:
	var packer := DuePackerScript.new({ "byte_order": "little", "seq_bytes": 2, "route_bytes": 2 })
	var data := packer.pack_message({
		"seq": 10,
		"route": 1,
		"buffer": PackedByteArray([1, 2, 3]),
	})
	_assert_eq(data, PackedByteArray([8, 0, 0, 0, 0, 1, 0, 10, 0, 1, 2, 3]), "消息打包（小端）")


func _test_roundtrip_route4_seq0() -> void:
	var packer := DuePackerScript.new({ "byte_order": "big", "seq_bytes": 0, "route_bytes": 4 })
	var buffer := PackedByteArray([1, 2, 3, 4, 5])
	var packet := packer.unpack(packer.pack_message({ "route": 1, "buffer": buffer }))
	_assert_eq(packet.get("is_heartbeat"), false, "route=4/seq=0 解包类型")
	_assert_eq(packet["message"]["route"], 1, "route=4/seq=0 路由")
	_assert_eq(packet["message"]["seq"], 0, "route=4/seq=0 序列号（应为 0）")
	_assert_eq(packet["message"]["buffer"], buffer, "route=4/seq=0 数据体")


func _test_roundtrip_route1_seq1() -> void:
	var packer := DuePackerScript.new({ "byte_order": "little", "seq_bytes": 1, "route_bytes": 1 })
	var buffer := PackedByteArray([9, 8, 7])
	var packet := packer.unpack(packer.pack_message({ "route": 100, "seq": 50, "buffer": buffer }))
	_assert_eq(packet["message"]["route"], 100, "route=1/seq=1 路由")
	_assert_eq(packet["message"]["seq"], 50, "route=1/seq=1 序列号")
	_assert_eq(packet["message"]["buffer"], buffer, "route=1/seq=1 数据体")


func _test_unpack_heartbeat() -> void:
	var packer := DuePackerScript.new({ "byte_order": "big" })
	var packet := packer.unpack(packer.pack_heartbeat())
	_assert_eq(packet.get("is_heartbeat"), true, "无时间戳心跳解包类型")
	_assert_eq(packet.get("millisecond"), 0, "无时间戳心跳毫秒（应为 0）")


func _test_unpack_heartbeat_with_timestamp() -> void:
	var ts := 1234567890123
	# 手工构造带 8 字节时间戳的心跳包：size = 1 + 8 = 9
	var stream := StreamPeerBuffer.new()
	stream.big_endian = true
	stream.put_u32(9)
	stream.put_u8(1 << 7)
	stream.put_u64(ts)

	var packer := DuePackerScript.new({ "byte_order": "big" })
	var packet := packer.unpack(stream.data_array)
	_assert_eq(packet.get("is_heartbeat"), true, "带时间戳心跳解包类型")
	_assert_eq(packet.get("millisecond"), ts, "带时间戳心跳毫秒")


func _test_route_overflow() -> void:
	var packer := DuePackerScript.new({ "route_bytes": 2 })
	# 2 字节有符号范围 -32768 ~ 32767
	_assert_eq(packer.pack_message({ "route": 40000 }).is_empty(), true, "路由越界返回空")


func _test_seq_overflow() -> void:
	var packer := DuePackerScript.new({ "seq_bytes": 1 })
	# 1 字节有符号范围 -128 ~ 127
	_assert_eq(packer.pack_message({ "route": 1, "seq": 200 }).is_empty(), true, "序列号越界返回空")


func _test_buffer_too_large() -> void:
	var packer := DuePackerScript.new({ "buffer_bytes": 4 })
	_assert_eq(
		packer.pack_message({ "route": 1, "buffer": PackedByteArray([1, 2, 3, 4, 5]) }).is_empty(),
		true,
		"消息体超长返回空"
	)


func _test_unpack_invalid() -> void:
	var packer := DuePackerScript.new({})
	# 长度不足 size + header（4 + 1）
	_assert_eq(packer.unpack(PackedByteArray([0, 0])).is_empty(), true, "无效数据解包返回空")


func _assert_eq(actual: Variant, expected: Variant, name: String) -> void:
	if actual == expected:
		_passed += 1
		print("  [PASS] " + name)
	else:
		_failed += 1
		printerr("  [FAIL] " + name)
		printerr("      expected: " + str(expected))
		printerr("      actual:   " + str(actual))


func _print_summary() -> void:
	print("")
	print("测试完成：%d 通过，%d 失败" % [_passed, _failed])
