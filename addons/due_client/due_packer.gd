class_name DuePacker
extends RefCounted
## due 协议打包器。
##
## 负责将消息打包为二进制数据、以及将二进制数据解包为消息。
## 协议格式（字节序可配置为 big/little，默认 big）：
##   [size: 4字节][header: 1字节][route: route_bytes字节][seq: seq_bytes字节][buffer]
## 其中 size 为 header 之后的总字节数；心跳包的 header 最高位为 1，
## 且可选携带 8 字节的服务器时间戳（毫秒）。

const BIG_ENDIAN := "big"
const LITTLE_ENDIAN := "little"

const DEFAULT_BYTE_ORDER := BIG_ENDIAN
const DEFAULT_SIZE_BYTES := 4
const DEFAULT_HEADER_BYTES := 1
const DEFAULT_ROUTE_BYTES := 2
const DEFAULT_SEQ_BYTES := 2
const DEFAULT_BUFFER_BYTES := 5000

## 字节序，可选 "big" 或 "little"，默认为 "big"
var byte_order: String
## 序列号字节长度，可选 0、1、2、4；0 表示不开启序列号编码
var seq_bytes: int
## 路由字节长度，可选 1、2、4
var route_bytes: int
## 消息体最大字节长度
var buffer_bytes: int

var _heartbeat: PackedByteArray


func _init(opts: Dictionary = {}) -> void:
	byte_order = opts.get("byte_order", DEFAULT_BYTE_ORDER)
	route_bytes = opts.get("route_bytes", DEFAULT_ROUTE_BYTES)
	seq_bytes = opts.get("seq_bytes", DEFAULT_SEQ_BYTES)
	buffer_bytes = opts.get("buffer_bytes", DEFAULT_BUFFER_BYTES)
	_heartbeat = _do_pack_heartbeat()


## 打包心跳包
func pack_heartbeat() -> PackedByteArray:
	return _heartbeat


## 打包消息
## message 结构：{ "seq": int, "route": int, "buffer": PackedByteArray }
## 出错时返回空 PackedByteArray
func pack_message(message: Dictionary) -> PackedByteArray:
	var seq: int = message.get("seq", 0)
	var route: int = message.get("route", 0)
	var buffer: PackedByteArray = message.get("buffer", PackedByteArray())

	var size: int = DEFAULT_HEADER_BYTES + route_bytes + seq_bytes + buffer.size()

	if not _check_range(route, route_bytes, "route overflow"):
		return PackedByteArray()
	if seq_bytes > 0 and not _check_range(seq, seq_bytes, "seq overflow"):
		return PackedByteArray()
	if buffer.size() > buffer_bytes:
		push_error("due-client: message too large")
		return PackedByteArray()

	var stream := StreamPeerBuffer.new()
	stream.big_endian = _is_big_endian()

	stream.put_u32(size)
	stream.put_u8(0)  # header：普通消息
	_put_int(stream, route, route_bytes)
	if seq_bytes > 0:
		_put_int(stream, seq, seq_bytes)
	stream.put_data(buffer)

	return stream.data_array


## 解包数据
## 返回结构：{ "is_heartbeat": bool, "millisecond": int, "message": Dictionary }
func unpack(data: PackedByteArray) -> Dictionary:
	if data.size() < DEFAULT_SIZE_BYTES + DEFAULT_HEADER_BYTES:
		push_error("due-client: invalid packet")
		return {}

	var stream := StreamPeerBuffer.new()
	stream.big_endian = _is_big_endian()
	stream.data_array = data
	stream.seek(0)

	var size: int = stream.get_u32()
	var header: int = stream.get_u8()
	var is_heartbeat: bool = (header >> 7) == 1

	if is_heartbeat:
		var result := { "is_heartbeat": true, "millisecond": 0 }
		if size + DEFAULT_SIZE_BYTES > stream.get_position():
			result["millisecond"] = stream.get_u64()
		return result

	var message := { "seq": 0, "route": 0, "buffer": PackedByteArray() }
	if route_bytes > 0:
		message["route"] = _get_int(stream, route_bytes)
	if seq_bytes > 0:
		message["seq"] = _get_int(stream, seq_bytes)

	if size + DEFAULT_SIZE_BYTES > stream.get_position():
		var offset: int = stream.get_position()
		message["buffer"] = data.slice(offset, size + DEFAULT_SIZE_BYTES)

	return { "is_heartbeat": false, "message": message }


func _do_pack_heartbeat() -> PackedByteArray:
	var stream := StreamPeerBuffer.new()
	stream.big_endian = _is_big_endian()
	stream.put_u32(DEFAULT_HEADER_BYTES)  # size = 1
	stream.put_u8(1 << 7)  # header：心跳包
	return stream.data_array


func _is_big_endian() -> bool:
	return byte_order == BIG_ENDIAN


func _put_int(stream: StreamPeerBuffer, value: int, size: int) -> void:
	match size:
		1:
			stream.put_8(value)
		2:
			stream.put_16(value)
		4:
			stream.put_32(value)


func _get_int(stream: StreamPeerBuffer, size: int) -> int:
	match size:
		1:
			return stream.get_8()
		2:
			return stream.get_16()
		4:
			return stream.get_32()
	return 0


func _check_range(value: int, size: int, message: String) -> bool:
	var bits: int = size * 8
	var min_val: int = -(1 << (bits - 1))
	var max_val: int = (1 << (bits - 1)) - 1
	if value > max_val or value < min_val:
		push_error("due-client: " + message)
		return false
	return true
