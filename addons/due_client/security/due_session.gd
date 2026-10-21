class_name DueSession
extends RefCounted
## 握手协商出的 AEAD 会话，与 Unity 的 Session 对应。
##
## 密文载荷布局：epoch(1) | counter(8) | ciphertext | tag；
## nonce 为 4 字节会话盐值拼接 8 字节计数器。

const DueAesGcmScript := preload("res://addons/due_client/security/due_aead.gd")

## 消息传输方向；与服务端的 handshake.Direction 对应
enum Direction {
	CLIENT_TO_SERVER = 0,  ## 客户端到服务端
	SERVER_TO_CLIENT = 1,  ## 服务端到客户端
}

## 握手协议版本，同时用于构造 AAD
const VERSION := 1
## 密文信封头长度
const ENVELOPE_HEADER_SIZE := 9
## 会话盐值长度
const SALT_SIZE := 4
## nonce 长度
const NONCE_SIZE := 12
## 认证标签长度
const TAG_SIZE := 16
## AAD 长度
const AAD_SIZE := 11

## 发送方向加解密器
var _send
## 接收方向加解密器
var _recv
## 会话盐值
var _salt: PackedByteArray
## 发送计数器
var _send_counter := 0
## 接收重放窗口
var _replay_highest := 0
var _replay_bits := 0
var _replay_inited := false


func _init(send_key: PackedByteArray, recv_key: PackedByteArray, salt: PackedByteArray) -> void:
	if salt.size() != SALT_SIZE:
		push_error("due-client: invalid session salt")
		return

	_send = DueAesGcmScript.new(send_key)
	_recv = DueAesGcmScript.new(recv_key)
	_salt = salt.duplicate()


## 会话是否可用
func is_valid() -> bool:
	return _send != null and _send.is_valid() and _recv != null and _recv.is_valid()


## 当前密钥世代的编号
func get_epoch() -> int:
	return VERSION


## 加密后额外附加的字节数（信封头 + 认证标签）
func get_overhead() -> int:
	return ENVELOPE_HEADER_SIZE + TAG_SIZE


## 构造附加认证数据：version(1) | direction(1) | epoch(1) | route(4) | seq(4)
static func make_aad(direction: int, epoch: int, route: int, seq: int) -> PackedByteArray:
	var aad := PackedByteArray()
	aad.resize(AAD_SIZE)
	aad[0] = VERSION
	aad[1] = direction
	aad[2] = epoch
	_write_u32_be(aad, 3, route)
	_write_u32_be(aad, 7, seq)
	return aad


## 加密消息载荷，返回可直接写入消息体的密文信封
func seal_message(
	plaintext: PackedByteArray, direction: int, route: int, seq: int
) -> PackedByteArray:
	if not is_valid():
		return PackedByteArray()

	var counter := _send_counter
	_send_counter += 1

	var body: PackedByteArray = _send.seal(
		_build_nonce(counter), plaintext, make_aad(direction, VERSION, route, seq)
	)
	if body.is_empty():
		return PackedByteArray()

	var output := PackedByteArray()
	output.resize(ENVELOPE_HEADER_SIZE + body.size())
	output[0] = VERSION
	_write_u64_be(output, 1, counter)
	for i in body.size():
		output[ENVELOPE_HEADER_SIZE + i] = body[i]

	return output


## 校验并解密消息载荷；失败时返回空数组
func open_message(
	sealed_data: PackedByteArray, direction: int, route: int, seq: int
) -> PackedByteArray:
	if not is_valid():
		return PackedByteArray()

	if sealed_data.size() < ENVELOPE_HEADER_SIZE + TAG_SIZE:
		push_error("due-client: invalid secure message")
		return PackedByteArray()

	if sealed_data[0] != VERSION:
		push_error("due-client: invalid secure message")
		return PackedByteArray()

	var counter := _read_u64_be(sealed_data, 1)
	var body := sealed_data.slice(ENVELOPE_HEADER_SIZE, sealed_data.size())
	var result: Dictionary = _recv.open_checked(
		_build_nonce(counter), body, make_aad(direction, VERSION, route, seq)
	)

	if not result["ok"]:
		return PackedByteArray()

	# 仅在认证通过后推进重放窗口
	if not _advance_replay(counter):
		push_error("due-client: replayed message")
		return PackedByteArray()

	return result["data"]


## 构造 nonce：salt(4) | counter(8)
func _build_nonce(counter: int) -> PackedByteArray:
	var nonce := PackedByteArray()
	nonce.resize(NONCE_SIZE)
	for i in SALT_SIZE:
		nonce[i] = _salt[i]
	_write_u64_be(nonce, SALT_SIZE, counter)
	return nonce


## 记录计数器并返回是否为新鲜消息（64 位滑动窗口）
func _advance_replay(counter: int) -> bool:
	if not _replay_inited:
		_replay_inited = true
		_replay_highest = counter
		_replay_bits = 1
		return true

	if counter > _replay_highest:
		var shift := counter - _replay_highest
		if shift >= 64:
			_replay_bits = 0
		else:
			_replay_bits = _replay_bits << shift
		_replay_bits |= 1
		_replay_highest = counter
		return true

	var diff := _replay_highest - counter
	if diff >= 64 or (_replay_bits & (1 << diff)) != 0:
		return false

	_replay_bits |= 1 << diff
	return true


## 写入 32 位大端整数
static func _write_u32_be(buffer: PackedByteArray, offset: int, value: int) -> void:
	value = value & 0xffffffff
	buffer[offset] = (value >> 24) & 0xff
	buffer[offset + 1] = (value >> 16) & 0xff
	buffer[offset + 2] = (value >> 8) & 0xff
	buffer[offset + 3] = value & 0xff


## 写入 64 位大端整数
static func _write_u64_be(buffer: PackedByteArray, offset: int, value: int) -> void:
	for i in range(7, -1, -1):
		buffer[offset + i] = value & 0xff
		value = value >> 8


## 读取 64 位大端整数
static func _read_u64_be(buffer: PackedByteArray, offset: int) -> int:
	var value := 0
	for i in 8:
		value = (value << 8) | buffer[offset + i]
	return value
