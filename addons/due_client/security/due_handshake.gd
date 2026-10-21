class_name DueHandshakeClient
extends RefCounted
## 客户端侧的会话安全握手，与 Unity 的 HandshakeClient 对应。
##
## 每条连接都需要重新创建实例，握手状态与连接一一对应。

const DueCryptoScript := preload("res://addons/due_client/security/due_crypto.gd")
const DueX25519Script := preload("res://addons/due_client/security/due_x25519.gd")
const DueHkdfScript := preload("res://addons/due_client/security/due_hkdf.gd")
const DueSessionScript := preload("res://addons/due_client/security/due_session.gd")
const DueAesGcmScript := preload("res://addons/due_client/security/due_aead.gd")

## 握手协议版本
const VERSION := 1
## ClientHello 帧类型
const FRAME_CLIENT_HELLO := 1
## ServerHello 帧类型
const FRAME_SERVER_HELLO := 2
## Finished 帧类型
const FRAME_FINISHED := 3
## 随机数字节长度
const RANDOM_SIZE := 32
## 公钥字节长度
const PUBLIC_KEY_SIZE := 32
## 认证标签字节长度
const MAC_SIZE := 32
## 握手帧头字节长度
const FRAME_HEADER_SIZE := 4
## 派生密钥材料的总长度：四个 32 字节密钥 + 4 字节盐值
const KEY_MATERIAL_SIZE := 32 * 4 + 4
## 握手转录的域分隔标签
const TRANSCRIPT_LABEL := "due-handshake-v1"

## 服务端签名验证器
var _verifier: Callable
## 客户端支持的套件编号
var _suites: Array
## 临时私钥
var _private_key := PackedByteArray()
## 客户端随机数
var _random := PackedByteArray()
## ClientHello 的 body
var _hello := PackedByteArray()
## 握手状态：0 初始，1 已发送 ClientHello，2 已完成
var _state := 0


func _init(verifier: Callable, suites: Array = [1]) -> void:
	# 与 Unity 的 HandshakeClient 一致：未提供套件时默认使用 AES-256-GCM
	if suites.is_empty():
		suites = [DueAesGcmScript.SUITE_ID]
	if suites.size() > 255:
		push_error("due-client: handshake too many aead suites")
		suites = suites.slice(0, 255)

	_verifier = verifier
	_suites = suites.duplicate()
	_state = 0


## 生成 ClientHello 帧；出错时返回空数组
func hello() -> PackedByteArray:
	if _state != 0:
		push_error("due-client: handshake unexpected state")
		return PackedByteArray()

	_private_key = DueX25519Script.generate_private_key()
	_random = DueCryptoScript.random_bytes(RANDOM_SIZE)

	var public_key := DueX25519Script.get_public_key(_private_key)
	var body := PackedByteArray()
	body.append_array(_random)
	body.append_array(public_key)
	body.append(_suites.size())
	for suite in _suites:
		body.append(suite)

	_hello = body
	_state = 1

	return _encode_frame(FRAME_CLIENT_HELLO, body)


## 处理 ServerHello 帧
## 返回结构：
##   成功：{ "ok": true, "session": DueSession, "finished": PackedByteArray }
##   失败：{ "ok": false, "error": String }
func handle(frame: PackedByteArray) -> Dictionary:
	if _state != 1:
		return _fail("handshake: unexpected state")

	var decoded := _decode_frame(frame)
	if not decoded["ok"]:
		return _fail(decoded["error"])

	if decoded["type"] != FRAME_SERVER_HELLO:
		return _fail("handshake: invalid message")

	var body: PackedByteArray = decoded["body"]
	if body.size() < 1 + RANDOM_SIZE + PUBLIC_KEY_SIZE + 2 + MAC_SIZE:
		return _fail("handshake: invalid message")

	var offset := 0
	var suite_id: int = body[offset]
	offset += 1
	var server_random := body.slice(offset, offset + RANDOM_SIZE)
	offset += RANDOM_SIZE
	var server_public_key := body.slice(offset, offset + PUBLIC_KEY_SIZE)
	offset += PUBLIC_KEY_SIZE
	var signature_size: int = (body[offset] << 8) | body[offset + 1]
	offset += 2

	if signature_size <= 0 or offset + signature_size + MAC_SIZE != body.size():
		return _fail("handshake: invalid message")

	var signature := body.slice(offset, offset + signature_size)
	offset += signature_size
	var server_mac := body.slice(offset, body.size())

	if not _suites.has(suite_id) or suite_id != DueAesGcmScript.SUITE_ID:
		return _fail("handshake: unsupported aead suite")

	# ServerHello 中被签名的部分：suite | random | public key
	var prefix := body.slice(0, 1 + RANDOM_SIZE + PUBLIC_KEY_SIZE)
	var label := DueCryptoScript.ascii(TRANSCRIPT_LABEL)
	var signed := DueCryptoScript.sha256([label, _hello, prefix])

	if not _verifier.is_valid() or not _verifier.call(signed, signature):
		return _fail("handshake: invalid server signature")

	# 握手转录：ClientHello body | ServerHello prefix | 服务端签名
	var transcript := DueCryptoScript.sha256([_hello, prefix, signature])

	# 临时密钥协商
	var shared := DueX25519Script.compute_shared_key(_private_key, server_public_key)
	if shared.is_empty():
		return _fail("handshake: key exchange failed")

	# HKDF 盐值：客户端随机数 | 服务端随机数
	var salt := PackedByteArray()
	salt.append_array(_random)
	salt.append_array(server_random)

	# 派生双向密钥、收尾密钥与会话盐值
	var material := DueHkdfScript.sha256(
		shared, salt, DueCryptoScript.concat([label, transcript]), KEY_MATERIAL_SIZE
	)
	var c2s_key := material.slice(0, 32)
	var s2c_key := material.slice(32, 64)
	var c2s_finish := material.slice(64, 96)
	var s2c_finish := material.slice(96, 128)
	var session_salt := material.slice(128, 132)

	# 校验服务端的收尾 MAC
	var expected := DueCryptoScript.hmac_sha256(s2c_finish, transcript)
	if not DueCryptoScript.fixed_time_equals(expected, server_mac):
		return _fail("handshake: invalid server finished mac")

	var session := DueSessionScript.new(c2s_key, s2c_key, session_salt)
	if not session.is_valid():
		return _fail("handshake: session init failed")

	var finished := _encode_frame(
		FRAME_FINISHED, DueCryptoScript.hmac_sha256(c2s_finish, transcript)
	)
	_state = 2

	return { "ok": true, "session": session, "finished": finished }


## 编码握手帧：version(1) | type(1) | length(2) | body
static func _encode_frame(type: int, body: PackedByteArray) -> PackedByteArray:
	var frame := PackedByteArray()
	frame.resize(FRAME_HEADER_SIZE + body.size())
	frame[0] = VERSION
	frame[1] = type
	frame[2] = (body.size() >> 8) & 0xff
	frame[3] = body.size() & 0xff
	for i in body.size():
		frame[FRAME_HEADER_SIZE + i] = body[i]
	return frame


## 解码并校验握手帧
static func _decode_frame(frame: PackedByteArray) -> Dictionary:
	if frame.size() < FRAME_HEADER_SIZE:
		return { "ok": false, "error": "handshake: invalid message" }

	if frame[0] != VERSION:
		return { "ok": false, "error": "handshake: invalid message" }

	var length: int = (frame[2] << 8) | frame[3]
	if length != frame.size() - FRAME_HEADER_SIZE:
		return { "ok": false, "error": "handshake: invalid message" }

	return {
		"ok": true,
		"type": frame[1],
		"body": frame.slice(FRAME_HEADER_SIZE, frame.size()),
	}


## 构造失败结果
static func _fail(message: String) -> Dictionary:
	return { "ok": false, "error": message }
