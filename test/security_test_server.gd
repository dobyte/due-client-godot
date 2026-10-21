extends RefCounted
## 按照 due 服务端握手流程实现的测试服务端，用于验证客户端握手逻辑。

const TestUtil := preload("res://test/security_test_util.gd")
const DueCryptoScript := preload("res://addons/due_client/security/due_crypto.gd")
const DueX25519Script := preload("res://addons/due_client/security/due_x25519.gd")
const DueHkdfScript := preload("res://addons/due_client/security/due_hkdf.gd")
const DueSessionScript := preload("res://addons/due_client/security/due_session.gd")
const DueAesGcmScript := preload("res://addons/due_client/security/due_aead.gd")

const VERSION := 1
const FRAME_CLIENT_HELLO := 1
const FRAME_SERVER_HELLO := 2
const FRAME_FINISHED := 3
const RANDOM_SIZE := 32
const KEY_SIZE := 32
const MAC_SIZE := 32
const KEY_MATERIAL_SIZE := 32 * 4 + 4
const LABEL := "due-handshake-v1"

## 服务端会话
var session

var _signer: CryptoKey
var _suite: int
var _crypto := Crypto.new()
var _transcript := PackedByteArray()
var _c2s_finish := PackedByteArray()
var _state := 0


func _init(signer: CryptoKey, suite: int = 1) -> void:
	_signer = signer
	_suite = suite


## 处理 ClientHello，返回 ServerHello 帧
func accept(frame: PackedByteArray) -> PackedByteArray:
	if _state != 0:
		return PackedByteArray()

	var decoded := _decode_frame(frame)
	if not decoded["ok"] or decoded["type"] != FRAME_CLIENT_HELLO:
		return PackedByteArray()

	var hello: PackedByteArray = decoded["body"]
	if hello.size() < RANDOM_SIZE + KEY_SIZE + 1:
		return PackedByteArray()

	var count: int = hello[RANDOM_SIZE + KEY_SIZE]
	if hello.size() != RANDOM_SIZE + KEY_SIZE + 1 + count:
		return PackedByteArray()

	var offered := false
	for i in count:
		if hello[RANDOM_SIZE + KEY_SIZE + 1 + i] == _suite:
			offered = true
	if not offered:
		return PackedByteArray()

	var client_random := hello.slice(0, RANDOM_SIZE)
	var client_public_key := hello.slice(RANDOM_SIZE, RANDOM_SIZE + KEY_SIZE)

	var private_key := DueX25519Script.generate_private_key()
	var public_key := DueX25519Script.get_public_key(private_key)
	var random := DueCryptoScript.random_bytes(RANDOM_SIZE)
	var prefix := DueCryptoScript.concat([PackedByteArray([_suite]), random, public_key])
	var label := DueCryptoScript.ascii(LABEL)
	var signed := DueCryptoScript.sha256([label, hello, prefix])

	var der := _crypto.sign(HashingContext.HASH_SHA256, signed, _signer)
	var signature := TestUtil.der_to_due_signature(der)
	if signature.is_empty():
		return PackedByteArray()

	var transcript := DueCryptoScript.sha256([hello, prefix, signature])
	var shared := DueX25519Script.compute_shared_key(private_key, client_public_key)
	var salt := DueCryptoScript.concat([client_random, random])
	var material := DueHkdfScript.sha256(
		shared, salt, DueCryptoScript.concat([label, transcript]), KEY_MATERIAL_SIZE
	)

	var c2s_key := material.slice(0, 32)
	var s2c_key := material.slice(32, 64)
	_c2s_finish = material.slice(64, 96)
	var s2c_finish := material.slice(96, 128)
	var session_salt := material.slice(128, 132)
	var mac := DueCryptoScript.hmac_sha256(s2c_finish, transcript)

	var body := PackedByteArray()
	body.append(_suite)
	body.append_array(random)
	body.append_array(public_key)
	body.append(signature.size() >> 8)
	body.append(signature.size() & 0xff)
	body.append_array(signature)
	body.append_array(mac)

	_transcript = transcript
	session = DueSessionScript.new(s2c_key, c2s_key, session_salt)
	_state = 1

	return _encode_frame(FRAME_SERVER_HELLO, body)


## 处理 Finished 帧，校验通过后返回服务端会话
func confirm(frame: PackedByteArray):
	if _state != 1:
		return null

	var decoded := _decode_frame(frame)
	if not decoded["ok"] or decoded["type"] != FRAME_FINISHED:
		return null

	var body: PackedByteArray = decoded["body"]
	if body.size() != MAC_SIZE:
		return null

	var expected := DueCryptoScript.hmac_sha256(_c2s_finish, _transcript)
	if not DueCryptoScript.fixed_time_equals(expected, body):
		return null

	_state = 2
	return session


## 编码握手帧：version(1) | type(1) | length(2) | body
static func _encode_frame(type: int, body: PackedByteArray) -> PackedByteArray:
	var frame := PackedByteArray([
		VERSION, type, (body.size() >> 8) & 0xff, body.size() & 0xff
	])
	frame.append_array(body)
	return frame


## 解码握手帧
static func _decode_frame(frame: PackedByteArray) -> Dictionary:
	if frame.size() < 4 or frame[0] != VERSION:
		return { "ok": false }

	var length: int = (frame[2] << 8) | frame[3]
	if length != frame.size() - 4:
		return { "ok": false }

	return { "ok": true, "type": frame[1], "body": frame.slice(4, frame.size()) }
