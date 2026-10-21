class_name DueAesGcm
extends RefCounted
## AES-256-GCM 加解密器（AEAD 套件编号 1，与服务端的 aesgcm.Suite 一致）。
## 与 Unity 的 AesGcmSuite / AesGcmCipher 对应。
##
## Godot 内置的 AESContext 只提供分组加密，GCM 所需的 GHASH 认证在脚本中实现。
## Seal 的输出为 ciphertext || tag。

const DueCryptoScript := preload("res://addons/due_client/security/due_crypto.gd")

## 线协议套件编号
const SUITE_ID := 1
## 套件名称
const NAME := "aes-gcm"
## 密钥字节长度
const KEY_SIZE := 32
## 分组字节长度
const BLOCK_SIZE := 16
## nonce 字节长度
const NONCE_SIZE := 12
## 认证标签字节长度
const TAG_SIZE := 16

var _aes: AESContext
var _hash_key: PackedByteArray
## 4 位分块乘法表，用于加速 GHASH
var _table: Array = []
## 右移 4 位时的规约表
var _reduce: Array = []
var _valid := false


func _init(key: PackedByteArray) -> void:
	if key.size() != KEY_SIZE:
		push_error("due-client: aes-gcm invalid key size")
		return

	_aes = AESContext.new()
	if _aes.start(AESContext.MODE_ECB_ENCRYPT, key) != OK:
		push_error("due-client: aes-gcm init failed")
		return

	_valid = true
	_hash_key = _encrypt_blocks(_zeros())
	_build_tables()


## 密钥是否有效
func is_valid() -> bool:
	return _valid


## 加密并附加认证标签，返回 ciphertext || tag
func seal(nonce: PackedByteArray, plaintext: PackedByteArray, aad: PackedByteArray) -> PackedByteArray:
	if not _validate_nonce(nonce):
		return PackedByteArray()

	var tag_mask := _encrypt_blocks(_counter_block(nonce, 1))
	var ciphertext := _crypt(nonce, plaintext)
	var tag := _tag(tag_mask, aad, ciphertext)
	var output := PackedByteArray()

	output.resize(ciphertext.size() + TAG_SIZE)
	for i in ciphertext.size():
		output[i] = ciphertext[i]
	for i in TAG_SIZE:
		output[ciphertext.size() + i] = tag[i]

	return output


## 校验并解密；认证失败时返回 ok = false
func open_checked(nonce: PackedByteArray, sealed_data: PackedByteArray, aad: PackedByteArray) -> Dictionary:
	if not _validate_nonce(nonce):
		return { "ok": false, "data": PackedByteArray() }

	if sealed_data.size() < TAG_SIZE:
		push_error("due-client: aes-gcm invalid ciphertext")
		return { "ok": false, "data": PackedByteArray() }

	var length := sealed_data.size() - TAG_SIZE
	var ciphertext := sealed_data.slice(0, length)
	var expected := sealed_data.slice(length, sealed_data.size())
	var tag_mask := _encrypt_blocks(_counter_block(nonce, 1))
	var tag := _tag(tag_mask, aad, ciphertext)

	if not DueCryptoScript.fixed_time_equals(tag, expected):
		push_error("due-client: aes-gcm authentication failed")
		return { "ok": false, "data": PackedByteArray() }

	return { "ok": true, "data": _crypt(nonce, ciphertext) }


## 校验并解密；认证失败时返回空数组
func open(nonce: PackedByteArray, sealed_data: PackedByteArray, aad: PackedByteArray) -> PackedByteArray:
	return open_checked(nonce, sealed_data, aad)["data"]


## 计算认证标签：GHASH(AAD | ciphertext) XOR E(K, J0)
func _tag(tag_mask: PackedByteArray, aad: PackedByteArray, ciphertext: PackedByteArray) -> PackedByteArray:
	var hash := _zeros()
	hash = _absorb(hash, aad)
	hash = _absorb(hash, ciphertext)

	var lengths := _zeros()
	_write_u64_be(lengths, 0, aad.size() * 8)
	_write_u64_be(lengths, 8, ciphertext.size() * 8)
	hash = _multiply(_xor(hash, lengths))

	var tag := PackedByteArray()
	tag.resize(TAG_SIZE)
	for i in TAG_SIZE:
		tag[i] = hash[i] ^ tag_mask[i]
	return tag


## 按 16 字节分块累加 GHASH 状态
func _absorb(state: PackedByteArray, data: PackedByteArray) -> PackedByteArray:
	var offset := 0
	while offset < data.size():
		var block := _zeros()
		var count: int = mini(BLOCK_SIZE, data.size() - offset)
		for i in count:
			block[i] = data[offset + i]
		state = _multiply(_xor(state, block))
		offset += BLOCK_SIZE
	return state


## 与哈希子密钥做 GF(2^128) 乘法
func _multiply(value: PackedByteArray) -> PackedByteArray:
	var result := _zeros()
	# 按位（从最高位到最低位）处理：从最后一个字节的低半字节开始
	for i in range(BLOCK_SIZE - 1, -1, -1):
		var byte: int = value[i]
		result = _shift4(result)
		result = _xor(result, _table[byte & 0x0f])
		result = _shift4(result)
		result = _xor(result, _table[byte >> 4])
	return result


## 构建 4 位分块乘法表与右移规约表
func _build_tables() -> void:
	var powers := []
	var power: PackedByteArray = _hash_key
	for _i in 4:
		powers.append(power)
		power = _shift1(power)

	for value in 16:
		var accumulator := _zeros()
		for bit in 4:
			if ((value >> bit) & 1) != 0:
				accumulator = _xor(accumulator, powers[3 - bit])
		_table.append(accumulator)

	var reduction := _zeros()
	reduction[0] = 0xE1
	var reductions := []
	for _i in 4:
		reductions.append(reduction)
		reduction = _shift1(reduction)

	for value in 16:
		var accumulator := _zeros()
		for bit in 4:
			if ((value >> bit) & 1) != 0:
				accumulator = _xor(accumulator, reductions[3 - bit])
		_reduce.append(accumulator)


## GF(2^128) 右移一位，溢出时按 x^128 + x^7 + x^2 + x + 1 规约
func _shift1(value: PackedByteArray) -> PackedByteArray:
	var result := value.duplicate()
	var lowest := result[BLOCK_SIZE - 1] & 1
	var carry := 0

	for i in BLOCK_SIZE:
		var current := result[i] & 1
		result[i] = (result[i] >> 1) | (carry << 7)
		carry = current

	if lowest != 0:
		result[0] ^= 0xE1

	return result


## GF(2^128) 右移四位，移出的低 4 位通过规约表补偿
func _shift4(value: PackedByteArray) -> PackedByteArray:
	var result := value.duplicate()
	var lowest := value[BLOCK_SIZE - 1] & 0x0f

	for i in range(BLOCK_SIZE - 1, 0, -1):
		result[i] = ((value[i] >> 4) | ((value[i - 1] & 0x0f) << 4)) & 0xff
	result[0] = value[0] >> 4

	return _xor(result, _reduce[lowest])


## CTR 加解密；起始计数为 2（计数器 1 用于标签掩码）
func _crypt(nonce: PackedByteArray, input: PackedByteArray) -> PackedByteArray:
	if input.is_empty():
		return PackedByteArray()

	var blocks := (input.size() + BLOCK_SIZE - 1) / BLOCK_SIZE
	var counters := PackedByteArray()
	counters.resize(blocks * BLOCK_SIZE)

	for i in blocks:
		var block := _counter_block(nonce, i + 2)
		for j in BLOCK_SIZE:
			counters[i * BLOCK_SIZE + j] = block[j]

	var stream := _encrypt_blocks(counters)
	var output := PackedByteArray()
	output.resize(input.size())

	for i in input.size():
		output[i] = input[i] ^ stream[i]

	return output


## 批量执行 AES 分组加密
func _encrypt_blocks(input: PackedByteArray) -> PackedByteArray:
	if input.is_empty():
		return PackedByteArray()
	return _aes.update(input)


## 校验 nonce 长度；GCM 要求 12 字节
func _validate_nonce(nonce: PackedByteArray) -> bool:
	if not _valid:
		return false
	if nonce.size() != NONCE_SIZE:
		push_error("due-client: aes-gcm invalid nonce")
		return false
	return true


## 构造计数器块：nonce(12) || counter(4, 大端)
static func _counter_block(nonce: PackedByteArray, counter: int) -> PackedByteArray:
	var block := _zeros()
	for i in NONCE_SIZE:
		block[i] = nonce[i]
	block[12] = (counter >> 24) & 0xff
	block[13] = (counter >> 16) & 0xff
	block[14] = (counter >> 8) & 0xff
	block[15] = counter & 0xff
	return block


## 16 字节全零块
static func _zeros() -> PackedByteArray:
	var block := PackedByteArray()
	block.resize(BLOCK_SIZE)
	return block


## 逐字节异或
static func _xor(left: PackedByteArray, right: PackedByteArray) -> PackedByteArray:
	var result := PackedByteArray()
	result.resize(left.size())
	for i in left.size():
		result[i] = left[i] ^ right[i]
	return result


## 写入 64 位大端整数
static func _write_u64_be(buffer: PackedByteArray, offset: int, value: int) -> void:
	for i in range(7, -1, -1):
		buffer[offset + i] = value & 0xff
		value = value >> 8
