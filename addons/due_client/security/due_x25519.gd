class_name DueX25519
extends RefCounted
## X25519（RFC 7748）密钥交换；用于握手阶段的临时密钥协商，对应 Unity 的 X25519。
##
## Godot 未暴露 X25519，这里使用 16 个 16 位分片（基 2^16）实现 255 位有限域运算。

const DueCryptoScript := preload("res://addons/due_client/security/due_crypto.gd")

const KEY_SIZE := 32
const LIMBS := 16
## 曲线常数 a24 = (486662 - 2) / 4
const A24 := 121665


## 生成随机私钥
static func generate_private_key() -> PackedByteArray:
	return DueCryptoScript.random_bytes(KEY_SIZE)


## 由私钥计算公钥
static func get_public_key(private_key: PackedByteArray) -> PackedByteArray:
	var base := PackedByteArray()
	base.resize(KEY_SIZE)
	base[0] = 9
	return _scalar_multiply(private_key, base)


## 计算共享密钥
static func compute_shared_key(
	private_key: PackedByteArray, public_key: PackedByteArray
) -> PackedByteArray:
	if public_key.size() != KEY_SIZE:
		push_error("due-client: x25519 invalid public key")
		return PackedByteArray()
	return _scalar_multiply(private_key, public_key)


## Montgomery 阶梯计算标量乘法
static func _scalar_multiply(
	private_key: PackedByteArray, point: PackedByteArray
) -> PackedByteArray:
	if private_key.size() != KEY_SIZE:
		push_error("due-client: x25519 invalid private key")
		return PackedByteArray()

	var scalar := private_key.duplicate()
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64

	var u := point.duplicate()
	u[31] &= 127

	var x1 := _from_bytes(u)
	var x2 := _one()
	var z2 := _zero()
	var x3 := x1.duplicate()
	var z3 := _one()
	var swap := 0

	for t in range(254, -1, -1):
		var bit := (scalar[t >> 3] >> (t & 7)) & 1

		if (swap ^ bit) != 0:
			_cswap(x2, x3)
			_cswap(z2, z3)

		swap = bit

		var a := _add(x2, z2)
		var aa := _mul(a, a)
		var b := _sub(x2, z2)
		var bb := _mul(b, b)
		var e := _sub(aa, bb)
		var c := _add(x3, z3)
		var d := _sub(x3, z3)
		var da := _mul(d, a)
		var cb := _mul(c, b)
		var sum := _add(da, cb)
		var diff := _sub(da, cb)

		x3 = _mul(sum, sum)
		z3 = _mul(x1, _mul(diff, diff))
		x2 = _mul(aa, bb)
		z2 = _mul(e, _add(aa, _mul_small(e, A24)))

	if swap != 0:
		_cswap(x2, x3)
		_cswap(z2, z3)

	return _to_bytes(_mul(x2, _invert(z2)))


## 交换两个分片数组
static func _cswap(left: Array, right: Array) -> void:
	for i in LIMBS:
		var value: int = left[i]
		left[i] = right[i]
		right[i] = value


## 构造全零分片
static func _zero() -> Array:
	var limbs := []
	limbs.resize(LIMBS)
	limbs.fill(0)
	return limbs


## 构造 1
static func _one() -> Array:
	var limbs := _zero()
	limbs[0] = 1
	return limbs


## 32 字节小端数组转分片
static func _from_bytes(bytes: PackedByteArray) -> Array:
	var limbs := _zero()
	for i in LIMBS:
		limbs[i] = bytes[i * 2] | (bytes[i * 2 + 1] << 8)
	return limbs


## 分片转 32 字节小端数组
static func _to_bytes(limbs: Array) -> PackedByteArray:
	var bytes := PackedByteArray()
	bytes.resize(KEY_SIZE)
	for i in LIMBS:
		bytes[i * 2] = limbs[i] & 0xff
		bytes[i * 2 + 1] = (limbs[i] >> 8) & 0xff
	return bytes


## 分片加法
static func _add(left: Array, right: Array) -> Array:
	var limbs := []
	for i in LIMBS:
		limbs.append(left[i] + right[i])
	return _normalize(limbs)


## 分片减法
static func _sub(left: Array, right: Array) -> Array:
	# left - right = left + (p - right)，避免借位分支
	return _add(left, _neg(right))


## 分片取负：p - value（value 需小于 p）
static func _neg(value: Array) -> Array:
	var limbs := []
	var borrow := 0

	for i in LIMBS:
		var current: int = _p_limb(i) - value[i] - borrow
		if current < 0:
			current += 65536
			borrow = 1
		else:
			borrow = 0
		limbs.append(current)

	return _normalize(limbs)


## 分片乘法
static func _mul(left: Array, right: Array) -> Array:
	var product := []
	product.resize(LIMBS * 2)
	product.fill(0)

	for i in LIMBS:
		var value: int = left[i]
		if value == 0:
			continue
		for j in LIMBS:
			product[i + j] += value * right[j]

	# 2^256 = 38 (mod p)，将高位折叠回低 16 个分片
	for i in range(LIMBS * 2 - 1, LIMBS - 1, -1):
		product[i - LIMBS] += 38 * product[i]

	return _normalize(product.slice(0, LIMBS))


## 分片与小整数相乘
static func _mul_small(value: Array, scalar: int) -> Array:
	var limbs := []
	for i in LIMBS:
		limbs.append(value[i] * scalar)
	return _normalize(limbs)


## 分片求逆（费马小定理，指数为 p - 2）
static func _invert(value: Array) -> Array:
	var exponent := []
	exponent.resize(LIMBS)
	exponent.fill(0xffff)
	exponent[0] = 0xffeb
	exponent[LIMBS - 1] = 0x7fff

	var result := _one()
	for bit in range(254, -1, -1):
		result = _mul(result, result)
		if ((exponent[bit >> 4] >> (bit & 15)) & 1) != 0:
			result = _mul(result, value)

	return result


## 进位并规约到 [0, p)
static func _normalize(limbs: Array) -> Array:
	_carry(limbs)
	for _i in 2:
		if not _gte_p(limbs):
			break
		_sub_p(limbs)
	return limbs


## 在基 2^16 下传播进位，并将溢出的高位按 2^256 = 38 折叠
static func _carry(limbs: Array) -> void:
	for _pass in 4:
		var carry := 0
		for i in LIMBS:
			var value: int = limbs[i] + carry
			carry = value >> 16
			limbs[i] = value & 0xffff
		if carry == 0:
			return
		limbs[0] += 38 * carry


## p = 2^255 - 19 的分片表示
static func _p_limb(index: int) -> int:
	if index == 0:
		return 65517
	if index == LIMBS - 1:
		return 32767
	return 65535


## 判断分片是否大于等于 p
static func _gte_p(limbs: Array) -> bool:
	for i in range(LIMBS - 1, -1, -1):
		var p := _p_limb(i)
		if limbs[i] > p:
			return true
		if limbs[i] < p:
			return false
	return true


## 分片减去 p
static func _sub_p(limbs: Array) -> void:
	var borrow := 0
	for i in LIMBS:
		var value: int = limbs[i] - _p_limb(i) - borrow
		if value < 0:
			value += 65536
			borrow = 1
		else:
			borrow = 0
		limbs[i] = value
