class_name DueCrypto
extends RefCounted
## due 安全模块内部使用的密码学工具，对应 Unity 的 CryptoUtil。

static var _crypto := Crypto.new()


## 生成指定长度的随机字节
static func random_bytes(length: int) -> PackedByteArray:
	return _crypto.generate_random_bytes(length)


## 计算多段数据的 SHA256
static func sha256(parts: Array) -> PackedByteArray:
	var ctx := HashingContext.new()
	ctx.start(HashingContext.HASH_SHA256)
	for part in parts:
		if part != null:
			ctx.update(part)
	return ctx.finish()


## 计算 HMAC-SHA256
static func hmac_sha256(key: PackedByteArray, data: PackedByteArray) -> PackedByteArray:
	return _crypto.hmac_digest(HashingContext.HASH_SHA256, key, data)


## 拼接多段数据
static func concat(parts: Array) -> PackedByteArray:
	var buffer := PackedByteArray()
	for part in parts:
		if part != null:
			buffer.append_array(part)
	return buffer


## 定长时间比较，避免时序侧信道
static func fixed_time_equals(left: PackedByteArray, right: PackedByteArray) -> bool:
	if left.size() != right.size():
		return false
	return _crypto.constant_time_compare(left, right)


## 从缓冲区切出指定长度的一段
static func slice(source: PackedByteArray, offset: int, count: int) -> PackedByteArray:
	if count < 0 or offset < 0 or offset + count > source.size():
		push_error("due-client: invalid buffer")
		return PackedByteArray()
	return source.slice(offset, offset + count)


## 字符串转 ASCII 字节
static func ascii(text: String) -> PackedByteArray:
	return text.to_ascii_buffer()
