extends RefCounted
## 安全模块测试辅助工具：十六进制转换与签名格式转换。


## 十六进制字符串转字节数组
static func hex(text: String) -> PackedByteArray:
	var cleaned := text.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
	return cleaned.hex_decode()


## 字节数组转十六进制字符串
static func to_hex(value: PackedByteArray) -> String:
	return value.hex_encode()


## 加载 PEM 私钥；兼容 due ecc signer 的 ECDSA PRIVATE KEY 标签
static func load_private_key(pem: String) -> CryptoKey:
	var content := pem
	if FileAccess.file_exists(pem):
		content = FileAccess.get_file_as_string(pem)

	content = content.replace("ECDSA PRIVATE KEY", "EC PRIVATE KEY")

	var key := CryptoKey.new()
	if key.load_from_string(content) != OK:
		return null

	return key


## 将 DER 编码的 ECDSA 签名转换为 due 的十进制文本签名（r、s 以空格分隔）
static func der_to_due_signature(der: PackedByteArray) -> PackedByteArray:
	var sequence := _read_tlv(der, 0)
	if sequence.is_empty() or sequence[0] != 0x30:
		return PackedByteArray()

	var first := _read_tlv(sequence[1], 0)
	if first.is_empty() or first[0] != 0x02:
		return PackedByteArray()

	var second := _read_tlv(sequence[1], first[2])
	if second.is_empty() or second[0] != 0x02:
		return PackedByteArray()

	var text := _bytes_to_decimal(first[1]) + " " + _bytes_to_decimal(second[1])
	return text.to_ascii_buffer()


## 读取一个 DER TLV，返回 [tag, value, 新偏移]；失败返回空数组
static func _read_tlv(data: PackedByteArray, offset: int) -> Array:
	if offset + 2 > data.size():
		return []

	var tag: int = data[offset]
	offset += 1
	var length: int = data[offset]
	offset += 1

	if (length & 0x80) != 0:
		var count := length & 0x7f
		length = 0
		for _i in count:
			if offset >= data.size():
				return []
			length = (length << 8) | data[offset]
			offset += 1

	if offset + length > data.size():
		return []

	return [tag, data.slice(offset, offset + length), offset + length]


## 大端字节数组转十进制字符串
static func _bytes_to_decimal(value: PackedByteArray) -> String:
	var work := value.duplicate()
	var digits := ""

	while true:
		var remainder := 0
		var zero := true

		for i in work.size():
			var current: int = remainder * 256 + work[i]
			work[i] = current / 10
			remainder = current % 10
			if work[i] != 0:
				zero = false

		digits = str(remainder) + digits

		if zero:
			return digits

	return digits
