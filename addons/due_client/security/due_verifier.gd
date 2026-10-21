class_name DueVerifier
extends RefCounted
## 服务端签名验证器；与 SecurityOptions.verifier 配合使用，对应 Unity 的 Verifier。
##
## 验证器为 Callable(data: PackedByteArray, signature: PackedByteArray) -> bool，
## data 为待验证的原始数据，signature 为服务端签名。

## 默认签名分隔符，与 due 的 ecc signer 保持一致
const DEFAULT_DELIMITER := " "
## 签名分量的最大字节数（覆盖 P-521）
const MAX_INTEGER_SIZE := 80

const HASH_ALGORITHMS := {
	"md5": HashingContext.HASH_MD5,
	"sha1": HashingContext.HASH_SHA1,
	"sha256": HashingContext.HASH_SHA256,
}

static var _crypto := Crypto.new()


## 创建 ECDSA 验证器。
## public_key 可以是 PEM 文件路径或 PEM 内容；delimiter 需与服务端配置一致。
static func ecdsa(
	public_key: String, hash: String = "sha256", delimiter: String = DEFAULT_DELIMITER
) -> Callable:
	var key := _load_public_key(public_key)
	var algorithm := _resolve_hash(hash)
	var separator := delimiter if not delimiter.is_empty() else DEFAULT_DELIMITER

	return func(data: PackedByteArray, signature: PackedByteArray) -> bool:
		if key == null or algorithm < 0:
			return false
		var der := _ecdsa_signature_to_der(signature, separator)
		if der.is_empty():
			return false
		return _crypto.verify(algorithm, data, der, key)


## 创建 RSA 验证器（PKCS#1 v1.5 填充）。
## public_key 可以是 PEM 文件路径或 PEM 内容；pss 与 Unity 保持一致保留该参数。
## 注意：Godot 仅支持 PKCS#1 v1.5，pss 为 true 时返回始终失败的验证器。
static func rsa(public_key: String, hash: String = "sha256", pss: bool = false) -> Callable:
	if pss:
		push_error("due-client: rsa pss padding is not supported by Godot")
		return func(_data: PackedByteArray, _signature: PackedByteArray) -> bool:
			return false

	var key := _load_public_key(public_key)
	var algorithm := _resolve_hash(hash)

	return func(data: PackedByteArray, signature: PackedByteArray) -> bool:
		if key == null or algorithm < 0:
			return false
		return _crypto.verify(algorithm, data, signature, key)


## 将 due 服务端的十进制签名（r、s）转换为 DER 编码
static func _ecdsa_signature_to_der(
	signature: PackedByteArray, delimiter: String
) -> PackedByteArray:
	var parts := signature.get_string_from_ascii().split(delimiter)
	if parts.size() != 2:
		return PackedByteArray()

	var r := _decimal_to_bytes(parts[0])
	var s := _decimal_to_bytes(parts[1])
	if r.is_empty() or s.is_empty():
		return PackedByteArray()

	var body := PackedByteArray()
	body.append_array(_der_integer(r))
	body.append_array(_der_integer(s))

	return _der_sequence(body)


## 将十进制字符串转换为大端整数（去除前导零）；溢出或非法字符时返回空数组
static func _decimal_to_bytes(text: String) -> PackedByteArray:
	if text.is_empty():
		return PackedByteArray()

	var bytes := PackedByteArray()
	bytes.resize(MAX_INTEGER_SIZE)

	for i in text.length():
		var code := text.unicode_at(i)
		if code < 48 or code > 57:
			return PackedByteArray()

		var carry := code - 48
		for j in range(MAX_INTEGER_SIZE - 1, -1, -1):
			var value: int = bytes[j] * 10 + carry
			bytes[j] = value & 0xff
			carry = value >> 8

		if carry != 0:
			return PackedByteArray()

	var offset := 0
	while offset < bytes.size() - 1 and bytes[offset] == 0:
		offset += 1

	return bytes.slice(offset, bytes.size())


## 构造 DER INTEGER
static func _der_integer(value: PackedByteArray) -> PackedByteArray:
	var offset := 0
	while offset < value.size() - 1 and value[offset] == 0:
		offset += 1

	var content := value.slice(offset, value.size())
	if (content[0] & 0x80) != 0:
		var padded := PackedByteArray([0])
		padded.append_array(content)
		content = padded

	var output := PackedByteArray([0x02, content.size()])
	output.append_array(content)
	return output


## 构造 DER SEQUENCE
static func _der_sequence(body: PackedByteArray) -> PackedByteArray:
	var output := PackedByteArray([0x30])
	if body.size() < 0x80:
		output.append(body.size())
	else:
		output.append(0x81)
		output.append(body.size())
	output.append_array(body)
	return output


## 解析哈希算法名称
static func _resolve_hash(name: String) -> int:
	var algorithm := name.to_lower()
	if not HASH_ALGORITHMS.has(algorithm):
		push_error("due-client: unsupported hash algorithm " + name)
		return -1
	return HASH_ALGORITHMS[algorithm]


## 加载公钥；参数可以是 PEM 文件路径或 PEM 内容
static func _load_public_key(public_key: String) -> CryptoKey:
	if public_key.is_empty():
		push_error("due-client: public key must not be empty")
		return null

	var content := public_key
	if FileAccess.file_exists(public_key):
		content = FileAccess.get_file_as_string(public_key)

	# due 的 ecc signer 生成的公钥使用 ECDSA PUBLIC KEY 标签，需转换为标准标签
	content = content.replace("ECDSA PUBLIC KEY", "PUBLIC KEY")

	var key := CryptoKey.new()
	var args: Array = [content]
	# Godot 4.7 起需要显式声明只加载公钥，旧版本则默认支持公钥
	if _supports_public_only(key):
		args.append(true)

	if key.callv("load_from_string", args) != OK:
		push_error("due-client: invalid public key")
		return null

	return key


## 检测 CryptoKey.load_from_string 是否支持 public_only 参数
static func _supports_public_only(key: CryptoKey) -> bool:
	for method in key.get_method_list():
		if method["name"] == "load_from_string":
			return method["args"].size() >= 2
	return false
