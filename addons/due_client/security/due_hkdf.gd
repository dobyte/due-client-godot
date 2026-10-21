class_name DueHkdf
extends RefCounted
## HKDF-SHA256 密钥派生（RFC 5869），对应 Unity 的 Hkdf。

const DueCryptoScript := preload("res://addons/due_client/security/due_crypto.gd")


## 派生指定长度的密钥材料
static func sha256(
	ikm: PackedByteArray, salt: PackedByteArray, info: PackedByteArray, length: int
) -> PackedByteArray:
	if salt.is_empty():
		salt = PackedByteArray()
		salt.resize(32)

	var pseudo_random_key := DueCryptoScript.hmac_sha256(salt, ikm)
	var output := PackedByteArray()
	var block := PackedByteArray()
	var counter := 1

	while output.size() < length:
		var input := PackedByteArray()
		input.append_array(block)
		input.append_array(info)
		input.append(counter)
		block = DueCryptoScript.hmac_sha256(pseudo_random_key, input)
		output.append_array(block)
		counter += 1

	return output.slice(0, length)
