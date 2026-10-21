extends SceneTree
## 安全模块单元测试：X25519、HKDF、AES-GCM、会话、验签与握手。
##
## 运行方式（在项目根目录执行）：
##     godot --headless --script res://test/test_security.gd

const TestUtil := preload("res://test/security_test_util.gd")
const TestServerScript := preload("res://test/security_test_server.gd")
const DueCryptoScript := preload("res://addons/due_client/security/due_crypto.gd")
const DueHkdfScript := preload("res://addons/due_client/security/due_hkdf.gd")
const DueX25519Script := preload("res://addons/due_client/security/due_x25519.gd")
const DueAesGcmScript := preload("res://addons/due_client/security/due_aead.gd")
const DueSessionScript := preload("res://addons/due_client/security/due_session.gd")
const DueVerifierScript := preload("res://addons/due_client/security/due_verifier.gd")
const DueHandshakeScript := preload("res://addons/due_client/security/due_handshake.gd")
const DueSecurityOptionsScript := preload("res://addons/due_client/security/due_security_options.gd")

## 测试用 P-256 私钥，与 due-benchmark/cluster/ws/gate/resource/key.pem 一致
const PRIVATE_KEY := """-----BEGIN ECDSA PRIVATE KEY-----
MHcCAQEEIBBzcsY8yb1Xtjfaqx54SUj/euyRIY1JwXpJaqWuV0omoAoGCCqGSM49
AwEHoUQDQgAE0KDj25at5TKOdvPmtF0gd2ImGa2a9w7NTi2ywa98NQKNtjT1eGRK
rzo6HWxeLAj42zQ7RJZ6Zwb/BeBHbcONzg==
-----END ECDSA PRIVATE KEY-----"""

## 与私钥配对的公钥，与 due-benchmark/cluster/ws/client/resource/key.pub.pem 一致
const PUBLIC_KEY := """-----BEGIN ECDSA PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0KDj25at5TKOdvPmtF0gd2ImGa2a
9w7NTi2ywa98NQKNtjT1eGRKrzo6HWxeLAj42zQ7RJZ6Zwb/BeBHbcONzg==
-----END ECDSA PUBLIC KEY-----"""

## 另一把公钥，用于验证公钥不匹配的场景
const OTHER_PUBLIC_KEY := """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDwj91zZjFTl/9yO3a2q5uqcqFqYi
3TcyNnvMCLcCfgAhY/vJ9t70BXx8+5S87DFJi48HFevW40B5Xat0+COK+w==
-----END PUBLIC KEY-----"""

var _passed := 0
var _failed := 0


func _init() -> void:
	print("=== 安全模块单元测试 ===")

	_test_x25519_rfc7748_scalar()
	_test_x25519_key_exchange()
	_test_hkdf_rfc5869_case1()
	_test_aes_gcm_zero_vector()
	_test_aes_gcm_nist_case16()
	_test_session_roundtrip()
	_test_session_envelope()
	_test_session_aad()
	_test_session_replay()
	_test_session_invalid()
	_test_make_aad()
	_test_security_options()
	_test_verifier_ecdsa()
	_test_verifier_rsa_pss()
	_test_handshake_establish()
	_test_handshake_invalid_signature()
	_test_handshake_invalid_finished_mac()
	_test_handshake_wrong_public_key()
	_test_handshake_state_machine()
	_test_handshake_default_suites()

	_print_summary()
	quit(0 if _failed == 0 else 1)


func _test_x25519_rfc7748_scalar() -> void:
	var scalar := TestUtil.hex(
		"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
	)
	var point := TestUtil.hex(
		"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
	)
	var expected := TestUtil.hex(
		"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
	)
	_assert_eq(DueX25519Script.compute_shared_key(scalar, point), expected, "X25519 RFC 7748 标量乘法")


func _test_x25519_key_exchange() -> void:
	var alice_private := TestUtil.hex(
		"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	)
	var alice_public := TestUtil.hex(
		"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	)
	var bob_private := TestUtil.hex(
		"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	)
	var bob_public := TestUtil.hex(
		"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	)
	var shared := TestUtil.hex(
		"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	)

	_assert_eq(DueX25519Script.get_public_key(alice_private), alice_public, "X25519 Alice 公钥")
	_assert_eq(DueX25519Script.get_public_key(bob_private), bob_public, "X25519 Bob 公钥")
	_assert_eq(
		DueX25519Script.compute_shared_key(alice_private, bob_public), shared, "X25519 共享密钥（A）"
	)
	_assert_eq(
		DueX25519Script.compute_shared_key(bob_private, alice_public), shared, "X25519 共享密钥（B）"
	)


func _test_hkdf_rfc5869_case1() -> void:
	var ikm := PackedByteArray()
	ikm.resize(22)
	ikm.fill(0x0b)

	var output := DueHkdfScript.sha256(
		ikm,
		TestUtil.hex("000102030405060708090a0b0c"),
		TestUtil.hex("f0f1f2f3f4f5f6f7f8f9"),
		42
	)
	var expected := TestUtil.hex(
		"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	)
	_assert_eq(output, expected, "HKDF-SHA256 RFC 5869 用例 1")


func _test_aes_gcm_zero_vector() -> void:
	var cipher := DueAesGcmScript.new(TestUtil.hex("00".repeat(32)))
	var sealed := cipher.seal(
		TestUtil.hex("00".repeat(12)), TestUtil.hex("00".repeat(16)), PackedByteArray()
	)
	var expected := TestUtil.hex(
		"cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
	)
	_assert_eq(sealed, expected, "AES-256-GCM 零向量")

	var opened := cipher.open_checked(
		TestUtil.hex("00".repeat(12)), sealed, PackedByteArray()
	)
	_assert_eq(opened["ok"], true, "AES-256-GCM 零向量解密")
	_assert_eq(opened["data"], TestUtil.hex("00".repeat(16)), "AES-256-GCM 零向量明文")


func _test_aes_gcm_nist_case16() -> void:
	var key := TestUtil.hex(
		"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
	)
	var nonce := TestUtil.hex("cafebabefacedbaddecaf888")
	var plaintext := TestUtil.hex(
		"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
		+ "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
	)
	var aad := TestUtil.hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	var expected := TestUtil.hex(
		"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
		+ "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
		+ "2df7cd675b4f09163b41ebf980a7f638"
	)

	var cipher := DueAesGcmScript.new(key)
	_assert_eq(cipher.seal(nonce, plaintext, aad), expected, "AES-256-GCM NIST 用例 16")

	var opened := cipher.open_checked(nonce, expected, aad)
	_assert_eq(opened["ok"], true, "AES-256-GCM NIST 用例 16 解密")
	_assert_eq(opened["data"], plaintext, "AES-256-GCM NIST 用例 16 明文")


func _test_session_roundtrip() -> void:
	var client := _create_client_session()
	var server := _create_server_session()
	var request := "hello gate".to_utf8_buffer()
	var response := "hello client".to_utf8_buffer()

	var sealed_request := client.seal_message(
		request, DueSessionScript.Direction.CLIENT_TO_SERVER, 1001, 7
	)
	var sealed_response := server.seal_message(
		response, DueSessionScript.Direction.SERVER_TO_CLIENT, 1002, 8
	)

	_assert_eq(
		server.open_message(sealed_request, DueSessionScript.Direction.CLIENT_TO_SERVER, 1001, 7),
		request,
		"会话加密/解密（客户端到服务端）"
	)
	_assert_eq(
		client.open_message(sealed_response, DueSessionScript.Direction.SERVER_TO_CLIENT, 1002, 8),
		response,
		"会话加密/解密（服务端到客户端）"
	)


func _test_session_envelope() -> void:
	var client := _create_client_session()
	var plaintext := "hello".to_utf8_buffer()
	var first := client.seal_message(plaintext, DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 2)
	var second := client.seal_message(plaintext, DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 2)

	_assert_eq(first[0], 1, "密文信封 epoch")
	_assert_eq(client.get_overhead(), 25, "会话信封开销")
	_assert_eq(first.size(), plaintext.size() + client.get_overhead(), "密文长度")
	_assert_eq(_read_counter(first), 0, "首个密文计数器为 0")
	_assert_eq(_read_counter(second), 1, "第二个密文计数器为 1")


func _test_session_aad() -> void:
	var client := _create_client_session()
	var server := _create_server_session()
	var sealed_data := client.seal_message(
		"hello".to_utf8_buffer(), DueSessionScript.Direction.CLIENT_TO_SERVER, 10, 2
	)

	_assert_eq(
		server.open_message(sealed_data, DueSessionScript.Direction.CLIENT_TO_SERVER, 11, 2).is_empty(),
		true,
		"路由被篡改时拒绝解密"
	)
	_assert_eq(
		server.open_message(sealed_data, DueSessionScript.Direction.CLIENT_TO_SERVER, 10, 3).is_empty(),
		true,
		"序列号被篡改时拒绝解密"
	)
	_assert_eq(
		server.open_message(sealed_data, DueSessionScript.Direction.SERVER_TO_CLIENT, 10, 2).is_empty(),
		true,
		"方向被篡改时拒绝解密"
	)

	# 认证失败不应推进重放窗口
	_assert_eq(
		server.open_message(sealed_data, DueSessionScript.Direction.CLIENT_TO_SERVER, 10, 2),
		"hello".to_utf8_buffer(),
		"认证失败不推进重放窗口"
	)


func _test_session_replay() -> void:
	var client := _create_client_session()
	var server := _create_server_session()
	var sealed_data := client.seal_message(
		"hello".to_utf8_buffer(), DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 1
	)

	_assert_eq(
		server.open_message(sealed_data, DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 1),
		"hello".to_utf8_buffer(),
		"首次消息解密成功"
	)
	_assert_eq(
		server.open_message(sealed_data, DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 1).is_empty(),
		true,
		"重放消息被拒绝"
	)

	# 窗口内的乱序消息应被接受
	var client2 := _create_client_session()
	var server2 := _create_server_session()
	var first := client2.seal_message("a".to_utf8_buffer(), 0, 1, 1)
	var second := client2.seal_message("b".to_utf8_buffer(), 0, 1, 1)
	var third := client2.seal_message("c".to_utf8_buffer(), 0, 1, 1)

	_assert_eq(server2.open_message(third, 0, 1, 1), "c".to_utf8_buffer(), "乱序消息（最新）")
	_assert_eq(server2.open_message(first, 0, 1, 1), "a".to_utf8_buffer(), "乱序消息（最早）")
	_assert_eq(server2.open_message(second, 0, 1, 1), "b".to_utf8_buffer(), "乱序消息（中间）")
	_assert_eq(server2.open_message(first, 0, 1, 1).is_empty(), true, "乱序窗口内不重复接受")


func _test_session_invalid() -> void:
	var client := _create_client_session()
	var server := _create_server_session()
	var sealed_data := client.seal_message(
		"hello".to_utf8_buffer(), DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 1
	)

	var tampered := sealed_data.duplicate()
	tampered[tampered.size() - 1] ^= 0xff
	_assert_eq(
		server.open_message(tampered, DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 1).is_empty(),
		true,
		"篡改密文被拒绝"
	)

	var wrong_epoch := sealed_data.duplicate()
	wrong_epoch[0] = 2
	_assert_eq(
		server.open_message(wrong_epoch, DueSessionScript.Direction.CLIENT_TO_SERVER, 1, 1).is_empty(),
		true,
		"epoch 不匹配被拒绝"
	)

	_assert_eq(
		client.open_message(PackedByteArray(), DueSessionScript.Direction.SERVER_TO_CLIENT, 1, 1).is_empty(),
		true,
		"空密文被拒绝"
	)
	_assert_eq(
		client.open_message(_zeros(24), DueSessionScript.Direction.SERVER_TO_CLIENT, 1, 1).is_empty(),
		true,
		"密文过短被拒绝"
	)


func _test_make_aad() -> void:
	var aad := DueSessionScript.make_aad(DueSessionScript.Direction.SERVER_TO_CLIENT, 1, 0x01020304, 0x05060708)
	_assert_eq(TestUtil.to_hex(aad), "0101010102030405060708", "AAD 规范编码")


func _test_security_options() -> void:
	var verifier := DueVerifierScript.ecdsa(PUBLIC_KEY)
	var options = DueSecurityOptionsScript.new(verifier)
	_assert_eq(options.verifier, verifier, "SecurityOptions(verifier) 构造")
	_assert_eq(options.suites, [DueAesGcmScript.SUITE_ID], "SecurityOptions 默认套件")
	_assert_eq(options.handshake_timeout, 5000, "SecurityOptions 默认握手超时")

	var custom = DueSecurityOptionsScript.new({
		"verifier": verifier,
		"handshake_timeout": 1000,
	})
	_assert_eq(custom.handshake_timeout, 1000, "SecurityOptions 字典构造")
	_assert_eq(custom.verifier, verifier, "SecurityOptions 字典验证器")


func _test_verifier_ecdsa() -> void:
	var signer := _create_signer()
	var verifier := DueVerifierScript.ecdsa(PUBLIC_KEY)
	var data := DueCryptoScript.sha256(["hello due".to_utf8_buffer()])
	var der := Crypto.new().sign(HashingContext.HASH_SHA256, data, signer)
	var signature := TestUtil.der_to_due_signature(der)

	_assert_eq(verifier.is_valid(), true, "ECDSA 验证器可用")
	_assert_eq(verifier.call(data, signature), true, "ECDSA 验签成功")
	_assert_eq(
		verifier.call(DueCryptoScript.sha256(["other".to_utf8_buffer()]), signature),
		false,
		"ECDSA 数据不匹配时验签失败"
	)

	var tampered := signature.duplicate()
	tampered[tampered.size() - 1] ^= 0xff
	_assert_eq(verifier.call(data, tampered), false, "ECDSA 签名损坏时验签失败")
	_assert_eq(DueVerifierScript.ecdsa(OTHER_PUBLIC_KEY).call(data, signature), false, "公钥不匹配时验签失败")


func _test_verifier_rsa_pss() -> void:
	var verifier := DueVerifierScript.rsa(PUBLIC_KEY, "sha256", true)
	var data := DueCryptoScript.sha256(["x".to_utf8_buffer()])
	_assert_eq(verifier.call(data, PackedByteArray()), false, "RSA PSS 不受支持时返回失败验证器")


func _test_handshake_establish() -> void:
	var signer := _create_signer()
	var client := DueHandshakeScript.new(DueVerifierScript.ecdsa(PUBLIC_KEY))
	var server := TestServerScript.new(signer)

	var server_hello := server.accept(client.hello())
	_assert_eq(server_hello.is_empty(), false, "服务端处理 ClientHello")

	var result := client.handle(server_hello)
	_assert_eq(result.get("ok", false), true, "客户端处理 ServerHello")
	if not result.get("ok", false):
		return

	var client_session: DueSessionScript = result["session"]
	var server_session: DueSessionScript = server.confirm(result["finished"])
	_assert_eq(server_session != null, true, "服务端校验 Finished")
	if server_session == null:
		return

	_assert_eq(client_session.get_epoch(), 1, "会话 epoch")
	_assert_eq(client_session.get_overhead(), 25, "会话开销")

	var request := "hello gate".to_utf8_buffer()
	var sealed_request := client_session.seal_message(
		request, DueSessionScript.Direction.CLIENT_TO_SERVER, 1001, 7
	)
	_assert_eq(
		server_session.open_message(sealed_request, DueSessionScript.Direction.CLIENT_TO_SERVER, 1001, 7),
		request,
		"握手后客户端到服务端消息"
	)

	var response := PackedByteArray()
	response.resize(300)
	for i in response.size():
		response[i] = i & 0xff
	var sealed_response := server_session.seal_message(
		response, DueSessionScript.Direction.SERVER_TO_CLIENT, 1002, 8
	)
	_assert_eq(
		client_session.open_message(sealed_response, DueSessionScript.Direction.SERVER_TO_CLIENT, 1002, 8),
		response,
		"握手后服务端到客户端消息（多分组）"
	)


func _test_handshake_invalid_signature() -> void:
	var client := DueHandshakeScript.new(DueVerifierScript.ecdsa(PUBLIC_KEY))
	var server := TestServerScript.new(_create_signer())
	var server_hello := server.accept(client.hello())

	# 帧头(4) + suite(1) + random(32) + publicKey(32) + 签名长度(2) 之后为签名
	server_hello[4 + 1 + 32 + 32 + 2] ^= 0xff
	_assert_eq(client.handle(server_hello).get("ok", false), false, "服务端签名非法时拒绝握手")


func _test_handshake_invalid_finished_mac() -> void:
	var client := DueHandshakeScript.new(DueVerifierScript.ecdsa(PUBLIC_KEY))
	var server := TestServerScript.new(_create_signer())
	var server_hello := server.accept(client.hello())

	server_hello[server_hello.size() - 1] ^= 0xff
	_assert_eq(client.handle(server_hello).get("ok", false), false, "服务端收尾 MAC 非法时拒绝握手")


func _test_handshake_wrong_public_key() -> void:
	var client := DueHandshakeScript.new(DueVerifierScript.ecdsa(OTHER_PUBLIC_KEY))
	var server := TestServerScript.new(_create_signer())
	var server_hello := server.accept(client.hello())

	_assert_eq(client.handle(server_hello).get("ok", false), false, "公钥不匹配时拒绝握手")


func _test_handshake_state_machine() -> void:
	var client := DueHandshakeScript.new(DueVerifierScript.ecdsa(PUBLIC_KEY))

	_assert_eq(
		client.handle(PackedByteArray([1, 2, 0, 0])).get("ok", false),
		false,
		"握手状态机拒绝乱序 Handle"
	)

	var hello := client.hello()
	_assert_eq(hello.is_empty(), false, "生成 ClientHello")
	_assert_eq(hello[0], 1, "ClientHello 版本")
	_assert_eq(client.hello().is_empty(), true, "握手状态机拒绝重复 Hello")

	var empty_verifier := DueHandshakeScript.new(Callable())
	_assert_eq(empty_verifier.hello().is_empty(), false, "无验证器仍可生成 ClientHello")


func _test_handshake_default_suites() -> void:
	var handshake := DueHandshakeScript.new(DueVerifierScript.ecdsa(PUBLIC_KEY), [])
	var frame := handshake.hello()
	_assert_eq(frame.is_empty(), false, "空套件列表仍生成 ClientHello")
	# 帧头(4) + random(32) + publicKey(32) 之后为套件数量
	_assert_eq(frame[4 + 32 + 32], 1, "空套件列表默认提供 1 个套件")
	_assert_eq(frame[4 + 32 + 32 + 1], DueAesGcmScript.SUITE_ID, "默认套件为 AES-256-GCM")


func _create_signer() -> CryptoKey:
	return TestUtil.load_private_key(PRIVATE_KEY)


func _create_client_session() -> DueSessionScript:
	return DueSessionScript.new(_key(1), _key(33), PackedByteArray([0x01, 0x02, 0x03, 0x04]))


func _create_server_session() -> DueSessionScript:
	return DueSessionScript.new(_key(33), _key(1), PackedByteArray([0x01, 0x02, 0x03, 0x04]))


func _key(seed: int) -> PackedByteArray:
	var key := PackedByteArray()
	key.resize(32)
	for i in key.size():
		key[i] = (seed + i) & 0xff
	return key


func _read_counter(sealed_data: PackedByteArray) -> int:
	var counter := 0
	for i in range(1, 9):
		counter = (counter << 8) | sealed_data[i]
	return counter


func _zeros(length: int) -> PackedByteArray:
	var buffer := PackedByteArray()
	buffer.resize(length)
	return buffer


func _assert_eq(actual: Variant, expected: Variant, name: String) -> void:
	if actual == expected:
		_passed += 1
		print("  [PASS] " + name)
	else:
		_failed += 1
		printerr("  [FAIL] " + name)
		printerr("      expected: " + str(expected))
		printerr("      actual:   " + str(actual))


func _print_summary() -> void:
	print("")
	print("测试完成：%d 通过，%d 失败" % [_passed, _failed])
