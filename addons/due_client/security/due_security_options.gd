class_name DueSecurityOptions
extends RefCounted
## 会话安全配置。
##
## 示例（与 Unity 的 SecurityOptions(verifier) 对应）：
##     var security := DueSecurityOptions.new(DueVerifier.ecdsa("keys/gate.pub.pem"))
##
## 也可以使用与 Unity 属性对应的字典形式：
##     var security := DueSecurityOptions.new({
##         "verifier": DueVerifier.ecdsa("keys/gate.pub.pem"),
##         "handshake_timeout": 5000,
##     })

const DueAesGcmScript := preload("res://addons/due_client/security/due_aead.gd")

## 服务端签名验证器（Callable），通常由服务端公钥创建
var verifier: Callable
## 客户端支持的 AEAD 套件编号；默认为 AES-256-GCM
var suites: Array
## 握手超时时间（毫秒）；小于等于 0 表示不启用超时
var handshake_timeout: int


func _init(opts: Variant = null) -> void:
	verifier = Callable()
	suites = [DueAesGcmScript.SUITE_ID]
	handshake_timeout = 5000

	if opts == null:
		return

	if opts is Callable:
		verifier = opts
	elif opts is Dictionary:
		verifier = opts.get("verifier", verifier)
		handshake_timeout = opts.get("handshake_timeout", handshake_timeout)
		var value = opts.get("suites", null)
		if value is Array:
			suites = value.duplicate()
	else:
		push_error("due-client: invalid security options")
