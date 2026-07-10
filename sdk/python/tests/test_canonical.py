from warden_sdk.canonical import canonical_json, dev_signature, sha256_hex


def test_canonical_sorts_keys_no_whitespace():
    assert canonical_json({"b": 1, "a": "x"}) == '{"a":"x","b":1}'


def test_canonical_nested_and_arrays():
    v = {"z": [3, 2, 1], "a": {"n": True, "m": None}}
    assert canonical_json(v) == '{"a":{"m":null,"n":true},"z":[3,2,1]}'


def test_dev_signature_matches_rust_formula():
    # sha256_hex("KEY|" + canonical_json(claims)) — the exact identity::sign.
    claims = {"sub": "alice", "act": {"sub": "agent"}}
    expected = sha256_hex("dev-secret|" + canonical_json(claims))
    assert dev_signature(claims, "dev-secret") == expected


def test_dev_signature_is_stable_across_key_order():
    a = {"sub": "alice", "aud": "warden:prod", "act": {"sub": "agent"}}
    b = {"act": {"sub": "agent"}, "aud": "warden:prod", "sub": "alice"}
    assert dev_signature(a, "k") == dev_signature(b, "k")
