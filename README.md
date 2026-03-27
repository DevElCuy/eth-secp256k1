# lua5.1-eth-secp256k1

LuaRocks-ready secp256k1 helpers for standard Lua 5.1.

## System Dependency
Ubuntu packages:
```bash
sudo apt install -y libsecp256k1-1 libsecp256k1-dev
```

## API
- `require("eth_secp256k1").recover_public_key(message_hash_32, signature_65)` returns a 65-byte uncompressed public key.
- `require("eth_secp256k1").recover_public_key_hex(message_hash_32, signature_hex)` does the same without Lua-side hex decoding.
- `require("eth_secp256k1").create_public_key(private_key_32)` returns a 65-byte uncompressed public key.
- `require("eth_secp256k1").create_public_key_hex(private_key_hex)` does the same and returns hex.
- `require("eth_secp256k1").sign_recoverable(message_hash_32, private_key_32)` returns a 65-byte recoverable signature with Ethereum-style `v` (`27` or `28`).
- `require("eth_secp256k1").sign_recoverable_hex(message_hash_32, private_key_hex)` does the same and returns hex.
- The module randomizes its secp256k1 signing context from `/dev/urandom` on first use and fails closed if entropy is unavailable.

## Build Locally
```bash
cd /sandbox/lua5.1-eth-secp256k1
luarocks make --local eth-secp256k1-0.1.0-1.rockspec
```

## Quick Test
Use together with the signed API adapter or a known vector to verify signing and recovery output.
