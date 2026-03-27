# lua5.1-eth-secp256k1

LuaRocks-ready secp256k1 recovery module for standard Lua 5.1.

## System Dependency
Ubuntu packages:
```bash
sudo apt install -y libsecp256k1-1 libsecp256k1-dev
```

## API
- `require("eth_secp256k1").recover_public_key(message_hash_32, signature_65)` returns a 65-byte uncompressed public key.
- `require("eth_secp256k1").recover_public_key_hex(message_hash_32, signature_hex)` does the same without Lua-side hex decoding.
- On failure each function returns `nil, err`.

## Notes
- The module uses `secp256k1_context_static` for verification-only workloads, so it does not allocate or mutate a process-global heap context.
- Recovery ids are limited to Ethereum-style `0/1` or `27/28`.

## Build Locally
```bash
cd /sandbox/lua5.1-eth-secp256k1
luarocks make --local eth-secp256k1-0.1.0-1.rockspec
```
