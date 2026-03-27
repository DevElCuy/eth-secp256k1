# lua5.1-eth-secp256k1

LuaRocks-ready secp256k1 recovery module for standard Lua 5.1.

## System Dependency
Ubuntu packages:
```bash
sudo apt install -y libsecp256k1-1 libsecp256k1-dev
```

## API
- `require("eth_secp256k1").recover_public_key(message_hash_32, signature_65)` returns a 65-byte uncompressed public key.
- On failure it returns `nil, err`.

## Build Locally
```bash
cd /sandbox/lua5.1-eth-secp256k1
luarocks make --local
```

## Quick Test
Use together with the signed API adapter or a known recovery vector to verify recovery output length is 65 bytes.
