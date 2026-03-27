#include <stddef.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

static const secp256k1_context *secp256k1_ctx = NULL;

static const secp256k1_context *ensure_context(void) {
  if (secp256k1_ctx == NULL) {
    secp256k1_selftest();
    secp256k1_ctx = secp256k1_context_static;
  }
  return secp256k1_ctx;
}

static int push_error(lua_State *L, const char *message) {
  lua_pushnil(L);
  lua_pushstring(L, message);
  return 2;
}

static int normalize_recovery_id(unsigned char value) {
  if (value == 27 || value == 28) {
    return (int)(value - 27);
  }
  if (value <= 1) {
    return (int)value;
  }
  return -1;
}

static int decode_hex_signature(const char *input, size_t input_len, unsigned char output[65]) {
  static const signed char hex_table[103] = {
    ['0'] = 0, ['1'] = 1, ['2'] = 2, ['3'] = 3, ['4'] = 4,
    ['5'] = 5, ['6'] = 6, ['7'] = 7, ['8'] = 8, ['9'] = 9,
    ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15,
  };
  size_t offset = 0;
  size_t i;

  if (input_len >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
    input += 2;
    input_len -= 2;
  }
  if (input_len != 130) {
    return 0;
  }

  for (i = 0; i < 65; i++) {
    unsigned char hi = (unsigned char)input[offset++];
    unsigned char lo = (unsigned char)input[offset++];
    signed char hi_val;
    signed char lo_val;

    if (hi >= sizeof(hex_table) || lo >= sizeof(hex_table)) {
      return 0;
    }
    hi_val = hex_table[hi];
    lo_val = hex_table[lo];
    if (hi_val < 0 || lo_val < 0) {
      return 0;
    }
    output[i] = (unsigned char)((hi_val << 4) | lo_val);
  }

  return 1;
}

static int recover_public_key(lua_State *L, const unsigned char *hash, size_t hash_len, const unsigned char *signature, size_t signature_len) {
  const secp256k1_context *ctx;
  secp256k1_ecdsa_recoverable_signature recoverable_signature;
  secp256k1_pubkey public_key;
  unsigned char serialized[65];
  size_t serialized_len = sizeof(serialized);
  int recovery_id;

  if (hash_len != 32) {
    return push_error(L, "Message hash must be 32 bytes.");
  }
  if (signature_len != 65) {
    return push_error(L, "Signature must be 65 bytes.");
  }

  recovery_id = normalize_recovery_id(signature[64]);
  if (recovery_id < 0) {
    return push_error(L, "Recovery id is invalid.");
  }

  ctx = ensure_context();
  if (ctx == NULL) {
    return push_error(L, "Unable to initialize secp256k1 verification context.");
  }

  if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &recoverable_signature, signature, recovery_id) != 1) {
    return push_error(L, "Signature parse failed.");
  }

  if (secp256k1_ecdsa_recover(ctx, &public_key, &recoverable_signature, hash) != 1) {
    return push_error(L, "Signature recovery failed.");
  }

  if (secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len, &public_key, SECP256K1_EC_UNCOMPRESSED) != 1 || serialized_len != 65) {
    return push_error(L, "Public key serialization failed.");
  }

  lua_pushlstring(L, (const char *)serialized, serialized_len);
  return 1;
}

static int l_recover_public_key(lua_State *L) {
  size_t hash_len = 0;
  size_t signature_len = 0;
  const unsigned char *hash = (const unsigned char *)luaL_checklstring(L, 1, &hash_len);
  const unsigned char *signature = (const unsigned char *)luaL_checklstring(L, 2, &signature_len);

  return recover_public_key(L, hash, hash_len, signature, signature_len);
}

static int l_recover_public_key_hex(lua_State *L) {
  size_t hash_len = 0;
  size_t signature_hex_len = 0;
  const unsigned char *hash = (const unsigned char *)luaL_checklstring(L, 1, &hash_len);
  const char *signature_hex = luaL_checklstring(L, 2, &signature_hex_len);
  unsigned char signature[65];

  if (!decode_hex_signature(signature_hex, signature_hex_len, signature)) {
    return push_error(L, "Signature must be 65 bytes encoded as hex.");
  }

  return recover_public_key(L, hash, hash_len, signature, sizeof(signature));
}

int luaopen_eth_secp256k1(lua_State *L) {
  luaL_Reg funcs[] = {
    {"recover_public_key", l_recover_public_key},
    {"recover_public_key_hex", l_recover_public_key_hex},
    {NULL, NULL}
  };

#if LUA_VERSION_NUM >= 502
  luaL_newlib(L, funcs);
#else
  lua_newtable(L);
  luaL_register(L, NULL, funcs);
#endif
  return 1;
}
