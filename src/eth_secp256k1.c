#include <stddef.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

static secp256k1_context *secp256k1_ctx = NULL;

static secp256k1_context *ensure_context(void) {
  if (secp256k1_ctx == NULL) {
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  }
  return secp256k1_ctx;
}

static int push_error(lua_State *L, const char *message) {
  lua_pushnil(L);
  lua_pushstring(L, message);
  return 2;
}

static int normalize_recovery_id(unsigned char value) {
  if (value >= 27) {
    value = (unsigned char)(value - 27);
  }
  if (value <= 3) {
    return (int)value;
  }
  return -1;
}

static int l_recover_public_key(lua_State *L) {
  size_t hash_len = 0;
  size_t signature_len = 0;
  const unsigned char *hash = (const unsigned char *)luaL_checklstring(L, 1, &hash_len);
  const unsigned char *signature = (const unsigned char *)luaL_checklstring(L, 2, &signature_len);
  secp256k1_context *ctx;
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
    return push_error(L, "Unable to create secp256k1 verification context.");
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

int luaopen_eth_secp256k1(lua_State *L) {
  luaL_Reg funcs[] = {
    {"recover_public_key", l_recover_public_key},
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
