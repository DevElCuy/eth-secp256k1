#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include <lua.h>
#include <lauxlib.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

static secp256k1_context *secp256k1_ctx = NULL;

static void secure_bzero(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len-- > 0) {
    *p++ = 0;
  }
}

static int randomize_context(secp256k1_context *ctx) {
  unsigned char seed[32];
  FILE *entropy;
  size_t read_len;
  int ok;

  entropy = fopen("/dev/urandom", "rb");
  if (entropy == NULL) {
    return 0;
  }

  read_len = fread(seed, 1, sizeof(seed), entropy);
  fclose(entropy);

  if (read_len != sizeof(seed)) {
    secure_bzero(seed, sizeof(seed));
    return 0;
  }

  ok = secp256k1_context_randomize(ctx, seed);
  secure_bzero(seed, sizeof(seed));

  return ok == 1;
}

static secp256k1_context *ensure_context(void) {
  if (secp256k1_ctx == NULL) {
    secp256k1_selftest();
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL) {
      return NULL;
    }
    if (!randomize_context(secp256k1_ctx)) {
      secp256k1_context_destroy(secp256k1_ctx);
      secp256k1_ctx = NULL;
      return NULL;
    }
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

static int hex_value(unsigned char value) {
  if (value >= '0' && value <= '9') {
    return (int)(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return (int)(value - 'a' + 10);
  }
  if (value >= 'A' && value <= 'F') {
    return (int)(value - 'A' + 10);
  }
  return -1;
}

static int decode_hex_bytes(const char *input, size_t input_len, unsigned char *output, size_t output_len) {
  size_t offset = 0;
  size_t i;

  if (input_len >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
    input += 2;
    input_len -= 2;
  }
  if (input_len != output_len * 2) {
    return 0;
  }

  for (i = 0; i < output_len; i++) {
    int hi = hex_value((unsigned char)input[offset++]);
    int lo = hex_value((unsigned char)input[offset++]);

    if (hi < 0 || lo < 0) {
      return 0;
    }
    output[i] = (unsigned char)((hi << 4) | lo);
  }

  return 1;
}

static void encode_hex_bytes(const unsigned char *input, size_t input_len, char *output) {
  static const char hex_chars[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < input_len; i++) {
    output[i * 2] = hex_chars[(input[i] >> 4) & 0x0f];
    output[i * 2 + 1] = hex_chars[input[i] & 0x0f];
  }
  output[input_len * 2] = '\0';
}

static int recover_public_key(lua_State *L, const unsigned char *hash, size_t hash_len, const unsigned char *signature, size_t signature_len) {
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
    return push_error(L, "Unable to initialize secp256k1 context.");
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

static int create_public_key(lua_State *L, const unsigned char *private_key, size_t private_key_len, int hex_output) {
  secp256k1_context *ctx;
  secp256k1_pubkey public_key;
  unsigned char serialized[65];
  size_t serialized_len = sizeof(serialized);

  if (private_key_len != 32) {
    return push_error(L, "Private key must be 32 bytes.");
  }

  ctx = ensure_context();
  if (ctx == NULL) {
    return push_error(L, "Unable to initialize secp256k1 context.");
  }

  if (secp256k1_ec_seckey_verify(ctx, private_key) != 1) {
    return push_error(L, "Private key is invalid.");
  }

  if (secp256k1_ec_pubkey_create(ctx, &public_key, private_key) != 1) {
    return push_error(L, "Public key creation failed.");
  }

  if (secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len, &public_key, SECP256K1_EC_UNCOMPRESSED) != 1 || serialized_len != 65) {
    return push_error(L, "Public key serialization failed.");
  }

  if (hex_output) {
    char encoded[131];
    encode_hex_bytes(serialized, serialized_len, encoded);
    lua_pushlstring(L, encoded, 130);
  } else {
    lua_pushlstring(L, (const char *)serialized, serialized_len);
  }

  return 1;
}

static int sign_recoverable(lua_State *L, const unsigned char *hash, size_t hash_len, const unsigned char *private_key, size_t private_key_len, int hex_output) {
  secp256k1_context *ctx;
  secp256k1_ecdsa_recoverable_signature recoverable_signature;
  unsigned char signature[65];
  int recovery_id = 0;

  if (hash_len != 32) {
    return push_error(L, "Message hash must be 32 bytes.");
  }
  if (private_key_len != 32) {
    return push_error(L, "Private key must be 32 bytes.");
  }

  ctx = ensure_context();
  if (ctx == NULL) {
    return push_error(L, "Unable to initialize secp256k1 context.");
  }

  if (secp256k1_ec_seckey_verify(ctx, private_key) != 1) {
    return push_error(L, "Private key is invalid.");
  }

  if (secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_signature, hash, private_key, NULL, NULL) != 1) {
    return push_error(L, "Recoverable signature generation failed.");
  }

  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, signature, &recovery_id, &recoverable_signature);
  signature[64] = (unsigned char)(recovery_id + 27);

  if (hex_output) {
    char encoded[131];
    encode_hex_bytes(signature, sizeof(signature), encoded);
    lua_pushlstring(L, encoded, 130);
  } else {
    lua_pushlstring(L, (const char *)signature, sizeof(signature));
  }

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

  if (!decode_hex_bytes(signature_hex, signature_hex_len, signature, sizeof(signature))) {
    return push_error(L, "Signature must be 65 bytes encoded as hex.");
  }

  return recover_public_key(L, hash, hash_len, signature, sizeof(signature));
}

static int l_create_public_key(lua_State *L) {
  size_t private_key_len = 0;
  const unsigned char *private_key = (const unsigned char *)luaL_checklstring(L, 1, &private_key_len);

  return create_public_key(L, private_key, private_key_len, 0);
}

static int l_create_public_key_hex(lua_State *L) {
  size_t private_key_hex_len = 0;
  const char *private_key_hex = luaL_checklstring(L, 1, &private_key_hex_len);
  unsigned char private_key[32];

  int result;

  if (!decode_hex_bytes(private_key_hex, private_key_hex_len, private_key, sizeof(private_key))) {
    return push_error(L, "Private key must be 32 bytes encoded as hex.");
  }

  result = create_public_key(L, private_key, sizeof(private_key), 1);
  secure_bzero(private_key, sizeof(private_key));
  return result;
}

static int l_sign_recoverable(lua_State *L) {
  size_t hash_len = 0;
  size_t private_key_len = 0;
  const unsigned char *hash = (const unsigned char *)luaL_checklstring(L, 1, &hash_len);
  const unsigned char *private_key = (const unsigned char *)luaL_checklstring(L, 2, &private_key_len);

  return sign_recoverable(L, hash, hash_len, private_key, private_key_len, 0);
}

static int l_sign_recoverable_hex(lua_State *L) {
  size_t hash_len = 0;
  size_t private_key_hex_len = 0;
  const unsigned char *hash = (const unsigned char *)luaL_checklstring(L, 1, &hash_len);
  const char *private_key_hex = luaL_checklstring(L, 2, &private_key_hex_len);
  unsigned char private_key[32];

  int result;

  if (!decode_hex_bytes(private_key_hex, private_key_hex_len, private_key, sizeof(private_key))) {
    return push_error(L, "Private key must be 32 bytes encoded as hex.");
  }

  result = sign_recoverable(L, hash, hash_len, private_key, sizeof(private_key), 1);
  secure_bzero(private_key, sizeof(private_key));
  return result;
}

int luaopen_eth_secp256k1(lua_State *L) {
  luaL_Reg funcs[] = {
    {"recover_public_key", l_recover_public_key},
    {"recover_public_key_hex", l_recover_public_key_hex},
    {"create_public_key", l_create_public_key},
    {"create_public_key_hex", l_create_public_key_hex},
    {"sign_recoverable", l_sign_recoverable},
    {"sign_recoverable_hex", l_sign_recoverable_hex},
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
