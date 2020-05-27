/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/der.h"

/* Well known OIDs precompiled */
extern const unsigned char der_oid_sigAlgs[10];
extern const unsigned char der_oid_id_sha256[11];
extern const unsigned char der_oid_id_sha384[11];
extern const unsigned char der_oid_id_sha512[11];
extern const unsigned char der_oid_id_sha224[11];
extern const unsigned char der_oid_id_sha512_224[11];
extern const unsigned char der_oid_id_sha512_256[11];
extern const unsigned char der_oid_id_sha3_224[11];
extern const unsigned char der_oid_id_sha3_256[11];
extern const unsigned char der_oid_id_sha3_384[11];
extern const unsigned char der_oid_id_sha3_512[11];
extern const unsigned char der_oid_id_shake128[11];
extern const unsigned char der_oid_id_shake256[11];
extern const unsigned char der_oid_id_shake128_len[11];
extern const unsigned char der_oid_id_shake256_len[11];
extern const unsigned char der_oid_id_KMACWithSHAKE128[11];
extern const unsigned char der_oid_id_KMACWithSHAKE256[11];

