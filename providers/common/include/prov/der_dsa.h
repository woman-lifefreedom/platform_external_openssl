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
extern const unsigned char der_oid_id_dsa[9];
extern const unsigned char der_oid_id_dsa_with_sha1[9];
extern const unsigned char der_oid_id_dsa_with_sha224[11];
extern const unsigned char der_oid_id_dsa_with_sha256[11];
extern const unsigned char der_oid_id_dsa_with_sha384[11];
extern const unsigned char der_oid_id_dsa_with_sha512[11];
extern const unsigned char der_oid_id_dsa_with_sha3_224[11];
extern const unsigned char der_oid_id_dsa_with_sha3_256[11];
extern const unsigned char der_oid_id_dsa_with_sha3_384[11];
extern const unsigned char der_oid_id_dsa_with_sha3_512[11];


int DER_w_algorithmIdentifier_DSA(WPACKET *pkt, int tag, DSA *dsa);
int DER_w_algorithmIdentifier_DSA_with(WPACKET *pkt, int tag,
                                       DSA *dsa, int mdnid);
