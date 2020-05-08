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
extern const unsigned char der_oid_ecdsa_with_SHA1[9];
extern const unsigned char der_oid_id_ecPublicKey[9];
extern const unsigned char der_oid_c2pnb163v1[10];
extern const unsigned char der_oid_c2pnb163v2[10];
extern const unsigned char der_oid_c2pnb163v3[10];
extern const unsigned char der_oid_c2pnb176w1[10];
extern const unsigned char der_oid_c2tnb191v1[10];
extern const unsigned char der_oid_c2tnb191v2[10];
extern const unsigned char der_oid_c2tnb191v3[10];
extern const unsigned char der_oid_c2onb191v4[10];
extern const unsigned char der_oid_c2onb191v5[10];
extern const unsigned char der_oid_c2pnb208w1[10];
extern const unsigned char der_oid_c2tnb239v1[10];
extern const unsigned char der_oid_c2tnb239v2[10];
extern const unsigned char der_oid_c2tnb239v3[10];
extern const unsigned char der_oid_c2onb239v4[10];
extern const unsigned char der_oid_c2onb239v5[10];
extern const unsigned char der_oid_c2pnb272w1[10];
extern const unsigned char der_oid_c2pnb304w1[10];
extern const unsigned char der_oid_c2tnb359v1[10];
extern const unsigned char der_oid_c2pnb368w1[10];
extern const unsigned char der_oid_c2tnb431r1[10];
extern const unsigned char der_oid_prime192v1[10];
extern const unsigned char der_oid_prime192v2[10];
extern const unsigned char der_oid_prime192v3[10];
extern const unsigned char der_oid_prime239v1[10];
extern const unsigned char der_oid_prime239v2[10];
extern const unsigned char der_oid_prime239v3[10];
extern const unsigned char der_oid_prime256v1[10];
extern const unsigned char der_oid_ecdsa_with_SHA224[10];
extern const unsigned char der_oid_ecdsa_with_SHA256[10];
extern const unsigned char der_oid_ecdsa_with_SHA384[10];
extern const unsigned char der_oid_ecdsa_with_SHA512[10];
extern const unsigned char der_oid_id_ecdsa_with_sha3_224[11];
extern const unsigned char der_oid_id_ecdsa_with_sha3_256[11];
extern const unsigned char der_oid_id_ecdsa_with_sha3_384[11];
extern const unsigned char der_oid_id_ecdsa_with_sha3_512[11];


int DER_w_algorithmIdentifier_EC(WPACKET *pkt, int cont, EC_KEY *ec);
int DER_w_algorithmIdentifier_ECDSA_with(WPACKET *pkt, int cont,
                                         EC_KEY *ec, int mdnid);
