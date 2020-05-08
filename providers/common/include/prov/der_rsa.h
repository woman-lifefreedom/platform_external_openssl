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
extern const unsigned char der_oid_rsaEncryption[11];
extern const unsigned char der_oid_id_RSAES_OAEP[11];
extern const unsigned char der_oid_id_pSpecified[11];
extern const unsigned char der_oid_id_RSASSA_PSS[11];
extern const unsigned char der_oid_md2WithRSAEncryption[11];
extern const unsigned char der_oid_md5WithRSAEncryption[11];
extern const unsigned char der_oid_sha1WithRSAEncryption[11];
extern const unsigned char der_oid_sha224WithRSAEncryption[11];
extern const unsigned char der_oid_sha256WithRSAEncryption[11];
extern const unsigned char der_oid_sha384WithRSAEncryption[11];
extern const unsigned char der_oid_sha512WithRSAEncryption[11];
extern const unsigned char der_oid_sha512_224WithRSAEncryption[11];
extern const unsigned char der_oid_sha512_256WithRSAEncryption[11];
extern const unsigned char der_oid_id_sha1[7];
extern const unsigned char der_oid_id_md2[10];
extern const unsigned char der_oid_id_md5[10];
extern const unsigned char der_oid_id_mgf1[11];
extern const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224[11];
extern const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256[11];
extern const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384[11];
extern const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512[11];


int DER_w_algorithmIdentifier_RSA(WPACKET *pkt, int tag, RSA *rsa);
int DER_w_algorithmIdentifier_RSA_with(WPACKET *pkt, int tag,
                                       RSA *rsa, int mdnid);
