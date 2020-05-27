/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include "internal/cryptlib.h"
#include "prov/der_rsa.h"
#include "prov/der_digests.h"

/* Well known OIDs precompiled */

/*
 * id-sha256 OBJECT IDENTIFIER ::= { hashAlgs 1 }
 */
#define DER_OID_V_id_sha256 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
#define DER_OID_SZ_id_sha256 11
const unsigned char der_oid_id_sha256[DER_OID_SZ_id_sha256] = {
    DER_OID_V_id_sha256
};

/*
 * id-sha384 OBJECT IDENTIFIER ::= { hashAlgs 2 }
 */
#define DER_OID_V_id_sha384 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
#define DER_OID_SZ_id_sha384 11
const unsigned char der_oid_id_sha384[DER_OID_SZ_id_sha384] = {
    DER_OID_V_id_sha384
};

/*
 * id-sha512 OBJECT IDENTIFIER ::= { hashAlgs 3 }
 */
#define DER_OID_V_id_sha512 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
#define DER_OID_SZ_id_sha512 11
const unsigned char der_oid_id_sha512[DER_OID_SZ_id_sha512] = {
    DER_OID_V_id_sha512
};

/*
 * id-sha224 OBJECT IDENTIFIER ::= { hashAlgs 4 }
 */
#define DER_OID_V_id_sha224 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
#define DER_OID_SZ_id_sha224 11
const unsigned char der_oid_id_sha224[DER_OID_SZ_id_sha224] = {
    DER_OID_V_id_sha224
};

/*
 * id-sha512-224 OBJECT IDENTIFIER ::= { hashAlgs 5 }
 */
#define DER_OID_V_id_sha512_224 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05
#define DER_OID_SZ_id_sha512_224 11
const unsigned char der_oid_id_sha512_224[DER_OID_SZ_id_sha512_224] = {
    DER_OID_V_id_sha512_224
};

/*
 * id-sha512-256 OBJECT IDENTIFIER ::= { hashAlgs 6 }
 */
#define DER_OID_V_id_sha512_256 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06
#define DER_OID_SZ_id_sha512_256 11
const unsigned char der_oid_id_sha512_256[DER_OID_SZ_id_sha512_256] = {
    DER_OID_V_id_sha512_256
};

/*
 * id-sha3-224 OBJECT IDENTIFIER ::= { hashAlgs 7 }
 */
#define DER_OID_V_id_sha3_224 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07
#define DER_OID_SZ_id_sha3_224 11
const unsigned char der_oid_id_sha3_224[DER_OID_SZ_id_sha3_224] = {
    DER_OID_V_id_sha3_224
};

/*
 * id-sha3-256 OBJECT IDENTIFIER ::= { hashAlgs 8 }
 */
#define DER_OID_V_id_sha3_256 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08
#define DER_OID_SZ_id_sha3_256 11
const unsigned char der_oid_id_sha3_256[DER_OID_SZ_id_sha3_256] = {
    DER_OID_V_id_sha3_256
};

/*
 * id-sha3-384 OBJECT IDENTIFIER ::= { hashAlgs 9 }
 */
#define DER_OID_V_id_sha3_384 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09
#define DER_OID_SZ_id_sha3_384 11
const unsigned char der_oid_id_sha3_384[DER_OID_SZ_id_sha3_384] = {
    DER_OID_V_id_sha3_384
};

/*
 * id-sha3-512 OBJECT IDENTIFIER ::= { hashAlgs 10 }
 */
#define DER_OID_V_id_sha3_512 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A
#define DER_OID_SZ_id_sha3_512 11
const unsigned char der_oid_id_sha3_512[DER_OID_SZ_id_sha3_512] = {
    DER_OID_V_id_sha3_512
};

/*
 * id-shake128 OBJECT IDENTIFIER ::= { hashAlgs 11 }
 */
#define DER_OID_V_id_shake128 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B
#define DER_OID_SZ_id_shake128 11
const unsigned char der_oid_id_shake128[DER_OID_SZ_id_shake128] = {
    DER_OID_V_id_shake128
};

/*
 * id-shake256 OBJECT IDENTIFIER ::= { hashAlgs 12 }
 */
#define DER_OID_V_id_shake256 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C
#define DER_OID_SZ_id_shake256 11
const unsigned char der_oid_id_shake256[DER_OID_SZ_id_shake256] = {
    DER_OID_V_id_shake256
};

/*
 * id-shake128-len OBJECT IDENTIFIER ::= { hashAlgs 17 }
 */
#define DER_OID_V_id_shake128_len DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x11
#define DER_OID_SZ_id_shake128_len 11
const unsigned char der_oid_id_shake128_len[DER_OID_SZ_id_shake128_len] = {
    DER_OID_V_id_shake128_len
};

/*
 * id-shake256-len OBJECT IDENTIFIER ::= { hashAlgs 18 }
 */
#define DER_OID_V_id_shake256_len DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x12
#define DER_OID_SZ_id_shake256_len 11
const unsigned char der_oid_id_shake256_len[DER_OID_SZ_id_shake256_len] = {
    DER_OID_V_id_shake256_len
};

/*
 * id-KMACWithSHAKE128 OBJECT IDENTIFIER ::={hashAlgs 19}
 */
#define DER_OID_V_id_KMACWithSHAKE128 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x13
#define DER_OID_SZ_id_KMACWithSHAKE128 11
const unsigned char der_oid_id_KMACWithSHAKE128[DER_OID_SZ_id_KMACWithSHAKE128] = {
    DER_OID_V_id_KMACWithSHAKE128
};

/*
 * id-KMACWithSHAKE256 OBJECT IDENTIFIER ::={ hashAlgs 20}
 */
#define DER_OID_V_id_KMACWithSHAKE256 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x14
#define DER_OID_SZ_id_KMACWithSHAKE256 11
const unsigned char der_oid_id_KMACWithSHAKE256[DER_OID_SZ_id_KMACWithSHAKE256] = {
    DER_OID_V_id_KMACWithSHAKE256
};

/*
 * rsaEncryption    OBJECT IDENTIFIER ::= { pkcs-1 1 }
 */
#define DER_OID_V_rsaEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
#define DER_OID_SZ_rsaEncryption 11
const unsigned char der_oid_rsaEncryption[DER_OID_SZ_rsaEncryption] = {
    DER_OID_V_rsaEncryption
};

/*
 * id-RSAES-OAEP    OBJECT IDENTIFIER ::= { pkcs-1 7 }
 */
#define DER_OID_V_id_RSAES_OAEP DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07
#define DER_OID_SZ_id_RSAES_OAEP 11
const unsigned char der_oid_id_RSAES_OAEP[DER_OID_SZ_id_RSAES_OAEP] = {
    DER_OID_V_id_RSAES_OAEP
};

/*
 * id-pSpecified    OBJECT IDENTIFIER ::= { pkcs-1 9 }
 */
#define DER_OID_V_id_pSpecified DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x09
#define DER_OID_SZ_id_pSpecified 11
const unsigned char der_oid_id_pSpecified[DER_OID_SZ_id_pSpecified] = {
    DER_OID_V_id_pSpecified
};

/*
 * id-RSASSA-PSS    OBJECT IDENTIFIER ::= { pkcs-1 10 }
 */
#define DER_OID_V_id_RSASSA_PSS DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A
#define DER_OID_SZ_id_RSASSA_PSS 11
const unsigned char der_oid_id_RSASSA_PSS[DER_OID_SZ_id_RSASSA_PSS] = {
    DER_OID_V_id_RSASSA_PSS
};

/*
 * md2WithRSAEncryption         OBJECT IDENTIFIER ::= { pkcs-1 2 }
 */
#define DER_OID_V_md2WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02
#define DER_OID_SZ_md2WithRSAEncryption 11
const unsigned char der_oid_md2WithRSAEncryption[DER_OID_SZ_md2WithRSAEncryption] = {
    DER_OID_V_md2WithRSAEncryption
};

/*
 * md5WithRSAEncryption         OBJECT IDENTIFIER ::= { pkcs-1 4 }
 */
#define DER_OID_V_md5WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04
#define DER_OID_SZ_md5WithRSAEncryption 11
const unsigned char der_oid_md5WithRSAEncryption[DER_OID_SZ_md5WithRSAEncryption] = {
    DER_OID_V_md5WithRSAEncryption
};

/*
 * sha1WithRSAEncryption        OBJECT IDENTIFIER ::= { pkcs-1 5 }
 */
#define DER_OID_V_sha1WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05
#define DER_OID_SZ_sha1WithRSAEncryption 11
const unsigned char der_oid_sha1WithRSAEncryption[DER_OID_SZ_sha1WithRSAEncryption] = {
    DER_OID_V_sha1WithRSAEncryption
};

/*
 * sha224WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 14 }
 */
#define DER_OID_V_sha224WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E
#define DER_OID_SZ_sha224WithRSAEncryption 11
const unsigned char der_oid_sha224WithRSAEncryption[DER_OID_SZ_sha224WithRSAEncryption] = {
    DER_OID_V_sha224WithRSAEncryption
};

/*
 * sha256WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 11 }
 */
#define DER_OID_V_sha256WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
#define DER_OID_SZ_sha256WithRSAEncryption 11
const unsigned char der_oid_sha256WithRSAEncryption[DER_OID_SZ_sha256WithRSAEncryption] = {
    DER_OID_V_sha256WithRSAEncryption
};

/*
 * sha384WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 12 }
 */
#define DER_OID_V_sha384WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C
#define DER_OID_SZ_sha384WithRSAEncryption 11
const unsigned char der_oid_sha384WithRSAEncryption[DER_OID_SZ_sha384WithRSAEncryption] = {
    DER_OID_V_sha384WithRSAEncryption
};

/*
 * sha512WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 13 }
 */
#define DER_OID_V_sha512WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D
#define DER_OID_SZ_sha512WithRSAEncryption 11
const unsigned char der_oid_sha512WithRSAEncryption[DER_OID_SZ_sha512WithRSAEncryption] = {
    DER_OID_V_sha512WithRSAEncryption
};

/*
 * sha512-224WithRSAEncryption  OBJECT IDENTIFIER ::= { pkcs-1 15 }
 */
#define DER_OID_V_sha512_224WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0F
#define DER_OID_SZ_sha512_224WithRSAEncryption 11
const unsigned char der_oid_sha512_224WithRSAEncryption[DER_OID_SZ_sha512_224WithRSAEncryption] = {
    DER_OID_V_sha512_224WithRSAEncryption
};

/*
 * sha512-256WithRSAEncryption  OBJECT IDENTIFIER ::= { pkcs-1 16 }
 */
#define DER_OID_V_sha512_256WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x10
#define DER_OID_SZ_sha512_256WithRSAEncryption 11
const unsigned char der_oid_sha512_256WithRSAEncryption[DER_OID_SZ_sha512_256WithRSAEncryption] = {
    DER_OID_V_sha512_256WithRSAEncryption
};

/*
 * id-sha1    OBJECT IDENTIFIER ::= {
 *     iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2)
 *     26
 * }
 */
#define DER_OID_V_id_sha1 DER_P_OBJECT, 5, 0x2B, 0x0E, 0x03, 0x02, 0x1A
#define DER_OID_SZ_id_sha1 7
const unsigned char der_oid_id_sha1[DER_OID_SZ_id_sha1] = {
    DER_OID_V_id_sha1
};

/*
 * id-md2 OBJECT IDENTIFIER ::= {
 *     iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 2
 * }
 */
#define DER_OID_V_id_md2 DER_P_OBJECT, 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02
#define DER_OID_SZ_id_md2 10
const unsigned char der_oid_id_md2[DER_OID_SZ_id_md2] = {
    DER_OID_V_id_md2
};

/*
 * id-md5 OBJECT IDENTIFIER ::= {
 *     iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5
 * }
 */
#define DER_OID_V_id_md5 DER_P_OBJECT, 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05
#define DER_OID_SZ_id_md5 10
const unsigned char der_oid_id_md5[DER_OID_SZ_id_md5] = {
    DER_OID_V_id_md5
};

/*
 * id-mgf1    OBJECT IDENTIFIER ::= { pkcs-1 8 }
 */
#define DER_OID_V_id_mgf1 DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08
#define DER_OID_SZ_id_mgf1 11
const unsigned char der_oid_id_mgf1[DER_OID_SZ_id_mgf1] = {
    DER_OID_V_id_mgf1
};

/*
 * id-rsassa-pkcs1-v1_5-with-sha3-224 OBJECT IDENTIFIER ::= { sigAlgs 13 }
 */
#define DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_224 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0D
#define DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_224 11
const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224[DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_224] = {
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_224
};

/*
 * id-rsassa-pkcs1-v1_5-with-sha3-256 OBJECT IDENTIFIER ::= { sigAlgs 14 }
 */
#define DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_256 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0E
#define DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_256 11
const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256[DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_256] = {
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_256
};

/*
 * id-rsassa-pkcs1-v1_5-with-sha3-384 OBJECT IDENTIFIER ::= { sigAlgs 15 }
 */
#define DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_384 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0F
#define DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_384 11
const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384[DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_384] = {
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_384
};

/*
 * id-rsassa-pkcs1-v1_5-with-sha3-512 OBJECT IDENTIFIER ::= { sigAlgs 16 }
 */
#define DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_512 DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10
#define DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_512 11
const unsigned char der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512[DER_OID_SZ_id_rsassa_pkcs1_v1_5_with_sha3_512] = {
    DER_OID_V_id_rsassa_pkcs1_v1_5_with_sha3_512
};

/*
 * md4WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 3 }
 */
#define DER_OID_V_md4WithRSAEncryption DER_P_OBJECT, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x03
#define DER_OID_SZ_md4WithRSAEncryption 11
const unsigned char der_oid_md4WithRSAEncryption[DER_OID_SZ_md4WithRSAEncryption] = {
    DER_OID_V_md4WithRSAEncryption
};

/*
 * ripemd160WithRSAEncryption    OBJECT IDENTIFIER ::= {
 *     iso(1) identified-organization(3) teletrust(36) algorithm(3) signatureAlgorithm(3) rsaSignature(1) 2
 * }
 */
#define DER_OID_V_ripemd160WithRSAEncryption DER_P_OBJECT, 6, 0x2B, 0x24, 0x03, 0x03, 0x01, 0x02
#define DER_OID_SZ_ripemd160WithRSAEncryption 8
const unsigned char der_oid_ripemd160WithRSAEncryption[DER_OID_SZ_ripemd160WithRSAEncryption] = {
    DER_OID_V_ripemd160WithRSAEncryption
};


/* More complex pre-compiled sequences.  TODO(3.0) refactor? */
/*-
 * From https://tools.ietf.org/html/rfc8017#appendix-A.2.1
 *
 * OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *     { OID id-sha1       PARAMETERS NULL }|
 *     { OID id-sha224     PARAMETERS NULL }|
 *     { OID id-sha256     PARAMETERS NULL }|
 *     { OID id-sha384     PARAMETERS NULL }|
 *     { OID id-sha512     PARAMETERS NULL }|
 *     { OID id-sha512-224 PARAMETERS NULL }|
 *     { OID id-sha512-256 PARAMETERS NULL },
 *     ...  -- Allows for future expansion --
 * }
 */
#define DER_V_NULL DER_P_NULL, 0
#define DER_SZ_NULL 2

/*
 * The names for the hash function AlgorithmIdentifiers are borrowed and
 * expanded from https://tools.ietf.org/html/rfc4055#section-2.1
 *
 * sha1Identifier  AlgorithmIdentifier  ::=  { id-sha1, NULL }
 * sha224Identifier  AlgorithmIdentifier  ::=  { id-sha224, NULL }
 * sha256Identifier  AlgorithmIdentifier  ::=  { id-sha256, NULL }
 * sha384Identifier  AlgorithmIdentifier  ::=  { id-sha384, NULL }
 * sha512Identifier  AlgorithmIdentifier  ::=  { id-sha512, NULL }
 */
/*
 * NOTE: Some of the arrays aren't used other than inside sizeof(), which
 * clang complains about (-Wno-unneeded-internal-declaration).  To get
 * around that, we make them non-static, and declare them an extra time to
 * avoid compilers complaining about definitions without declarations.
 */
#if 0                            /* Currently unused */
#define DER_AID_V_sha1Identifier                                        \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_sha1 + DER_SZ_NULL,                               \
        DER_OID_V_id_sha1,                                              \
        DER_V_NULL
extern const unsigned char der_aid_sha1Identifier[];
const unsigned char der_aid_sha1Identifier[] = {
    DER_AID_V_sha1Identifier
};
#define DER_AID_SZ_sha1Identifier sizeof(der_aid_sha1Identifier)
#endif

#define DER_AID_V_sha224Identifier                                      \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_sha224 + DER_SZ_NULL,                             \
        DER_OID_V_id_sha224,                                            \
        DER_V_NULL
extern const unsigned char der_aid_sha224Identifier[];
const unsigned char der_aid_sha224Identifier[] = {
    DER_AID_V_sha224Identifier
};
#define DER_AID_SZ_sha224Identifier sizeof(der_aid_sha224Identifier)

#define DER_AID_V_sha256Identifier                                      \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_sha256 + DER_SZ_NULL,                             \
        DER_OID_V_id_sha256,                                            \
        DER_V_NULL
extern const unsigned char der_aid_sha256Identifier[];
const unsigned char der_aid_sha256Identifier[] = {
    DER_AID_V_sha256Identifier
};
#define DER_AID_SZ_sha256Identifier sizeof(der_aid_sha256Identifier)

#define DER_AID_V_sha384Identifier                                      \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_sha384 + DER_SZ_NULL,                             \
        DER_OID_V_id_sha384,                                            \
        DER_V_NULL
extern const unsigned char der_aid_sha384Identifier[];
const unsigned char der_aid_sha384Identifier[] = {
    DER_AID_V_sha384Identifier
};
#define DER_AID_SZ_sha384Identifier sizeof(der_aid_sha384Identifier)

#define DER_AID_V_sha512Identifier                                      \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_sha512 + DER_SZ_NULL,                             \
        DER_OID_V_id_sha512,                                            \
        DER_V_NULL
extern const unsigned char der_aid_sha512Identifier[];
const unsigned char der_aid_sha512Identifier[] = {
    DER_AID_V_sha512Identifier
};
#define DER_AID_SZ_sha512Identifier sizeof(der_aid_sha512Identifier)

#define DER_AID_V_sha512_224Identifier                                  \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_sha512_224 + DER_SZ_NULL,                         \
        DER_OID_V_id_sha512_224,                                        \
        DER_V_NULL
extern const unsigned char der_aid_sha512_224Identifier[];
const unsigned char der_aid_sha512_224Identifier[] = {
    DER_AID_V_sha512_224Identifier
};
#define DER_AID_SZ_sha512_224Identifier sizeof(der_aid_sha512_224Identifier)

#define DER_AID_V_sha512_256Identifier                                  \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_sha512_256 + DER_SZ_NULL,                         \
        DER_OID_V_id_sha512_256,                                        \
        DER_V_NULL
extern const unsigned char der_aid_sha512_256Identifier[];
const unsigned char der_aid_sha512_256Identifier[] = {
    DER_AID_V_sha512_256Identifier
};
#define DER_AID_SZ_sha512_256Identifier sizeof(der_aid_sha512_256Identifier)

/*-
 * From https://tools.ietf.org/html/rfc8017#appendix-A.2.1
 *
 * HashAlgorithm ::= AlgorithmIdentifier {
 *    {OAEP-PSSDigestAlgorithms}
 * }
 *
 * ...
 *
 * PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
 *     { OID id-mgf1 PARAMETERS HashAlgorithm },
 *     ...  -- Allows for future expansion --
 * }
 */

/*
 * The names for the MGF1 AlgorithmIdentifiers are borrowed and expanded
 * from https://tools.ietf.org/html/rfc4055#section-2.1
 *
 * mgf1SHA1Identifier  AlgorithmIdentifier  ::=
 *                      { id-mgf1, sha1Identifier }
 * mgf1SHA224Identifier  AlgorithmIdentifier  ::=
 *                      { id-mgf1, sha224Identifier }
 * mgf1SHA256Identifier  AlgorithmIdentifier  ::=
 *                      { id-mgf1, sha256Identifier }
 * mgf1SHA384Identifier  AlgorithmIdentifier  ::=
 *                      { id-mgf1, sha384Identifier }
 * mgf1SHA512Identifier  AlgorithmIdentifier  ::=
 *                      { id-mgf1, sha512Identifier }
 */
#if 0                            /* Currently unused */
#define DER_AID_V_mgf1SHA1Identifier                                    \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                                   \
        DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha1Identifier,                 \
        DER_OID_V_id_mgf1,                                              \
        DER_AID_V_sha1Identifier
static const unsigned char der_aid_mgf1SHA1Identifier[] = {
    DER_AID_V_mgf1SHA1Identifier
};
#define DER_AID_SZ_mgf1SHA1Identifier sizeof(der_aid_mgf1SHA1Identifier)
#endif

#define DER_AID_V_mgf1SHA224Identifier                          \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                           \
        DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha224Identifier,       \
        DER_OID_V_id_mgf1,                                      \
        DER_AID_V_sha224Identifier
static const unsigned char der_aid_mgf1SHA224Identifier[] = {
    DER_AID_V_mgf1SHA224Identifier
};
#define DER_AID_SZ_mgf1SHA224Identifier sizeof(der_aid_mgf1SHA224Identifier)

#define DER_AID_V_mgf1SHA256Identifier                          \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                           \
        DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha256Identifier,       \
        DER_OID_V_id_mgf1,                                      \
        DER_AID_V_sha256Identifier
static const unsigned char der_aid_mgf1SHA256Identifier[] = {
    DER_AID_V_mgf1SHA256Identifier
};
#define DER_AID_SZ_mgf1SHA256Identifier sizeof(der_aid_mgf1SHA256Identifier)

#define DER_AID_V_mgf1SHA384Identifier                          \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                           \
        DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha384Identifier,       \
        DER_OID_V_id_mgf1,                                      \
        DER_AID_V_sha384Identifier
static const unsigned char der_aid_mgf1SHA384Identifier[] = {
    DER_AID_V_mgf1SHA384Identifier
};
#define DER_AID_SZ_mgf1SHA384Identifier sizeof(der_aid_mgf1SHA384Identifier)

#define DER_AID_V_mgf1SHA512Identifier                          \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                           \
        DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha512Identifier,       \
        DER_OID_V_id_mgf1,                                      \
        DER_AID_V_sha512Identifier
static const unsigned char der_aid_mgf1SHA512Identifier[] = {
    DER_AID_V_mgf1SHA512Identifier
};
#define DER_AID_SZ_mgf1SHA512Identifier sizeof(der_aid_mgf1SHA512Identifier)

#define DER_AID_V_mgf1SHA512_224Identifier                      \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                           \
        DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha512_224Identifier,   \
        DER_OID_V_id_mgf1,                                      \
        DER_AID_V_sha512_224Identifier
static const unsigned char der_aid_mgf1SHA512_224Identifier[] = {
    DER_AID_V_mgf1SHA512_224Identifier
};
#define DER_AID_SZ_mgf1SHA512_224Identifier sizeof(der_aid_mgf1SHA512_224Identifier)

#define DER_AID_V_mgf1SHA512_256Identifier                      \
    DER_P_SEQUENCE|DER_F_CONSTRUCTED,                           \
        DER_OID_SZ_id_mgf1 + DER_AID_SZ_sha512_256Identifier,   \
        DER_OID_V_id_mgf1,                                      \
        DER_AID_V_sha512_256Identifier
static const unsigned char der_aid_mgf1SHA512_256Identifier[] = {
    DER_AID_V_mgf1SHA512_256Identifier
};
#define DER_AID_SZ_mgf1SHA512_256Identifier sizeof(der_aid_mgf1SHA512_256Identifier)


#define MGF1_SHA_CASE(bits, var)                                \
    case NID_sha##bits:                                         \
        var = der_aid_mgf1SHA##bits##Identifier;                \
        var##_sz = sizeof(der_aid_mgf1SHA##bits##Identifier);   \
        break;

/*-
 * The name is borrowed from https://tools.ietf.org/html/rfc8017#appendix-A.2.1
 *
 * MaskGenAlgorithm ::= AlgorithmIdentifier { {PKCS1MGFAlgorithms} }
 */
static int DER_w_MaskGenAlgorithm(WPACKET *pkt, int tag,
                                  const RSA_PSS_PARAMS_30 *pss)
{
    if (pss != NULL && rsa_pss_params_30_maskgenalg(pss) == NID_mgf1) {
        int maskgenhashalg_nid = rsa_pss_params_30_maskgenhashalg(pss);
        const unsigned char *maskgenalg = NULL;
        size_t maskgenalg_sz = 0;

        switch (maskgenhashalg_nid) {
        case NID_sha1:
            break;
            MGF1_SHA_CASE(224, maskgenalg);
            MGF1_SHA_CASE(256, maskgenalg);
            MGF1_SHA_CASE(384, maskgenalg);
            MGF1_SHA_CASE(512, maskgenalg);
            MGF1_SHA_CASE(512_224, maskgenalg);
            MGF1_SHA_CASE(512_256, maskgenalg);
        default:
            return 0;
        }

        /* If there is none (or it was the default), we write nothing */
        if (maskgenalg == NULL)
            return 1;

        return DER_w_precompiled(pkt, tag, maskgenalg, maskgenalg_sz);
    }
    return 0;
}

#define OAEP_PSS_MD_CASE(name, var)                                     \
    case NID_##name:                                                    \
        var = der_oid_id_##name;                                        \
        var##_sz = sizeof(der_oid_id_##name);                           \
        break;

int DER_w_RSASSA_PSS_params(WPACKET *pkt, int tag, const RSA_PSS_PARAMS_30 *pss)
{
    int hashalg_nid, default_hashalg_nid;
    int saltlen, default_saltlen;
    int trailerfield, default_trailerfield;
    const unsigned char *hashalg = NULL;
    size_t hashalg_sz = 0;

    /*
     * For an unrestricted key, this function should not have been called;
     * the caller must be in control, because unrestricted keys are permitted
     * in some situations (when encoding the public key in a SubjectKeyInfo,
     * for example) while not in others, and this function doesn't know the
     * intent.  Therefore, we assert that here, the PSS parameters must show
     * that the key is restricted.
     */
    if (!ossl_assert(pss != NULL && !rsa_pss_params_30_is_unrestricted(pss)))
        return 0;

    hashalg_nid = rsa_pss_params_30_hashalg(pss);
    saltlen = rsa_pss_params_30_saltlen(pss);
    trailerfield = rsa_pss_params_30_trailerfield(pss);

    /* Getting default values */
    default_hashalg_nid = rsa_pss_params_30_hashalg(NULL);
    default_saltlen = rsa_pss_params_30_saltlen(NULL);
    default_trailerfield = rsa_pss_params_30_trailerfield(NULL);

    /*
     * From https://tools.ietf.org/html/rfc8017#appendix-A.2.1:
     *
     * OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
     *     { OID id-sha1       PARAMETERS NULL }|
     *     { OID id-sha224     PARAMETERS NULL }|
     *     { OID id-sha256     PARAMETERS NULL }|
     *     { OID id-sha384     PARAMETERS NULL }|
     *     { OID id-sha512     PARAMETERS NULL }|
     *     { OID id-sha512-224 PARAMETERS NULL }|
     *     { OID id-sha512-256 PARAMETERS NULL },
     *     ...  -- Allows for future expansion --
     * }
     */
    switch (hashalg_nid) {
        OAEP_PSS_MD_CASE(sha1, hashalg);
        OAEP_PSS_MD_CASE(sha224, hashalg);
        OAEP_PSS_MD_CASE(sha256, hashalg);
        OAEP_PSS_MD_CASE(sha384, hashalg);
        OAEP_PSS_MD_CASE(sha512, hashalg);
        OAEP_PSS_MD_CASE(sha512_224, hashalg);
        OAEP_PSS_MD_CASE(sha512_256, hashalg);
    default:
        return 0;
    }

    return DER_w_begin_sequence(pkt, tag)
        && (trailerfield == default_trailerfield
            || DER_w_ulong(pkt, 3, trailerfield))
        && (saltlen == default_saltlen || DER_w_ulong(pkt, 2, saltlen))
        && DER_w_MaskGenAlgorithm(pkt, 1, pss)
        && (hashalg_nid == default_hashalg_nid
            || DER_w_precompiled(pkt, 0, hashalg, hashalg_sz))
        && DER_w_end_sequence(pkt, tag);
}

/* Aliases so we can have a uniform RSA_CASE */
#define der_oid_rsassaPss der_oid_id_RSASSA_PSS

#define RSA_CASE(name, var)                                             \
    var##_nid = NID_##name;                                             \
    var##_oid = der_oid_##name;                                         \
    var##_oid_sz = sizeof(der_oid_##name);                              \
    break;

int DER_w_algorithmIdentifier_RSA(WPACKET *pkt, int tag, RSA *rsa)
{
    int rsa_nid = NID_undef;
    const unsigned char *rsa_oid = NULL;
    size_t rsa_oid_sz = 0;
    RSA_PSS_PARAMS_30 *pss_params = rsa_get0_pss_params_30(rsa);

    switch (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        RSA_CASE(rsaEncryption, rsa);
    case RSA_FLAG_TYPE_RSASSAPSS:
        RSA_CASE(rsassaPss, rsa);
    }

    if (rsa_oid == NULL)
        return 0;

    return DER_w_begin_sequence(pkt, tag)
        && (rsa_nid != NID_rsassaPss
            || rsa_pss_params_30_is_unrestricted(pss_params)
            || DER_w_RSASSA_PSS_params(pkt, -1, pss_params))
        && DER_w_precompiled(pkt, -1, rsa_oid, rsa_oid_sz)
        && DER_w_end_sequence(pkt, tag);
}

/* Aliases so we can have a uniform MD_with_RSA_CASE */
#define der_oid_sha3_224WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224
#define der_oid_sha3_256WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256
#define der_oid_sha3_384WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384
#define der_oid_sha3_512WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512

#define MD_with_RSA_CASE(name, var)                                     \
    case NID_##name:                                                    \
        var = der_oid_##name##WithRSAEncryption;                        \
        var##_sz = sizeof(der_oid_##name##WithRSAEncryption);           \
        break;

int DER_w_algorithmIdentifier_RSA_with(WPACKET *pkt, int tag,
                                       RSA *rsa, int mdnid)
{
    const unsigned char *precompiled = NULL;
    size_t precompiled_sz = 0;

    switch (mdnid) {
#ifndef FIPS_MODULE
        MD_with_RSA_CASE(md2, precompiled);
        MD_with_RSA_CASE(md5, precompiled);
        MD_with_RSA_CASE(md4, precompiled);
        MD_with_RSA_CASE(ripemd160, precompiled);
/* TODO(3.0) Decide what to do about mdc2 and md5_sha1 */
#endif
        MD_with_RSA_CASE(sha1, precompiled);
        MD_with_RSA_CASE(sha224, precompiled);
        MD_with_RSA_CASE(sha256, precompiled);
        MD_with_RSA_CASE(sha384, precompiled);
        MD_with_RSA_CASE(sha512, precompiled);
        MD_with_RSA_CASE(sha512_224, precompiled);
        MD_with_RSA_CASE(sha512_256, precompiled);
        MD_with_RSA_CASE(sha3_224, precompiled);
        MD_with_RSA_CASE(sha3_256, precompiled);
        MD_with_RSA_CASE(sha3_384, precompiled);
        MD_with_RSA_CASE(sha3_512, precompiled);
    default:
        return 0;
    }

    return DER_w_begin_sequence(pkt, tag)
        /* No parameters (yet?) */
        && DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)
        && DER_w_end_sequence(pkt, tag);
}
