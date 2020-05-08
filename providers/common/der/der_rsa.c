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
#include "prov/der_rsa.h"

/* Well known OIDs precompiled */

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


int DER_w_algorithmIdentifier_RSA(WPACKET *pkt, int tag, RSA *rsa)
{
    return DER_w_begin_sequence(pkt, tag)
        /* No parameters (yet?) */
        && DER_w_precompiled(pkt, -1, der_oid_rsaEncryption,
                             sizeof(der_oid_rsaEncryption))
        && DER_w_end_sequence(pkt, tag);
}

/* Aliases so we can have a uniform MD_CASE */
#define der_oid_sha3_224WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_224
#define der_oid_sha3_256WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_256
#define der_oid_sha3_384WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_384
#define der_oid_sha3_512WithRSAEncryption \
    der_oid_id_rsassa_pkcs1_v1_5_with_sha3_512

#define MD_CASE(name)                                                   \
    case NID_##name:                                                    \
        precompiled = der_oid_##name##WithRSAEncryption;                \
        precompiled_sz = sizeof(der_oid_##name##WithRSAEncryption);     \
        break;

int DER_w_algorithmIdentifier_RSA_with(WPACKET *pkt, int tag,
                                       RSA *rsa, int mdnid)
{
    const unsigned char *precompiled = NULL;
    size_t precompiled_sz = 0;

    switch (mdnid) {
#ifndef FIPS_MODE
        MD_CASE(md2);
        MD_CASE(md5);
#endif
        MD_CASE(sha1);
        MD_CASE(sha224);
        MD_CASE(sha256);
        MD_CASE(sha384);
        MD_CASE(sha512);
        MD_CASE(sha3_224);
        MD_CASE(sha3_256);
        MD_CASE(sha3_384);
        MD_CASE(sha3_512);
    default:
        return 0;
    }

    return DER_w_begin_sequence(pkt, tag)
        /* No parameters (yet?) */
        && DER_w_precompiled(pkt, -1, precompiled, precompiled_sz)
        && DER_w_end_sequence(pkt, tag);
}
