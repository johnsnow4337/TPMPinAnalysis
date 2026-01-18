/** @file
  TPM2.0 Specification data structures
  (Trusted Platform Module Library Specification, Family "2.0", Level 00, Revision 00.96,
  @http://www.trustedcomputinggroup.org/resources/tpm_library_specification)

  Check http://trustedcomputinggroup.org for latest specification updates.

Copyright (c) 2013 - 2015, Intel Corporation. All rights reserved. <BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TPM20_H_
#define _TPM20_H_

#include "Tpm12.h"

#pragma pack (1)

//--- Converted all 'typedef's to 'using's or removed typedef ---//

// Annex A Algorithm Constants

// Table 205 - Defines for SHA1 Hash Values
#define SHA1_DIGEST_SIZE  20
#define SHA1_BLOCK_SIZE   64

// Table 206 - Defines for SHA256 Hash Values
#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

// Table 207 - Defines for SHA384 Hash Values
#define SHA384_DIGEST_SIZE  48
#define SHA384_BLOCK_SIZE   128

// Table 208 - Defines for SHA512 Hash Values
#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE   128

// Table 209 - Defines for SM3_256 Hash Values
#define SM3_256_DIGEST_SIZE  32
#define SM3_256_BLOCK_SIZE   64

// Table 210 - Defines for Architectural Limits Values
#define MAX_SESSION_NUMBER  3

// Annex B Implementation Definitions

// Table 211 - Defines for Logic Values
#define YES    1
#define NO     0
#define SET    1
#define CLEAR  0

// Table 215 - Defines for RSA Algorithm Constants
#define MAX_RSA_KEY_BITS   2048
#define MAX_RSA_KEY_BYTES  ((2048 + 7) / 8)

// Table 216 - Defines for ECC Algorithm Constants
#define MAX_ECC_KEY_BITS   256
#define MAX_ECC_KEY_BYTES  ((256 + 7) / 8)

// Table 217 - Defines for AES Algorithm Constants
#define MAX_AES_KEY_BITS          128
#define MAX_AES_BLOCK_SIZE_BYTES  16
#define MAX_AES_KEY_BYTES         ((128 + 7) / 8)

// Table 218 - Defines for SM4 Algorithm Constants
#define MAX_SM4_KEY_BITS          128
#define MAX_SM4_BLOCK_SIZE_BYTES  16
#define MAX_SM4_KEY_BYTES         ((128 + 7) / 8)

// Table 219 - Defines for Symmetric Algorithm Constants
#define MAX_SYM_KEY_BITS    MAX_AES_KEY_BITS
#define MAX_SYM_KEY_BYTES   MAX_AES_KEY_BYTES
#define MAX_SYM_BLOCK_SIZE  MAX_AES_BLOCK_SIZE_BYTES

// Table 220 - Defines for Implementation Values
using  BSIZE = UINT16;
#define BUFFER_ALIGNMENT     4
#define IMPLEMENTATION_PCR   24
#define PLATFORM_PCR         24
#define DRTM_PCR             17
#define NUM_LOCALITIES       5
#define MAX_HANDLE_NUM       3
#define MAX_ACTIVE_SESSIONS  64
using  CONTEXT_SLOT = UINT16;
using  CONTEXT_COUNTER = UINT64;
#define MAX_LOADED_SESSIONS            3
#define MAX_SESSION_NUM                3
#define MAX_LOADED_OBJECTS             3
#define MIN_EVICT_OBJECTS              2
#define PCR_SELECT_MIN                 ((PLATFORM_PCR + 7) / 8)
#define PCR_SELECT_MAX                 ((IMPLEMENTATION_PCR + 7) / 8)
#define NUM_POLICY_PCR_GROUP           1
#define NUM_AUTHVALUE_PCR_GROUP        1
#define MAX_CONTEXT_SIZE               4000
#define MAX_DIGEST_BUFFER              1024
#define MAX_NV_INDEX_SIZE              1024
#define MAX_CAP_BUFFER                 1024
#define NV_MEMORY_SIZE                 16384
#define NUM_STATIC_PCR                 16
#define MAX_ALG_LIST_SIZE              64
#define TIMER_PRESCALE                 100000
#define PRIMARY_SEED_SIZE              32
#define CONTEXT_ENCRYPT_ALG            TPM_ALG_AES
#define CONTEXT_ENCRYPT_KEY_BITS       MAX_SYM_KEY_BITS
#define CONTEXT_ENCRYPT_KEY_BYTES      ((CONTEXT_ENCRYPT_KEY_BITS + 7) / 8)
#define CONTEXT_INTEGRITY_HASH_ALG     TPM_ALG_SHA256
#define CONTEXT_INTEGRITY_HASH_SIZE    SHA256_DIGEST_SIZE
#define PROOF_SIZE                     CONTEXT_INTEGRITY_HASH_SIZE
#define NV_CLOCK_UPDATE_INTERVAL       12
#define NUM_POLICY_PCR                 1
#define MAX_COMMAND_SIZE               4096
#define MAX_RESPONSE_SIZE              4096
#define ORDERLY_BITS                   8
#define MAX_ORDERLY_COUNT              ((1 << ORDERLY_BITS) - 1)
#define ALG_ID_FIRST                   TPM_ALG_FIRST
#define ALG_ID_LAST                    TPM_ALG_LAST
#define MAX_SYM_DATA                   128
#define MAX_RNG_ENTROPY_SIZE           64
#define RAM_INDEX_SPACE                512
#define RSA_DEFAULT_PUBLIC_EXPONENT    0x00010001
#define CRT_FORMAT_RSA                 YES
#define PRIVATE_VENDOR_SPECIFIC_BYTES  ((MAX_RSA_KEY_BYTES / 2) * ( 3 + CRT_FORMAT_RSA * 2))

// Capability related MAX_ value
#define MAX_CAP_DATA        (MAX_CAP_BUFFER - sizeof(TPM_CAP) - sizeof(UINT32))
#define MAX_CAP_ALGS        (MAX_CAP_DATA / sizeof(TPMS_ALG_PROPERTY))
#define MAX_CAP_HANDLES     (MAX_CAP_DATA / sizeof(TPM_HANDLE))
#define MAX_CAP_CC          (MAX_CAP_DATA / sizeof(TPM_CC))
#define MAX_TPM_PROPERTIES  (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PROPERTY))
#define MAX_PCR_PROPERTIES  (MAX_CAP_DATA / sizeof(TPMS_TAGGED_PCR_SELECT))
#define MAX_ECC_CURVES      (MAX_CAP_DATA / sizeof(TPM_ECC_CURVE))

//
// Always set 5 here, because we want to support all hash algo in BIOS.
//
#define HASH_COUNT  5

// 5 Base Types

// Table 3 - Definition of Base Types
using  BYTE = UINT8;

// Table 4 - Definition of Types for Documentation Clarity
//
// NOTE: Comment because it has same name as TPM1.2 (value is same, so not runtime issue)
//
// using  TPM_ALGORITHM_ID = UINT32;
// using  TPM_MODIFIER_INDICATOR = UINT32;
using  TPM_AUTHORIZATION_SIZE = UINT32;
using  TPM_PARAMETER_SIZE = UINT32;
using  TPM_KEY_SIZE = UINT16;
using  TPM_KEY_BITS = UINT16;

// 6 Constants

// Table 6 - TPM_GENERATED Constants
using  TPM_GENERATED = UINT32;
#define TPM_GENERATED_VALUE  (TPM_GENERATED)(0xff544347)

//--- TPM_ALG_ID is converted to enum rather than typedef and #defines ---//
// Table 7 - TPM_ALG_ID Constants
enum TPM_ALG_ID : UINT16{
//
// NOTE: Comment some algo which has same name as TPM1.2 (value is same, so not runtime issue)
//
     TPM_ALG_ERROR   = 0x0000,
     TPM_ALG_FIRST   = 0x0001,
//      TPM_ALG_RSA             = 0x0001,
//      TPM_ALG_SHA             = 0x0004,
     TPM_ALG_SHA1   = 0x0004,
//      TPM_ALG_HMAC            = 0x0005,
     TPM_ALG_AES   = 0x0006,
//      TPM_ALG_MGF1            = 0x0007,
     TPM_ALG_KEYEDHASH   = 0x0008,
//      TPM_ALG_XOR             = 0x000A,
     TPM_ALG_SHA256           = 0x000B,
     TPM_ALG_SHA384           = 0x000C,
     TPM_ALG_SHA512           = 0x000D,
     TPM_ALG_NULL             = 0x0010,
     TPM_ALG_SM3_256          = 0x0012,
     TPM_ALG_SM4              = 0x0013,
     TPM_ALG_RSASSA           = 0x0014,
     TPM_ALG_RSAES            = 0x0015,
     TPM_ALG_RSAPSS           = 0x0016,
     TPM_ALG_OAEP             = 0x0017,
     TPM_ALG_ECDSA            = 0x0018,
     TPM_ALG_ECDH             = 0x0019,
     TPM_ALG_ECDAA            = 0x001A,
     TPM_ALG_SM2              = 0x001B,
     TPM_ALG_ECSCHNORR        = 0x001C,
     TPM_ALG_ECMQV            = 0x001D,
     TPM_ALG_KDF1_SP800_56a   = 0x0020,
     TPM_ALG_KDF2             = 0x0021,
     TPM_ALG_KDF1_SP800_108   = 0x0022,
     TPM_ALG_ECC              = 0x0023,
     TPM_ALG_SYMCIPHER        = 0x0025,
     TPM_ALG_CTR              = 0x0040,
     TPM_ALG_OFB              = 0x0041,
     TPM_ALG_CBC              = 0x0042,
     TPM_ALG_CFB              = 0x0043,
     TPM_ALG_ECB              = 0x0044,
     TPM_ALG_LAST             = 0x0044
};

// Table 8 - TPM_ECC_CURVE Constants
using  TPM_ECC_CURVE = UINT16;
#define TPM_ECC_NONE       (TPM_ECC_CURVE)(0x0000)
#define TPM_ECC_NIST_P192  (TPM_ECC_CURVE)(0x0001)
#define TPM_ECC_NIST_P224  (TPM_ECC_CURVE)(0x0002)
#define TPM_ECC_NIST_P256  (TPM_ECC_CURVE)(0x0003)
#define TPM_ECC_NIST_P384  (TPM_ECC_CURVE)(0x0004)
#define TPM_ECC_NIST_P521  (TPM_ECC_CURVE)(0x0005)
#define TPM_ECC_BN_P256    (TPM_ECC_CURVE)(0x0010)
#define TPM_ECC_BN_P638    (TPM_ECC_CURVE)(0x0011)
#define TPM_ECC_SM2_P256   (TPM_ECC_CURVE)(0x0020)

//--- TPM_CC is converted to enum rather than typedef and #defines ---//
// Table 11 - TPM_CC Constants (Numeric Order)
enum TPM_CC : UINT32 {
     TPM_CC_FIRST                       = 0x0000011F,
     TPM_CC_PP_FIRST                    = 0x0000011F,
     TPM_CC_NV_UndefineSpaceSpecial     = 0x0000011F,
     TPM_CC_EvictControl                = 0x00000120,
     TPM_CC_HierarchyControl            = 0x00000121,
     TPM_CC_NV_UndefineSpace            = 0x00000122,
     TPM_CC_ChangeEPS                   = 0x00000124,
     TPM_CC_ChangePPS                   = 0x00000125,
     TPM_CC_Clear                       = 0x00000126,
     TPM_CC_ClearControl                = 0x00000127,
     TPM_CC_ClockSet                    = 0x00000128,
     TPM_CC_HierarchyChangeAuth         = 0x00000129,
     TPM_CC_NV_DefineSpace              = 0x0000012A,
     TPM_CC_PCR_Allocate                = 0x0000012B,
     TPM_CC_PCR_SetAuthPolicy           = 0x0000012C,
     TPM_CC_PP_Commands                 = 0x0000012D,
     TPM_CC_SetPrimaryPolicy            = 0x0000012E,
     TPM_CC_FieldUpgradeStart           = 0x0000012F,
     TPM_CC_ClockRateAdjust             = 0x00000130,
     TPM_CC_CreatePrimary               = 0x00000131,
     TPM_CC_NV_GlobalWriteLock          = 0x00000132,
     TPM_CC_PP_LAST                     = 0x00000132,
     TPM_CC_GetCommandAuditDigest       = 0x00000133,
     TPM_CC_NV_Increment                = 0x00000134,
     TPM_CC_NV_SetBits                  = 0x00000135,
     TPM_CC_NV_Extend                   = 0x00000136,
     TPM_CC_NV_Write                    = 0x00000137,
     TPM_CC_NV_WriteLock                = 0x00000138,
     TPM_CC_DictionaryAttackLockReset   = 0x00000139,
     TPM_CC_DictionaryAttackParameters  = 0x0000013A,
     TPM_CC_NV_ChangeAuth               = 0x0000013B,
     TPM_CC_PCR_Event                   = 0x0000013C,
     TPM_CC_PCR_Reset                   = 0x0000013D,
     TPM_CC_SequenceComplete            = 0x0000013E,
     TPM_CC_SetAlgorithmSet             = 0x0000013F,
     TPM_CC_SetCommandCodeAuditStatus   = 0x00000140,
     TPM_CC_FieldUpgradeData            = 0x00000141,
     TPM_CC_IncrementalSelfTest         = 0x00000142,
     TPM_CC_SelfTest                    = 0x00000143,
     TPM_CC_Startup                     = 0x00000144,
     TPM_CC_Shutdown                    = 0x00000145,
     TPM_CC_StirRandom                  = 0x00000146,
     TPM_CC_ActivateCredential          = 0x00000147,
     TPM_CC_Certify                     = 0x00000148,
     TPM_CC_PolicyNV                    = 0x00000149,
     TPM_CC_CertifyCreation             = 0x0000014A,
     TPM_CC_Duplicate                   = 0x0000014B,
     TPM_CC_GetTime                     = 0x0000014C,
     TPM_CC_GetSessionAuditDigest       = 0x0000014D,
     TPM_CC_NV_Read                     = 0x0000014E,
     TPM_CC_NV_ReadLock                 = 0x0000014F,
     TPM_CC_ObjectChangeAuth            = 0x00000150,
     TPM_CC_PolicySecret                = 0x00000151,
     TPM_CC_Rewrap                      = 0x00000152,
     TPM_CC_Create                      = 0x00000153,
     TPM_CC_ECDH_ZGen                   = 0x00000154,
     TPM_CC_HMAC                        = 0x00000155,
     TPM_CC_Import                      = 0x00000156,
     TPM_CC_Load                        = 0x00000157,
     TPM_CC_Quote                       = 0x00000158,
     TPM_CC_RSA_Decrypt                 = 0x00000159,
     TPM_CC_HMAC_Start                  = 0x0000015B,
     TPM_CC_SequenceUpdate              = 0x0000015C,
     TPM_CC_Sign                        = 0x0000015D,
     TPM_CC_Unseal                      = 0x0000015E,
     TPM_CC_PolicySigned                = 0x00000160,
     TPM_CC_ContextLoad                 = 0x00000161,
     TPM_CC_ContextSave                 = 0x00000162,
     TPM_CC_ECDH_KeyGen                 = 0x00000163,
     TPM_CC_EncryptDecrypt              = 0x00000164,
     TPM_CC_FlushContext                = 0x00000165,
     TPM_CC_LoadExternal                = 0x00000167,
     TPM_CC_MakeCredential              = 0x00000168,
     TPM_CC_NV_ReadPublic               = 0x00000169,
     TPM_CC_PolicyAuthorize             = 0x0000016A,
     TPM_CC_PolicyAuthValue             = 0x0000016B,
     TPM_CC_PolicyCommandCode           = 0x0000016C,
     TPM_CC_PolicyCounterTimer          = 0x0000016D,
     TPM_CC_PolicyCpHash                = 0x0000016E,
     TPM_CC_PolicyLocality              = 0x0000016F,
     TPM_CC_PolicyNameHash              = 0x00000170,
     TPM_CC_PolicyOR                    = 0x00000171,
     TPM_CC_PolicyTicket                = 0x00000172,
     TPM_CC_ReadPublic                  = 0x00000173,
     TPM_CC_RSA_Encrypt                 = 0x00000174,
     TPM_CC_StartAuthSession            = 0x00000176,
     TPM_CC_VerifySignature             = 0x00000177,
     TPM_CC_ECC_Parameters              = 0x00000178,
     TPM_CC_FirmwareRead                = 0x00000179,
     TPM_CC_GetCapability               = 0x0000017A,
     TPM_CC_GetRandom                   = 0x0000017B,
     TPM_CC_GetTestResult               = 0x0000017C,
     TPM_CC_Hash                        = 0x0000017D,
     TPM_CC_PCR_Read                    = 0x0000017E,
     TPM_CC_PolicyPCR                   = 0x0000017F,
     TPM_CC_PolicyRestart               = 0x00000180,
     TPM_CC_ReadClock                   = 0x00000181,
     TPM_CC_PCR_Extend                  = 0x00000182,
     TPM_CC_PCR_SetAuthValue            = 0x00000183,
     TPM_CC_NV_Certify                  = 0x00000184,
     TPM_CC_EventSequenceComplete       = 0x00000185,
     TPM_CC_HashSequenceStart           = 0x00000186,
     TPM_CC_PolicyPhysicalPresence      = 0x00000187,
     TPM_CC_PolicyDuplicationSelect     = 0x00000188,
     TPM_CC_PolicyGetDigest             = 0x00000189,
     TPM_CC_TestParms                   = 0x0000018A,
     TPM_CC_Commit                      = 0x0000018B,
     TPM_CC_PolicyPassword              = 0x0000018C,
     TPM_CC_ZGen_2Phase                 = 0x0000018D,
     TPM_CC_EC_Ephemeral                = 0x0000018E,
     TPM_CC_LAST                        = 0x0000018E
};

//--- TPM_RC is converted to enum rather than typedef and #defines ---//
// Table 15 - TPM_RC Constants (Actions)
enum TPM_RC : UINT32 {
     TPM_RC_SUCCESS            = 0x000,
     TPM_RC_BAD_TAG            = 0x030,
     RC_VER1                   = 0x100,
     TPM_RC_INITIALIZE         = RC_VER1 + 0x000,
     TPM_RC_FAILURE            = RC_VER1 + 0x001,
     TPM_RC_SEQUENCE           = RC_VER1 + 0x003,
     TPM_RC_PRIVATE            = RC_VER1 + 0x00B,
     TPM_RC_HMAC               = RC_VER1 + 0x019,
     TPM_RC_DISABLED           = RC_VER1 + 0x020,
     TPM_RC_EXCLUSIVE          = RC_VER1 + 0x021,
     TPM_RC_AUTH_TYPE          = RC_VER1 + 0x024,
     TPM_RC_AUTH_MISSING       = RC_VER1 + 0x025,
     TPM_RC_POLICY             = RC_VER1 + 0x026,
     TPM_RC_PCR                = RC_VER1 + 0x027,
     TPM_RC_PCR_CHANGED        = RC_VER1 + 0x028,
     TPM_RC_UPGRADE            = RC_VER1 + 0x02D,
     TPM_RC_TOO_MANY_CONTEXTS  = RC_VER1 + 0x02E,
     TPM_RC_AUTH_UNAVAILABLE   = RC_VER1 + 0x02F,
     TPM_RC_REBOOT             = RC_VER1 + 0x030,
     TPM_RC_UNBALANCED         = RC_VER1 + 0x031,
     TPM_RC_COMMAND_SIZE       = RC_VER1 + 0x042,
     TPM_RC_COMMAND_CODE       = RC_VER1 + 0x043,
     TPM_RC_AUTHSIZE           = RC_VER1 + 0x044,
     TPM_RC_AUTH_CONTEXT       = RC_VER1 + 0x045,
     TPM_RC_NV_RANGE           = RC_VER1 + 0x046,
     TPM_RC_NV_SIZE            = RC_VER1 + 0x047,
     TPM_RC_NV_LOCKED          = RC_VER1 + 0x048,
     TPM_RC_NV_AUTHORIZATION   = RC_VER1 + 0x049,
     TPM_RC_NV_UNINITIALIZED   = RC_VER1 + 0x04A,
     TPM_RC_NV_SPACE           = RC_VER1 + 0x04B,
     TPM_RC_NV_DEFINED         = RC_VER1 + 0x04C,
     TPM_RC_BAD_CONTEXT        = RC_VER1 + 0x050,
     TPM_RC_CPHASH             = RC_VER1 + 0x051,
     TPM_RC_PARENT             = RC_VER1 + 0x052,
     TPM_RC_NEEDS_TEST         = RC_VER1 + 0x053,
     TPM_RC_NO_RESULT          = RC_VER1 + 0x054,
     TPM_RC_SENSITIVE          = RC_VER1 + 0x055,
     RC_MAX_FM0                = RC_VER1 + 0x07F,
     RC_FMT1                   = 0x080,
     TPM_RC_ASYMMETRIC         = RC_FMT1 + 0x001,
     TPM_RC_ATTRIBUTES         = RC_FMT1 + 0x002,
     TPM_RC_HASH               = RC_FMT1 + 0x003,
     TPM_RC_VALUE              = RC_FMT1 + 0x004,
     TPM_RC_HIERARCHY          = RC_FMT1 + 0x005,
     TPM_RC_KEY_SIZE           = RC_FMT1 + 0x007,
     TPM_RC_MGF                = RC_FMT1 + 0x008,
     TPM_RC_MODE               = RC_FMT1 + 0x009,
     TPM_RC_TYPE               = RC_FMT1 + 0x00A,
     TPM_RC_HANDLE             = RC_FMT1 + 0x00B,
     TPM_RC_KDF                = RC_FMT1 + 0x00C,
     TPM_RC_RANGE              = RC_FMT1 + 0x00D,
     TPM_RC_AUTH_FAIL          = RC_FMT1 + 0x00E,
     TPM_RC_NONCE              = RC_FMT1 + 0x00F,
     TPM_RC_PP                 = RC_FMT1 + 0x010,
     TPM_RC_SCHEME             = RC_FMT1 + 0x012,
     TPM_RC_SIZE               = RC_FMT1 + 0x015,
     TPM_RC_SYMMETRIC          = RC_FMT1 + 0x016,
     TPM_RC_TAG                = RC_FMT1 + 0x017,
     TPM_RC_SELECTOR           = RC_FMT1 + 0x018,
     TPM_RC_INSUFFICIENT       = RC_FMT1 + 0x01A,
     TPM_RC_SIGNATURE          = RC_FMT1 + 0x01B,
     TPM_RC_KEY                = RC_FMT1 + 0x01C,
     TPM_RC_POLICY_FAIL        = RC_FMT1 + 0x01D,
     TPM_RC_INTEGRITY          = RC_FMT1 + 0x01F,
     TPM_RC_TICKET             = RC_FMT1 + 0x020,
     TPM_RC_RESERVED_BITS      = RC_FMT1 + 0x021,
     TPM_RC_BAD_AUTH           = RC_FMT1 + 0x022,
     TPM_RC_EXPIRED            = RC_FMT1 + 0x023,
     TPM_RC_POLICY_CC          = RC_FMT1 + 0x024 ,
     TPM_RC_BINDING            = RC_FMT1 + 0x025,
     TPM_RC_CURVE              = RC_FMT1 + 0x026,
     TPM_RC_ECC_POINT          = RC_FMT1 + 0x027,
     RC_WARN                   = 0x900,
     TPM_RC_CONTEXT_GAP        = RC_WARN + 0x001,
     TPM_RC_OBJECT_MEMORY      = RC_WARN + 0x002,
     TPM_RC_SESSION_MEMORY     = RC_WARN + 0x003,
     TPM_RC_MEMORY             = RC_WARN + 0x004,
     TPM_RC_SESSION_HANDLES    = RC_WARN + 0x005,
     TPM_RC_OBJECT_HANDLES     = RC_WARN + 0x006,
     TPM_RC_LOCALITY           = RC_WARN + 0x007,
     TPM_RC_YIELDED            = RC_WARN + 0x008,
     TPM_RC_CANCELED           = RC_WARN + 0x009,
     TPM_RC_TESTING            = RC_WARN + 0x00A,
     TPM_RC_REFERENCE_H0       = RC_WARN + 0x010,
     TPM_RC_REFERENCE_H1       = RC_WARN + 0x011,
     TPM_RC_REFERENCE_H2       = RC_WARN + 0x012,
     TPM_RC_REFERENCE_H3       = RC_WARN + 0x013,
     TPM_RC_REFERENCE_H4       = RC_WARN + 0x014,
     TPM_RC_REFERENCE_H5       = RC_WARN + 0x015,
     TPM_RC_REFERENCE_H6       = RC_WARN + 0x016,
     TPM_RC_REFERENCE_S0       = RC_WARN + 0x018,
     TPM_RC_REFERENCE_S1       = RC_WARN + 0x019,
     TPM_RC_REFERENCE_S2       = RC_WARN + 0x01A,
     TPM_RC_REFERENCE_S3       = RC_WARN + 0x01B,
     TPM_RC_REFERENCE_S4       = RC_WARN + 0x01C,
     TPM_RC_REFERENCE_S5       = RC_WARN + 0x01D,
     TPM_RC_REFERENCE_S6       = RC_WARN + 0x01E,
     TPM_RC_NV_RATE            = RC_WARN + 0x020,
     TPM_RC_LOCKOUT            = RC_WARN + 0x021,
     TPM_RC_RETRY              = RC_WARN + 0x022,
     TPM_RC_NV_UNAVAILABLE     = RC_WARN + 0x023,
     TPM_RC_NOT_USED           = RC_WARN + 0x7F,
     TPM_RC_H                  = 0x000,
     TPM_RC_P                  = 0x040,
     TPM_RC_S                  = 0x800,
     TPM_RC_1                  = 0x100,
     TPM_RC_2                  = 0x200,
     TPM_RC_3                  = 0x300,
     TPM_RC_4                  = 0x400,
     TPM_RC_5                  = 0x500,
     TPM_RC_6                  = 0x600,
     TPM_RC_7                  = 0x700,
     TPM_RC_8                  = 0x800,
     TPM_RC_9                  = 0x900,
     TPM_RC_A                  = 0xA00,
     TPM_RC_B                  = 0xB00,
     TPM_RC_C                  = 0xC00,
     TPM_RC_D                  = 0xD00,
     TPM_RC_E                  = 0xE00,
     TPM_RC_F                  = 0xF00,
     TPM_RC_N_MASK             = 0xF00
};
// Table 16 - TPM_CLOCK_ADJUST Constants
using  TPM_CLOCK_ADJUST = INT8;
#define TPM_CLOCK_COARSE_SLOWER  (TPM_CLOCK_ADJUST)(-3)
#define TPM_CLOCK_MEDIUM_SLOWER  (TPM_CLOCK_ADJUST)(-2)
#define TPM_CLOCK_FINE_SLOWER    (TPM_CLOCK_ADJUST)(-1)
#define TPM_CLOCK_NO_CHANGE      (TPM_CLOCK_ADJUST)(0)
#define TPM_CLOCK_FINE_FASTER    (TPM_CLOCK_ADJUST)(1)
#define TPM_CLOCK_MEDIUM_FASTER  (TPM_CLOCK_ADJUST)(2)
#define TPM_CLOCK_COARSE_FASTER  (TPM_CLOCK_ADJUST)(3)

// Table 17 - TPM_EO Constants
using  TPM_EO = UINT16;
#define TPM_EO_EQ           (TPM_EO)(0x0000)
#define TPM_EO_NEQ          (TPM_EO)(0x0001)
#define TPM_EO_SIGNED_GT    (TPM_EO)(0x0002)
#define TPM_EO_UNSIGNED_GT  (TPM_EO)(0x0003)
#define TPM_EO_SIGNED_LT    (TPM_EO)(0x0004)
#define TPM_EO_UNSIGNED_LT  (TPM_EO)(0x0005)
#define TPM_EO_SIGNED_GE    (TPM_EO)(0x0006)
#define TPM_EO_UNSIGNED_GE  (TPM_EO)(0x0007)
#define TPM_EO_SIGNED_LE    (TPM_EO)(0x0008)
#define TPM_EO_UNSIGNED_LE  (TPM_EO)(0x0009)
#define TPM_EO_BITSET       (TPM_EO)(0x000A)
#define TPM_EO_BITCLEAR     (TPM_EO)(0x000B)

//--- TPM_ST is converted to enum rather than typedef and #defines ---//
// Table 18 - TPM_ST Constants
enum TPM_ST : UINT16 {
    TPM_ST_RSP_COMMAND           = 0x00C4,
    TPM_ST_NULL                  = 0X8000,
    TPM_ST_NO_SESSIONS           = 0x8001,
    TPM_ST_SESSIONS              = 0x8002,
    TPM_ST_ATTEST_NV             = 0x8014,
    TPM_ST_ATTEST_COMMAND_AUDIT  = 0x8015,
    TPM_ST_ATTEST_SESSION_AUDIT  = 0x8016,
    TPM_ST_ATTEST_CERTIFY        = 0x8017,
    TPM_ST_ATTEST_QUOTE          = 0x8018,
    TPM_ST_ATTEST_TIME           = 0x8019,
    TPM_ST_ATTEST_CREATION       = 0x801A,
    TPM_ST_CREATION              = 0x8021,
    TPM_ST_VERIFIED              = 0x8022,
    TPM_ST_AUTH_SECRET           = 0x8023,
    TPM_ST_HASHCHECK             = 0x8024,
    TPM_ST_AUTH_SIGNED           = 0x8025,
    TPM_ST_FU_MANIFEST           = 0x8029
} ;

// Table 19 - TPM_SU Constants
using  TPM_SU = UINT16;
#define TPM_SU_CLEAR  (TPM_SU)(0x0000)
#define TPM_SU_STATE  (TPM_SU)(0x0001)

// Table 20 - TPM_SE Constants
//--- TPM_SE is converted to enum rather than typedef and #defines ---//
// Table 20 - TPM_SE Constants
enum  TPM_SE : UINT8{
    TPM_SE_HMAC = 0x0,
    TPM_SE_POLICY = 0x1,
    TPM_SE_TRIAL = 0x03
    };

// Table 21 - TPM_CAP Constants
using  TPM_CAP = UINT32;
#define TPM_CAP_FIRST            (TPM_CAP)(0x00000000)
#define TPM_CAP_ALGS             (TPM_CAP)(0x00000000)
#define TPM_CAP_HANDLES          (TPM_CAP)(0x00000001)
#define TPM_CAP_COMMANDS         (TPM_CAP)(0x00000002)
#define TPM_CAP_PP_COMMANDS      (TPM_CAP)(0x00000003)
#define TPM_CAP_AUDIT_COMMANDS   (TPM_CAP)(0x00000004)
#define TPM_CAP_PCRS             (TPM_CAP)(0x00000005)
#define TPM_CAP_TPM_PROPERTIES   (TPM_CAP)(0x00000006)
#define TPM_CAP_PCR_PROPERTIES   (TPM_CAP)(0x00000007)
#define TPM_CAP_ECC_CURVES       (TPM_CAP)(0x00000008)
#define TPM_CAP_LAST             (TPM_CAP)(0x00000008)
#define TPM_CAP_VENDOR_PROPERTY  (TPM_CAP)(0x00000100)

// Table 22 - TPM_PT Constants
using  TPM_PT = UINT32;
#define TPM_PT_NONE                 (TPM_PT)(0x00000000)
#define PT_GROUP                    (TPM_PT)(0x00000100)
#define PT_FIXED                    (TPM_PT)(PT_GROUP * 1)
#define TPM_PT_FAMILY_INDICATOR     (TPM_PT)(PT_FIXED + 0)
#define TPM_PT_LEVEL                (TPM_PT)(PT_FIXED + 1)
#define TPM_PT_REVISION             (TPM_PT)(PT_FIXED + 2)
#define TPM_PT_DAY_OF_YEAR          (TPM_PT)(PT_FIXED + 3)
#define TPM_PT_YEAR                 (TPM_PT)(PT_FIXED + 4)
#define TPM_PT_MANUFACTURER         (TPM_PT)(PT_FIXED + 5)
#define TPM_PT_VENDOR_STRING_1      (TPM_PT)(PT_FIXED + 6)
#define TPM_PT_VENDOR_STRING_2      (TPM_PT)(PT_FIXED + 7)
#define TPM_PT_VENDOR_STRING_3      (TPM_PT)(PT_FIXED + 8)
#define TPM_PT_VENDOR_STRING_4      (TPM_PT)(PT_FIXED + 9)
#define TPM_PT_VENDOR_TPM_TYPE      (TPM_PT)(PT_FIXED + 10)
#define TPM_PT_FIRMWARE_VERSION_1   (TPM_PT)(PT_FIXED + 11)
#define TPM_PT_FIRMWARE_VERSION_2   (TPM_PT)(PT_FIXED + 12)
#define TPM_PT_INPUT_BUFFER         (TPM_PT)(PT_FIXED + 13)
#define TPM_PT_HR_TRANSIENT_MIN     (TPM_PT)(PT_FIXED + 14)
#define TPM_PT_HR_PERSISTENT_MIN    (TPM_PT)(PT_FIXED + 15)
#define TPM_PT_HR_LOADED_MIN        (TPM_PT)(PT_FIXED + 16)
#define TPM_PT_ACTIVE_SESSIONS_MAX  (TPM_PT)(PT_FIXED + 17)
#define TPM_PT_PCR_COUNT            (TPM_PT)(PT_FIXED + 18)
#define TPM_PT_PCR_SELECT_MIN       (TPM_PT)(PT_FIXED + 19)
#define TPM_PT_CONTEXT_GAP_MAX      (TPM_PT)(PT_FIXED + 20)
#define TPM_PT_NV_COUNTERS_MAX      (TPM_PT)(PT_FIXED + 22)
#define TPM_PT_NV_INDEX_MAX         (TPM_PT)(PT_FIXED + 23)
#define TPM_PT_MEMORY               (TPM_PT)(PT_FIXED + 24)
#define TPM_PT_CLOCK_UPDATE         (TPM_PT)(PT_FIXED + 25)
#define TPM_PT_CONTEXT_HASH         (TPM_PT)(PT_FIXED + 26)
#define TPM_PT_CONTEXT_SYM          (TPM_PT)(PT_FIXED + 27)
#define TPM_PT_CONTEXT_SYM_SIZE     (TPM_PT)(PT_FIXED + 28)
#define TPM_PT_ORDERLY_COUNT        (TPM_PT)(PT_FIXED + 29)
#define TPM_PT_MAX_COMMAND_SIZE     (TPM_PT)(PT_FIXED + 30)
#define TPM_PT_MAX_RESPONSE_SIZE    (TPM_PT)(PT_FIXED + 31)
#define TPM_PT_MAX_DIGEST           (TPM_PT)(PT_FIXED + 32)
#define TPM_PT_MAX_OBJECT_CONTEXT   (TPM_PT)(PT_FIXED + 33)
#define TPM_PT_MAX_SESSION_CONTEXT  (TPM_PT)(PT_FIXED + 34)
#define TPM_PT_PS_FAMILY_INDICATOR  (TPM_PT)(PT_FIXED + 35)
#define TPM_PT_PS_LEVEL             (TPM_PT)(PT_FIXED + 36)
#define TPM_PT_PS_REVISION          (TPM_PT)(PT_FIXED + 37)
#define TPM_PT_PS_DAY_OF_YEAR       (TPM_PT)(PT_FIXED + 38)
#define TPM_PT_PS_YEAR              (TPM_PT)(PT_FIXED + 39)
#define TPM_PT_SPLIT_MAX            (TPM_PT)(PT_FIXED + 40)
#define TPM_PT_TOTAL_COMMANDS       (TPM_PT)(PT_FIXED + 41)
#define TPM_PT_LIBRARY_COMMANDS     (TPM_PT)(PT_FIXED + 42)
#define TPM_PT_VENDOR_COMMANDS      (TPM_PT)(PT_FIXED + 43)
#define PT_VAR                      (TPM_PT)(PT_GROUP * 2)
#define TPM_PT_PERMANENT            (TPM_PT)(PT_VAR + 0)
#define TPM_PT_STARTUP_CLEAR        (TPM_PT)(PT_VAR + 1)
#define TPM_PT_HR_NV_INDEX          (TPM_PT)(PT_VAR + 2)
#define TPM_PT_HR_LOADED            (TPM_PT)(PT_VAR + 3)
#define TPM_PT_HR_LOADED_AVAIL      (TPM_PT)(PT_VAR + 4)
#define TPM_PT_HR_ACTIVE            (TPM_PT)(PT_VAR + 5)
#define TPM_PT_HR_ACTIVE_AVAIL      (TPM_PT)(PT_VAR + 6)
#define TPM_PT_HR_TRANSIENT_AVAIL   (TPM_PT)(PT_VAR + 7)
#define TPM_PT_HR_PERSISTENT        (TPM_PT)(PT_VAR + 8)
#define TPM_PT_HR_PERSISTENT_AVAIL  (TPM_PT)(PT_VAR + 9)
#define TPM_PT_NV_COUNTERS          (TPM_PT)(PT_VAR + 10)
#define TPM_PT_NV_COUNTERS_AVAIL    (TPM_PT)(PT_VAR + 11)
#define TPM_PT_ALGORITHM_SET        (TPM_PT)(PT_VAR + 12)
#define TPM_PT_LOADED_CURVES        (TPM_PT)(PT_VAR + 13)
#define TPM_PT_LOCKOUT_COUNTER      (TPM_PT)(PT_VAR + 14)
#define TPM_PT_MAX_AUTH_FAIL        (TPM_PT)(PT_VAR + 15)
#define TPM_PT_LOCKOUT_INTERVAL     (TPM_PT)(PT_VAR + 16)
#define TPM_PT_LOCKOUT_RECOVERY     (TPM_PT)(PT_VAR + 17)
#define TPM_PT_NV_WRITE_RECOVERY    (TPM_PT)(PT_VAR + 18)
#define TPM_PT_AUDIT_COUNTER_0      (TPM_PT)(PT_VAR + 19)
#define TPM_PT_AUDIT_COUNTER_1      (TPM_PT)(PT_VAR + 20)

// Table 23 - TPM_PT_PCR Constants
using  TPM_PT_PCR = UINT32;
#define TPM_PT_PCR_FIRST         (TPM_PT_PCR)(0x00000000)
#define TPM_PT_PCR_SAVE          (TPM_PT_PCR)(0x00000000)
#define TPM_PT_PCR_EXTEND_L0     (TPM_PT_PCR)(0x00000001)
#define TPM_PT_PCR_RESET_L0      (TPM_PT_PCR)(0x00000002)
#define TPM_PT_PCR_EXTEND_L1     (TPM_PT_PCR)(0x00000003)
#define TPM_PT_PCR_RESET_L1      (TPM_PT_PCR)(0x00000004)
#define TPM_PT_PCR_EXTEND_L2     (TPM_PT_PCR)(0x00000005)
#define TPM_PT_PCR_RESET_L2      (TPM_PT_PCR)(0x00000006)
#define TPM_PT_PCR_EXTEND_L3     (TPM_PT_PCR)(0x00000007)
#define TPM_PT_PCR_RESET_L3      (TPM_PT_PCR)(0x00000008)
#define TPM_PT_PCR_EXTEND_L4     (TPM_PT_PCR)(0x00000009)
#define TPM_PT_PCR_RESET_L4      (TPM_PT_PCR)(0x0000000A)
#define TPM_PT_PCR_NO_INCREMENT  (TPM_PT_PCR)(0x00000011)
#define TPM_PT_PCR_DRTM_RESET    (TPM_PT_PCR)(0x00000012)
#define TPM_PT_PCR_POLICY        (TPM_PT_PCR)(0x00000013)
#define TPM_PT_PCR_AUTH          (TPM_PT_PCR)(0x00000014)
#define TPM_PT_PCR_LAST          (TPM_PT_PCR)(0x00000014)

// Table 24 - TPM_PS Constants
using  TPM_PS = UINT32;
#define TPM_PS_MAIN            (TPM_PS)(0x00000000)
#define TPM_PS_PC              (TPM_PS)(0x00000001)
#define TPM_PS_PDA             (TPM_PS)(0x00000002)
#define TPM_PS_CELL_PHONE      (TPM_PS)(0x00000003)
#define TPM_PS_SERVER          (TPM_PS)(0x00000004)
#define TPM_PS_PERIPHERAL      (TPM_PS)(0x00000005)
#define TPM_PS_TSS             (TPM_PS)(0x00000006)
#define TPM_PS_STORAGE         (TPM_PS)(0x00000007)
#define TPM_PS_AUTHENTICATION  (TPM_PS)(0x00000008)
#define TPM_PS_EMBEDDED        (TPM_PS)(0x00000009)
#define TPM_PS_HARDCOPY        (TPM_PS)(0x0000000A)
#define TPM_PS_INFRASTRUCTURE  (TPM_PS)(0x0000000B)
#define TPM_PS_VIRTUALIZATION  (TPM_PS)(0x0000000C)
#define TPM_PS_TNC             (TPM_PS)(0x0000000D)
#define TPM_PS_MULTI_TENANT    (TPM_PS)(0x0000000E)
#define TPM_PS_TC              (TPM_PS)(0x0000000F)

// 7 Handles

// Table 25 - Handles Types
//
// NOTE: Comment because it has same name as TPM1.2 (value is same, so not runtime issue)
//
// using     TPM_HANDLE = UINT32;

// Table 26 - TPM_HT Constants
using  TPM_HT = UINT8;
#define TPM_HT_PCR             (TPM_HT)(0x00)
#define TPM_HT_NV_INDEX        (TPM_HT)(0x01)
#define TPM_HT_HMAC_SESSION    (TPM_HT)(0x02)
#define TPM_HT_LOADED_SESSION  (TPM_HT)(0x02)
#define TPM_HT_POLICY_SESSION  (TPM_HT)(0x03)
#define TPM_HT_ACTIVE_SESSION  (TPM_HT)(0x03)
#define TPM_HT_PERMANENT       (TPM_HT)(0x40)
#define TPM_HT_TRANSIENT       (TPM_HT)(0x80)
#define TPM_HT_PERSISTENT      (TPM_HT)(0x81)

// Table 27 - TPM_RH Constants
using  TPM_RH = UINT32;
#define TPM_RH_FIRST        (TPM_RH)(0x40000000)
#define TPM_RH_SRK          (TPM_RH)(0x40000000)
#define TPM_RH_OWNER        (TPM_RH)(0x40000001)
#define TPM_RH_REVOKE       (TPM_RH)(0x40000002)
#define TPM_RH_TRANSPORT    (TPM_RH)(0x40000003)
#define TPM_RH_OPERATOR     (TPM_RH)(0x40000004)
#define TPM_RH_ADMIN        (TPM_RH)(0x40000005)
#define TPM_RH_EK           (TPM_RH)(0x40000006)
#define TPM_RH_NULL         (TPM_RH)(0x40000007)
#define TPM_RH_UNASSIGNED   (TPM_RH)(0x40000008)
#define TPM_RS_PW           (TPM_RH)(0x40000009)
#define TPM_RH_LOCKOUT      (TPM_RH)(0x4000000A)
#define TPM_RH_ENDORSEMENT  (TPM_RH)(0x4000000B)
#define TPM_RH_PLATFORM     (TPM_RH)(0x4000000C)
#define TPM_RH_PLATFORM_NV  (TPM_RH)(0x4000000D)
#define TPM_RH_AUTH_00      (TPM_RH)(0x40000010)
#define TPM_RH_AUTH_FF      (TPM_RH)(0x4000010F)
#define TPM_RH_LAST         (TPM_RH)(0x4000010F)

// Table 28 - TPM_HC Constants
using  TPM_HC = TPM_HANDLE;
#define HR_HANDLE_MASK        (TPM_HC)(0x00FFFFFF)
#define HR_RANGE_MASK         (TPM_HC)(0xFF000000)
#define HR_SHIFT              (TPM_HC)(24)
#define HR_PCR                (TPM_HC)((TPM_HC)TPM_HT_PCR << HR_SHIFT)
#define HR_HMAC_SESSION       (TPM_HC)((TPM_HC)TPM_HT_HMAC_SESSION << HR_SHIFT)
#define HR_POLICY_SESSION     (TPM_HC)((TPM_HC)TPM_HT_POLICY_SESSION << HR_SHIFT)
#define HR_TRANSIENT          (TPM_HC)((TPM_HC)TPM_HT_TRANSIENT << HR_SHIFT)
#define HR_PERSISTENT         (TPM_HC)((TPM_HC)TPM_HT_PERSISTENT << HR_SHIFT)
#define HR_NV_INDEX           (TPM_HC)((TPM_HC)TPM_HT_NV_INDEX << HR_SHIFT)
#define HR_PERMANENT          (TPM_HC)((TPM_HC)TPM_HT_PERMANENT << HR_SHIFT)
#define PCR_FIRST             (TPM_HC)(HR_PCR + 0)
#define PCR_LAST              (TPM_HC)(PCR_FIRST + IMPLEMENTATION_PCR - 1)
#define HMAC_SESSION_FIRST    (TPM_HC)(HR_HMAC_SESSION + 0)
#define HMAC_SESSION_LAST     (TPM_HC)(HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)
#define LOADED_SESSION_FIRST  (TPM_HC)(HMAC_SESSION_FIRST)
#define LOADED_SESSION_LAST   (TPM_HC)(HMAC_SESSION_LAST)
#define POLICY_SESSION_FIRST  (TPM_HC)(HR_POLICY_SESSION + 0)
#define POLICY_SESSION_LAST   (TPM_HC)(POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1)
#define TRANSIENT_FIRST       (TPM_HC)(HR_TRANSIENT + 0)
#define ACTIVE_SESSION_FIRST  (TPM_HC)(POLICY_SESSION_FIRST)
#define ACTIVE_SESSION_LAST   (TPM_HC)(POLICY_SESSION_LAST)
#define TRANSIENT_LAST        (TPM_HC)(TRANSIENT_FIRST+MAX_LOADED_OBJECTS - 1)
#define PERSISTENT_FIRST      (TPM_HC)(HR_PERSISTENT + 0)
#define PERSISTENT_LAST       (TPM_HC)(PERSISTENT_FIRST + 0x00FFFFFF)
#define PLATFORM_PERSISTENT   (TPM_HC)(PERSISTENT_FIRST + 0x00800000)
#define NV_INDEX_FIRST        (TPM_HC)(HR_NV_INDEX + 0)
#define NV_INDEX_LAST         (TPM_HC)(NV_INDEX_FIRST + 0x00FFFFFF)
#define PERMANENT_FIRST       (TPM_HC)(TPM_RH_FIRST)
#define PERMANENT_LAST        (TPM_HC)(TPM_RH_LAST)

// 8 Attribute Structures

// Table 29 - TPMA_ALGORITHM Bits
bitfield  TPMA_ALGORITHM{  
      asymmetric    : 1;
      symmetric     : 1;
      hash          : 1;
      object        : 1;
      reserved4_7   : 4;
      signing       : 1;
      encrypting    : 1;
      method        : 1;
      reserved11_31 : 21;
} ;

// Table 30 - TPMA_OBJECT Bits
bitfield  TPMA_OBJECT{  
      padding            : 1;
      fixedTPM             : 1;
      stClear              : 1;
      padding            : 1;
      fixedParent          : 1;
      sensitiveDataOrigin  : 1;
      userWithAuth         : 1;
      adminWithPolicy      : 1;
      padding          : 2;
      noDA                 : 1;
      encryptedDuplication : 1;
      padding        : 4;
      restricted           : 1;
      decrypt              : 1;
      sign                 : 1;
      padding        : 13;
} [[bitfield_order(std::core::BitfieldOrder::LeastToMostSignificant, 32)]];

// Table 31 - TPMA_SESSION Bits
bitfield  TPMA_SESSION{  
      continueSession : 1;
      auditExclusive  : 1;
      auditReset      : 1;
      reserved3_4     : 2;
      decrypt         : 1;
      encrypt         : 1;
      audit           : 1;
} ;

// Table 32 - TPMA_LOCALITY Bits
//
// NOTE: Use low case here to resolve conflict
//
bitfield  TPMA_LOCALITY{
      locZero  : 1;
      locOne   : 1;
      locTwo   : 1;
      locThree : 1;
      locFour  : 1;
      Extended : 3;
} ;

// Table 33 - TPMA_PERMANENT Bits
bitfield  TPMA_PERMANENT{  
      ownerAuthSet       : 1;
      endorsementAuthSet : 1;
      lockoutAuthSet     : 1;
      reserved3_7        : 5;
      disableClear       : 1;
      inLockout          : 1;
      tpmGeneratedEPS    : 1;
      reserved11_31      : 21;
} ;

// Table 34 - TPMA_STARTUP_CLEAR Bits
bitfield  TPMA_STARTUP_CLEAR{  
      phEnable     : 1;
      shEnable     : 1;
      ehEnable     : 1;
      reserved3_30 : 28;
      orderly      : 1;
} ;

// Table 35 - TPMA_MEMORY Bits
bitfield  TPMA_MEMORY{  
      sharedRAM         : 1;
      sharedNV          : 1;
      objectCopiedToRam : 1;
      reserved3_31      : 29;
} ;

// Table 36 - TPMA_CC Bits
bitfield TPMA_CC {  
      commandIndex  : 16;
      reserved16_21 : 6;
      nv            : 1;
      extensive     : 1;
      flushed       : 1;
      cHandles      : 3;
      rHandle       : 1;
      V             : 1;
      Res           : 2;
} ;

// 9 Interface Types

// Table 37 - TPMI_YES_NO Type
using  TPMI_YES_NO = BYTE;

// Table 38 - TPMI_DH_OBJECT Type
using  TPMI_DH_OBJECT = TPM_HANDLE;

// Table 39 - TPMI_DH_PERSISTENT Type
using  TPMI_DH_PERSISTENT = TPM_HANDLE;

// Table 40 - TPMI_DH_ENTITY Type
using  TPMI_DH_ENTITY = TPM_HANDLE;

// Table 41 - TPMI_DH_PCR Type
using  TPMI_DH_PCR = TPM_HANDLE;

// Table 42 - TPMI_SH_AUTH_SESSION Type
using  TPMI_SH_AUTH_SESSION = TPM_HANDLE;

// Table 43 - TPMI_SH_HMAC Type
using  TPMI_SH_HMAC = TPM_HANDLE;

// Table 44 - TPMI_SH_POLICY Type
using  TPMI_SH_POLICY = TPM_HANDLE;

// Table 45 - TPMI_DH_CONTEXT Type
using  TPMI_DH_CONTEXT = TPM_HANDLE;

// Table 46 - TPMI_RH_HIERARCHY Type
using  TPMI_RH_HIERARCHY = TPM_HANDLE;

// Table 47 - TPMI_RH_HIERARCHY_AUTH Type
using  TPMI_RH_HIERARCHY_AUTH = TPM_HANDLE;

// Table 48 - TPMI_RH_PLATFORM Type
using  TPMI_RH_PLATFORM = TPM_HANDLE;

// Table 49 - TPMI_RH_OWNER Type
using  TPMI_RH_OWNER = TPM_HANDLE;

// Table 50 - TPMI_RH_ENDORSEMENT Type
using  TPMI_RH_ENDORSEMENT = TPM_HANDLE;

// Table 51 - TPMI_RH_PROVISION Type
using  TPMI_RH_PROVISION = TPM_HANDLE;

// Table 52 - TPMI_RH_CLEAR Type
using  TPMI_RH_CLEAR = TPM_HANDLE;

// Table 53 - TPMI_RH_NV_AUTH Type
using  TPMI_RH_NV_AUTH = TPM_HANDLE;

// Table 54 - TPMI_RH_LOCKOUT Type
using  TPMI_RH_LOCKOUT = TPM_HANDLE;

// Table 55 - TPMI_RH_NV_INDEX Type
using  TPMI_RH_NV_INDEX = TPM_HANDLE;

// Table 56 - TPMI_ALG_HASH Type
using  TPMI_ALG_HASH = TPM_ALG_ID;

// Table 57 - TPMI_ALG_ASYM Type
using  TPMI_ALG_ASYM = TPM_ALG_ID;

// Table 58 - TPMI_ALG_SYM Type
using  TPMI_ALG_SYM = TPM_ALG_ID;

// Table 59 - TPMI_ALG_SYM_OBJECT Type
using  TPMI_ALG_SYM_OBJECT = TPM_ALG_ID;

// Table 60 - TPMI_ALG_SYM_MODE Type
using  TPMI_ALG_SYM_MODE = TPM_ALG_ID;

// Table 61 - TPMI_ALG_KDF Type
using  TPMI_ALG_KDF = TPM_ALG_ID;

// Table 62 - TPMI_ALG_SIG_SCHEME Type
using  TPMI_ALG_SIG_SCHEME = TPM_ALG_ID;

// Table 63 - TPMI_ECC_KEY_EXCHANGE Type
using  TPMI_ECC_KEY_EXCHANGE = TPM_ALG_ID;

// Table 64 - TPMI_ST_COMMAND_TAG Type
using  TPMI_ST_COMMAND_TAG = TPM_ST;

// 10 Structure Definitions

// Table 65 - TPMS_ALGORITHM_DESCRIPTION Structure
struct  TPMS_ALGORITHM_DESCRIPTION{  
  TPM_ALG_ID        alg;
  TPMA_ALGORITHM    attributes;
} ;

//--- Add selector into TPMU_HA union ---//
// Table 66 - TPMU_HA Union
union  TPMU_HA{ 
    if (parent.hashAlg == TPM_ALG_SHA1){
        BYTE    sha1[SHA1_DIGEST_SIZE];
    }else if (parent.hashAlg == TPM_ALG_SHA256){
        BYTE    sha256[SHA256_DIGEST_SIZE];
    }else if (parent.hashAlg == TPM_ALG_SM3_256){
  BYTE    sm3_256[SM3_256_DIGEST_SIZE];
    }else if (parent.hashAlg == TPM_ALG_SHA384){
  BYTE    sha384[SHA384_DIGEST_SIZE];
    }else if (parent.hashAlg == TPM_ALG_SHA512){
  BYTE    sha512[SHA512_DIGEST_SIZE];
  }
} ;

//--- Define digest as TPMU_HA ---//
// Table 67 - TPMT_HA Structure
struct  TPMT_HA{  
  TPMI_ALG_HASH    hashAlg;
  TPMU_HA          digest;
} ;

//--- Calculate buffer size with size field rather than sizeof (TPMU_HA) ---//
// Table 68 - TPM2B_DIGEST Structure
struct  TPM2B_DIGEST{  
  UINT16    size;
  BYTE      buffer[size] [[format_read("ArraySize")]];
} ;

//--- Calculate buffer size with size field rather than sizeof (TPMT_HA) ---//
// Table 69 - TPM2B_DATA Structure
struct  TPM2B_DATA{ 
  UINT16    size;
  BYTE      buffer[size];
} ;

// Table 70 - TPM2B_NONCE Types
using  TPM2B_NONCE = TPM2B_DIGEST;

// Table 71 - TPM2B_AUTH Types
using  TPM2B_AUTH = TPM2B_DIGEST;

// Table 72 - TPM2B_OPERAND Types
using  TPM2B_OPERAND = TPM2B_DIGEST;

// Table 73 - TPM2B_EVENT Structure
struct  TPM2B_EVENT{  
  UINT16    size;
  BYTE      buffer[1024];
} ;

// Table 74 - TPM2B_MAX_BUFFER Structure
struct  TPM2B_MAX_BUFFER{  
  UINT16    size;
  BYTE      buffer[MAX_DIGEST_BUFFER];
} ;

// Table 75 - TPM2B_MAX_NV_BUFFER Structure
struct  TPM2B_MAX_NV_BUFFER{  
  UINT16    size;
  BYTE      buffer[MAX_NV_INDEX_SIZE];
} ;

//--- Calculate buffer size with size field rather than sizeof (UINT64) ---//
// Table 76 - TPM2B_TIMEOUT Structure
struct TPM2B_TIMEOUT {  
  UINT16    size;
  BYTE      buffer[size];
} ;

//--- Calculate buffer size with size field rather than MAX_SYM_BLOCK_SIZE ---//
// Table 77 -- TPM2B_IV Structure <I/O>
struct  TPM2B_IV{  
  UINT16    size;
  BYTE      buffer[size];
} ;

// Table 78 - TPMU_NAME Union
union  TPMU_NAME{  
  TPMT_HA       digest;
  TPM_HANDLE    handle;
} ;

//--- Replace buffer with TPMU_NAME structure ---//
// Table 79 - TPM2B_NAME Structure
struct TPM2B_NAME {  
  UINT16    size;
  TPMU_NAME      name;
} ;

//--- Calculate pcrSelect size with sizeofSelect field rather than PCR_SELECT_MAX ---//
// Table 80 - TPMS_PCR_SELECT Structure
struct  TPMS_PCR_SELECT{  
  UINT8    sizeofSelect;
  BYTE     pcrSelect[sizeofSelect];
} ;

//--- Calculate pcrSelect size with sizeofSelect field rather than PCR_SELECT_MAX ---//
// Table 81 - TPMS_PCR_SELECTION Structure
struct TPMS_PCR_SELECTION {  
  TPMI_ALG_HASH    hash;
  UINT8            sizeofSelect;
  BYTE             pcrSelect[sizeofSelect];
} ;

// Table 84 - TPMT_TK_CREATION Structure
struct TPMT_TK_CREATION {  
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} ;

// Table 85 - TPMT_TK_VERIFIED Structure
struct TPMT_TK_VERIFIED {  
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} ;

// Table 86 - TPMT_TK_AUTH Structure
struct TPMT_TK_AUTH {  
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} ;

// Table 87 - TPMT_TK_HASHCHECK Structure
struct TPMT_TK_HASHCHECK {  
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} ;

// Table 88 - TPMS_ALG_PROPERTY Structure
struct TPMS_ALG_PROPERTY {  
  TPM_ALG_ID        alg;
  TPMA_ALGORITHM    algProperties;
} ;

// Table 89 - TPMS_TAGGED_PROPERTY Structure
struct  TPMS_TAGGED_PROPERTY{  
  TPM_PT    property;
  UINT32    value;
} ;

//--- Calculate pcrSelect size with sizeofSelect field rather than PCR_SELECT_MAX ---//
// Table 90 - TPMS_TAGGED_PCR_SELECT Structure
struct TPMS_TAGGED_PCR_SELECT {  
  TPM_PT    tag;
  UINT8     sizeofSelect;
  BYTE      pcrSelect[sizeofSelect];
} ;

//--- Calculate commandCodes size with count field rather than MAX_CAP_CC ---//
// Table 91 - TPML_CC Structure
struct TPML_CC {  
  UINT32    count;
  TPM_CC    commandCodes[count];
} ;

//--- Calculate commandAttributes size with count field rather than MAX_CAP_CC ---//
// Table 92 - TPML_CCA Structure
struct TPML_CCA {  
  UINT32     count;
  TPMA_CC    commandAttributes[count];
} ;

//--- Calculate algorithms size with count field rather than MAX_ALG_LIST_SIZE ---//
// Table 93 - TPML_ALG Structure
struct TPML_ALG {  
  UINT32        count;
  TPM_ALG_ID    algorithms[count];
} ;

//--- Calculate handle size with count field rather than MAX_CAP_HANDLES ---//
// Table 94 - TPML_HANDLE Structure
struct TPML_HANDLE {  
  UINT32        count;
  TPM_HANDLE    handle[count];
} ;

//--- Calculate digests size with count field rather than 8 ---//
// Table 95 - TPML_DIGEST Structure
struct TPML_DIGEST {  
  UINT32          count;
  TPM2B_DIGEST    digests[count];
} ;

//--- Calculate digests size with count field rather than HASH_COUNT ---//
// Table 96 -- TPML_DIGEST_VALUES Structure <I/O>
struct TPML_DIGEST_VALUES {  
  UINT32     count;
  TPMT_HA    digests[count];
} ;

//--- Replace buffer with TPML_DIGEST_VALUES structure ---//
// Table 97 - TPM2B_DIGEST_VALUES Structure
struct TPM2B_DIGEST_VALUES {  
  UINT16    size;
  TPML_DIGEST_VALUES      buffer;
} ;

//--- Calculate pcrSelections size with count field rather than HASH_COUNT ---//
// Table 98 - TPML_PCR_SELECTION Structure
struct  TPML_PCR_SELECTION{  
  UINT32                count;
  TPMS_PCR_SELECTION    pcrSelections[count];
} ;

//--- Calculate algProperties size with count field rather than MAX_CAP_ALGS ---//
// Table 99 - TPML_ALG_PROPERTY Structure
struct TPML_ALG_PROPERTY {  
  UINT32               count;
  TPMS_ALG_PROPERTY    algProperties[count];
} ;

//--- Calculate tpmProperty size with count field rather than MAX_TPM_PROPERTIES ---//
// Table 100 - TPML_TAGGED_TPM_PROPERTY Structure
struct TPML_TAGGED_TPM_PROPERTY {  
  UINT32                  count;
  TPMS_TAGGED_PROPERTY    tpmProperty[count];
} ;

//--- Calculate pcrProperty size with count field rather than MAX_PCR_PROPERTIES ---//
// Table 101 - TPML_TAGGED_PCR_PROPERTY Structure
struct  TPML_TAGGED_PCR_PROPERTY{  
  UINT32                    count;
  TPMS_TAGGED_PCR_SELECT    pcrProperty[count];
} ;

//--- Calculate eccCurves size with count field rather than MAX_ECC_CURVES ---//
// Table 102 - TPML_ECC_CURVE Structure
struct TPML_ECC_CURVE {  
  UINT32           count;
  TPM_ECC_CURVE    eccCurves[count];
} ;

// Table 103 - TPMU_CAPABILITIES Union
union TPMU_CAPABILITIES { 
  TPML_ALG_PROPERTY           algorithms;
  TPML_HANDLE                 handles;
  TPML_CCA                    command;
  TPML_CC                     ppCommands;
  TPML_CC                     auditCommands;
  TPML_PCR_SELECTION          assignedPCR;
  TPML_TAGGED_TPM_PROPERTY    tpmProperties;
  TPML_TAGGED_PCR_PROPERTY    pcrProperties;
  TPML_ECC_CURVE              eccCurves;
} ;

// Table 104 - TPMS_CAPABILITY_DATA Structure
struct TPMS_CAPABILITY_DATA {  
  TPM_CAP              capability;
  TPMU_CAPABILITIES    data;
} ;

// Table 105 - TPMS_CLOCK_INFO Structure
struct TPMS_CLOCK_INFO {  
  UINT64         clock;
  UINT32         resetCount;
  UINT32         restartCount;
  TPMI_YES_NO    safe;
} ;

// Table 106 - TPMS_TIME_INFO Structure
struct TPMS_TIME_INFO {  
  UINT64             time;
  TPMS_CLOCK_INFO    clockInfo;
} ;

// Table 107 - TPMS_TIME_ATTEST_INFO Structure
struct  TPMS_TIME_ATTEST_INFO{  
  TPMS_TIME_INFO    time;
  UINT64            firmwareVersion;
} ;

// Table 108 - TPMS_CERTIFY_INFO Structure
struct  TPMS_CERTIFY_INFO{  
  TPM2B_NAME    name;
  TPM2B_NAME    qualifiedName;
} ;

// Table 109 - TPMS_QUOTE_INFO Structure
struct  TPMS_QUOTE_INFO{  
  TPML_PCR_SELECTION    pcrSelect;
  TPM2B_DIGEST          pcrDigest;
} ;

// Table 110 - TPMS_COMMAND_AUDIT_INFO Structure
struct TPMS_COMMAND_AUDIT_INFO {  
  UINT64          auditCounter;
  TPM_ALG_ID      digestAlg;
  TPM2B_DIGEST    auditDigest;
  TPM2B_DIGEST    commandDigest;
} ;

// Table 111 - TPMS_SESSION_AUDIT_INFO Structure
struct TPMS_SESSION_AUDIT_INFO {  
  TPMI_YES_NO     exclusiveSession;
  TPM2B_DIGEST    sessionDigest;
} ;

// Table 112 - TPMS_CREATION_INFO Structure
struct TPMS_CREATION_INFO {  
  TPM2B_NAME      objectName;
  TPM2B_DIGEST    creationHash;
} ;

// Table 113 - TPMS_NV_CERTIFY_INFO Structure
struct TPMS_NV_CERTIFY_INFO {  
  TPM2B_NAME             indexName;
  UINT16                 offset;
  TPM2B_MAX_NV_BUFFER    nvContents;
} ;

// Table 114 - TPMI_ST_ATTEST Type
using  TPMI_ST_ATTEST = TPM_ST;

// Table 115 - TPMU_ATTEST Union
union TPMU_ATTEST {  
  TPMS_CERTIFY_INFO          certify;
  TPMS_CREATION_INFO         creation;
  TPMS_QUOTE_INFO            quote;
  TPMS_COMMAND_AUDIT_INFO    commandAudit;
  TPMS_SESSION_AUDIT_INFO    sessionAudit;
  TPMS_TIME_ATTEST_INFO      time;
  TPMS_NV_CERTIFY_INFO       nv;
} ;

// Table 116 - TPMS_ATTEST Structure
struct TPMS_ATTEST {  
  TPM_GENERATED      magic;
  TPMI_ST_ATTEST     type;
  TPM2B_NAME         qualifiedSigner;
  TPM2B_DATA         extraData;
  TPMS_CLOCK_INFO    clockInfo;
  UINT64             firmwareVersion;
  TPMU_ATTEST        attested;
} ;

//--- Replace buffer with TPMS_ATTEST structure ---//
// Table 117 - TPM2B_ATTEST Structure
struct TPM2B_ATTEST {  
  UINT16    size;
  TPMS_ATTEST      attestationData;
} ;

// Table 118 - TPMS_AUTH_COMMAND Structure
struct  TPMS_AUTH_COMMAND{  
  TPMI_SH_AUTH_SESSION    sessionHandle;
  TPM2B_NONCE             nonce;
  TPMA_SESSION            sessionAttributes;
  TPM2B_AUTH              hmac;
} ;

// Table 119 - TPMS_AUTH_RESPONSE Structure
struct  TPMS_AUTH_RESPONSE{  
  TPM2B_NONCE     nonce;
  TPMA_SESSION    sessionAttributes;
  TPM2B_AUTH      hmac;
} ;

// 11 Algorithm Parameters and Structures

// Table 120 - TPMI_AES_KEY_BITS Type
using  TPMI_AES_KEY_BITS = TPM_KEY_BITS;

// Table 121 - TPMI_SM4_KEY_BITS Type
using  TPMI_SM4_KEY_BITS = TPM_KEY_BITS;

// Table 122 - TPMU_SYM_KEY_BITS Union
union  TPMU_SYM_KEY_BITS{  
  TPMI_AES_KEY_BITS    aes;
  TPMI_SM4_KEY_BITS    SM4;
  TPM_KEY_BITS         sym;
  TPMI_ALG_HASH     xor;
} ;

// Table 123 - TPMU_SYM_MODE Union
union  TPMU_SYM_MODE{  
  TPMI_ALG_SYM_MODE    aes;
  TPMI_ALG_SYM_MODE    SM4;
  TPMI_ALG_SYM_MODE    sym;
} ;

// Table 125 - TPMT_SYM_DEF Structure
struct TPMT_SYM_DEF {  
  TPMI_ALG_SYM         algorithm;
  TPMU_SYM_KEY_BITS    keyBits;
  TPMU_SYM_MODE        mode;
} ;

// Table 126 - TPMT_SYM_DEF_OBJECT Structure
struct  TPMT_SYM_DEF_OBJECT{  
  TPMI_ALG_SYM_OBJECT    algorithm;
  TPMU_SYM_KEY_BITS      keyBits;
  TPMU_SYM_MODE          mode;
} ;

//--- Calculate buffer size with size field rather than MAX_SYM_KEY_BYTES ---//
// Table 127 - TPM2B_SYM_KEY Structure
struct  TPM2B_SYM_KEY{  
  UINT16    size;
  BYTE      buffer[size];
} ;

// Table 128 - TPMS_SYMCIPHER_PARMS Structure
struct  TPMS_SYMCIPHER_PARMS{  
  TPMT_SYM_DEF_OBJECT    sym;
} ;

//--- Calculate buffer size with size field rather than MAX_SYM_DATA ---//
// Table 129 - TPM2B_SENSITIVE_DATA Structure
struct  TPM2B_SENSITIVE_DATA{  
  UINT16    size;
  //--- Wraps for TPMU_SENSITIVE_CREATE ---//
  BYTE      buffer[size];
} ;

// Table 130 - TPMS_SENSITIVE_CREATE Structure
struct TPMS_SENSITIVE_CREATE {  
  TPM2B_AUTH              userAuth;
  TPM2B_SENSITIVE_DATA    data;
} ;

// Table 131 - TPM2B_SENSITIVE_CREATE Structure
struct TPM2B_SENSITIVE_CREATE {  
  UINT16                   size;
  TPMS_SENSITIVE_CREATE    sensitive;
} ;

// Table 132 - TPMS_SCHEME_SIGHASH Structure
struct TPMS_SCHEME_SIGHASH { 
  TPMI_ALG_HASH    hashAlg;
} ;

// Table 133 - TPMI_ALG_KEYEDHASH_SCHEME Type
using  TPMI_ALG_KEYEDHASH_SCHEME = TPM_ALG_ID;

// Table 134 - HMAC_SIG_SCHEME Types
using  TPMS_SCHEME_HMAC = TPMS_SCHEME_SIGHASH;

// Table 135 - TPMS_SCHEME_XOR Structure
struct TPMS_SCHEME_XOR {  
  TPMI_ALG_HASH    hashAlg;
  TPMI_ALG_KDF     kdf;
} ;

//--- Add selector for TPMU_SCHEME_KEYEDHASH union ---//
// Table 136 - TPMU_SCHEME_KEYEDHASH Union
 union TPMU_SCHEME_KEYEDHASH{
     if (parent.scheme == TPM_ALGORITHM_ID::TPM_ALG_HMAC){
        TPMS_SCHEME_HMAC    hmac;
     }else if (parent.scheme == TPM_ALGORITHM_ID::TPM_ALG_XOR){
        TPMS_SCHEME_XOR  xor;
    }
 } ;

// Table 137 - TPMT_KEYEDHASH_SCHEME Structure
//--- Use scheme as selector for TPMU_SCHEME_KEYEDHASH union ---//
struct TPMT_KEYEDHASH_SCHEME { 
  TPMI_ALG_KEYEDHASH_SCHEME    scheme;
  if (scheme == TPM_ALGORITHM_ID::TPM_ALG_HMAC || scheme == TPM_ALGORITHM_ID::TPM_ALG_XOR){
    TPMU_SCHEME_KEYEDHASH        details;
  }
} [[inline]];

// Table 138 - RSA_SIG_SCHEMES Types
using  TPMS_SCHEME_RSASSA = TPMS_SCHEME_SIGHASH;
using  TPMS_SCHEME_RSAPSS = TPMS_SCHEME_SIGHASH;

// Table 139 - ECC_SIG_SCHEMES Types
using  TPMS_SCHEME_ECDSA = TPMS_SCHEME_SIGHASH;
using  TPMS_SCHEME_SM2 = TPMS_SCHEME_SIGHASH;
using  TPMS_SCHEME_ECSCHNORR = TPMS_SCHEME_SIGHASH;

// Table 140 - TPMS_SCHEME_ECDAA Structure
struct  TPMS_SCHEME_ECDAA{ 
  TPMI_ALG_HASH    hashAlg;
  UINT16           count;
} ;

// Table 141 - TPMU_SIG_SCHEME Union
union  TPMU_SIG_SCHEME{  
  TPMS_SCHEME_RSASSA       rsassa;
  TPMS_SCHEME_RSAPSS       rsapss;
  TPMS_SCHEME_ECDSA        ecdsa;
  TPMS_SCHEME_ECDAA        ecdaa;
  TPMS_SCHEME_ECSCHNORR    ecSchnorr;
  TPMS_SCHEME_HMAC         hmac;
  TPMS_SCHEME_SIGHASH      anyScheme; //--- Rename to 'anyScheme' from 'any' as any is reserved in ImHex---//
} ;

// Table 142 - TPMT_SIG_SCHEME Structure
struct TPMT_SIG_SCHEME { 
  TPMI_ALG_SIG_SCHEME    scheme;
  TPMU_SIG_SCHEME        details;
} ;

// Table 143 - TPMS_SCHEME_OAEP Structure
struct TPMS_SCHEME_OAEP {  
  TPMI_ALG_HASH    hashAlg;
} ;

// Table 144 - TPMS_SCHEME_ECDH Structure
struct TPMS_SCHEME_ECDH {  
  TPMI_ALG_HASH    hashAlg;
} ;

// Table 145 - TPMS_SCHEME_MGF1 Structure
struct TPMS_SCHEME_MGF1 {  
  TPMI_ALG_HASH    hashAlg;
} ;

// Table 146 - TPMS_SCHEME_KDF1_SP800_56a Structure
struct  TPMS_SCHEME_KDF1_SP800_56a{  
  TPMI_ALG_HASH    hashAlg;
} ;

// Table 147 - TPMS_SCHEME_KDF2 Structure
struct TPMS_SCHEME_KDF2 {  
  TPMI_ALG_HASH    hashAlg;
} ;

// Table 148 - TPMS_SCHEME_KDF1_SP800_108 Structure
struct  TPMS_SCHEME_KDF1_SP800_108{  
  TPMI_ALG_HASH    hashAlg;
} ;

// Table 149 - TPMU_KDF_SCHEME Union
union TPMU_KDF_SCHEME {  
  TPMS_SCHEME_MGF1              mgf1;
  TPMS_SCHEME_KDF1_SP800_56a    kdf1_SP800_56a;
  TPMS_SCHEME_KDF2              kdf2;
  TPMS_SCHEME_KDF1_SP800_108    kdf1_sp800_108;
} ;

// Table 150 - TPMT_KDF_SCHEME Structure
struct TPMT_KDF_SCHEME {  
  TPMI_ALG_KDF       scheme;
  TPMU_KDF_SCHEME    details;
} ;

// Table 151 - TPMI_ALG_ASYM_SCHEME Type
using  TPMI_ALG_ASYM_SCHEME = TPM_ALG_ID;

// Table 152 - TPMU_ASYM_SCHEME Union
union TPMU_ASYM_SCHEME {  
  TPMS_SCHEME_RSASSA       rsassa;
  TPMS_SCHEME_RSAPSS       rsapss;
  TPMS_SCHEME_OAEP         oaep;
  TPMS_SCHEME_ECDSA        ecdsa;
  TPMS_SCHEME_ECDAA        ecdaa;
  TPMS_SCHEME_ECSCHNORR    ecSchnorr;
  TPMS_SCHEME_SIGHASH      anySig;
} ;

// Table 153 - TPMT_ASYM_SCHEME Structure
struct TPMT_ASYM_SCHEME {  
  TPMI_ALG_ASYM_SCHEME    scheme;
  TPMU_ASYM_SCHEME        details;
} ;

// Table 154 - TPMI_ALG_RSA_SCHEME Type
using  TPMI_ALG_RSA_SCHEME = TPM_ALG_ID;

// Table 155 - TPMT_RSA_SCHEME Structure
struct TPMT_RSA_SCHEME { 
  TPMI_ALG_RSA_SCHEME    scheme;
  TPMU_ASYM_SCHEME       details;
} ;

// Table 156 - TPMI_ALG_RSA_DECRYPT Type
using  TPMI_ALG_RSA_DECRYPT = TPM_ALG_ID;

// Table 157 - TPMT_RSA_DECRYPT Structure
struct TPMT_RSA_DECRYPT {  
  TPMI_ALG_RSA_DECRYPT    scheme;
  TPMU_ASYM_SCHEME        details;
} ;

//--- Calculate buffer size with size field rather than MAX_RSA_KEY_BYTES ---//
// Table 158 - TPM2B_PUBLIC_KEY_RSA Structure
struct TPM2B_PUBLIC_KEY_RSA {  
  UINT16    size;
  BYTE      buffer[size];
} ;

// Table 159 - TPMI_RSA_KEY_BITS Type
using  TPMI_RSA_KEY_BITS = TPM_KEY_BITS;

//--- Calculate buffer size with size field rather than MAX_RSA_KEY_BYTES/2 ---//
// Table 160 - TPM2B_PRIVATE_KEY_RSA Structure
struct TPM2B_PRIVATE_KEY_RSA {  
  UINT16    size;
  BYTE      buffer[size];
} ;

//--- Calculate buffer size with size field rather than MAX_ECC_KEY_BYTES ---//
// Table 161 - TPM2B_ECC_PARAMETER Structure
struct TPM2B_ECC_PARAMETER {  
  UINT16    size;
  BYTE      buffer[size];
} ;

// Table 162 - TPMS_ECC_POINT Structure
struct TPMS_ECC_POINT {  
  TPM2B_ECC_PARAMETER    x;
  TPM2B_ECC_PARAMETER    y;
} ;

// Table 163 -- TPM2B_ECC_POINT Structure <I/O>
struct  TPM2B_ECC_POINT{  
  UINT16            size;
  TPMS_ECC_POINT    point;
} ;

// Table 164 - TPMI_ALG_ECC_SCHEME Type
using  TPMI_ALG_ECC_SCHEME = TPM_ALG_ID;

// Table 165 - TPMI_ECC_CURVE Type
using  TPMI_ECC_CURVE = TPM_ECC_CURVE;

// Table 166 - TPMT_ECC_SCHEME Structure
struct TPMT_ECC_SCHEME {  
  TPMI_ALG_ECC_SCHEME    scheme;
  TPMU_SIG_SCHEME        details;
} ;

// Table 167 - TPMS_ALGORITHM_DETAIL_ECC Structure
struct  TPMS_ALGORITHM_DETAIL_ECC{  
  TPM_ECC_CURVE          curveID;
  UINT16                 keySize;
  TPMT_KDF_SCHEME        kdf;
  TPMT_ECC_SCHEME        sign;
  TPM2B_ECC_PARAMETER    p;
  TPM2B_ECC_PARAMETER    a;
  TPM2B_ECC_PARAMETER    b;
  TPM2B_ECC_PARAMETER    gX;
  TPM2B_ECC_PARAMETER    gY;
  TPM2B_ECC_PARAMETER    n;
  TPM2B_ECC_PARAMETER    h;
} ;

// Table 168 - TPMS_SIGNATURE_RSASSA Structure
struct TPMS_SIGNATURE_RSASSA {  
  TPMI_ALG_HASH           hash;
  TPM2B_PUBLIC_KEY_RSA    sig;
} ;

// Table 169 - TPMS_SIGNATURE_RSAPSS Structure
struct TPMS_SIGNATURE_RSAPSS {  
  TPMI_ALG_HASH           hash;
  TPM2B_PUBLIC_KEY_RSA    sig;
} ;

// Table 170 - TPMS_SIGNATURE_ECDSA Structure
struct TPMS_SIGNATURE_ECDSA {  
  TPMI_ALG_HASH          hash;
  TPM2B_ECC_PARAMETER    signatureR;
  TPM2B_ECC_PARAMETER    signatureS;
} ;

// Table 171 - TPMU_SIGNATURE Union
union TPMU_SIGNATURE { 
  TPMS_SIGNATURE_RSASSA    rsassa;
  TPMS_SIGNATURE_RSAPSS    rsapss;
  TPMS_SIGNATURE_ECDSA     ecdsa;
  TPMS_SIGNATURE_ECDSA     sm2;
  TPMS_SIGNATURE_ECDSA     ecdaa;
  TPMS_SIGNATURE_ECDSA     ecschnorr;
  TPMT_HA                  hmac;
  TPMS_SCHEME_SIGHASH      anySig; //--- Rename to 'anySig' from 'any' as any is reserved in ImHex---//
} ;

// Table 172 - TPMT_SIGNATURE Structure
struct TPMT_SIGNATURE {  
  TPMI_ALG_SIG_SCHEME    sigAlg;
  TPMU_SIGNATURE         signature;
} ;

//--- Retype ecc as TPMS_ECC_POINT, add selector ---//
// Table 173 - TPMU_ENCRYPTED_SECRET Union
union TPMU_ENCRYPTED_SECRET {  
  TPMS_ECC_POINT    ecc;
  BYTE    rsa[MAX_RSA_KEY_BYTES];
  TPM2B_DIGEST    symmetric;
  TPM2B_DIGEST    keyedHash;
} ;

//--- Calculate secret size with size field rather than sizeof (TPMU_ENCRYPTED_SECRET) ---//
// Table 174 - TPM2B_ENCRYPTED_SECRET Structure
struct TPM2B_ENCRYPTED_SECRET {  
  UINT16    size;
  BYTE      secret[size];
} ;

// 12 Key/Object Complex

// Table 175 - TPMI_ALG_PUBLIC Type
using  TPMI_ALG_PUBLIC = TPM_ALG_ID;

//--- Changed to struct from union ---//
//--- Add selector for TPMU_PUBLIC_ID union ---//
// Table 176 - TPMU_PUBLIC_ID Union
 struct TPMU_PUBLIC_ID{
   if (parent.type == TPM_ALG_ID::TPM_ALG_KEYEDHASH){
        TPM2B_DIGEST            keyedHash;
   }else if (parent.type == TPM_ALG_ID::TPM_ALG_SYMCIPHER){
        TPM2B_DIGEST            sym;
   }else if (parent.type == TPM_ALG_ID::TPM_ALG_RSA){
        TPM2B_PUBLIC_KEY_RSA    rsa;
   }else if (parent.type == TPM_ALG_ID::TPM_ALG_ECC){
   TPMS_ECC_POINT          ecc;
   }
 } ;

// Table 177 - TPMS_KEYEDHASH_PARMS Structure
struct  TPMS_KEYEDHASH_PARMS{  
  TPMT_KEYEDHASH_SCHEME    scheme;
} ;

// Table 178 - TPMS_ASYM_PARMS Structure
struct TPMS_ASYM_PARMS {  
  TPMT_SYM_DEF_OBJECT    symmetric;
  TPMT_ASYM_SCHEME       scheme;
} ;

// Table 179 - TPMS_RSA_PARMS Structure
struct TPMS_RSA_PARMS {  
  TPMT_SYM_DEF_OBJECT    symmetric;
  TPMT_RSA_SCHEME        scheme;
  TPMI_RSA_KEY_BITS      keyBits;
  UINT32                 exponent;
} ;

// Table 180 - TPMS_ECC_PARMS Structure
struct TPMS_ECC_PARMS {  
  TPMT_SYM_DEF_OBJECT    symmetric;
  TPMT_ECC_SCHEME        scheme;
  TPMI_ECC_CURVE         curveID;
  TPMT_KDF_SCHEME        kdf;
} ;

//--- Changed from union to struct ---//
//--- Add selector for TPMU_PUBLIC_PARMS union ---//
// Table 181 - TPMU_PUBLIC_PARMS Union
  struct TPMU_PUBLIC_PARMS{
   if (parent.type == TPM_ALG_ID::TPM_ALG_KEYEDHASH){
       TPMS_KEYEDHASH_PARMS    keyedHashDetail;
   }else if (parent.type == TPM_ALG_ID::TPM_ALG_SYMCIPHER){
       TPMT_SYM_DEF_OBJECT     symDetail;
   }else if (parent.type == TPM_ALG_ID::TPM_ALG_RSA){
       TPMS_RSA_PARMS          rsaDetail;
   }else if (parent.type == TPM_ALG_ID::TPM_ALG_ECC){
       TPMS_ECC_PARMS          eccDetail;
   }else{
   TPMS_ASYM_PARMS         asymDetail;
   }
 } ;
// Table 182 - TPMT_PUBLIC_PARMS Structure
struct TPMT_PUBLIC_PARMS {  
  TPMI_ALG_PUBLIC      type;
  TPMU_PUBLIC_PARMS    parameters;
} ;


// Table 183 - TPMT_PUBLIC Structure
struct TPMT_PUBLIC {  
  TPMI_ALG_PUBLIC      type;
  TPMI_ALG_HASH        nameAlg;
  TPMA_OBJECT          objectAttributes;
  TPM2B_DIGEST      authPolicy [[format_read("readDigest")]];
  TPMU_PUBLIC_PARMS    parameters;
  TPMU_PUBLIC_ID       unique;
} ;

// Table 184 - TPM2B_PUBLIC Structure
struct TPM2B_PUBLIC {  
  UINT16         size;
  TPMT_PUBLIC    publicArea;
} ;

// Table 185 - TPM2B_PRIVATE_VENDOR_SPECIFIC Structure
struct TPM2B_PRIVATE_VENDOR_SPECIFIC {  
  UINT16    size;
  BYTE      buffer[PRIVATE_VENDOR_SPECIFIC_BYTES];
} ;

//--- Add selector for TPMU_SENSITIVE_COMPOSITE union ---//
// Table 186 - TPMU_SENSITIVE_COMPOSITE Union
union TPMU_SENSITIVE_COMPOSITE{
  if (parent.sensitiveType == TPM_ALG_RSA){
    TPM2B_PRIVATE_KEY_RSA            rsa;
  }else if (parent.sensitiveType == TPM_ALG_ECC){
    TPM2B_ECC_PARAMETER              ecc;
  }else if (parent.sensitiveType == TPM_ALG_KEYEDHASH){
    TPM2B_SENSITIVE_DATA             bits;
  }else if (parent.sensitiveType == TPM_ALG_SYMCIPHER){
    TPM2B_SYM_KEY                    sym;
  }else{
    TPM2B_PRIVATE_VENDOR_SPECIFIC    anyAlg; //--- Rename 'anyAlg' from 'any' as any is reserved for ImHex ---//
  }
} ;

// Table 187 - TPMT_SENSITIVE Structure
struct  TPMT_SENSITIVE{  
  TPMI_ALG_PUBLIC             sensitiveType;
  TPM2B_AUTH                  authValue;
  TPM2B_DIGEST                seedValue;
  TPMU_SENSITIVE_COMPOSITE    sensitive;
} ;

// Table 188 - TPM2B_SENSITIVE Structure
struct  TPM2B_SENSITIVE{  
  UINT16            size;
  TPMT_SENSITIVE    sensitiveArea;
} ;

//--- Add size input to _PRIVATE to calculate size of sensitive/encryptedSensitive ---//
//--- Replacing the direct instantitation of sensitive/encryptedSensitive a TPMT_SENSITIVE structure ---//
// Table 189 - _PRIVATE Structure
struct _PRIVATE{
  TPM2B_DIGEST      integrityOuter;
  TPM2B_DIGEST      integrityInner;
  /*encryptedSensitive is an encrypted TPM2B_SENSITIVE structure*/
  u8 encryptedSensitive [parent.size-integrityOuter.size-integrityInner.size-4];
} ;

//--- Retype buffer as _PRIVATE strucuture---//
// Table 190 - TPM2B_PRIVATE Structure
struct  TPM2B_PRIVATE{  
  UINT16    size;
  _PRIVATE      buffer;
} ;

// Table 191 - _ID_OBJECT Structure
struct  _ID_OBJECT{ 
  TPM2B_DIGEST    integrityHMAC;
  TPM2B_DIGEST    encIdentity;
} ;

//--- Retype credential as _ID_OBJECT strucuture ---//
// Table 192 - TPM2B_ID_OBJECT Structure
struct TPM2B_ID_OBJECT { 
  UINT16    size;
  _ID_OBJECT      credential;
} ;

// 13 NV Storage Structures

// Table 193 - TPM_NV_INDEX Bits
//
// NOTE: Comment here to resolve conflict
//
// struct TPM_NV_INDEX { 
//  UINT32 index : 22;
//  UINT32 space : 2;
//  UINT32 RH_NV : 8;
// } ;

// Table 195 - TPMA_NV Bits
bitfield  TPMA_NV{  
      TPMA_NV_PPWRITE        : 1;
      TPMA_NV_OWNERWRITE     : 1;
      TPMA_NV_AUTHWRITE      : 1;
      TPMA_NV_POLICYWRITE    : 1;
      TPMA_NV_COUNTER        : 1;
      TPMA_NV_BITS           : 1;
      TPMA_NV_EXTEND         : 1;
      reserved7_9            : 3;
      TPMA_NV_POLICY_DELETE  : 1;
      TPMA_NV_WRITELOCKED    : 1;
      TPMA_NV_WRITEALL       : 1;
      TPMA_NV_WRITEDEFINE    : 1;
      TPMA_NV_WRITE_STCLEAR  : 1;
      TPMA_NV_GLOBALLOCK     : 1;
      TPMA_NV_PPREAD         : 1;
      TPMA_NV_OWNERREAD      : 1;
      TPMA_NV_AUTHREAD       : 1;
      TPMA_NV_POLICYREAD     : 1;
      reserved20_24          : 5;
      TPMA_NV_NO_DA          : 1;
      TPMA_NV_ORDERLY        : 1;
      TPMA_NV_CLEAR_STCLEAR  : 1;
      TPMA_NV_READLOCKED     : 1;
      TPMA_NV_WRITTEN        : 1;
      TPMA_NV_PLATFORMCREATE : 1;
      TPMA_NV_READ_STCLEAR   : 1;
} ;

// Table 196 - TPMS_NV_PUBLIC Structure
struct  TPMS_NV_PUBLIC{  
  TPMI_RH_NV_INDEX    nvIndex;
  TPMI_ALG_HASH       nameAlg;
  TPMA_NV             attributes;
  TPM2B_DIGEST        authPolicy;
  UINT16              dataSize;
} ;

// Table 197 - TPM2B_NV_PUBLIC Structure
struct  TPM2B_NV_PUBLIC{  
  UINT16            size;
  TPMS_NV_PUBLIC    nvPublic;
} ;

// 14 Context Data

// Table 198 - TPM2B_CONTEXT_SENSITIVE Structure
struct TPM2B_CONTEXT_SENSITIVE {  
  UINT16    size;
  BYTE      buffer[size];
} ;

// Table 199 - TPMS_CONTEXT_DATA Structure
struct  TPMS_CONTEXT_DATA{  
  TPM2B_DIGEST               integrity;
  TPM2B_CONTEXT_SENSITIVE    encrypted;
} ;

// Table 200 - TPM2B_CONTEXT_DATA Structure
struct  TPM2B_CONTEXT_DATA{  
  UINT16    size;
  TPMS_CONTEXT_DATA      buffer;
} ;

// Table 201 - TPMS_CONTEXT Structure
struct  TPMS_CONTEXT{  
  UINT64                sequence;
  TPMI_DH_CONTEXT       savedHandle;
  TPMI_RH_HIERARCHY     hierarchy;
  TPM2B_CONTEXT_DATA    contextBlob;
} ;

// 15 Creation Data

// Table 203 - TPMS_CREATION_DATA Structure
struct  TPMS_CREATION_DATA{  
  TPML_PCR_SELECTION    pcrSelect;
  TPM2B_DIGEST          pcrDigest;
  TPMA_LOCALITY         locality;
  TPM_ALG_ID            parentNameAlg;
  TPM2B_NAME            parentName;
  TPM2B_NAME            parentQualifiedName;
  TPM2B_DATA            outsideInfo;
} ;

// Table 204 - TPM2B_CREATION_DATA Structure
struct TPM2B_CREATION_DATA {  
  UINT16                size;
  TPMS_CREATION_DATA    creationData;
} ;

//
// Command Header
//
struct TPM2_COMMAND_HEADER {  
  TPM_ST    tag;
  UINT32    paramSize;
  TPM_CC    commandCode;
} ;

struct TPM2_RESPONSE_HEADER {  
  TPM_ST    tag;
  UINT32    paramSize;
  TPM_RC    responseCode;
} ;

#pragma pack ()

//
// TCG Algorithm Registry
//
#define HASH_ALG_SHA1     0x00000001
#define HASH_ALG_SHA256   0x00000002
#define HASH_ALG_SHA384   0x00000004
#define HASH_ALG_SHA512   0x00000008
#define HASH_ALG_SM3_256  0x00000010

#endif
