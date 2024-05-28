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

#include <Tpm12.h>

//--- Remove #pragma pack (1) ---//

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
#define MAX_RSA_KEY_BYTES  ((MAX_RSA_KEY_BITS + 7) / 8)

// Table 216 - Defines for ECC Algorithm Constants
#define MAX_ECC_KEY_BITS   256
#define MAX_ECC_KEY_BYTES  ((MAX_ECC_KEY_BITS + 7) / 8)

// Table 217 - Defines for AES Algorithm Constants
#define MAX_AES_KEY_BITS          128
#define MAX_AES_BLOCK_SIZE_BYTES  16
#define MAX_AES_KEY_BYTES         ((MAX_AES_KEY_BITS + 7) / 8)

// Table 218 - Defines for SM4 Algorithm Constants
#define MAX_SM4_KEY_BITS          128
#define MAX_SM4_BLOCK_SIZE_BYTES  16
#define MAX_SM4_KEY_BYTES         ((MAX_SM4_KEY_BITS + 7) / 8)

// Table 219 - Defines for Symmetric Algorithm Constants
#define MAX_SYM_KEY_BITS    MAX_AES_KEY_BITS
#define MAX_SYM_KEY_BYTES   MAX_AES_KEY_BYTES
#define MAX_SYM_BLOCK_SIZE  MAX_AES_BLOCK_SIZE_BYTES

// Table 220 - Defines for Implementation Values
typedef UINT16 BSIZE;
#define BUFFER_ALIGNMENT     4
#define IMPLEMENTATION_PCR   24
#define PLATFORM_PCR         24
#define DRTM_PCR             17
#define NUM_LOCALITIES       5
#define MAX_HANDLE_NUM       3
#define MAX_ACTIVE_SESSIONS  64
typedef UINT16 CONTEXT_SLOT;
typedef UINT64 CONTEXT_COUNTER;
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
typedef UINT8 BYTE;

// Table 4 - Definition of Types for Documentation Clarity
//
// NOTE: Comment because it has same name as TPM1.2 (value is same, so not runtime issue)
//
// typedef UINT32 TPM_ALGORITHM_ID;
// typedef UINT32 TPM_MODIFIER_INDICATOR;
typedef UINT32 TPM_AUTHORIZATION_SIZE;
typedef UINT32 TPM_PARAMETER_SIZE;
typedef UINT16 TPM_KEY_SIZE;
typedef UINT16 TPM_KEY_BITS;

// 6 Constants

// Table 6 - TPM_GENERATED Constants
typedef UINT32 TPM_GENERATED;
#define TPM_GENERATED_VALUE  (TPM_GENERATED)(0xff544347)

//--- TPM_ALG_ID is converted to enum rather than typedef and #defines ---//
// Table 7 - TPM_ALG_ID Constants
enum <UINT16> TPM_ALG_ID{
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
typedef UINT16 TPM_ECC_CURVE;
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
enum <UINT32> TPM_CC{
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
enum <UINT32> TPM_RC{
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
///--- Re-type TPM_CLOCK_ADJUST from INT8 to char ---//
typedef char TPM_CLOCK_ADJUST;
#define TPM_CLOCK_COARSE_SLOWER  (TPM_CLOCK_ADJUST)(-3)
#define TPM_CLOCK_MEDIUM_SLOWER  (TPM_CLOCK_ADJUST)(-2)
#define TPM_CLOCK_FINE_SLOWER    (TPM_CLOCK_ADJUST)(-1)
#define TPM_CLOCK_NO_CHANGE      (TPM_CLOCK_ADJUST)(0)
#define TPM_CLOCK_FINE_FASTER    (TPM_CLOCK_ADJUST)(1)
#define TPM_CLOCK_MEDIUM_FASTER  (TPM_CLOCK_ADJUST)(2)
#define TPM_CLOCK_COARSE_FASTER  (TPM_CLOCK_ADJUST)(3)

// Table 17 - TPM_EO Constants
typedef UINT16 TPM_EO;
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
typedef enum<UINT16> {
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
} TPM_ST;

// Table 19 - TPM_SU Constants
typedef UINT16 TPM_SU;
#define TPM_SU_CLEAR  (TPM_SU)(0x0000)
#define TPM_SU_STATE  (TPM_SU)(0x0001)

//--- TPM_SE is converted to enum rather than typedef and #defines ---//
// Table 20 - TPM_SE Constants
enum<UINT8>  TPM_SE{
    TPM_SE_HMAC = 0x0,
    TPM_SE_POLICY = 0x1,
    TPM_SE_TRIAL = 0x03
    };
#define TPM_SE_HMAC    (TPM_SE)(0x00)
#define TPM_SE_POLICY  (TPM_SE)(0x01)
#define TPM_SE_TRIAL   (TPM_SE)(0x03)

// Table 21 - TPM_CAP Constants
typedef UINT32 TPM_CAP;
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
typedef UINT32 TPM_PT;
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
typedef UINT32 TPM_PT_PCR;
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
typedef UINT32 TPM_PS;
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
// typedef UINT32    TPM_HANDLE;

// Table 26 - TPM_HT Constants
typedef UINT8 TPM_HT;
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
typedef UINT32 TPM_RH;
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
typedef TPM_HANDLE TPM_HC;
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
typedef struct {
  UINT32    asymmetric    : 1;
  UINT32    symmetric     : 1;
  UINT32    hash          : 1;
  UINT32    object        : 1;
  UINT32    reserved4_7   : 4;
  UINT32    signing       : 1;
  UINT32    encrypting    : 1;
  UINT32    method        : 1;
  UINT32    reserved11_31 : 21;
} TPMA_ALGORITHM;

//--- Bitfield is flipped as 010 editor views bit in little endian no-matter what ---//
// Table 30 - TPMA_OBJECT Bits
  typedef struct {
   UINT32    reserved19_31        : 13;
   UINT32    sign                 : 1;
   UINT32    decrypt              : 1;
   UINT32    restricted           : 1;
   UINT32    reserved12_15        : 4;
   UINT32    encryptedDuplication : 1;
   UINT32    noDA                 : 1;
   UINT32    reserved8_9          : 2;
   UINT32    adminWithPolicy      : 1;
   UINT32    userWithAuth         : 1;
   UINT32    sensitiveDataOrigin  : 1;
   UINT32    fixedParent          : 1;
   UINT32    reserved4            : 1;
   UINT32    stClear              : 1;
   UINT32    fixedTPM             : 1;
   UINT32    reserved1            : 1;
 } TPMA_OBJECT;

// Table 31 - TPMA_SESSION Bits
typedef struct {
  UINT8    continueSession : 1;
  UINT8    auditExclusive  : 1;
  UINT8    auditReset      : 1;
  UINT8    reserved3_4     : 2;
  UINT8    decrypt         : 1;
  UINT8    encrypt         : 1;
  UINT8    audit           : 1;
} TPMA_SESSION;

// Table 32 - TPMA_LOCALITY Bits
//
// NOTE: Use low case here to resolve conflict
//
typedef struct {
  UINT8    locZero  : 1;
  UINT8    locOne   : 1;
  UINT8    locTwo   : 1;
  UINT8    locThree : 1;
  UINT8    locFour  : 1;
  UINT8    Extended : 3;
} TPMA_LOCALITY;

// Table 33 - TPMA_PERMANENT Bits
typedef struct {
  UINT32    ownerAuthSet       : 1;
  UINT32    endorsementAuthSet : 1;
  UINT32    lockoutAuthSet     : 1;
  UINT32    reserved3_7        : 5;
  UINT32    disableClear       : 1;
  UINT32    inLockout          : 1;
  UINT32    tpmGeneratedEPS    : 1;
  UINT32    reserved11_31      : 21;
} TPMA_PERMANENT;

// Table 34 - TPMA_STARTUP_CLEAR Bits
typedef struct {
  UINT32    phEnable     : 1;
  UINT32    shEnable     : 1;
  UINT32    ehEnable     : 1;
  UINT32    reserved3_30 : 28;
  UINT32    orderly      : 1;
} TPMA_STARTUP_CLEAR;

// Table 35 - TPMA_MEMORY Bits
typedef struct {
  UINT32    sharedRAM         : 1;
  UINT32    sharedNV          : 1;
  UINT32    objectCopiedToRam : 1;
  UINT32    reserved3_31      : 29;
} TPMA_MEMORY;

// Table 36 - TPMA_CC Bits
typedef struct {
  UINT32    commandIndex  : 16;
  UINT32    reserved16_21 : 6;
  UINT32    nv            : 1;
  UINT32    extensive     : 1;
  UINT32    flushed       : 1;
  UINT32    cHandles      : 3;
  UINT32    rHandle       : 1;
  UINT32    V             : 1;
  UINT32    Res           : 2;
} TPMA_CC;

// 9 Interface Types

// Table 37 - TPMI_YES_NO Type
typedef BYTE TPMI_YES_NO;

// Table 38 - TPMI_DH_OBJECT Type
typedef TPM_HANDLE TPMI_DH_OBJECT;

// Table 39 - TPMI_DH_PERSISTENT Type
typedef TPM_HANDLE TPMI_DH_PERSISTENT;

// Table 40 - TPMI_DH_ENTITY Type
typedef TPM_HANDLE TPMI_DH_ENTITY;

// Table 41 - TPMI_DH_PCR Type
typedef TPM_HANDLE TPMI_DH_PCR;

// Table 42 - TPMI_SH_AUTH_SESSION Type
typedef TPM_HANDLE TPMI_SH_AUTH_SESSION;

// Table 43 - TPMI_SH_HMAC Type
typedef TPM_HANDLE TPMI_SH_HMAC;

// Table 44 - TPMI_SH_POLICY Type
typedef TPM_HANDLE TPMI_SH_POLICY;

// Table 45 - TPMI_DH_CONTEXT Type
typedef TPM_HANDLE TPMI_DH_CONTEXT;

// Table 46 - TPMI_RH_HIERARCHY Type
typedef TPM_HANDLE TPMI_RH_HIERARCHY;

// Table 47 - TPMI_RH_HIERARCHY_AUTH Type
typedef TPM_HANDLE TPMI_RH_HIERARCHY_AUTH;

// Table 48 - TPMI_RH_PLATFORM Type
typedef TPM_HANDLE TPMI_RH_PLATFORM;

// Table 49 - TPMI_RH_OWNER Type
typedef TPM_HANDLE TPMI_RH_OWNER;

// Table 50 - TPMI_RH_ENDORSEMENT Type
typedef TPM_HANDLE TPMI_RH_ENDORSEMENT;

// Table 51 - TPMI_RH_PROVISION Type
typedef TPM_HANDLE TPMI_RH_PROVISION;

// Table 52 - TPMI_RH_CLEAR Type
typedef TPM_HANDLE TPMI_RH_CLEAR;

// Table 53 - TPMI_RH_NV_AUTH Type
typedef TPM_HANDLE TPMI_RH_NV_AUTH;

// Table 54 - TPMI_RH_LOCKOUT Type
typedef TPM_HANDLE TPMI_RH_LOCKOUT;

// Table 55 - TPMI_RH_NV_INDEX Type
typedef TPM_HANDLE TPMI_RH_NV_INDEX;

// Table 56 - TPMI_ALG_HASH Type
typedef TPM_ALG_ID TPMI_ALG_HASH;

// Table 57 - TPMI_ALG_ASYM Type
typedef TPM_ALG_ID TPMI_ALG_ASYM;

// Table 58 - TPMI_ALG_SYM Type
typedef TPM_ALG_ID TPMI_ALG_SYM;

// Table 59 - TPMI_ALG_SYM_OBJECT Type
typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;

// Table 60 - TPMI_ALG_SYM_MODE Type
typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;

// Table 61 - TPMI_ALG_KDF Type
typedef TPM_ALG_ID TPMI_ALG_KDF;

// Table 62 - TPMI_ALG_SIG_SCHEME Type
typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;

// Table 63 - TPMI_ECC_KEY_EXCHANGE Type
typedef TPM_ALG_ID TPMI_ECC_KEY_EXCHANGE;

// Table 64 - TPMI_ST_COMMAND_TAG Type
typedef TPM_ST TPMI_ST_COMMAND_TAG;

// 10 Structure Definitions

// Table 65 - TPMS_ALGORITHM_DESCRIPTION Structure
typedef struct {
  TPM_ALG_ID        alg;
  TPMA_ALGORITHM    attributes;
} TPMS_ALGORITHM_DESCRIPTION;

//--- Add selector into TPMU_HA union ---//
// Table 66 - TPMU_HA Union
typedef union (TPMI_ALG_HASH hashAlg) {
    if (hashAlg == TPM_ALG_SHA1){
        BYTE    sha1[SHA1_DIGEST_SIZE];
    }else if (hashAlg == TPM_ALG_SHA256){
        BYTE    sha256[SHA256_DIGEST_SIZE];
    }else if (hashAlg == TPM_ALG_SM3_256){
  BYTE    sm3_256[SM3_256_DIGEST_SIZE];
    }else if (hashAlg == TPM_ALG_SHA384){
  BYTE    sha384[SHA384_DIGEST_SIZE];
    }else if (hashAlg == TPM_ALG_SHA512){
  BYTE    sha512[SHA512_DIGEST_SIZE];
  };
} TPMU_HA;

//--- Pass hashAlg as selector to TPMU_HA ---//
// Table 67 - TPMT_HA Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
  TPMU_HA          digest(hashAlg);
} TPMT_HA;

//--- Calculate buffer size with size field rather than sizeof (TPMU_HA) ---//
// Table 68 - TPM2B_DIGEST Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_DIGEST;

//--- Calculate buffer size with size field rather than sizeof (TPMT_HA) ---//
// Table 69 - TPM2B_DATA Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_DATA;

// Table 70 - TPM2B_NONCE Types
typedef TPM2B_DIGEST TPM2B_NONCE;

// Table 71 - TPM2B_AUTH Types
typedef TPM2B_DIGEST TPM2B_AUTH;

// Table 72 - TPM2B_OPERAND Types
typedef TPM2B_DIGEST TPM2B_OPERAND;

// Table 73 - TPM2B_EVENT Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[1024];
} TPM2B_EVENT;

// Table 74 - TPM2B_MAX_BUFFER Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[MAX_DIGEST_BUFFER];
} TPM2B_MAX_BUFFER;

// Table 75 - TPM2B_MAX_NV_BUFFER Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[MAX_NV_INDEX_SIZE];
} TPM2B_MAX_NV_BUFFER;

//--- Calculate buffer size with size field rather than sizeof (UINT64) ---//
// Table 76 - TPM2B_TIMEOUT Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_TIMEOUT;

//--- Calculate buffer size with size field rather than MAX_SYM_BLOCK_SIZE ---//
// Table 77 -- TPM2B_IV Structure <I/O>
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_IV;

// Table 78 - TPMU_NAME Union
typedef union {
  TPMT_HA       digest;
  TPM_HANDLE    handle;
} TPMU_NAME;

//--- Replace buffer with TPMU_NAME structure ---//
// Table 79 - TPM2B_NAME Structure
typedef struct {
  UINT16    size;
  TPMU_NAME      name;
} TPM2B_NAME;

//--- Calculate pcrSelect size with sizeofSelect field rather than PCR_SELECT_MAX ---//
// Table 80 - TPMS_PCR_SELECT Structure
typedef struct {
  UINT8    sizeofSelect;
  BYTE     pcrSelect[sizeofSelect];
} TPMS_PCR_SELECT;

//--- Calculate pcrSelect size with sizeofSelect field rather than PCR_SELECT_MAX ---//
// Table 81 - TPMS_PCR_SELECTION Structure
typedef struct {
  TPMI_ALG_HASH    hash;
  UINT8            sizeofSelect;
  BYTE             pcrSelect[sizeofSelect];
} TPMS_PCR_SELECTION;

// Table 84 - TPMT_TK_CREATION Structure
typedef struct {
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} TPMT_TK_CREATION;

// Table 85 - TPMT_TK_VERIFIED Structure
typedef struct {
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} TPMT_TK_VERIFIED;

// Table 86 - TPMT_TK_AUTH Structure
typedef struct {
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} TPMT_TK_AUTH;

// Table 87 - TPMT_TK_HASHCHECK Structure
typedef struct {
  TPM_ST               tag;
  TPMI_RH_HIERARCHY    hierarchy;
  TPM2B_DIGEST         digest;
} TPMT_TK_HASHCHECK;

// Table 88 - TPMS_ALG_PROPERTY Structure
typedef struct {
  TPM_ALG_ID        alg;
  TPMA_ALGORITHM    algProperties;
} TPMS_ALG_PROPERTY;

// Table 89 - TPMS_TAGGED_PROPERTY Structure
typedef struct {
  TPM_PT    property;
  UINT32    value;
} TPMS_TAGGED_PROPERTY;

//--- Calculate pcrSelect size with sizeofSelect field rather than PCR_SELECT_MAX ---//
// Table 90 - TPMS_TAGGED_PCR_SELECT Structure
typedef struct {
  TPM_PT    tag;
  UINT8     sizeofSelect;
  BYTE      pcrSelect[sizeofSelect];
} TPMS_TAGGED_PCR_SELECT;

//--- Calculate commandCodes size with count field rather than MAX_CAP_CC ---//
// Table 91 - TPML_CC Structure
typedef struct {
  UINT32    count;
  TPM_CC    commandCodes[count];
} TPML_CC;

//--- Calculate commandAttributes size with count field rather than MAX_CAP_CC ---//
// Table 92 - TPML_CCA Structure
typedef struct {
  UINT32     count;
  TPMA_CC    commandAttributes[count];
} TPML_CCA;

//--- Calculate algorithms size with count field rather than MAX_ALG_LIST_SIZE ---//
// Table 93 - TPML_ALG Structure
typedef struct {
  UINT32        count;
  TPM_ALG_ID    algorithms[count];
} TPML_ALG;

//--- Calculate handle size with count field rather than MAX_CAP_HANDLES ---//
// Table 94 - TPML_HANDLE Structure
typedef struct {
  UINT32        count;
  TPM_HANDLE    handle[count];
} TPML_HANDLE;

//--- Calculate digests size with count field rather than 8 ---//
// Table 95 - TPML_DIGEST Structure
typedef struct {
  UINT32          count;
  TPM2B_DIGEST    digests[count];
} TPML_DIGEST;

//--- Calculate digests size with count field rather than HASH_COUNT ---//
// Table 96 -- TPML_DIGEST_VALUES Structure <I/O>
typedef struct {
  UINT32     count;
  TPMT_HA    digests[count];
} TPML_DIGEST_VALUES;

//--- Replace buffer with TPML_DIGEST_VALUES structure ---//
// Table 97 - TPM2B_DIGEST_VALUES Structure
typedef struct {
  UINT16    size;
  TPML_DIGEST_VALUES      buffer;
} TPM2B_DIGEST_VALUES;

//--- Calculate pcrSelections size with count field rather than HASH_COUNT ---//
// Table 98 - TPML_PCR_SELECTION Structure
typedef struct {
  UINT32                count;
  TPMS_PCR_SELECTION    pcrSelections[count];
} TPML_PCR_SELECTION;

//--- Calculate algProperties size with count field rather than MAX_CAP_ALGS ---//
// Table 99 - TPML_ALG_PROPERTY Structure
typedef struct {
  UINT32               count;
  TPMS_ALG_PROPERTY    algProperties[count];
} TPML_ALG_PROPERTY;

//--- Calculate tpmProperty size with count field rather than MAX_TPM_PROPERTIES ---//
// Table 100 - TPML_TAGGED_TPM_PROPERTY Structure
typedef struct {
  UINT32                  count;
  TPMS_TAGGED_PROPERTY    tpmProperty[count];
} TPML_TAGGED_TPM_PROPERTY;

//--- Calculate pcrProperty size with count field rather than MAX_PCR_PROPERTIES ---//
// Table 101 - TPML_TAGGED_PCR_PROPERTY Structure
typedef struct {
  UINT32                    count;
  TPMS_TAGGED_PCR_SELECT    pcrProperty[count];
} TPML_TAGGED_PCR_PROPERTY;

//--- Calculate eccCurves size with count field rather than MAX_ECC_CURVES ---//
// Table 102 - TPML_ECC_CURVE Structure
typedef struct {
  UINT32           count;
  TPM_ECC_CURVE    eccCurves[count];
} TPML_ECC_CURVE;

// Table 103 - TPMU_CAPABILITIES Union
typedef union {
  TPML_ALG_PROPERTY           algorithms;
  TPML_HANDLE                 handles;
  TPML_CCA                    command;
  TPML_CC                     ppCommands;
  TPML_CC                     auditCommands;
  TPML_PCR_SELECTION          assignedPCR;
  TPML_TAGGED_TPM_PROPERTY    tpmProperties;
  TPML_TAGGED_PCR_PROPERTY    pcrProperties;
  TPML_ECC_CURVE              eccCurves;
} TPMU_CAPABILITIES;

// Table 104 - TPMS_CAPABILITY_DATA Structure
typedef struct {
  TPM_CAP              capability;
  TPMU_CAPABILITIES    data;
} TPMS_CAPABILITY_DATA;

// Table 105 - TPMS_CLOCK_INFO Structure
typedef struct {
  UINT64         clock;
  UINT32         resetCount;
  UINT32         restartCount;
  TPMI_YES_NO    safe;
} TPMS_CLOCK_INFO;

// Table 106 - TPMS_TIME_INFO Structure
typedef struct {
  UINT64             time;
  TPMS_CLOCK_INFO    clockInfo;
} TPMS_TIME_INFO;

// Table 107 - TPMS_TIME_ATTEST_INFO Structure
typedef struct {
  TPMS_TIME_INFO    time;
  UINT64            firmwareVersion;
} TPMS_TIME_ATTEST_INFO;

// Table 108 - TPMS_CERTIFY_INFO Structure
typedef struct {
  TPM2B_NAME    name;
  TPM2B_NAME    qualifiedName;
} TPMS_CERTIFY_INFO;

// Table 109 - TPMS_QUOTE_INFO Structure
typedef struct {
  TPML_PCR_SELECTION    pcrSelect;
  TPM2B_DIGEST          pcrDigest;
} TPMS_QUOTE_INFO;

// Table 110 - TPMS_COMMAND_AUDIT_INFO Structure
typedef struct {
  UINT64          auditCounter;
  TPM_ALG_ID      digestAlg;
  TPM2B_DIGEST    auditDigest;
  TPM2B_DIGEST    commandDigest;
} TPMS_COMMAND_AUDIT_INFO;

// Table 111 - TPMS_SESSION_AUDIT_INFO Structure
typedef struct {
  TPMI_YES_NO     exclusiveSession;
  TPM2B_DIGEST    sessionDigest;
} TPMS_SESSION_AUDIT_INFO;

// Table 112 - TPMS_CREATION_INFO Structure
typedef struct {
  TPM2B_NAME      objectName;
  TPM2B_DIGEST    creationHash;
} TPMS_CREATION_INFO;

// Table 113 - TPMS_NV_CERTIFY_INFO Structure
typedef struct {
  TPM2B_NAME             indexName;
  UINT16                 offset;
  TPM2B_MAX_NV_BUFFER    nvContents;
} TPMS_NV_CERTIFY_INFO;

// Table 114 - TPMI_ST_ATTEST Type
typedef TPM_ST TPMI_ST_ATTEST;

// Table 115 - TPMU_ATTEST Union
typedef union {
  TPMS_CERTIFY_INFO          certify;
  TPMS_CREATION_INFO         creation;
  TPMS_QUOTE_INFO            quote;
  TPMS_COMMAND_AUDIT_INFO    commandAudit;
  TPMS_SESSION_AUDIT_INFO    sessionAudit;
  TPMS_TIME_ATTEST_INFO      time;
  TPMS_NV_CERTIFY_INFO       nv;
} TPMU_ATTEST;

// Table 116 - TPMS_ATTEST Structure
typedef struct {
  TPM_GENERATED      magic;
  TPMI_ST_ATTEST     type;
  TPM2B_NAME         qualifiedSigner;
  TPM2B_DATA         extraData;
  TPMS_CLOCK_INFO    clockInfo;
  UINT64             firmwareVersion;
  TPMU_ATTEST        attested;
} TPMS_ATTEST;

//--- Replace buffer with TPMS_ATTEST structure ---//
// Table 117 - TPM2B_ATTEST Structure
typedef struct {
  UINT16    size;
  TPMS_ATTEST      attestationData;
} TPM2B_ATTEST;

// Table 118 - TPMS_AUTH_COMMAND Structure
typedef struct {
  TPMI_SH_AUTH_SESSION    sessionHandle;
  TPM2B_NONCE             nonce;
  TPMA_SESSION            sessionAttributes;
  TPM2B_AUTH              hmac;
} TPMS_AUTH_COMMAND;

// Table 119 - TPMS_AUTH_RESPONSE Structure
typedef struct {
  TPM2B_NONCE     nonce;
  TPMA_SESSION    sessionAttributes;
  TPM2B_AUTH      hmac;
} TPMS_AUTH_RESPONSE;

// 11 Algorithm Parameters and Structures

// Table 120 - TPMI_AES_KEY_BITS Type
typedef TPM_KEY_BITS TPMI_AES_KEY_BITS;

// Table 121 - TPMI_SM4_KEY_BITS Type
typedef TPM_KEY_BITS TPMI_SM4_KEY_BITS;

// Table 122 - TPMU_SYM_KEY_BITS Union
typedef union {
  TPMI_AES_KEY_BITS    aes;
  TPMI_SM4_KEY_BITS    SM4;
  TPM_KEY_BITS         sym;
  TPMI_ALG_HASH     xor;
} TPMU_SYM_KEY_BITS;

// Table 123 - TPMU_SYM_MODE Union
typedef union {
  TPMI_ALG_SYM_MODE    aes;
  TPMI_ALG_SYM_MODE    SM4;
  TPMI_ALG_SYM_MODE    sym;
} TPMU_SYM_MODE;

// Table 125 - TPMT_SYM_DEF Structure
typedef struct {
  TPMI_ALG_SYM         algorithm;
  TPMU_SYM_KEY_BITS    keyBits;
  TPMU_SYM_MODE        mode;
} TPMT_SYM_DEF;

// Table 126 - TPMT_SYM_DEF_OBJECT Structure
typedef struct {
  TPMI_ALG_SYM_OBJECT    algorithm;
  TPMU_SYM_KEY_BITS      keyBits;
  TPMU_SYM_MODE          mode;
} TPMT_SYM_DEF_OBJECT;

//--- Calculate buffer size with size field rather than MAX_SYM_KEY_BYTES ---//
// Table 127 - TPM2B_SYM_KEY Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_SYM_KEY;

// Table 128 - TPMS_SYMCIPHER_PARMS Structure
typedef struct {
  TPMT_SYM_DEF_OBJECT    sym;
} TPMS_SYMCIPHER_PARMS;

//--- Calculate buffer size with size field rather than MAX_SYM_DATA ---//
// Table 129 - TPM2B_SENSITIVE_DATA Structure
typedef struct {
  UINT16    size;
  //--- Wraps for TPMU_SENSITIVE_CREATE ---//
  BYTE      buffer[size];
} TPM2B_SENSITIVE_DATA;

// Table 130 - TPMS_SENSITIVE_CREATE Structure
typedef struct {
  TPM2B_AUTH              userAuth;
  TPM2B_SENSITIVE_DATA    data;
} TPMS_SENSITIVE_CREATE;

// Table 131 - TPM2B_SENSITIVE_CREATE Structure
typedef struct {
  UINT16                   size;
  TPMS_SENSITIVE_CREATE    sensitive;
} TPM2B_SENSITIVE_CREATE;

// Table 132 - TPMS_SCHEME_SIGHASH Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_SIGHASH;

// Table 133 - TPMI_ALG_KEYEDHASH_SCHEME Type
typedef TPM_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;

// Table 134 - HMAC_SIG_SCHEME Types
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_HMAC;

// Table 135 - TPMS_SCHEME_XOR Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
  TPMI_ALG_KDF     kdf;
} TPMS_SCHEME_XOR;

//--- Add selector for TPMU_SCHEME_KEYEDHASH union ---//
// Table 136 - TPMU_SCHEME_KEYEDHASH Union
 typedef union(int selector) {
     if (selector == TPM_ALG_HMAC){
        TPMS_SCHEME_HMAC    hmac;
     }else if (selector == TPM_ALG_XOR){
        TPMS_SCHEME_XOR  xor;
    }
 } TPMU_SCHEME_KEYEDHASH;

// Table 137 - TPMT_KEYEDHASH_SCHEME Structure
//--- Use scheme as selector for TPMU_SCHEME_KEYEDHASH union ---//
typedef struct {
  TPMI_ALG_KEYEDHASH_SCHEME    scheme;
  TPMU_SCHEME_KEYEDHASH        details(scheme);
} TPMT_KEYEDHASH_SCHEME;

// Table 138 - RSA_SIG_SCHEMES Types
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_RSASSA;
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_RSAPSS;

// Table 139 - ECC_SIG_SCHEMES Types
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_ECDSA;
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_SM2;
typedef TPMS_SCHEME_SIGHASH TPMS_SCHEME_ECSCHNORR;

// Table 140 - TPMS_SCHEME_ECDAA Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
  UINT16           count;
} TPMS_SCHEME_ECDAA;

// Table 141 - TPMU_SIG_SCHEME Union
typedef union {
  TPMS_SCHEME_RSASSA       rsassa;
  TPMS_SCHEME_RSAPSS       rsapss;
  TPMS_SCHEME_ECDSA        ecdsa;
  TPMS_SCHEME_ECDAA        ecdaa;
  TPMS_SCHEME_ECSCHNORR    ecSchnorr;
  TPMS_SCHEME_HMAC         hmac;
  TPMS_SCHEME_SIGHASH      any;
} TPMU_SIG_SCHEME;

// Table 142 - TPMT_SIG_SCHEME Structure
typedef struct {
  TPMI_ALG_SIG_SCHEME    scheme;
  TPMU_SIG_SCHEME        details;
} TPMT_SIG_SCHEME;

// Table 143 - TPMS_SCHEME_OAEP Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_OAEP;

// Table 144 - TPMS_SCHEME_ECDH Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_ECDH;

// Table 145 - TPMS_SCHEME_MGF1 Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_MGF1;

// Table 146 - TPMS_SCHEME_KDF1_SP800_56a Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF1_SP800_56a;

// Table 147 - TPMS_SCHEME_KDF2 Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF2;

// Table 148 - TPMS_SCHEME_KDF1_SP800_108 Structure
typedef struct {
  TPMI_ALG_HASH    hashAlg;
} TPMS_SCHEME_KDF1_SP800_108;

// Table 149 - TPMU_KDF_SCHEME Union
typedef union {
  TPMS_SCHEME_MGF1              mgf1;
  TPMS_SCHEME_KDF1_SP800_56a    kdf1_SP800_56a;
  TPMS_SCHEME_KDF2              kdf2;
  TPMS_SCHEME_KDF1_SP800_108    kdf1_sp800_108;
} TPMU_KDF_SCHEME;

// Table 150 - TPMT_KDF_SCHEME Structure
typedef struct {
  TPMI_ALG_KDF       scheme;
  TPMU_KDF_SCHEME    details;
} TPMT_KDF_SCHEME;

// Table 151 - TPMI_ALG_ASYM_SCHEME Type
typedef TPM_ALG_ID TPMI_ALG_ASYM_SCHEME;

// Table 152 - TPMU_ASYM_SCHEME Union
typedef union {
  TPMS_SCHEME_RSASSA       rsassa;
  TPMS_SCHEME_RSAPSS       rsapss;
  TPMS_SCHEME_OAEP         oaep;
  TPMS_SCHEME_ECDSA        ecdsa;
  TPMS_SCHEME_ECDAA        ecdaa;
  TPMS_SCHEME_ECSCHNORR    ecSchnorr;
  TPMS_SCHEME_SIGHASH      anySig;
} TPMU_ASYM_SCHEME;

// Table 153 - TPMT_ASYM_SCHEME Structure
typedef struct {
  TPMI_ALG_ASYM_SCHEME    scheme;
  TPMU_ASYM_SCHEME        details;
} TPMT_ASYM_SCHEME;

// Table 154 - TPMI_ALG_RSA_SCHEME Type
typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;

// Table 155 - TPMT_RSA_SCHEME Structure
typedef struct {
  TPMI_ALG_RSA_SCHEME    scheme;
  TPMU_ASYM_SCHEME       details;
} TPMT_RSA_SCHEME;

// Table 156 - TPMI_ALG_RSA_DECRYPT Type
typedef TPM_ALG_ID TPMI_ALG_RSA_DECRYPT;

// Table 157 - TPMT_RSA_DECRYPT Structure
typedef struct {
  TPMI_ALG_RSA_DECRYPT    scheme;
  TPMU_ASYM_SCHEME        details;
} TPMT_RSA_DECRYPT;

//--- Calculate buffer size with size field rather than MAX_RSA_KEY_BYTES ---//
// Table 158 - TPM2B_PUBLIC_KEY_RSA Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_PUBLIC_KEY_RSA;

// Table 159 - TPMI_RSA_KEY_BITS Type
typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

//--- Calculate buffer size with size field rather than MAX_RSA_KEY_BYTES/2 ---//
// Table 160 - TPM2B_PRIVATE_KEY_RSA Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_PRIVATE_KEY_RSA;

//--- Calculate buffer size with size field rather than MAX_ECC_KEY_BYTES ---//
// Table 161 - TPM2B_ECC_PARAMETER Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_ECC_PARAMETER;

// Table 162 - TPMS_ECC_POINT Structure
typedef struct {
  TPM2B_ECC_PARAMETER    x;
  TPM2B_ECC_PARAMETER    y;
} TPMS_ECC_POINT;

// Table 163 -- TPM2B_ECC_POINT Structure <I/O>
typedef struct {
  UINT16            size;
  TPMS_ECC_POINT    point;
} TPM2B_ECC_POINT;

// Table 164 - TPMI_ALG_ECC_SCHEME Type
typedef TPM_ALG_ID TPMI_ALG_ECC_SCHEME;

// Table 165 - TPMI_ECC_CURVE Type
typedef TPM_ECC_CURVE TPMI_ECC_CURVE;

// Table 166 - TPMT_ECC_SCHEME Structure
typedef struct {
  TPMI_ALG_ECC_SCHEME    scheme;
  TPMU_SIG_SCHEME        details;
} TPMT_ECC_SCHEME;

// Table 167 - TPMS_ALGORITHM_DETAIL_ECC Structure
typedef struct {
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
} TPMS_ALGORITHM_DETAIL_ECC;

// Table 168 - TPMS_SIGNATURE_RSASSA Structure
typedef struct {
  TPMI_ALG_HASH           hash;
  TPM2B_PUBLIC_KEY_RSA    sig;
} TPMS_SIGNATURE_RSASSA;

// Table 169 - TPMS_SIGNATURE_RSAPSS Structure
typedef struct {
  TPMI_ALG_HASH           hash;
  TPM2B_PUBLIC_KEY_RSA    sig;
} TPMS_SIGNATURE_RSAPSS;

// Table 170 - TPMS_SIGNATURE_ECDSA Structure
typedef struct {
  TPMI_ALG_HASH          hash;
  TPM2B_ECC_PARAMETER    signatureR;
  TPM2B_ECC_PARAMETER    signatureS;
} TPMS_SIGNATURE_ECDSA;

// Table 171 - TPMU_SIGNATURE Union
typedef union {
  TPMS_SIGNATURE_RSASSA    rsassa;
  TPMS_SIGNATURE_RSAPSS    rsapss;
  TPMS_SIGNATURE_ECDSA     ecdsa;
  TPMS_SIGNATURE_ECDSA     sm2;
  TPMS_SIGNATURE_ECDSA     ecdaa;
  TPMS_SIGNATURE_ECDSA     ecschnorr;
  TPMT_HA                  hmac;
  TPMS_SCHEME_SIGHASH      any;
} TPMU_SIGNATURE;

// Table 172 - TPMT_SIGNATURE Structure
typedef struct {
  TPMI_ALG_SIG_SCHEME    sigAlg;
  TPMU_SIGNATURE         signature;
} TPMT_SIGNATURE;

//--- Retype ecc as TPMS_ECC_POINT ---//
// Table 173 - TPMU_ENCRYPTED_SECRET Union
typedef union {
  TPMS_ECC_POINT    ecc[sizeof (TPMS_ECC_POINT)];
  BYTE    rsa[MAX_RSA_KEY_BYTES];
  BYTE    symmetric[sizeof (TPM2B_DIGEST)];
  BYTE    keyedHash[sizeof (TPM2B_DIGEST)];
} TPMU_ENCRYPTED_SECRET;

//--- Calculate secret size with size field rather than sizeof (TPMU_ENCRYPTED_SECRET) ---//
// Table 174 - TPM2B_ENCRYPTED_SECRET Structure
typedef struct {
  UINT16    size;
  BYTE      secret[size];
} TPM2B_ENCRYPTED_SECRET;

// 12 Key/Object Complex

// Table 175 - TPMI_ALG_PUBLIC Type
typedef TPM_ALG_ID TPMI_ALG_PUBLIC;

//--- Add selector for TPMU_PUBLIC_ID union ---//
// Table 176 - TPMU_PUBLIC_ID Union
 typedef union(int selector) {
   if (selector == TPM_ALG_KEYEDHASH){
        TPM2B_DIGEST            keyedHash;
   }else if (selector == TPM_ALG_SYMCIPHER){
        TPM2B_DIGEST            sym;
   }else if (selector == TPM_ALG_RSA){
        TPM2B_PUBLIC_KEY_RSA    rsa;
   }else if (selector == TPM_ALG_ECC){
   TPMS_ECC_POINT          ecc;
   }
 } TPMU_PUBLIC_ID;

// Table 177 - TPMS_KEYEDHASH_PARMS Structure
typedef struct {
  TPMT_KEYEDHASH_SCHEME    scheme;
} TPMS_KEYEDHASH_PARMS;

// Table 178 - TPMS_ASYM_PARMS Structure
typedef struct {
  TPMT_SYM_DEF_OBJECT    symmetric;
  TPMT_ASYM_SCHEME       scheme;
} TPMS_ASYM_PARMS;

// Table 179 - TPMS_RSA_PARMS Structure
typedef struct {
  TPMT_SYM_DEF_OBJECT    symmetric;
  TPMT_RSA_SCHEME        scheme;
  TPMI_RSA_KEY_BITS      keyBits;
  UINT32                 exponent;
} TPMS_RSA_PARMS;

// Table 180 - TPMS_ECC_PARMS Structure
typedef struct {
  TPMT_SYM_DEF_OBJECT    symmetric;
  TPMT_ECC_SCHEME        scheme;
  TPMI_ECC_CURVE         curveID;
  TPMT_KDF_SCHEME        kdf;
} TPMS_ECC_PARMS;

//--- Add selector for TPMU_PUBLIC_PARMS union ---//
// Table 181 - TPMU_PUBLIC_PARMS Union
  typedef union(int selector) {
   if (selector == TPM_ALG_KEYEDHASH){
       TPMS_KEYEDHASH_PARMS    keyedHashDetail;
   }else if (selector == TPM_ALG_SYMCIPHER){
       TPMT_SYM_DEF_OBJECT     symDetail;
   }else if (selector == TPM_ALG_RSA){
       TPMS_RSA_PARMS          rsaDetail;
   }else if (selector == TPM_ALG_ECC){
       TPMS_ECC_PARMS          eccDetail;
   }else{
   TPMS_ASYM_PARMS         asymDetail;
   }
 } TPMU_PUBLIC_PARMS;

//--- Use type as selector for TPMU_PUBLIC_PARMS union ---//
// Table 182 - TPMT_PUBLIC_PARMS Structure
typedef struct {
  TPMI_ALG_PUBLIC      type;
  TPMU_PUBLIC_PARMS    parameters(type);
} TPMT_PUBLIC_PARMS;

//--- Use type as selector for both TPMU_PUBLIC_PARMS and TPMU_PUBLIC_ID unions ---//
// Table 183 - TPMT_PUBLIC Structure
 typedef struct {
   TPMI_ALG_PUBLIC      type;
   TPMI_ALG_HASH        nameAlg;
   TPMA_OBJECT          objectAttributes;
   TPM2B_DIGEST         authPolicy;
   TPMU_PUBLIC_PARMS    parameters(type);
   TPMU_PUBLIC_ID       unique(type);
 } TPMT_PUBLIC;

// Table 184 - TPM2B_PUBLIC Structure
typedef struct {
  UINT16         size;
  TPMT_PUBLIC    publicArea;
} TPM2B_PUBLIC;

// Table 185 - TPM2B_PRIVATE_VENDOR_SPECIFIC Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[PRIVATE_VENDOR_SPECIFIC_BYTES];
} TPM2B_PRIVATE_VENDOR_SPECIFIC;

//--- Add selector for TPMU_SENSITIVE_COMPOSITE union ---//
// Table 186 - TPMU_SENSITIVE_COMPOSITE Union
typedef union(TPMI_ALG_PUBLIC type) {
  if (type == TPM_ALG_RSA){
    TPM2B_PRIVATE_KEY_RSA            rsa;
  }else if (type == TPM_ALG_ECC){
    TPM2B_ECC_PARAMETER              ecc;
  }else if (type == TPM_ALG_KEYEDHASH){
    TPM2B_SENSITIVE_DATA             bits;
  }else if (type == TPM_ALG_SYMCIPHER){
    TPM2B_SYM_KEY                    sym;
  }else{
    TPM2B_PRIVATE_VENDOR_SPECIFIC    any;
  };
} TPMU_SENSITIVE_COMPOSITE;

//--- Use sensitiveType as selector for TPMU_SENSITIVE_COMPOSITE union ---//
// Table 187 - TPMT_SENSITIVE Structure
typedef struct {
  TPMI_ALG_PUBLIC             sensitiveType;
  TPM2B_AUTH                  authValue;
  TPM2B_DIGEST                seedValue;
  TPMU_SENSITIVE_COMPOSITE    sensitive(sensitiveType);
} TPMT_SENSITIVE;

// Table 188 - TPM2B_SENSITIVE Structure
typedef struct {
  UINT16            size;
  TPMT_SENSITIVE    sensitiveArea;
} TPM2B_SENSITIVE;

//--- Add size input to _PRIVATE to calculate size of sensitive/encryptedSensitive ---//
//--- Replacing the direct instantitation of sensitive/encryptedSensitive a TPMT_SENSITIVE structure ---//
// Table 189 - _PRIVATE Structure
typedef struct (int size) {
  TPM2B_DIGEST      integrityOuter;
  TPM2B_DIGEST      integrityInner;
  /*encryptedSensitive is an encrypted TPM2B_SENSITIVE structure*/
  byte    encryptedSensitive[size-integrityOuter.size-integrityInner.size-4];
} _PRIVATE;

//--- Retype buffer as _PRIVATE strucuture, passing size for the above calcuations ---//
// Table 190 - TPM2B_PRIVATE Structure
typedef struct {
  UINT16    size;
  _PRIVATE      buffer(size);
} TPM2B_PRIVATE;

// Table 191 - _ID_OBJECT Structure
typedef struct {
  TPM2B_DIGEST    integrityHMAC;
  TPM2B_DIGEST    encIdentity;
} _ID_OBJECT;

//--- Retype credential as _ID_OBJECT strucuture ---//
// Table 192 - TPM2B_ID_OBJECT Structure
typedef struct {
  UINT16    size;
  _ID_OBJECT      credential;
} TPM2B_ID_OBJECT;

// 13 NV Storage Structures

// Table 193 - TPM_NV_INDEX Bits
//
// NOTE: Comment here to resolve conflict
//
// typedef struct {
//  UINT32 index : 22;
//  UINT32 space : 2;
//  UINT32 RH_NV : 8;
// } TPM_NV_INDEX;

// Table 195 - TPMA_NV Bits
typedef struct {
  UINT32    TPMA_NV_PPWRITE        : 1;
  UINT32    TPMA_NV_OWNERWRITE     : 1;
  UINT32    TPMA_NV_AUTHWRITE      : 1;
  UINT32    TPMA_NV_POLICYWRITE    : 1;
  UINT32    TPMA_NV_COUNTER        : 1;
  UINT32    TPMA_NV_BITS           : 1;
  UINT32    TPMA_NV_EXTEND         : 1;
  UINT32    reserved7_9            : 3;
  UINT32    TPMA_NV_POLICY_DELETE  : 1;
  UINT32    TPMA_NV_WRITELOCKED    : 1;
  UINT32    TPMA_NV_WRITEALL       : 1;
  UINT32    TPMA_NV_WRITEDEFINE    : 1;
  UINT32    TPMA_NV_WRITE_STCLEAR  : 1;
  UINT32    TPMA_NV_GLOBALLOCK     : 1;
  UINT32    TPMA_NV_PPREAD         : 1;
  UINT32    TPMA_NV_OWNERREAD      : 1;
  UINT32    TPMA_NV_AUTHREAD       : 1;
  UINT32    TPMA_NV_POLICYREAD     : 1;
  UINT32    reserved20_24          : 5;
  UINT32    TPMA_NV_NO_DA          : 1;
  UINT32    TPMA_NV_ORDERLY        : 1;
  UINT32    TPMA_NV_CLEAR_STCLEAR  : 1;
  UINT32    TPMA_NV_READLOCKED     : 1;
  UINT32    TPMA_NV_WRITTEN        : 1;
  UINT32    TPMA_NV_PLATFORMCREATE : 1;
  UINT32    TPMA_NV_READ_STCLEAR   : 1;
} TPMA_NV;

// Table 196 - TPMS_NV_PUBLIC Structure
typedef struct {
  TPMI_RH_NV_INDEX    nvIndex;
  TPMI_ALG_HASH       nameAlg;
  TPMA_NV             attributes;
  TPM2B_DIGEST        authPolicy;
  UINT16              dataSize;
} TPMS_NV_PUBLIC;

// Table 197 - TPM2B_NV_PUBLIC Structure
typedef struct {
  UINT16            size;
  TPMS_NV_PUBLIC    nvPublic;
} TPM2B_NV_PUBLIC;

// 14 Context Data

//--- Calculate buffer size using size field rather than MAX_CONTEXT_SIZE ---//
// Table 198 - TPM2B_CONTEXT_SENSITIVE Structure
typedef struct {
  UINT16    size;
  BYTE      buffer[size];
} TPM2B_CONTEXT_SENSITIVE;

// Table 199 - TPMS_CONTEXT_DATA Structure
typedef struct {
  TPM2B_DIGEST               integrity;
  TPM2B_CONTEXT_SENSITIVE    encrypted;
} TPMS_CONTEXT_DATA;

//--- Retype buffer as TPMS_CONTEXT_DATA strucuture ---//
// Table 200 - TPM2B_CONTEXT_DATA Structure
typedef struct {
  UINT16    size;
  TPMS_CONTEXT_DATA      buffer;
} TPM2B_CONTEXT_DATA;

// Table 201 - TPMS_CONTEXT Structure
typedef struct {
  UINT64                sequence;
  TPMI_DH_CONTEXT       savedHandle;
  TPMI_RH_HIERARCHY     hierarchy;
  TPM2B_CONTEXT_DATA    contextBlob;
} TPMS_CONTEXT;

// 15 Creation Data

// Table 203 - TPMS_CREATION_DATA Structure
typedef struct {
  TPML_PCR_SELECTION    pcrSelect;
  TPM2B_DIGEST          pcrDigest;
  TPMA_LOCALITY         locality;
  TPM_ALG_ID            parentNameAlg;
  TPM2B_NAME            parentName;
  TPM2B_NAME            parentQualifiedName;
  TPM2B_DATA            outsideInfo;
} TPMS_CREATION_DATA;

// Table 204 - TPM2B_CREATION_DATA Structure
typedef struct {
  UINT16                size;
  TPMS_CREATION_DATA    creationData;
} TPM2B_CREATION_DATA;

//
// Command Header
//
typedef struct {
  TPM_ST    tag;
  UINT32    paramSize;
  TPM_CC    commandCode;
} TPM2_COMMAND_HEADER;

typedef struct {
  TPM_ST    tag;
  UINT32    paramSize;
  TPM_RC    responseCode;
} TPM2_RESPONSE_HEADER;

//--- Remove #pragma pack () ---//

//
// TCG Algorithm Registry
//
#define HASH_ALG_SHA1     0x00000001
#define HASH_ALG_SHA256   0x00000002
#define HASH_ALG_SHA384   0x00000004
#define HASH_ALG_SHA512   0x00000008
#define HASH_ALG_SM3_256  0x00000010

#endif
