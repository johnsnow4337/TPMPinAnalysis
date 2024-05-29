#pragma once

#pragma warning(push)

#pragma warning(disable:4668) 

#pragma once

#pragma region Input Buffer SAL 1 compatibility macros

#pragma endregion Input Buffer SAL 1 compatibility macros

#pragma once

#pragma once

#pragma once

#pragma warning(pop)

#pragma warning(push)

#pragma warning(disable:4668)    

#pragma warning(disable:4820)    

#pragma warning(disable:4201)    

#pragma once

#pragma warning(push)

#pragma warning(disable:4001) 

#pragma once

#pragma warning(push)

#pragma warning(disable:4001) 

#pragma once

#pragma warning(pop)

#pragma warning(pop)

#pragma region Application Family or OneCore or Games Family

typedef   long HRESULT;

typedef unsigned int ALG_ID;

typedef ULONG_PTR HCRYPTPROV;

typedef ULONG_PTR HCRYPTKEY;

typedef ULONG_PTR HCRYPTHASH;

typedef struct _CMS_KEY_INFO {

DWORD       dwVersion;                      

ALG_ID  Algid;                              

BYTE    *pbOID;                             

DWORD   cbOID;                              

} CMS_KEY_INFO, *PCMS_KEY_INFO;

typedef struct _HMAC_Info {

ALG_ID  HashAlgid;

BYTE    *pbInnerString;

DWORD   cbInnerString;

BYTE    *pbOuterString;

DWORD   cbOuterString;

} HMAC_INFO, *PHMAC_INFO;

typedef struct _SCHANNEL_ALG {

DWORD   dwUse;

ALG_ID  Algid;

DWORD   cBits;

DWORD   dwFlags;

DWORD   dwReserved;

} SCHANNEL_ALG, *PSCHANNEL_ALG;

typedef struct _PROV_ENUMALGS {

ALG_ID    aiAlgid;

DWORD     dwBitLen;

DWORD     dwNameLen;

CHAR      szName[20];

} PROV_ENUMALGS;

typedef struct _PROV_ENUMALGS_EX {

ALG_ID    aiAlgid;

DWORD     dwDefaultLen;

DWORD     dwMinLen;

DWORD     dwMaxLen;

DWORD     dwProtocols;

DWORD     dwNameLen;

CHAR      szName[20];

DWORD     dwLongNameLen;

CHAR      szLongName[40];

} PROV_ENUMALGS_EX;

typedef struct _PUBLICKEYSTRUC {

BYTE    bType;

BYTE    bVersion;

WORD    reserved;

ALG_ID  aiKeyAlg;

} BLOBHEADER, PUBLICKEYSTRUC;

typedef struct _RSAPUBKEY {

DWORD   magic;                  

DWORD   bitlen;                 

DWORD   pubexp;                 

} RSAPUBKEY;

typedef struct _PUBKEY {

DWORD   magic;

DWORD   bitlen;                 

} DHPUBKEY, DSSPUBKEY, KEAPUBKEY, TEKPUBKEY;

typedef struct _DSSSEED {

DWORD   counter;

BYTE    seed[20];

} DSSSEED;

typedef struct _PUBKEYVER3 {

DWORD   magic;

DWORD   bitlenP;                

DWORD   bitlenQ;                

DWORD   bitlenJ;                

DSSSEED DSSSeed;

} DHPUBKEY_VER3, DSSPUBKEY_VER3;

typedef struct _PRIVKEYVER3 {

DWORD   magic;

DWORD   bitlenP;                

DWORD   bitlenQ;                

DWORD   bitlenJ;                

DWORD   bitlenX;                

DSSSEED DSSSeed;

} DHPRIVKEY_VER3, DSSPRIVKEY_VER3;

typedef struct _KEY_TYPE_SUBTYPE {

DWORD   dwKeySpec;

GUID    Type;

GUID    Subtype;

} KEY_TYPE_SUBTYPE, *PKEY_TYPE_SUBTYPE;

typedef struct _CERT_FORTEZZA_DATA_PROP {

unsigned char   SerialNumber[8];

int             CertIndex;

unsigned char   CertLabel[36];

} CERT_FORTEZZA_DATA_PROP;

typedef struct _CRYPT_RC4_KEY_STATE {

unsigned char Key[16];

unsigned char SBox[256];

unsigned char i;

unsigned char j;

} CRYPT_RC4_KEY_STATE, *PCRYPT_RC4_KEY_STATE;

typedef struct _CRYPT_DES_KEY_STATE {

unsigned char Key[8];

unsigned char IV[8];

unsigned char Feedback[8];

} CRYPT_DES_KEY_STATE, *PCRYPT_DES_KEY_STATE;

typedef struct _CRYPT_3DES_KEY_STATE {

unsigned char Key[24];

unsigned char IV[8];

unsigned char Feedback[8];

} CRYPT_3DES_KEY_STATE, *PCRYPT_3DES_KEY_STATE;

typedef struct _CRYPT_AES_128_KEY_STATE {

unsigned char Key[16];

unsigned char IV[16];

unsigned char EncryptionState[11][16];      

unsigned char DecryptionState[11][16];

unsigned char Feedback[16];

} CRYPT_AES_128_KEY_STATE, *PCRYPT_AES_128_KEY_STATE;

typedef struct _CRYPT_AES_256_KEY_STATE {

unsigned char Key[32];

unsigned char IV[16];

unsigned char EncryptionState[15][16];      

unsigned char DecryptionState[15][16];

unsigned char Feedback[16];

} CRYPT_AES_256_KEY_STATE, *PCRYPT_AES_256_KEY_STATE;

typedef struct _CRYPTOAPI_BLOB {

DWORD   cbData;

BYTE    *pbData;

} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB,

CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB,

CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB,

CERT_NAME_BLOB, *PCERT_NAME_BLOB,

CERT_RDN_VALUE_BLOB, *PCERT_RDN_VALUE_BLOB,

CERT_BLOB, *PCERT_BLOB,

CRL_BLOB, *PCRL_BLOB,

DATA_BLOB, *PDATA_BLOB,

CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB,

CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB,

CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB,

CRYPT_DER_BLOB, *PCRYPT_DER_BLOB,

CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;

typedef struct _CMS_DH_KEY_INFO {

DWORD               dwVersion;                      

ALG_ID          Algid;                              

LPSTR           pszContentEncObjId; 

CRYPT_DATA_BLOB PubInfo;            

void            *pReserved;         

} CMS_DH_KEY_INFO, *PCMS_DH_KEY_INFO;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptAcquireContextA(

HCRYPTPROV  *phProv,

LPCSTR    szContainer,

LPCSTR    szProvider,

DWORD       dwProvType,

DWORD       dwFlags

);

BOOL

__stdcall

CryptAcquireContextW(

HCRYPTPROV  *phProv,

LPCWSTR    szContainer,

LPCWSTR    szProvider,

DWORD       dwProvType,

DWORD       dwFlags

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CryptReleaseContext(

HCRYPTPROV  hProv,

DWORD       dwFlags

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptGenKey(

HCRYPTPROV  hProv,

ALG_ID      Algid,

DWORD       dwFlags,

HCRYPTKEY   *phKey

);

BOOL

__stdcall

CryptDeriveKey(

HCRYPTPROV  hProv,

ALG_ID      Algid,

HCRYPTHASH  hBaseData,

DWORD       dwFlags,

HCRYPTKEY   *phKey

);

BOOL

__stdcall

CryptDestroyKey(

HCRYPTKEY   hKey

);

BOOL

__stdcall

CryptSetKeyParam(

HCRYPTKEY   hKey,

DWORD       dwParam,

const BYTE  *pbData,

DWORD       dwFlags

);

BOOL

__stdcall

CryptGetKeyParam(

HCRYPTKEY   hKey,

DWORD   dwParam,

BYTE    *pbData,

DWORD   *pdwDataLen,

DWORD   dwFlags

);

BOOL

__stdcall

CryptSetHashParam(

HCRYPTHASH  hHash,

DWORD       dwParam,

const BYTE  *pbData,

DWORD       dwFlags

);

BOOL

__stdcall

CryptGetHashParam(

HCRYPTHASH  hHash,

DWORD   dwParam,

BYTE    *pbData,

DWORD   *pdwDataLen,

DWORD   dwFlags

);

BOOL

__stdcall

CryptSetProvParam(

HCRYPTPROV  hProv,

DWORD       dwParam,

const BYTE  *pbData,

DWORD       dwFlags

);

BOOL

__stdcall

CryptGetProvParam(

HCRYPTPROV  hProv,

DWORD   dwParam,

BYTE    *pbData,

DWORD   *pdwDataLen,

DWORD   dwFlags

);

BOOL

__stdcall

CryptGenRandom(

HCRYPTPROV  hProv,

DWORD   dwLen,

BYTE    *pbBuffer

);

BOOL

__stdcall

CryptGetUserKey(

HCRYPTPROV  hProv,

DWORD       dwKeySpec,

HCRYPTKEY   *phUserKey

);

BOOL

__stdcall

CryptExportKey(

HCRYPTKEY   hKey,

HCRYPTKEY   hExpKey,

DWORD   dwBlobType,

DWORD   dwFlags,

BYTE    *pbData,

DWORD   *pdwDataLen

);

BOOL

__stdcall

CryptImportKey(

HCRYPTPROV  hProv,

const BYTE  *pbData,

DWORD       dwDataLen,

HCRYPTKEY   hPubKey,

DWORD       dwFlags,

HCRYPTKEY   *phKey

);

BOOL

__stdcall

CryptEncrypt(

HCRYPTKEY   hKey,

HCRYPTHASH  hHash,

BOOL    Final,

DWORD   dwFlags,

BYTE    *pbData,

DWORD   *pdwDataLen,

DWORD   dwBufLen

);

BOOL

__stdcall

CryptDecrypt(

HCRYPTKEY   hKey,

HCRYPTHASH  hHash,

BOOL        Final,

DWORD       dwFlags,

BYTE        *pbData,

DWORD       *pdwDataLen

);

BOOL

__stdcall

CryptCreateHash(

HCRYPTPROV  hProv,

ALG_ID      Algid,

HCRYPTKEY   hKey,

DWORD       dwFlags,

HCRYPTHASH  *phHash

);

BOOL

__stdcall

CryptHashData(

HCRYPTHASH  hHash,

const BYTE  *pbData,

DWORD   dwDataLen,

DWORD   dwFlags

);

BOOL

__stdcall

CryptHashSessionKey(

HCRYPTHASH  hHash,

HCRYPTKEY   hKey,

DWORD   dwFlags

);

BOOL

__stdcall

CryptDestroyHash(

HCRYPTHASH  hHash

);

BOOL

__stdcall

CryptSignHashA(

HCRYPTHASH  hHash,

DWORD       dwKeySpec,

LPCSTR    szDescription,

DWORD       dwFlags,

BYTE        *pbSignature,

DWORD       *pdwSigLen

);

BOOL

__stdcall

CryptSignHashW(

HCRYPTHASH  hHash,

DWORD       dwKeySpec,

LPCWSTR    szDescription,

DWORD       dwFlags,

BYTE        *pbSignature,

DWORD       *pdwSigLen

);

BOOL

__stdcall

CryptVerifySignatureA(

HCRYPTHASH  hHash,

const BYTE  *pbSignature,

DWORD       dwSigLen,

HCRYPTKEY   hPubKey,

LPCSTR    szDescription,

DWORD       dwFlags

);

BOOL

__stdcall

CryptVerifySignatureW(

HCRYPTHASH  hHash,

const BYTE  *pbSignature,

DWORD       dwSigLen,

HCRYPTKEY   hPubKey,

LPCWSTR    szDescription,

DWORD       dwFlags

);

BOOL

__stdcall

CryptSetProviderA(

LPCSTR    pszProvName,

DWORD       dwProvType

);

BOOL

__stdcall

CryptSetProviderW(

LPCWSTR    pszProvName,

DWORD       dwProvType

);

BOOL

__stdcall

CryptSetProviderExA(

LPCSTR pszProvName,

DWORD dwProvType,

DWORD *pdwReserved,

DWORD dwFlags

);

BOOL

__stdcall

CryptSetProviderExW(

LPCWSTR pszProvName,

DWORD dwProvType,

DWORD *pdwReserved,

DWORD dwFlags

);

BOOL

__stdcall

CryptGetDefaultProviderA(

DWORD   dwProvType,

DWORD   *pdwReserved,

DWORD   dwFlags,

LPSTR pszProvName,

DWORD   *pcbProvName

);

BOOL

__stdcall

CryptGetDefaultProviderW(

DWORD   dwProvType,

DWORD   *pdwReserved,

DWORD   dwFlags,

LPWSTR pszProvName,

DWORD   *pcbProvName

);

BOOL

__stdcall

CryptEnumProviderTypesA(

DWORD   dwIndex,

DWORD   *pdwReserved,

DWORD   dwFlags,

DWORD   *pdwProvType,

LPSTR szTypeName,

DWORD   *pcbTypeName

);

BOOL

__stdcall

CryptEnumProviderTypesW(

DWORD   dwIndex,

DWORD   *pdwReserved,

DWORD   dwFlags,

DWORD   *pdwProvType,

LPWSTR szTypeName,

DWORD   *pcbTypeName

);

BOOL

__stdcall

CryptEnumProvidersA(

DWORD   dwIndex,

DWORD   *pdwReserved,

DWORD   dwFlags,

DWORD   *pdwProvType,

LPSTR szProvName,

DWORD   *pcbProvName

);

BOOL

__stdcall

CryptEnumProvidersW(

DWORD   dwIndex,

DWORD   *pdwReserved,

DWORD   dwFlags,

DWORD   *pdwProvType,

LPWSTR szProvName,

DWORD   *pcbProvName

);

BOOL

__stdcall

CryptContextAddRef(

HCRYPTPROV  hProv,

DWORD       *pdwReserved,

DWORD       dwFlags

);

BOOL

__stdcall

CryptDuplicateKey(

HCRYPTKEY   hKey,

DWORD   *pdwReserved,

DWORD   dwFlags,

HCRYPTKEY   *phKey

);

BOOL

__stdcall

CryptDuplicateHash(

HCRYPTHASH  hHash,

DWORD       *pdwReserved,

DWORD       dwFlags,

HCRYPTHASH  *phHash

);

#pragma endregion

#pragma region Desktop Family or Games

BOOL

__cdecl

GetEncSChannel(

BYTE **pData,

DWORD *dwDecSize

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

#pragma once

#pragma warning(push)

#pragma warning(disable:4820) 

#pragma region Desktop Family or OneCore or Games Family

typedef   LONG NTSTATUS;

typedef NTSTATUS *PNTSTATUS;

typedef struct __BCRYPT_KEY_LENGTHS_STRUCT

{

ULONG   dwMinLength;

ULONG   dwMaxLength;

ULONG   dwIncrement;

} BCRYPT_KEY_LENGTHS_STRUCT;

typedef BCRYPT_KEY_LENGTHS_STRUCT BCRYPT_AUTH_TAG_LENGTHS_STRUCT;

typedef struct _BCRYPT_OID

{

ULONG   cbOID;

PUCHAR  pbOID;

} BCRYPT_OID;

typedef struct _BCRYPT_OID_LIST

{

ULONG       dwOIDCount;

BCRYPT_OID  *pOIDs;

} BCRYPT_OID_LIST;

typedef struct _BCRYPT_PKCS1_PADDING_INFO

{

LPCWSTR pszAlgId;

} BCRYPT_PKCS1_PADDING_INFO;

typedef struct _BCRYPT_PSS_PADDING_INFO

{

LPCWSTR pszAlgId;

ULONG   cbSalt;

} BCRYPT_PSS_PADDING_INFO;

typedef struct _BCRYPT_OAEP_PADDING_INFO

{

LPCWSTR pszAlgId;

PUCHAR   pbLabel;

ULONG   cbLabel;

} BCRYPT_OAEP_PADDING_INFO;

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO

{

ULONG       cbSize;

ULONG       dwInfoVersion;

PUCHAR      pbNonce;

ULONG       cbNonce;

PUCHAR      pbAuthData;

ULONG       cbAuthData;

PUCHAR      pbTag;

ULONG       cbTag;

PUCHAR      pbMacContext;

ULONG       cbMacContext;

ULONG       cbAAD;

ULONGLONG   cbData;

ULONG       dwFlags;

} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, *PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef struct _BCryptBuffer {

ULONG   cbBuffer;             

ULONG   BufferType;           

PVOID   pvBuffer;             

} BCryptBuffer, * PBCryptBuffer;

typedef struct _BCryptBufferDesc {

ULONG   ulVersion;            

ULONG   cBuffers;             

PBCryptBuffer pBuffers;       

} BCryptBufferDesc, * PBCryptBufferDesc;

typedef PVOID BCRYPT_HANDLE;

typedef PVOID BCRYPT_ALG_HANDLE;

typedef PVOID BCRYPT_KEY_HANDLE;

typedef PVOID BCRYPT_HASH_HANDLE;

typedef PVOID BCRYPT_SECRET_HANDLE;

typedef struct _BCRYPT_KEY_BLOB

{

ULONG   Magic;

} BCRYPT_KEY_BLOB;

typedef struct _BCRYPT_RSAKEY_BLOB

{

ULONG   Magic;

ULONG   BitLength;

ULONG   cbPublicExp;

ULONG   cbModulus;

ULONG   cbPrime1;

ULONG   cbPrime2;

} BCRYPT_RSAKEY_BLOB;

typedef struct _BCRYPT_ECCKEY_BLOB

{

ULONG   dwMagic;

ULONG   cbKey;

} BCRYPT_ECCKEY_BLOB, *PBCRYPT_ECCKEY_BLOB;

typedef struct _SSL_ECCKEY_BLOB

{

ULONG   dwCurveType;

ULONG   cbKey;

} SSL_ECCKEY_BLOB, *PSSL_ECCKEY_BLOB;

typedef enum

{

BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE    = 0x1,

BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE      = 0x2,

BCRYPT_ECC_PRIME_MONTGOMERY_CURVE           = 0x3

} ECC_CURVE_TYPE_ENUM;

typedef enum

{

BCRYPT_NO_CURVE_GENERATION_ALG_ID = 0x0

} ECC_CURVE_ALG_ID_ENUM;

typedef struct _BCRYPT_ECCFULLKEY_BLOB

{

ULONG                   dwMagic;

ULONG                   dwVersion;              

ECC_CURVE_TYPE_ENUM     dwCurveType;            

ECC_CURVE_ALG_ID_ENUM   dwCurveGenerationAlgId; 

ULONG                   cbFieldLength;          

ULONG                   cbSubgroupOrder;        

ULONG                   cbCofactor;             

ULONG                   cbSeed;                 

} BCRYPT_ECCFULLKEY_BLOB, *PBCRYPT_ECCFULLKEY_BLOB;

typedef struct _BCRYPT_DH_KEY_BLOB

{

ULONG   dwMagic;

ULONG   cbKey;

} BCRYPT_DH_KEY_BLOB, *PBCRYPT_DH_KEY_BLOB;

typedef   struct _BCRYPT_DH_PARAMETER_HEADER

{

ULONG           cbLength;

ULONG           dwMagic;

ULONG           cbKeyLength;

} BCRYPT_DH_PARAMETER_HEADER;

typedef struct _BCRYPT_DSA_KEY_BLOB

{

ULONG   dwMagic;

ULONG   cbKey;

UCHAR   Count[4];

UCHAR   Seed[20];

UCHAR   q[20];

} BCRYPT_DSA_KEY_BLOB, *PBCRYPT_DSA_KEY_BLOB;

typedef enum

{

DSA_HASH_ALGORITHM_SHA1,

DSA_HASH_ALGORITHM_SHA256,

DSA_HASH_ALGORITHM_SHA512

} HASHALGORITHM_ENUM;

typedef enum

{

DSA_FIPS186_2,

DSA_FIPS186_3

} DSAFIPSVERSION_ENUM;

typedef struct _BCRYPT_DSA_KEY_BLOB_V2

{

ULONG                                   dwMagic;

ULONG                                   cbKey;

HASHALGORITHM_ENUM                      hashAlgorithm;

DSAFIPSVERSION_ENUM                     standardVersion;

ULONG                                   cbSeedLength;

ULONG                                   cbGroupSize;

UCHAR                                   Count[4];

} BCRYPT_DSA_KEY_BLOB_V2, *PBCRYPT_DSA_KEY_BLOB_V2;

typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER

{

ULONG   dwMagic;

ULONG   dwVersion;

ULONG   cbKeyData;

} BCRYPT_KEY_DATA_BLOB_HEADER, *PBCRYPT_KEY_DATA_BLOB_HEADER;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER

{

ULONG           cbLength;

ULONG           dwMagic;

ULONG           cbKeyLength;

UCHAR           Count[4];

UCHAR           Seed[20];

UCHAR           q[20];

} BCRYPT_DSA_PARAMETER_HEADER;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER_V2

{

ULONG                   cbLength;

ULONG                   dwMagic;

ULONG                   cbKeyLength;

HASHALGORITHM_ENUM      hashAlgorithm;

DSAFIPSVERSION_ENUM     standardVersion;

ULONG                   cbSeedLength;

ULONG                   cbGroupSize;

UCHAR                   Count[4];

} BCRYPT_DSA_PARAMETER_HEADER_V2;

typedef struct _BCRYPT_ECC_CURVE_NAMES

{

ULONG   dwEccCurveNames;

LPWSTR  *pEccCurveNames;

} BCRYPT_ECC_CURVE_NAMES;

typedef enum {

BCRYPT_HASH_OPERATION_HASH_DATA = 1,

BCRYPT_HASH_OPERATION_FINISH_HASH = 2,

} BCRYPT_HASH_OPERATION_TYPE;

typedef struct _BCRYPT_MULTI_HASH_OPERATION {

ULONG                           iHash;          

BCRYPT_HASH_OPERATION_TYPE      hashOperation;  

PUCHAR                          pbBuffer;       

ULONG                           cbBuffer;

} BCRYPT_MULTI_HASH_OPERATION;

typedef enum{

BCRYPT_OPERATION_TYPE_HASH = 1,     

} BCRYPT_MULTI_OPERATION_TYPE;

typedef struct _BCRYPT_MULTI_OBJECT_LENGTH_STRUCT

{

ULONG   cbPerObject;

ULONG   cbPerElement;           

} BCRYPT_MULTI_OBJECT_LENGTH_STRUCT;

NTSTATUS

__stdcall

BCryptOpenAlgorithmProvider(

BCRYPT_ALG_HANDLE   *phAlgorithm,

LPCWSTR pszAlgId,

LPCWSTR pszImplementation,

ULONG   dwFlags);

typedef struct _BCRYPT_ALGORITHM_IDENTIFIER

{

LPWSTR  pszName;

ULONG   dwClass;

ULONG   dwFlags;

} BCRYPT_ALGORITHM_IDENTIFIER;

NTSTATUS

__stdcall

BCryptEnumAlgorithms(

ULONG   dwAlgOperations,

ULONG   *pAlgCount,

BCRYPT_ALGORITHM_IDENTIFIER **ppAlgList,

ULONG   dwFlags);

typedef struct _BCRYPT_PROVIDER_NAME

{

LPWSTR  pszProviderName;

} BCRYPT_PROVIDER_NAME;

NTSTATUS

__stdcall

BCryptEnumProviders(

LPCWSTR pszAlgId,

ULONG   *pImplCount,

BCRYPT_PROVIDER_NAME    **ppImplList,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptGetProperty(

BCRYPT_HANDLE   hObject,

LPCWSTR pszProperty,

PUCHAR   pbOutput,

ULONG   cbOutput,

ULONG   *pcbResult,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptSetProperty(

BCRYPT_HANDLE   hObject,

LPCWSTR pszProperty,

PUCHAR   pbInput,

ULONG   cbInput,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptCloseAlgorithmProvider(

BCRYPT_ALG_HANDLE   hAlgorithm,

ULONG   dwFlags);

VOID

__stdcall

BCryptFreeBuffer(

PVOID   pvBuffer);

NTSTATUS

__stdcall

BCryptGenerateSymmetricKey(

BCRYPT_ALG_HANDLE   hAlgorithm,

BCRYPT_KEY_HANDLE   *phKey,

PUCHAR   pbKeyObject,

ULONG   cbKeyObject,

PUCHAR   pbSecret,

ULONG   cbSecret,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptGenerateKeyPair(

BCRYPT_ALG_HANDLE   hAlgorithm,

BCRYPT_KEY_HANDLE   *phKey,

ULONG   dwLength,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptEncrypt(

BCRYPT_KEY_HANDLE hKey,

PUCHAR   pbInput,

ULONG   cbInput,

VOID    *pPaddingInfo,

PUCHAR   pbIV,

ULONG   cbIV,

PUCHAR   pbOutput,

ULONG   cbOutput,

ULONG   *pcbResult,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptDecrypt(

BCRYPT_KEY_HANDLE   hKey,

PUCHAR   pbInput,

ULONG   cbInput,

VOID    *pPaddingInfo,

PUCHAR   pbIV,

ULONG   cbIV,

PUCHAR   pbOutput,

ULONG   cbOutput,

ULONG   *pcbResult,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptExportKey(

BCRYPT_KEY_HANDLE   hKey,

BCRYPT_KEY_HANDLE   hExportKey,

LPCWSTR pszBlobType,

PUCHAR   pbOutput,

ULONG   cbOutput,

ULONG   *pcbResult,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptImportKey(

BCRYPT_ALG_HANDLE hAlgorithm,

BCRYPT_KEY_HANDLE hImportKey,

LPCWSTR pszBlobType,

BCRYPT_KEY_HANDLE *phKey,

PUCHAR   pbKeyObject,

ULONG   cbKeyObject,

PUCHAR   pbInput,

ULONG   cbInput,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptImportKeyPair(

BCRYPT_ALG_HANDLE hAlgorithm,

BCRYPT_KEY_HANDLE hImportKey,

LPCWSTR pszBlobType,

BCRYPT_KEY_HANDLE *phKey,

PUCHAR   pbInput,

ULONG   cbInput,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptDuplicateKey(

BCRYPT_KEY_HANDLE   hKey,

BCRYPT_KEY_HANDLE   *phNewKey,

PUCHAR   pbKeyObject,

ULONG   cbKeyObject,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptFinalizeKeyPair(

BCRYPT_KEY_HANDLE   hKey,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptDestroyKey(

BCRYPT_KEY_HANDLE   hKey);

NTSTATUS

__stdcall

BCryptDestroySecret(

BCRYPT_SECRET_HANDLE   hSecret);

NTSTATUS

__stdcall

BCryptSignHash(

BCRYPT_KEY_HANDLE   hKey,

VOID    *pPaddingInfo,

PUCHAR   pbInput,

ULONG   cbInput,

PUCHAR   pbOutput,

ULONG   cbOutput,

ULONG   *pcbResult,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptVerifySignature(

BCRYPT_KEY_HANDLE   hKey,

VOID    *pPaddingInfo,

PUCHAR   pbHash,

ULONG   cbHash,

PUCHAR   pbSignature,

ULONG   cbSignature,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptSecretAgreement(

BCRYPT_KEY_HANDLE       hPrivKey,

BCRYPT_KEY_HANDLE       hPubKey,

BCRYPT_SECRET_HANDLE    *phAgreedSecret,

ULONG                   dwFlags);

NTSTATUS

__stdcall

BCryptDeriveKey(

BCRYPT_SECRET_HANDLE hSharedSecret,

LPCWSTR              pwszKDF,

BCryptBufferDesc     *pParameterList,

PUCHAR pbDerivedKey,

ULONG                cbDerivedKey,

ULONG                *pcbResult,

ULONG                dwFlags);

NTSTATUS

__stdcall

BCryptKeyDerivation(

BCRYPT_KEY_HANDLE hKey,

BCryptBufferDesc     *pParameterList,

PUCHAR pbDerivedKey,

ULONG                cbDerivedKey,

ULONG                *pcbResult,

ULONG                dwFlags);

NTSTATUS

__stdcall

BCryptCreateHash(

BCRYPT_ALG_HANDLE   hAlgorithm,

BCRYPT_HASH_HANDLE  *phHash,

PUCHAR   pbHashObject,

ULONG   cbHashObject,

PUCHAR   pbSecret,   

ULONG   cbSecret,   

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptHashData(

BCRYPT_HASH_HANDLE  hHash,

PUCHAR   pbInput,

ULONG   cbInput,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptFinishHash(

BCRYPT_HASH_HANDLE hHash,

PUCHAR   pbOutput,

ULONG   cbOutput,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptDuplicateHash(

BCRYPT_HASH_HANDLE  hHash,

BCRYPT_HASH_HANDLE  *phNewHash,

PUCHAR   pbHashObject,

ULONG   cbHashObject,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptDestroyHash(

BCRYPT_HASH_HANDLE  hHash);

NTSTATUS

__stdcall

BCryptHash(

BCRYPT_ALG_HANDLE   hAlgorithm,

PUCHAR              pbSecret,   

ULONG               cbSecret,   

PUCHAR              pbInput,

ULONG               cbInput,

PUCHAR              pbOutput,

ULONG               cbOutput );

NTSTATUS

__stdcall

BCryptGenRandom(

BCRYPT_ALG_HANDLE   hAlgorithm,

PUCHAR  pbBuffer,

ULONG   cbBuffer,

ULONG   dwFlags);

NTSTATUS

__stdcall

BCryptDeriveKeyCapi(

BCRYPT_HASH_HANDLE  hHash,

BCRYPT_ALG_HANDLE   hTargetAlg,

PUCHAR              pbDerivedKey,

ULONG               cbDerivedKey,

ULONG               dwFlags);

NTSTATUS

__stdcall

BCryptDeriveKeyPBKDF2(

BCRYPT_ALG_HANDLE   hPrf,

PUCHAR              pbPassword,

ULONG               cbPassword,

PUCHAR              pbSalt,

ULONG               cbSalt,

ULONGLONG           cIterations,

PUCHAR              pbDerivedKey,

ULONG               cbDerivedKey,

ULONG               dwFlags);

typedef struct _BCRYPT_INTERFACE_VERSION

{

USHORT MajorVersion;

USHORT MinorVersion;

} BCRYPT_INTERFACE_VERSION, *PBCRYPT_INTERFACE_VERSION;

typedef struct _CRYPT_INTERFACE_REG

{

ULONG dwInterface;

ULONG dwFlags;

ULONG cFunctions;

PWSTR *rgpszFunctions;

}

CRYPT_INTERFACE_REG, *PCRYPT_INTERFACE_REG;

typedef struct _CRYPT_IMAGE_REG

{

PWSTR pszImage;

ULONG cInterfaces;

PCRYPT_INTERFACE_REG *rgpInterfaces;

}

CRYPT_IMAGE_REG, *PCRYPT_IMAGE_REG;

typedef struct _CRYPT_PROVIDER_REG

{

ULONG cAliases;

PWSTR *rgpszAliases;

PCRYPT_IMAGE_REG pUM;

PCRYPT_IMAGE_REG pKM;

}

CRYPT_PROVIDER_REG, *PCRYPT_PROVIDER_REG;

typedef struct _CRYPT_PROVIDERS

{

ULONG cProviders;

PWSTR *rgpszProviders;

}

CRYPT_PROVIDERS, *PCRYPT_PROVIDERS;

typedef struct _CRYPT_CONTEXT_CONFIG

{

ULONG dwFlags;

ULONG dwReserved;

}

CRYPT_CONTEXT_CONFIG, *PCRYPT_CONTEXT_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_CONFIG

{

ULONG dwFlags;

ULONG dwReserved;

}

CRYPT_CONTEXT_FUNCTION_CONFIG, *PCRYPT_CONTEXT_FUNCTION_CONFIG;

typedef struct _CRYPT_CONTEXTS

{

ULONG cContexts;

PWSTR *rgpszContexts;

}

CRYPT_CONTEXTS, *PCRYPT_CONTEXTS;

typedef struct _CRYPT_CONTEXT_FUNCTIONS

{

ULONG cFunctions;

PWSTR *rgpszFunctions;

}

CRYPT_CONTEXT_FUNCTIONS, *PCRYPT_CONTEXT_FUNCTIONS;

typedef struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS

{

ULONG cProviders;

PWSTR *rgpszProviders;

}

CRYPT_CONTEXT_FUNCTION_PROVIDERS, *PCRYPT_CONTEXT_FUNCTION_PROVIDERS;

typedef struct _CRYPT_PROPERTY_REF

{

PWSTR pszProperty;

ULONG cbValue;

PUCHAR pbValue;

}

CRYPT_PROPERTY_REF, *PCRYPT_PROPERTY_REF;

typedef struct _CRYPT_IMAGE_REF

{

PWSTR pszImage;

ULONG dwFlags;

}

CRYPT_IMAGE_REF, *PCRYPT_IMAGE_REF;

typedef struct _CRYPT_PROVIDER_REF

{

ULONG dwInterface;

PWSTR pszFunction;

PWSTR pszProvider;

ULONG cProperties;

PCRYPT_PROPERTY_REF *rgpProperties;

PCRYPT_IMAGE_REF pUM;

PCRYPT_IMAGE_REF pKM;

}

CRYPT_PROVIDER_REF, *PCRYPT_PROVIDER_REF;

typedef struct _CRYPT_PROVIDER_REFS

{

ULONG cProviders;

PCRYPT_PROVIDER_REF *rgpProviders;

}

CRYPT_PROVIDER_REFS, *PCRYPT_PROVIDER_REFS;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

NTSTATUS

__stdcall

BCryptQueryProviderRegistration(

LPCWSTR pszProvider,

ULONG dwMode,

ULONG dwInterface,

ULONG* pcbBuffer,

PCRYPT_PROVIDER_REG *ppBuffer);

NTSTATUS

__stdcall

BCryptEnumRegisteredProviders(

ULONG* pcbBuffer,

PCRYPT_PROVIDERS *ppBuffer);

NTSTATUS

__stdcall

BCryptCreateContext(

ULONG dwTable,

LPCWSTR pszContext,

PCRYPT_CONTEXT_CONFIG pConfig); 

NTSTATUS

__stdcall

BCryptDeleteContext(

ULONG dwTable,

LPCWSTR pszContext);

NTSTATUS

__stdcall

BCryptEnumContexts(

ULONG dwTable,

ULONG* pcbBuffer,

PCRYPT_CONTEXTS *ppBuffer);

NTSTATUS

__stdcall

BCryptConfigureContext(

ULONG dwTable,

LPCWSTR pszContext,

PCRYPT_CONTEXT_CONFIG pConfig);

NTSTATUS

__stdcall

BCryptQueryContextConfiguration(

ULONG dwTable,

LPCWSTR pszContext,

ULONG* pcbBuffer,

PCRYPT_CONTEXT_CONFIG *ppBuffer);

NTSTATUS

__stdcall

BCryptAddContextFunction(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction,

ULONG dwPosition);

NTSTATUS

__stdcall

BCryptRemoveContextFunction(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction);

NTSTATUS

__stdcall

BCryptEnumContextFunctions(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

ULONG* pcbBuffer,

PCRYPT_CONTEXT_FUNCTIONS *ppBuffer);

NTSTATUS

__stdcall

BCryptConfigureContextFunction(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction,

PCRYPT_CONTEXT_FUNCTION_CONFIG pConfig);

NTSTATUS

__stdcall

BCryptQueryContextFunctionConfiguration(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction,

ULONG* pcbBuffer,

PCRYPT_CONTEXT_FUNCTION_CONFIG *ppBuffer);

NTSTATUS

__stdcall

BCryptEnumContextFunctionProviders(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction,

ULONG* pcbBuffer,

PCRYPT_CONTEXT_FUNCTION_PROVIDERS *ppBuffer);

NTSTATUS

__stdcall

BCryptSetContextFunctionProperty(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction,

LPCWSTR pszProperty,

ULONG cbValue,

PUCHAR pbValue);

NTSTATUS

__stdcall

BCryptQueryContextFunctionProperty(

ULONG dwTable,

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction,

LPCWSTR pszProperty,

ULONG* pcbValue,

PUCHAR *ppbValue);

NTSTATUS

__stdcall

BCryptRegisterConfigChangeNotify(

HANDLE *phEvent);

NTSTATUS

__stdcall

BCryptUnregisterConfigChangeNotify(

HANDLE hEvent);

NTSTATUS __stdcall

BCryptResolveProviders(

LPCWSTR pszContext,

ULONG dwInterface,

LPCWSTR pszFunction,

LPCWSTR pszProvider,

ULONG dwMode,

ULONG dwFlags,

ULONG* pcbBuffer,

PCRYPT_PROVIDER_REFS *ppBuffer);

#pragma endregion

#pragma region Application Family or OneCore Family

NTSTATUS

__stdcall

BCryptGetFipsAlgorithmMode(

BOOLEAN *pfEnabled

);

#pragma endregion

#pragma region Desktop Family

#pragma endregion

#pragma warning(pop)

#pragma endregion

#pragma region Application Family or OneCore or Games Family

#pragma warning(push)

#pragma warning(disable:4820) 

typedef LONG SECURITY_STATUS;

typedef LPVOID (__stdcall *PFN_NCRYPT_ALLOC)(

SIZE_T cbSize

);

typedef VOID (__stdcall *PFN_NCRYPT_FREE)(

LPVOID pv

);

typedef struct NCRYPT_ALLOC_PARA {

DWORD                   cbSize;     

PFN_NCRYPT_ALLOC        pfnAlloc;

PFN_NCRYPT_FREE         pfnFree;

} NCRYPT_ALLOC_PARA;

typedef BCryptBuffer     NCryptBuffer;

typedef BCryptBuffer*    PNCryptBuffer;

typedef BCryptBufferDesc NCryptBufferDesc;

typedef BCryptBufferDesc* PNCryptBufferDesc;

typedef ULONG_PTR NCRYPT_HANDLE;

typedef ULONG_PTR NCRYPT_PROV_HANDLE;

typedef ULONG_PTR NCRYPT_KEY_HANDLE;

typedef ULONG_PTR NCRYPT_HASH_HANDLE;

typedef ULONG_PTR NCRYPT_SECRET_HANDLE;

typedef  

struct _NCRYPT_CIPHER_PADDING_INFO

{

ULONG       cbSize;

DWORD       dwFlags;

PUCHAR      pbIV;

ULONG       cbIV;

PUCHAR      pbOtherInfo;

ULONG       cbOtherInfo;

} NCRYPT_CIPHER_PADDING_INFO, *PNCRYPT_CIPHER_PADDING_INFO;

typedef struct _NCRYPT_PLATFORM_ATTEST_PADDING_INFO {

ULONG  magic;  

ULONG  pcrMask;

} NCRYPT_PLATFORM_ATTEST_PADDING_INFO;

typedef struct _NCRYPT_KEY_ATTEST_PADDING_INFO {

ULONG   magic;  

PUCHAR  pbKeyBlob;

ULONG   cbKeyBlob;

PUCHAR  pbKeyAuth;

ULONG   cbKeyAuth;

} NCRYPT_KEY_ATTEST_PADDING_INFO;

typedef struct _NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES

{

ULONG Version; 

ULONG Flags;   

ULONG cbPublicKeyBlob;

} NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES, *PNCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES;

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_STATEMENT

{

ULONG Magic;        

ULONG Version;      

ULONG cbSignature;  

ULONG cbReport;     

ULONG cbAttributes; 

} NCRYPT_VSM_KEY_ATTESTATION_STATEMENT, *PNCRYPT_VSM_KEY_ATTESTATION_STATEMENT;

#pragma warning(disable:4214) 

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS

{

ULONG Version;            

ULONGLONG TrustletId;     

ULONG MinSvn;             

ULONG FlagsMask;          

ULONG FlagsExpected;      

ULONG AllowDebugging : 1; 

ULONG Reserved : 31;      

} NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS, *PNCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS;

#pragma warning(default:4214) 

#pragma warning(disable:4214) 

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_HEADER

{

ULONG Version;         

ULONG KeyUsage;        

ULONG PerBootKey : 1;  

ULONG Reserved : 31;   

ULONG cbAlgName;       

ULONG cbNonce;         

ULONG cbAuthTag;       

ULONG cbWrappingKey;   

ULONG cbIsolatedKey;   

} NCRYPT_EXPORTED_ISOLATED_KEY_HEADER, *PNCRYPT_EXPORTED_ISOLATED_KEY_HEADER;

#pragma warning(default:4214) 

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE

{

NCRYPT_EXPORTED_ISOLATED_KEY_HEADER Header;

} NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE, *PNCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE;

typedef struct __NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT

{

UINT32 Magic;  

UINT32 Version;  

UINT32 HeaderSize;  

UINT32 cbCertifyInfo;

UINT32 cbSignature;

UINT32 cbTpmPublic;

} NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT,*PNCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT

{

ULONG Magic;        

ULONG Version;      

ULONG pcrAlg;       

ULONG cbSignature;  

ULONG cbQuote;      

ULONG cbPcrs;       

} NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT, *PNCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT;

SECURITY_STATUS

__stdcall

NCryptOpenStorageProvider(

NCRYPT_PROV_HANDLE *phProvider,

LPCWSTR pszProviderName,

DWORD   dwFlags);

typedef struct _NCryptAlgorithmName

{

LPWSTR  pszName;

DWORD   dwClass;            

DWORD   dwAlgOperations;    

DWORD   dwFlags;

} NCryptAlgorithmName;

SECURITY_STATUS

__stdcall

NCryptEnumAlgorithms(

NCRYPT_PROV_HANDLE hProvider,

DWORD   dwAlgOperations,

DWORD * pdwAlgCount,

NCryptAlgorithmName **ppAlgList,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptIsAlgSupported(

NCRYPT_PROV_HANDLE hProvider,

LPCWSTR pszAlgId,

DWORD   dwFlags);

typedef struct NCryptKeyName

{

LPWSTR  pszName;

LPWSTR  pszAlgid;

DWORD   dwLegacyKeySpec;

DWORD   dwFlags;

} NCryptKeyName;

SECURITY_STATUS

__stdcall

NCryptEnumKeys(

NCRYPT_PROV_HANDLE hProvider,

LPCWSTR pszScope,

NCryptKeyName **ppKeyName,

PVOID * ppEnumState,

DWORD   dwFlags);

typedef struct NCryptProviderName

{

LPWSTR  pszName;

LPWSTR  pszComment;

} NCryptProviderName;

#pragma region Desktop Family or OneCore Family

SECURITY_STATUS

__stdcall

NCryptEnumStorageProviders(

DWORD * pdwProviderCount,

NCryptProviderName **ppProviderList,

DWORD   dwFlags);

#pragma endregion

SECURITY_STATUS

__stdcall

NCryptFreeBuffer(

PVOID   pvInput);

SECURITY_STATUS

__stdcall

NCryptOpenKey(

NCRYPT_PROV_HANDLE hProvider,

NCRYPT_KEY_HANDLE *phKey,

LPCWSTR pszKeyName,

DWORD  dwLegacyKeySpec,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptCreatePersistedKey(

NCRYPT_PROV_HANDLE hProvider,

NCRYPT_KEY_HANDLE *phKey,

LPCWSTR pszAlgId,

LPCWSTR pszKeyName,

DWORD   dwLegacyKeySpec,

DWORD   dwFlags);

typedef struct __NCRYPT_UI_POLICY

{

DWORD   dwVersion;

DWORD   dwFlags;

LPCWSTR pszCreationTitle;

LPCWSTR pszFriendlyName;

LPCWSTR pszDescription;

} NCRYPT_UI_POLICY;

typedef struct __NCRYPT_KEY_ACCESS_POLICY_BLOB

{

DWORD   dwVersion;

DWORD   dwPolicyFlags;

DWORD cbUserSid;

DWORD cbApplicationSid;

}NCRYPT_KEY_ACCESS_POLICY_BLOB;

typedef struct __NCRYPT_SUPPORTED_LENGTHS

{

DWORD   dwMinLength;

DWORD   dwMaxLength;

DWORD   dwIncrement;

DWORD   dwDefaultLength;

} NCRYPT_SUPPORTED_LENGTHS;

typedef struct __NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO

{

DWORD       dwVersion;

INT32       iExpiration;

BYTE        pabNonce[32];

BYTE        pabPolicyRef[32];

BYTE        pabHMAC[32];

} NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO;

typedef struct __NCRYPT_PCP_TPM_FW_VERSION_INFO

{

UINT16      major1;

UINT16      major2;

UINT16      minor1;

UINT16      minor2;

} NCRYPT_PCP_TPM_FW_VERSION_INFO;

typedef struct __NCRYPT_PCP_RAW_POLICYDIGEST

{

DWORD   dwVersion;

DWORD   cbDigest;

} NCRYPT_PCP_RAW_POLICYDIGEST_INFO;

SECURITY_STATUS

__stdcall

NCryptGetProperty(

NCRYPT_HANDLE hObject,

LPCWSTR pszProperty,

PBYTE pbOutput,

DWORD   cbOutput,

DWORD * pcbResult,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptSetProperty(

NCRYPT_HANDLE hObject,

LPCWSTR pszProperty,

PBYTE pbInput,

DWORD   cbInput,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptFinalizeKey(

NCRYPT_KEY_HANDLE hKey,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptEncrypt(

NCRYPT_KEY_HANDLE hKey,

PBYTE pbInput,

DWORD   cbInput,

VOID *pPaddingInfo,

PBYTE pbOutput,

DWORD   cbOutput,

DWORD * pcbResult,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptDecrypt(

NCRYPT_KEY_HANDLE hKey,

PBYTE pbInput,

DWORD   cbInput,

VOID *pPaddingInfo,

PBYTE pbOutput,

DWORD   cbOutput,

DWORD * pcbResult,

DWORD   dwFlags);

typedef struct _NCRYPT_KEY_BLOB_HEADER

{

ULONG   cbSize;             

ULONG   dwMagic;

ULONG   cbAlgName;          

ULONG   cbKeyData;

} NCRYPT_KEY_BLOB_HEADER, *PNCRYPT_KEY_BLOB_HEADER;

typedef struct NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER

{

DWORD magic;

DWORD cbHeader;

DWORD cbPublic;

DWORD cbPrivate;

DWORD cbName;

} NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER, *PNCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER;

SECURITY_STATUS

__stdcall

NCryptImportKey(

NCRYPT_PROV_HANDLE hProvider,

NCRYPT_KEY_HANDLE hImportKey,

LPCWSTR pszBlobType,

NCryptBufferDesc *pParameterList,

NCRYPT_KEY_HANDLE *phKey,

PBYTE pbData,

DWORD   cbData,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptExportKey(

NCRYPT_KEY_HANDLE hKey,

NCRYPT_KEY_HANDLE hExportKey,

LPCWSTR pszBlobType,

NCryptBufferDesc *pParameterList,

PBYTE pbOutput,

DWORD   cbOutput,

DWORD * pcbResult,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptSignHash(

NCRYPT_KEY_HANDLE hKey,

VOID *pPaddingInfo,

PBYTE pbHashValue,

DWORD   cbHashValue,

PBYTE pbSignature,

DWORD   cbSignature,

DWORD * pcbResult,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptVerifySignature(

NCRYPT_KEY_HANDLE hKey,

VOID *pPaddingInfo,

PBYTE pbHashValue,

DWORD   cbHashValue,

PBYTE pbSignature,

DWORD   cbSignature,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptDeleteKey(

NCRYPT_KEY_HANDLE hKey,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptFreeObject(

NCRYPT_HANDLE hObject);

#pragma region Desktop Family or OneCore Family

BOOL

__stdcall

NCryptIsKeyHandle(

NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS

__stdcall

NCryptTranslateHandle(

NCRYPT_PROV_HANDLE *phProvider,

NCRYPT_KEY_HANDLE *phKey,

HCRYPTPROV hLegacyProv,

HCRYPTKEY hLegacyKey,

DWORD  dwLegacyKeySpec,

DWORD   dwFlags);

#pragma endregion

#pragma region Desktop Family or OneCore Family

SECURITY_STATUS

__stdcall

NCryptNotifyChangeKey(

NCRYPT_PROV_HANDLE hProvider,

HANDLE *phEvent,

DWORD   dwFlags);

#pragma endregion

SECURITY_STATUS

__stdcall

NCryptSecretAgreement(

NCRYPT_KEY_HANDLE hPrivKey,

NCRYPT_KEY_HANDLE hPubKey,

NCRYPT_SECRET_HANDLE *phAgreedSecret,

DWORD   dwFlags);

SECURITY_STATUS

__stdcall

NCryptDeriveKey(

NCRYPT_SECRET_HANDLE hSharedSecret,

LPCWSTR              pwszKDF,

NCryptBufferDesc     *pParameterList,

PBYTE pbDerivedKey,

DWORD                cbDerivedKey,

DWORD                *pcbResult,

ULONG                dwFlags);

SECURITY_STATUS

__stdcall

NCryptKeyDerivation(

NCRYPT_KEY_HANDLE   hKey,

NCryptBufferDesc    *pParameterList,

PUCHAR pbDerivedKey,

DWORD               cbDerivedKey,

DWORD               *pcbResult,

ULONG               dwFlags);

SECURITY_STATUS

__stdcall

NCryptCreateClaim(

NCRYPT_KEY_HANDLE   hSubjectKey,

NCRYPT_KEY_HANDLE   hAuthorityKey,

DWORD               dwClaimType,

NCryptBufferDesc    *pParameterList,

PBYTE pbClaimBlob,

DWORD               cbClaimBlob,

DWORD               *pcbResult,

DWORD               dwFlags);

SECURITY_STATUS

__stdcall

NCryptVerifyClaim(

NCRYPT_KEY_HANDLE   hSubjectKey,

NCRYPT_KEY_HANDLE   hAuthorityKey,

DWORD               dwClaimType,

NCryptBufferDesc    *pParameterList,

PBYTE pbClaimBlob,

DWORD               cbClaimBlob,

NCryptBufferDesc    *pOutput,

DWORD               dwFlags);

#pragma warning(pop)

typedef ULONG_PTR HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;

typedef ULONG_PTR HCRYPTPROV_LEGACY;

typedef struct _CRYPT_BIT_BLOB {

DWORD   cbData;

BYTE    *pbData;

DWORD   cUnusedBits;

} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER {

LPSTR               pszObjId;

CRYPT_OBJID_BLOB    Parameters;

} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CRYPT_OBJID_TABLE {

DWORD   dwAlgId;

LPCSTR  pszObjId;

} CRYPT_OBJID_TABLE, *PCRYPT_OBJID_TABLE;

typedef struct _CRYPT_HASH_INFO {

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_HASH_BLOB             Hash;

} CRYPT_HASH_INFO, *PCRYPT_HASH_INFO;

typedef struct _CERT_EXTENSION {

LPSTR               pszObjId;

BOOL                fCritical;

CRYPT_OBJID_BLOB    Value;

} CERT_EXTENSION, *PCERT_EXTENSION;

typedef const CERT_EXTENSION* PCCERT_EXTENSION;

typedef struct _CRYPT_ATTRIBUTE_TYPE_VALUE {

LPSTR               pszObjId;

CRYPT_OBJID_BLOB    Value;

} CRYPT_ATTRIBUTE_TYPE_VALUE, *PCRYPT_ATTRIBUTE_TYPE_VALUE;

typedef struct _CRYPT_ATTRIBUTE {

LPSTR               pszObjId;

DWORD               cValue;

PCRYPT_ATTR_BLOB    rgValue;

} CRYPT_ATTRIBUTE, *PCRYPT_ATTRIBUTE;

typedef struct _CRYPT_ATTRIBUTES {

DWORD                cAttr;

PCRYPT_ATTRIBUTE     rgAttr;

} CRYPT_ATTRIBUTES, *PCRYPT_ATTRIBUTES;

typedef struct _CERT_RDN_ATTR {

LPSTR                   pszObjId;

DWORD                   dwValueType;

CERT_RDN_VALUE_BLOB     Value;

} CERT_RDN_ATTR, *PCERT_RDN_ATTR;

typedef struct _CERT_RDN {

DWORD           cRDNAttr;

PCERT_RDN_ATTR  rgRDNAttr;

} CERT_RDN, *PCERT_RDN;

typedef struct _CERT_NAME_INFO {

DWORD       cRDN;

PCERT_RDN   rgRDN;

} CERT_NAME_INFO, *PCERT_NAME_INFO;

typedef struct _CERT_NAME_VALUE {

DWORD               dwValueType;

CERT_RDN_VALUE_BLOB Value;

} CERT_NAME_VALUE, *PCERT_NAME_VALUE;

typedef struct _CERT_PUBLIC_KEY_INFO {

CRYPT_ALGORITHM_IDENTIFIER    Algorithm;

CRYPT_BIT_BLOB                PublicKey;

} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO{

DWORD                       dwVersion;  

CRYPT_DER_BLOB              PrivateKey; 

LPSTR                       szCurveOid; 

CRYPT_BIT_BLOB              PublicKey;  

}  CRYPT_ECC_PRIVATE_KEY_INFO, *PCRYPT_ECC_PRIVATE_KEY_INFO;

typedef struct _CRYPT_PRIVATE_KEY_INFO{

DWORD                       Version;

CRYPT_ALGORITHM_IDENTIFIER  Algorithm;

CRYPT_DER_BLOB              PrivateKey;

PCRYPT_ATTRIBUTES           pAttributes;

}  CRYPT_PRIVATE_KEY_INFO, *PCRYPT_PRIVATE_KEY_INFO;

typedef struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO{

CRYPT_ALGORITHM_IDENTIFIER  EncryptionAlgorithm;

CRYPT_DATA_BLOB             EncryptedPrivateKey;

} CRYPT_ENCRYPTED_PRIVATE_KEY_INFO, *PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO;

typedef BOOL (__stdcall *PCRYPT_DECRYPT_PRIVATE_KEY_FUNC)(

CRYPT_ALGORITHM_IDENTIFIER Algorithm,

CRYPT_DATA_BLOB EncryptedPrivateKey,

BYTE* pbClearTextKey,

DWORD* pcbClearTextKey,

LPVOID pVoidDecryptFunc);

typedef BOOL (__stdcall *PCRYPT_ENCRYPT_PRIVATE_KEY_FUNC)(

CRYPT_ALGORITHM_IDENTIFIER* pAlgorithm,

CRYPT_DATA_BLOB* pClearTextPrivateKey,

BYTE* pbEncryptedKey,

DWORD* pcbEncryptedKey,

LPVOID pVoidEncryptFunc);

typedef BOOL (__stdcall *PCRYPT_RESOLVE_HCRYPTPROV_FUNC)(

CRYPT_PRIVATE_KEY_INFO      *pPrivateKeyInfo,

HCRYPTPROV                  *phCryptProv,

LPVOID                      pVoidResolveFunc);

typedef struct _CRYPT_PKCS8_IMPORT_PARAMS{

CRYPT_DIGEST_BLOB               PrivateKey;             

PCRYPT_RESOLVE_HCRYPTPROV_FUNC  pResolvehCryptProvFunc; 

LPVOID                          pVoidResolveFunc;       

PCRYPT_DECRYPT_PRIVATE_KEY_FUNC pDecryptPrivateKeyFunc;

LPVOID                          pVoidDecryptFunc;

} CRYPT_PKCS8_IMPORT_PARAMS, *PCRYPT_PKCS8_IMPORT_PARAMS, CRYPT_PRIVATE_KEY_BLOB_AND_PARAMS, *PCRYPT_PRIVATE_KEY_BLOB_AND_PARAMS;

typedef struct _CRYPT_PKCS8_EXPORT_PARAMS{

HCRYPTPROV                      hCryptProv;

DWORD                           dwKeySpec;

LPSTR                           pszPrivateKeyObjId;

PCRYPT_ENCRYPT_PRIVATE_KEY_FUNC pEncryptPrivateKeyFunc;

LPVOID                          pVoidEncryptFunc;

} CRYPT_PKCS8_EXPORT_PARAMS, *PCRYPT_PKCS8_EXPORT_PARAMS;

typedef struct _CERT_INFO {

DWORD                       dwVersion;

CRYPT_INTEGER_BLOB          SerialNumber;

CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;

CERT_NAME_BLOB              Issuer;

FILETIME                    NotBefore;

FILETIME                    NotAfter;

CERT_NAME_BLOB              Subject;

CERT_PUBLIC_KEY_INFO        SubjectPublicKeyInfo;

CRYPT_BIT_BLOB              IssuerUniqueId;

CRYPT_BIT_BLOB              SubjectUniqueId;

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;

} CERT_INFO, *PCERT_INFO;

typedef struct _CRL_ENTRY {

CRYPT_INTEGER_BLOB  SerialNumber;

FILETIME            RevocationDate;

DWORD               cExtension;

PCERT_EXTENSION     rgExtension;

} CRL_ENTRY, *PCRL_ENTRY;

typedef struct _CRL_INFO {

DWORD                       dwVersion;

CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;

CERT_NAME_BLOB              Issuer;

FILETIME                    ThisUpdate;

FILETIME                    NextUpdate;

DWORD                       cCRLEntry;

PCRL_ENTRY                  rgCRLEntry;

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;

} CRL_INFO, *PCRL_INFO;

typedef struct _CERT_OR_CRL_BLOB {

DWORD                   dwChoice;

DWORD                   cbEncoded;

BYTE                    *pbEncoded;

} CERT_OR_CRL_BLOB, * PCERT_OR_CRL_BLOB;

typedef struct _CERT_OR_CRL_BUNDLE {

DWORD                   cItem;

PCERT_OR_CRL_BLOB       rgItem;

} CERT_OR_CRL_BUNDLE, *PCERT_OR_CRL_BUNDLE;

typedef struct _CERT_REQUEST_INFO {

DWORD                   dwVersion;

CERT_NAME_BLOB          Subject;

CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;

DWORD                   cAttribute;

PCRYPT_ATTRIBUTE        rgAttribute;

} CERT_REQUEST_INFO, *PCERT_REQUEST_INFO;

typedef struct _CERT_KEYGEN_REQUEST_INFO {

DWORD                   dwVersion;

CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;

LPWSTR                  pwszChallengeString;        

} CERT_KEYGEN_REQUEST_INFO, *PCERT_KEYGEN_REQUEST_INFO;

typedef struct _CERT_SIGNED_CONTENT_INFO {

CRYPT_DER_BLOB              ToBeSigned;

CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;

CRYPT_BIT_BLOB              Signature;

} CERT_SIGNED_CONTENT_INFO, *PCERT_SIGNED_CONTENT_INFO;

typedef struct _CTL_USAGE {

DWORD               cUsageIdentifier;

LPSTR               *rgpszUsageIdentifier;      

} CTL_USAGE, *PCTL_USAGE,

CERT_ENHKEY_USAGE, *PCERT_ENHKEY_USAGE;

typedef const CTL_USAGE* PCCTL_USAGE;

typedef const CERT_ENHKEY_USAGE* PCCERT_ENHKEY_USAGE;

typedef struct _CTL_ENTRY {

CRYPT_DATA_BLOB     SubjectIdentifier;          

DWORD               cAttribute;

PCRYPT_ATTRIBUTE    rgAttribute;                

} CTL_ENTRY, *PCTL_ENTRY;

typedef struct _CTL_INFO {

DWORD                       dwVersion;

CTL_USAGE                   SubjectUsage;

CRYPT_DATA_BLOB             ListIdentifier;     

CRYPT_INTEGER_BLOB          SequenceNumber;     

FILETIME                    ThisUpdate;

FILETIME                    NextUpdate;         

CRYPT_ALGORITHM_IDENTIFIER  SubjectAlgorithm;

DWORD                       cCTLEntry;

PCTL_ENTRY                  rgCTLEntry;         

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;        

} CTL_INFO, *PCTL_INFO;

typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO {

LPSTR                   pszTimeStampAlgorithm;   

LPSTR                   pszContentType;          

CRYPT_OBJID_BLOB        Content;

DWORD                   cAttribute;

PCRYPT_ATTRIBUTE        rgAttribute;

} CRYPT_TIME_STAMP_REQUEST_INFO, *PCRYPT_TIME_STAMP_REQUEST_INFO;

typedef struct _CRYPT_ENROLLMENT_NAME_VALUE_PAIR {

LPWSTR      pwszName;

LPWSTR      pwszValue;

} CRYPT_ENROLLMENT_NAME_VALUE_PAIR, * PCRYPT_ENROLLMENT_NAME_VALUE_PAIR;

typedef struct _CRYPT_CSP_PROVIDER {

DWORD           dwKeySpec;

LPWSTR          pwszProviderName;

CRYPT_BIT_BLOB  Signature;

} CRYPT_CSP_PROVIDER, * PCRYPT_CSP_PROVIDER;

BOOL

__stdcall

CryptFormatObject(

DWORD dwCertEncodingType,

DWORD dwFormatType,

DWORD dwFormatStrType,

void *pFormatStruct,

LPCSTR lpszStructType,

const BYTE *pbEncoded,

DWORD cbEncoded,

void *pbFormat,

DWORD *pcbFormat

);

typedef LPVOID (__stdcall *PFN_CRYPT_ALLOC)(

size_t cbSize

);

typedef VOID (__stdcall *PFN_CRYPT_FREE)(

LPVOID pv

);

typedef struct _CRYPT_ENCODE_PARA {

DWORD                   cbSize;

PFN_CRYPT_ALLOC         pfnAlloc;           

PFN_CRYPT_FREE          pfnFree;            

} CRYPT_ENCODE_PARA, *PCRYPT_ENCODE_PARA;

BOOL

__stdcall

CryptEncodeObjectEx(

DWORD dwCertEncodingType,

LPCSTR lpszStructType,

const void *pvStructInfo,

DWORD dwFlags,

PCRYPT_ENCODE_PARA pEncodePara,

void *pvEncoded,

DWORD *pcbEncoded

);

BOOL

__stdcall

CryptEncodeObject(

DWORD dwCertEncodingType,

LPCSTR lpszStructType,

const void *pvStructInfo,

BYTE *pbEncoded,

DWORD *pcbEncoded

);

typedef struct _CRYPT_DECODE_PARA {

DWORD                   cbSize;

PFN_CRYPT_ALLOC         pfnAlloc;           

PFN_CRYPT_FREE          pfnFree;            

} CRYPT_DECODE_PARA, *PCRYPT_DECODE_PARA;

BOOL

__stdcall

CryptDecodeObjectEx(

DWORD dwCertEncodingType,

LPCSTR lpszStructType,

const BYTE *pbEncoded,

DWORD cbEncoded,

DWORD dwFlags,

PCRYPT_DECODE_PARA pDecodePara,

void *pvStructInfo,

DWORD *pcbStructInfo

);

BOOL

__stdcall

CryptDecodeObject(

DWORD dwCertEncodingType,

LPCSTR lpszStructType,

const BYTE *pbEncoded,

DWORD cbEncoded,

DWORD dwFlags,

void *pvStructInfo,

DWORD *pcbStructInfo

);

typedef struct _CERT_EXTENSIONS {

DWORD           cExtension;

PCERT_EXTENSION rgExtension;

} CERT_EXTENSIONS, *PCERT_EXTENSIONS;

typedef struct _CERT_AUTHORITY_KEY_ID_INFO {

CRYPT_DATA_BLOB     KeyId;

CERT_NAME_BLOB      CertIssuer;

CRYPT_INTEGER_BLOB  CertSerialNumber;

} CERT_AUTHORITY_KEY_ID_INFO, *PCERT_AUTHORITY_KEY_ID_INFO;

typedef struct _CERT_PRIVATE_KEY_VALIDITY {

FILETIME            NotBefore;

FILETIME            NotAfter;

} CERT_PRIVATE_KEY_VALIDITY, *PCERT_PRIVATE_KEY_VALIDITY;

typedef struct _CERT_KEY_ATTRIBUTES_INFO {

CRYPT_DATA_BLOB             KeyId;

CRYPT_BIT_BLOB              IntendedKeyUsage;

PCERT_PRIVATE_KEY_VALIDITY  pPrivateKeyUsagePeriod;     

} CERT_KEY_ATTRIBUTES_INFO, *PCERT_KEY_ATTRIBUTES_INFO;

typedef struct _CERT_POLICY_ID {

DWORD                   cCertPolicyElementId;

LPSTR                   *rgpszCertPolicyElementId;  

} CERT_POLICY_ID, *PCERT_POLICY_ID;

typedef struct _CERT_KEY_USAGE_RESTRICTION_INFO {

DWORD                   cCertPolicyId;

PCERT_POLICY_ID         rgCertPolicyId;

CRYPT_BIT_BLOB          RestrictedKeyUsage;

} CERT_KEY_USAGE_RESTRICTION_INFO, *PCERT_KEY_USAGE_RESTRICTION_INFO;

typedef struct _CERT_OTHER_NAME {

LPSTR               pszObjId;

CRYPT_OBJID_BLOB    Value;

} CERT_OTHER_NAME, *PCERT_OTHER_NAME;

typedef struct _CERT_ALT_NAME_ENTRY {

DWORD   dwAltNameChoice;

union {                                             

PCERT_OTHER_NAME            pOtherName;         

LPWSTR                      pwszRfc822Name;     

LPWSTR                      pwszDNSName;        

CERT_NAME_BLOB              DirectoryName;      

LPWSTR                      pwszURL;            

CRYPT_DATA_BLOB             IPAddress;          

LPSTR                       pszRegisteredID;    

} DUMMYUNIONNAME;                                   

} CERT_ALT_NAME_ENTRY, *PCERT_ALT_NAME_ENTRY;

typedef struct _CERT_ALT_NAME_INFO {

DWORD                   cAltEntry;

PCERT_ALT_NAME_ENTRY    rgAltEntry;

} CERT_ALT_NAME_INFO, *PCERT_ALT_NAME_INFO;

typedef struct _CERT_BASIC_CONSTRAINTS_INFO {

CRYPT_BIT_BLOB          SubjectType;

BOOL                    fPathLenConstraint;

DWORD                   dwPathLenConstraint;

DWORD                   cSubtreesConstraint;

CERT_NAME_BLOB          *rgSubtreesConstraint;

} CERT_BASIC_CONSTRAINTS_INFO, *PCERT_BASIC_CONSTRAINTS_INFO;

typedef struct _CERT_BASIC_CONSTRAINTS2_INFO {

BOOL                    fCA;

BOOL                    fPathLenConstraint;

DWORD                   dwPathLenConstraint;

} CERT_BASIC_CONSTRAINTS2_INFO, *PCERT_BASIC_CONSTRAINTS2_INFO;

typedef struct _CERT_POLICY_QUALIFIER_INFO {

LPSTR                       pszPolicyQualifierId;   

CRYPT_OBJID_BLOB            Qualifier;              

} CERT_POLICY_QUALIFIER_INFO, *PCERT_POLICY_QUALIFIER_INFO;

typedef struct _CERT_POLICY_INFO {

LPSTR                       pszPolicyIdentifier;    

DWORD                       cPolicyQualifier;       

CERT_POLICY_QUALIFIER_INFO  *rgPolicyQualifier;

} CERT_POLICY_INFO, *PCERT_POLICY_INFO;

typedef struct _CERT_POLICIES_INFO {

DWORD                       cPolicyInfo;

CERT_POLICY_INFO            *rgPolicyInfo;

} CERT_POLICIES_INFO, *PCERT_POLICIES_INFO;

typedef struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE {

LPSTR   pszOrganization;

DWORD   cNoticeNumbers;

int     *rgNoticeNumbers;

} CERT_POLICY_QUALIFIER_NOTICE_REFERENCE, *PCERT_POLICY_QUALIFIER_NOTICE_REFERENCE;

typedef struct _CERT_POLICY_QUALIFIER_USER_NOTICE {

CERT_POLICY_QUALIFIER_NOTICE_REFERENCE  *pNoticeReference;  

LPWSTR                                  pszDisplayText;     

} CERT_POLICY_QUALIFIER_USER_NOTICE, *PCERT_POLICY_QUALIFIER_USER_NOTICE;

typedef struct _CPS_URLS {

LPWSTR                      pszURL;

CRYPT_ALGORITHM_IDENTIFIER  *pAlgorithm; 

CRYPT_DATA_BLOB             *pDigest;    

} CPS_URLS, *PCPS_URLS;

typedef struct _CERT_POLICY95_QUALIFIER1 {

LPWSTR      pszPracticesReference;      

LPSTR       pszNoticeIdentifier;        

LPSTR       pszNSINoticeIdentifier;     

DWORD       cCPSURLs;

CPS_URLS    *rgCPSURLs;                 

} CERT_POLICY95_QUALIFIER1, *PCERT_POLICY95_QUALIFIER1;

typedef struct _CERT_POLICY_MAPPING {

LPSTR                       pszIssuerDomainPolicy;      

LPSTR                       pszSubjectDomainPolicy;     

} CERT_POLICY_MAPPING, *PCERT_POLICY_MAPPING;

typedef struct _CERT_POLICY_MAPPINGS_INFO {

DWORD                       cPolicyMapping;

PCERT_POLICY_MAPPING        rgPolicyMapping;

} CERT_POLICY_MAPPINGS_INFO, *PCERT_POLICY_MAPPINGS_INFO;

typedef struct _CERT_POLICY_CONSTRAINTS_INFO {

BOOL                        fRequireExplicitPolicy;

DWORD                       dwRequireExplicitPolicySkipCerts;

BOOL                        fInhibitPolicyMapping;

DWORD                       dwInhibitPolicyMappingSkipCerts;

} CERT_POLICY_CONSTRAINTS_INFO, *PCERT_POLICY_CONSTRAINTS_INFO;

typedef struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY {

LPSTR               pszObjId;

DWORD               cValue;

PCRYPT_DER_BLOB     rgValue;

} CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY, *PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;

typedef struct _CRYPT_CONTENT_INFO {

LPSTR               pszObjId;

CRYPT_DER_BLOB      Content;

} CRYPT_CONTENT_INFO, *PCRYPT_CONTENT_INFO;

typedef struct _CRYPT_SEQUENCE_OF_ANY {

DWORD               cValue;

PCRYPT_DER_BLOB     rgValue;

} CRYPT_SEQUENCE_OF_ANY, *PCRYPT_SEQUENCE_OF_ANY;

typedef struct _CERT_AUTHORITY_KEY_ID2_INFO {

CRYPT_DATA_BLOB     KeyId;

CERT_ALT_NAME_INFO  AuthorityCertIssuer;    

CRYPT_INTEGER_BLOB  AuthorityCertSerialNumber;

} CERT_AUTHORITY_KEY_ID2_INFO, *PCERT_AUTHORITY_KEY_ID2_INFO;

typedef struct _CERT_ACCESS_DESCRIPTION {

LPSTR               pszAccessMethod;        

CERT_ALT_NAME_ENTRY AccessLocation;

} CERT_ACCESS_DESCRIPTION, *PCERT_ACCESS_DESCRIPTION;

typedef struct _CERT_AUTHORITY_INFO_ACCESS {

DWORD                       cAccDescr;

PCERT_ACCESS_DESCRIPTION    rgAccDescr;

} CERT_AUTHORITY_INFO_ACCESS, *PCERT_AUTHORITY_INFO_ACCESS,

CERT_SUBJECT_INFO_ACCESS, *PCERT_SUBJECT_INFO_ACCESS;

typedef struct _CRL_DIST_POINT_NAME {

DWORD   dwDistPointNameChoice;

union {

CERT_ALT_NAME_INFO      FullName;       

} DUMMYUNIONNAME;

} CRL_DIST_POINT_NAME, *PCRL_DIST_POINT_NAME;

typedef struct _CRL_DIST_POINT {

CRL_DIST_POINT_NAME     DistPointName;      

CRYPT_BIT_BLOB          ReasonFlags;        

CERT_ALT_NAME_INFO      CRLIssuer;          

} CRL_DIST_POINT, *PCRL_DIST_POINT;

typedef struct _CRL_DIST_POINTS_INFO {

DWORD                   cDistPoint;

PCRL_DIST_POINT         rgDistPoint;

} CRL_DIST_POINTS_INFO, *PCRL_DIST_POINTS_INFO;

typedef struct _CROSS_CERT_DIST_POINTS_INFO {

DWORD                   dwSyncDeltaTime;

DWORD                   cDistPoint;

PCERT_ALT_NAME_INFO     rgDistPoint;

} CROSS_CERT_DIST_POINTS_INFO, *PCROSS_CERT_DIST_POINTS_INFO;

typedef struct _CERT_PAIR {

CERT_BLOB    Forward;        

CERT_BLOB    Reverse;        

} CERT_PAIR, *PCERT_PAIR;

typedef struct _CRL_ISSUING_DIST_POINT {

CRL_DIST_POINT_NAME     DistPointName;              

BOOL                    fOnlyContainsUserCerts;

BOOL                    fOnlyContainsCACerts;

CRYPT_BIT_BLOB          OnlySomeReasonFlags;        

BOOL                    fIndirectCRL;

} CRL_ISSUING_DIST_POINT, *PCRL_ISSUING_DIST_POINT;

typedef struct _CERT_GENERAL_SUBTREE {

CERT_ALT_NAME_ENTRY     Base;

DWORD                   dwMinimum;

BOOL                    fMaximum;

DWORD                   dwMaximum;

} CERT_GENERAL_SUBTREE, *PCERT_GENERAL_SUBTREE;

typedef struct _CERT_NAME_CONSTRAINTS_INFO {

DWORD                   cPermittedSubtree;

PCERT_GENERAL_SUBTREE   rgPermittedSubtree;

DWORD                   cExcludedSubtree;

PCERT_GENERAL_SUBTREE   rgExcludedSubtree;

} CERT_NAME_CONSTRAINTS_INFO, *PCERT_NAME_CONSTRAINTS_INFO;

typedef struct _CERT_DSS_PARAMETERS {

CRYPT_UINT_BLOB     p;

CRYPT_UINT_BLOB     q;

CRYPT_UINT_BLOB     g;

} CERT_DSS_PARAMETERS, *PCERT_DSS_PARAMETERS;

typedef struct _CERT_DH_PARAMETERS {

CRYPT_UINT_BLOB     p;

CRYPT_UINT_BLOB     g;

} CERT_DH_PARAMETERS, *PCERT_DH_PARAMETERS;

typedef struct _CERT_ECC_SIGNATURE {

CRYPT_UINT_BLOB     r;

CRYPT_UINT_BLOB     s;

} CERT_ECC_SIGNATURE, *PCERT_ECC_SIGNATURE;

typedef struct _CERT_X942_DH_VALIDATION_PARAMS {

CRYPT_BIT_BLOB      seed;

DWORD               pgenCounter;

} CERT_X942_DH_VALIDATION_PARAMS, *PCERT_X942_DH_VALIDATION_PARAMS;

typedef struct _CERT_X942_DH_PARAMETERS {

CRYPT_UINT_BLOB     p;          

CRYPT_UINT_BLOB     g;          

CRYPT_UINT_BLOB     q;          

CRYPT_UINT_BLOB     j;          

PCERT_X942_DH_VALIDATION_PARAMS pValidationParams;  

} CERT_X942_DH_PARAMETERS, *PCERT_X942_DH_PARAMETERS;

typedef struct _CRYPT_X942_OTHER_INFO {

LPSTR               pszContentEncryptionObjId;

BYTE                rgbCounter[4];

BYTE                rgbKeyLength[4];

CRYPT_DATA_BLOB     PubInfo;    

} CRYPT_X942_OTHER_INFO, *PCRYPT_X942_OTHER_INFO;

typedef struct _CRYPT_ECC_CMS_SHARED_INFO {

CRYPT_ALGORITHM_IDENTIFIER  Algorithm;

CRYPT_DATA_BLOB             EntityUInfo;    

BYTE                        rgbSuppPubInfo[4];

} CRYPT_ECC_CMS_SHARED_INFO, *PCRYPT_ECC_CMS_SHARED_INFO;

typedef struct _CRYPT_RC2_CBC_PARAMETERS {

DWORD               dwVersion;

BOOL                fIV;            

BYTE                rgbIV[8];

} CRYPT_RC2_CBC_PARAMETERS, *PCRYPT_RC2_CBC_PARAMETERS;

typedef struct _CRYPT_SMIME_CAPABILITY {

LPSTR               pszObjId;

CRYPT_OBJID_BLOB    Parameters;

} CRYPT_SMIME_CAPABILITY, *PCRYPT_SMIME_CAPABILITY;

typedef struct _CRYPT_SMIME_CAPABILITIES {

DWORD                   cCapability;

PCRYPT_SMIME_CAPABILITY rgCapability;

} CRYPT_SMIME_CAPABILITIES, *PCRYPT_SMIME_CAPABILITIES;

typedef struct _CERT_QC_STATEMENT {

LPSTR               pszStatementId;     

CRYPT_OBJID_BLOB    StatementInfo;      

} CERT_QC_STATEMENT, *PCERT_QC_STATEMENT;

typedef struct _CERT_QC_STATEMENTS_EXT_INFO {

DWORD                   cStatement;

PCERT_QC_STATEMENT      rgStatement;

} CERT_QC_STATEMENTS_EXT_INFO, *PCERT_QC_STATEMENTS_EXT_INFO;

typedef struct _CRYPT_MASK_GEN_ALGORITHM {

LPSTR                       pszObjId;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

} CRYPT_MASK_GEN_ALGORITHM, *PCRYPT_MASK_GEN_ALGORITHM;

typedef struct _CRYPT_RSA_SSA_PSS_PARAMETERS {

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_MASK_GEN_ALGORITHM    MaskGenAlgorithm;

DWORD                       dwSaltLength;

DWORD                       dwTrailerField;

} CRYPT_RSA_SSA_PSS_PARAMETERS, *PCRYPT_RSA_SSA_PSS_PARAMETERS;

typedef struct _CRYPT_PSOURCE_ALGORITHM {

LPSTR                       pszObjId;

CRYPT_DATA_BLOB             EncodingParameters;

} CRYPT_PSOURCE_ALGORITHM, *PCRYPT_PSOURCE_ALGORITHM;

typedef struct _CRYPT_RSAES_OAEP_PARAMETERS {

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_MASK_GEN_ALGORITHM    MaskGenAlgorithm;

CRYPT_PSOURCE_ALGORITHM     PSourceAlgorithm;

} CRYPT_RSAES_OAEP_PARAMETERS, *PCRYPT_RSAES_OAEP_PARAMETERS;

typedef struct _CMC_TAGGED_ATTRIBUTE {

DWORD               dwBodyPartID;

CRYPT_ATTRIBUTE     Attribute;

} CMC_TAGGED_ATTRIBUTE, *PCMC_TAGGED_ATTRIBUTE;

typedef struct _CMC_TAGGED_CERT_REQUEST {

DWORD               dwBodyPartID;

CRYPT_DER_BLOB      SignedCertRequest;

} CMC_TAGGED_CERT_REQUEST, *PCMC_TAGGED_CERT_REQUEST;

typedef struct _CMC_TAGGED_REQUEST {

DWORD               dwTaggedRequestChoice;

union {

PCMC_TAGGED_CERT_REQUEST   pTaggedCertRequest;

} DUMMYUNIONNAME;

} CMC_TAGGED_REQUEST, *PCMC_TAGGED_REQUEST;

typedef struct _CMC_TAGGED_CONTENT_INFO {

DWORD               dwBodyPartID;

CRYPT_DER_BLOB      EncodedContentInfo;

} CMC_TAGGED_CONTENT_INFO, *PCMC_TAGGED_CONTENT_INFO;

typedef struct _CMC_TAGGED_OTHER_MSG {

DWORD               dwBodyPartID;

LPSTR               pszObjId;

CRYPT_OBJID_BLOB    Value;

} CMC_TAGGED_OTHER_MSG, *PCMC_TAGGED_OTHER_MSG;

typedef struct _CMC_DATA_INFO {

DWORD                       cTaggedAttribute;

PCMC_TAGGED_ATTRIBUTE       rgTaggedAttribute;

DWORD                       cTaggedRequest;

PCMC_TAGGED_REQUEST         rgTaggedRequest;

DWORD                       cTaggedContentInfo;

PCMC_TAGGED_CONTENT_INFO    rgTaggedContentInfo;

DWORD                       cTaggedOtherMsg;

PCMC_TAGGED_OTHER_MSG       rgTaggedOtherMsg;

} CMC_DATA_INFO, *PCMC_DATA_INFO;

typedef struct _CMC_RESPONSE_INFO {

DWORD                       cTaggedAttribute;

PCMC_TAGGED_ATTRIBUTE       rgTaggedAttribute;

DWORD                       cTaggedContentInfo;

PCMC_TAGGED_CONTENT_INFO    rgTaggedContentInfo;

DWORD                       cTaggedOtherMsg;

PCMC_TAGGED_OTHER_MSG       rgTaggedOtherMsg;

} CMC_RESPONSE_INFO, *PCMC_RESPONSE_INFO;

typedef struct _CMC_PEND_INFO {

CRYPT_DATA_BLOB             PendToken;

FILETIME                    PendTime;

} CMC_PEND_INFO, *PCMC_PEND_INFO;

typedef struct _CMC_STATUS_INFO {

DWORD                       dwStatus;

DWORD                       cBodyList;

DWORD                       *rgdwBodyList;

LPWSTR                      pwszStatusString;   

DWORD                       dwOtherInfoChoice;

union  {

DWORD                       dwFailInfo;

PCMC_PEND_INFO              pPendInfo;

} DUMMYUNIONNAME;

} CMC_STATUS_INFO, *PCMC_STATUS_INFO;

typedef struct _CMC_ADD_EXTENSIONS_INFO {

DWORD                       dwCmcDataReference;

DWORD                       cCertReference;

DWORD                       *rgdwCertReference;

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;

} CMC_ADD_EXTENSIONS_INFO, *PCMC_ADD_EXTENSIONS_INFO;

typedef struct _CMC_ADD_ATTRIBUTES_INFO {

DWORD                       dwCmcDataReference;

DWORD                       cCertReference;

DWORD                       *rgdwCertReference;

DWORD                       cAttribute;

PCRYPT_ATTRIBUTE            rgAttribute;

} CMC_ADD_ATTRIBUTES_INFO, *PCMC_ADD_ATTRIBUTES_INFO;

typedef struct _CERT_TEMPLATE_EXT {

LPSTR               pszObjId;

DWORD               dwMajorVersion;

BOOL                fMinorVersion;      

DWORD               dwMinorVersion;

} CERT_TEMPLATE_EXT, *PCERT_TEMPLATE_EXT;

typedef struct _CERT_HASHED_URL {

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_HASH_BLOB             Hash;

LPWSTR                      pwszUrl;    

} CERT_HASHED_URL, *PCERT_HASHED_URL;

typedef struct _CERT_LOGOTYPE_DETAILS {

LPWSTR                      pwszMimeType;   

DWORD                       cHashedUrl;

PCERT_HASHED_URL            rgHashedUrl;

} CERT_LOGOTYPE_DETAILS, *PCERT_LOGOTYPE_DETAILS;

typedef struct _CERT_LOGOTYPE_REFERENCE {

DWORD                       cHashedUrl;

PCERT_HASHED_URL            rgHashedUrl;

} CERT_LOGOTYPE_REFERENCE, *PCERT_LOGOTYPE_REFERENCE;

typedef struct _CERT_LOGOTYPE_IMAGE_INFO {

DWORD                       dwLogotypeImageInfoChoice;

DWORD                       dwFileSize;     

DWORD                       dwXSize;        

DWORD                       dwYSize;        

DWORD                       dwLogotypeImageResolutionChoice;

union {

DWORD                       dwNumBits;      

DWORD                       dwTableSize;    

} DUMMYUNIONNAME;

LPWSTR                      pwszLanguage;   

} CERT_LOGOTYPE_IMAGE_INFO, *PCERT_LOGOTYPE_IMAGE_INFO;

typedef struct _CERT_LOGOTYPE_IMAGE {

CERT_LOGOTYPE_DETAILS       LogotypeDetails;

PCERT_LOGOTYPE_IMAGE_INFO   pLogotypeImageInfo; 

} CERT_LOGOTYPE_IMAGE, *PCERT_LOGOTYPE_IMAGE;

typedef struct _CERT_LOGOTYPE_AUDIO_INFO {

DWORD                       dwFileSize;     

DWORD                       dwPlayTime;     

DWORD                       dwChannels;     

DWORD                       dwSampleRate;   

LPWSTR                      pwszLanguage;   

} CERT_LOGOTYPE_AUDIO_INFO, *PCERT_LOGOTYPE_AUDIO_INFO;

typedef struct _CERT_LOGOTYPE_AUDIO {

CERT_LOGOTYPE_DETAILS       LogotypeDetails;

PCERT_LOGOTYPE_AUDIO_INFO   pLogotypeAudioInfo; 

} CERT_LOGOTYPE_AUDIO, *PCERT_LOGOTYPE_AUDIO;

typedef struct _CERT_LOGOTYPE_DATA {

DWORD                       cLogotypeImage;

PCERT_LOGOTYPE_IMAGE        rgLogotypeImage;

DWORD                       cLogotypeAudio;

PCERT_LOGOTYPE_AUDIO        rgLogotypeAudio;

} CERT_LOGOTYPE_DATA, *PCERT_LOGOTYPE_DATA;

typedef struct _CERT_LOGOTYPE_INFO {

DWORD                       dwLogotypeInfoChoice;

union {

PCERT_LOGOTYPE_DATA         pLogotypeDirectInfo;

PCERT_LOGOTYPE_REFERENCE    pLogotypeIndirectInfo;

} DUMMYUNIONNAME;

} CERT_LOGOTYPE_INFO, *PCERT_LOGOTYPE_INFO;

typedef struct _CERT_OTHER_LOGOTYPE_INFO {

LPSTR                       pszObjId;

CERT_LOGOTYPE_INFO          LogotypeInfo;

} CERT_OTHER_LOGOTYPE_INFO, *PCERT_OTHER_LOGOTYPE_INFO;

typedef struct _CERT_LOGOTYPE_EXT_INFO {

DWORD                       cCommunityLogo;

PCERT_LOGOTYPE_INFO         rgCommunityLogo;

PCERT_LOGOTYPE_INFO         pIssuerLogo;        

PCERT_LOGOTYPE_INFO         pSubjectLogo;       

DWORD                       cOtherLogo;

PCERT_OTHER_LOGOTYPE_INFO   rgOtherLogo;

} CERT_LOGOTYPE_EXT_INFO, *PCERT_LOGOTYPE_EXT_INFO;

typedef struct _CERT_BIOMETRIC_DATA {

DWORD                       dwTypeOfBiometricDataChoice;

union {

DWORD                       dwPredefined;

LPSTR                       pszObjId;

} DUMMYUNIONNAME;

CERT_HASHED_URL             HashedUrl;      

} CERT_BIOMETRIC_DATA, *PCERT_BIOMETRIC_DATA;

typedef struct _CERT_BIOMETRIC_EXT_INFO {

DWORD                       cBiometricData;

PCERT_BIOMETRIC_DATA        rgBiometricData;

} CERT_BIOMETRIC_EXT_INFO, *PCERT_BIOMETRIC_EXT_INFO;

typedef struct _OCSP_SIGNATURE_INFO {

CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;

CRYPT_BIT_BLOB              Signature;

DWORD                       cCertEncoded;

PCERT_BLOB                  rgCertEncoded;

} OCSP_SIGNATURE_INFO, *POCSP_SIGNATURE_INFO;

typedef struct _OCSP_SIGNED_REQUEST_INFO {

CRYPT_DER_BLOB              ToBeSigned;             

POCSP_SIGNATURE_INFO        pOptionalSignatureInfo; 

} OCSP_SIGNED_REQUEST_INFO, *POCSP_SIGNED_REQUEST_INFO;

typedef struct _OCSP_CERT_ID {

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;  

CRYPT_HASH_BLOB             IssuerNameHash; 

CRYPT_HASH_BLOB             IssuerKeyHash;  

CRYPT_INTEGER_BLOB          SerialNumber;

} OCSP_CERT_ID, *POCSP_CERT_ID;

typedef struct _OCSP_REQUEST_ENTRY {

OCSP_CERT_ID                CertId;

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;

} OCSP_REQUEST_ENTRY, *POCSP_REQUEST_ENTRY;

typedef struct _OCSP_REQUEST_INFO {

DWORD                       dwVersion;

PCERT_ALT_NAME_ENTRY        pRequestorName;     

DWORD                       cRequestEntry;

POCSP_REQUEST_ENTRY         rgRequestEntry;

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;

} OCSP_REQUEST_INFO, *POCSP_REQUEST_INFO;

typedef struct _OCSP_RESPONSE_INFO {

DWORD                       dwStatus;

LPSTR                       pszObjId;   

CRYPT_OBJID_BLOB            Value;      

} OCSP_RESPONSE_INFO, *POCSP_RESPONSE_INFO;

typedef struct _OCSP_BASIC_SIGNED_RESPONSE_INFO {

CRYPT_DER_BLOB              ToBeSigned;     

OCSP_SIGNATURE_INFO         SignatureInfo;

} OCSP_BASIC_SIGNED_RESPONSE_INFO, *POCSP_BASIC_SIGNED_RESPONSE_INFO;

typedef struct _OCSP_BASIC_REVOKED_INFO {

FILETIME                    RevocationDate;

DWORD                       dwCrlReasonCode;

} OCSP_BASIC_REVOKED_INFO, *POCSP_BASIC_REVOKED_INFO;

typedef struct _OCSP_BASIC_RESPONSE_ENTRY {

OCSP_CERT_ID                CertId;

DWORD                       dwCertStatus;

union {

POCSP_BASIC_REVOKED_INFO    pRevokedInfo;

} DUMMYUNIONNAME;

FILETIME                    ThisUpdate;

FILETIME                    NextUpdate; 

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;

} OCSP_BASIC_RESPONSE_ENTRY, *POCSP_BASIC_RESPONSE_ENTRY;

typedef struct _OCSP_BASIC_RESPONSE_INFO {

DWORD                       dwVersion;

DWORD                       dwResponderIdChoice;

union {

CERT_NAME_BLOB              ByNameResponderId;

CRYPT_HASH_BLOB              ByKeyResponderId;

} DUMMYUNIONNAME;

FILETIME                    ProducedAt;

DWORD                       cResponseEntry;

POCSP_BASIC_RESPONSE_ENTRY  rgResponseEntry;

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;

} OCSP_BASIC_RESPONSE_INFO, *POCSP_BASIC_RESPONSE_INFO;

typedef struct _CERT_SUPPORTED_ALGORITHM_INFO {

CRYPT_ALGORITHM_IDENTIFIER  Algorithm;

CRYPT_BIT_BLOB              IntendedKeyUsage;       

CERT_POLICIES_INFO          IntendedCertPolicies;   

} CERT_SUPPORTED_ALGORITHM_INFO, *PCERT_SUPPORTED_ALGORITHM_INFO;

typedef struct _CERT_TPM_SPECIFICATION_INFO {

LPWSTR                      pwszFamily;             

DWORD                       dwLevel;

DWORD                       dwRevision;

} CERT_TPM_SPECIFICATION_INFO, *PCERT_TPM_SPECIFICATION_INFO;

typedef void *HCRYPTOIDFUNCSET;

typedef void *HCRYPTOIDFUNCADDR;

typedef struct _CRYPT_OID_FUNC_ENTRY {

LPCSTR  pszOID;

void    *pvFuncAddr;

} CRYPT_OID_FUNC_ENTRY, *PCRYPT_OID_FUNC_ENTRY;

BOOL

__stdcall

CryptInstallOIDFunctionAddress(

HMODULE hModule,         

DWORD dwEncodingType,

LPCSTR pszFuncName,

DWORD cFuncEntry,

const CRYPT_OID_FUNC_ENTRY rgFuncEntry[],

DWORD dwFlags

);

HCRYPTOIDFUNCSET

__stdcall

CryptInitOIDFunctionSet(

LPCSTR pszFuncName,

DWORD dwFlags

);

BOOL

__stdcall

CryptGetOIDFunctionAddress(

HCRYPTOIDFUNCSET hFuncSet,

DWORD dwEncodingType,

LPCSTR pszOID,

DWORD dwFlags,

void **ppvFuncAddr,

HCRYPTOIDFUNCADDR *phFuncAddr

);

BOOL

__stdcall

CryptGetDefaultOIDDllList(

HCRYPTOIDFUNCSET hFuncSet,

DWORD dwEncodingType,

WCHAR *pwszDllList,

DWORD *pcchDllList

);

BOOL

__stdcall

CryptGetDefaultOIDFunctionAddress(

HCRYPTOIDFUNCSET hFuncSet,

DWORD dwEncodingType,

LPCWSTR pwszDll,

DWORD dwFlags,

void **ppvFuncAddr,

HCRYPTOIDFUNCADDR *phFuncAddr

);

BOOL

__stdcall

CryptFreeOIDFunctionAddress(

HCRYPTOIDFUNCADDR hFuncAddr,

DWORD dwFlags

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptRegisterOIDFunction(

DWORD dwEncodingType,

LPCSTR pszFuncName,

LPCSTR pszOID,

LPCWSTR pwszDll,

LPCSTR pszOverrideFuncName

);

BOOL

__stdcall

CryptUnregisterOIDFunction(

DWORD dwEncodingType,

LPCSTR pszFuncName,

LPCSTR pszOID

);

BOOL

__stdcall

CryptRegisterDefaultOIDFunction(

DWORD dwEncodingType,

LPCSTR pszFuncName,

DWORD dwIndex,

LPCWSTR pwszDll

);

BOOL

__stdcall

CryptUnregisterDefaultOIDFunction(

DWORD dwEncodingType,

LPCSTR pszFuncName,

LPCWSTR pwszDll

);

BOOL

__stdcall

CryptSetOIDFunctionValue(

DWORD dwEncodingType,

LPCSTR pszFuncName,

LPCSTR pszOID,

LPCWSTR pwszValueName,

DWORD dwValueType,

const BYTE *pbValueData,

DWORD cbValueData

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CryptGetOIDFunctionValue(

DWORD dwEncodingType,

LPCSTR pszFuncName,

LPCSTR pszOID,

LPCWSTR pwszValueName,

DWORD *pdwValueType,

BYTE *pbValueData,

DWORD *pcbValueData

);

typedef BOOL (__stdcall *PFN_CRYPT_ENUM_OID_FUNC)(

DWORD dwEncodingType,

LPCSTR pszFuncName,

LPCSTR pszOID,

DWORD cValue,

const DWORD rgdwValueType[],

LPCWSTR const rgpwszValueName[],

const BYTE * const rgpbValueData[],

const DWORD rgcbValueData[],

void *pvArg

);

BOOL

__stdcall

CryptEnumOIDFunction(

DWORD dwEncodingType,

LPCSTR pszFuncName,

LPCSTR pszOID,

DWORD dwFlags,

void *pvArg,

PFN_CRYPT_ENUM_OID_FUNC pfnEnumOIDFunc

);

typedef struct _CRYPT_OID_INFO {

DWORD           cbSize;

LPCSTR          pszOID;

LPCWSTR         pwszName;

DWORD           dwGroupId;

union {

DWORD       dwValue;

ALG_ID      Algid;

DWORD       dwLength;

} DUMMYUNIONNAME;

CRYPT_DATA_BLOB ExtraInfo;

} CRYPT_OID_INFO, *PCRYPT_OID_INFO;

typedef const CRYPT_OID_INFO CCRYPT_OID_INFO, *PCCRYPT_OID_INFO;

PCCRYPT_OID_INFO

__stdcall

CryptFindOIDInfo(

DWORD dwKeyType,

void *pvKey,

DWORD dwGroupId

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptRegisterOIDInfo(

PCCRYPT_OID_INFO pInfo,

DWORD dwFlags

);

BOOL

__stdcall

CryptUnregisterOIDInfo(

PCCRYPT_OID_INFO pInfo

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef BOOL (__stdcall *PFN_CRYPT_ENUM_OID_INFO)(

PCCRYPT_OID_INFO pInfo,

void *pvArg

);

BOOL

__stdcall

CryptEnumOIDInfo(

DWORD dwGroupId,

DWORD dwFlags,

void *pvArg,

PFN_CRYPT_ENUM_OID_INFO pfnEnumOIDInfo

);

LPCWSTR

__stdcall

CryptFindLocalizedName(

LPCWSTR pwszCryptName

);

typedef struct _CERT_STRONG_SIGN_SERIALIZED_INFO {

DWORD                   dwFlags;

LPWSTR                  pwszCNGSignHashAlgids;

LPWSTR                  pwszCNGPubKeyMinBitLengths; 

} CERT_STRONG_SIGN_SERIALIZED_INFO, *PCERT_STRONG_SIGN_SERIALIZED_INFO;

typedef struct _CERT_STRONG_SIGN_PARA {

DWORD                   cbSize;

DWORD                   dwInfoChoice;

union  {

void                                *pvInfo;

PCERT_STRONG_SIGN_SERIALIZED_INFO   pSerializedInfo;

LPSTR                               pszOID;

} DUMMYUNIONNAME;

} CERT_STRONG_SIGN_PARA, *PCERT_STRONG_SIGN_PARA;

typedef const CERT_STRONG_SIGN_PARA *PCCERT_STRONG_SIGN_PARA;

typedef void *HCRYPTMSG;

typedef struct _CERT_ISSUER_SERIAL_NUMBER {

CERT_NAME_BLOB      Issuer;

CRYPT_INTEGER_BLOB  SerialNumber;

} CERT_ISSUER_SERIAL_NUMBER, *PCERT_ISSUER_SERIAL_NUMBER;

typedef struct _CERT_ID {

DWORD   dwIdChoice;

union {

CERT_ISSUER_SERIAL_NUMBER   IssuerSerialNumber;

CRYPT_HASH_BLOB             KeyId;

CRYPT_HASH_BLOB             HashId;

} DUMMYUNIONNAME;

} CERT_ID, *PCERT_ID;

typedef struct _CMSG_SIGNER_ENCODE_INFO {

DWORD                       cbSize;

PCERT_INFO                  pCertInfo;

union {

HCRYPTPROV                  hCryptProv;

NCRYPT_KEY_HANDLE           hNCryptKey;

} DUMMYUNIONNAME;

DWORD                       dwKeySpec;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

void                        *pvHashAuxInfo;

DWORD                       cAuthAttr;

PCRYPT_ATTRIBUTE            rgAuthAttr;

DWORD                       cUnauthAttr;

PCRYPT_ATTRIBUTE            rgUnauthAttr;

} CMSG_SIGNER_ENCODE_INFO, *PCMSG_SIGNER_ENCODE_INFO;

typedef struct _CMSG_SIGNED_ENCODE_INFO {

DWORD                       cbSize;

DWORD                       cSigners;

PCMSG_SIGNER_ENCODE_INFO    rgSigners;

DWORD                       cCertEncoded;

PCERT_BLOB                  rgCertEncoded;

DWORD                       cCrlEncoded;

PCRL_BLOB                   rgCrlEncoded;

} CMSG_SIGNED_ENCODE_INFO, *PCMSG_SIGNED_ENCODE_INFO;

typedef struct _CMSG_RECIPIENT_ENCODE_INFO CMSG_RECIPIENT_ENCODE_INFO,

*PCMSG_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_ENVELOPED_ENCODE_INFO {

DWORD                       cbSize;

HCRYPTPROV_LEGACY           hCryptProv;

CRYPT_ALGORITHM_IDENTIFIER  ContentEncryptionAlgorithm;

void                        *pvEncryptionAuxInfo;

DWORD                       cRecipients;

PCERT_INFO                  *rgpRecipients;

} CMSG_ENVELOPED_ENCODE_INFO, *PCMSG_ENVELOPED_ENCODE_INFO;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO {

DWORD                       cbSize;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

void                        *pvKeyEncryptionAuxInfo;

HCRYPTPROV_LEGACY           hCryptProv;

CRYPT_BIT_BLOB              RecipientPublicKey;

CERT_ID                     RecipientId;

} CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO, *PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO {

DWORD                       cbSize;

CRYPT_BIT_BLOB              RecipientPublicKey;

CERT_ID                     RecipientId;

FILETIME                    Date;

PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;

} CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO,

*PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO {

DWORD                       cbSize;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

void                        *pvKeyEncryptionAuxInfo;

CRYPT_ALGORITHM_IDENTIFIER  KeyWrapAlgorithm;

void                        *pvKeyWrapAuxInfo;

HCRYPTPROV_LEGACY           hCryptProv;

DWORD                       dwKeySpec;

DWORD                       dwKeyChoice;

union {

PCRYPT_ALGORITHM_IDENTIFIER pEphemeralAlgorithm;

PCERT_ID                    pSenderId;

} DUMMYUNIONNAME;

CRYPT_DATA_BLOB             UserKeyingMaterial;     

DWORD                                       cRecipientEncryptedKeys;

PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO   *rgpRecipientEncryptedKeys;

} CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO, *PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO {

DWORD                       cbSize;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

void                        *pvKeyEncryptionAuxInfo;

HCRYPTPROV                  hCryptProv;

DWORD                       dwKeyChoice;

union {

HCRYPTKEY                   hKeyEncryptionKey;

void                        *pvKeyEncryptionKey;

} DUMMYUNIONNAME;

CRYPT_DATA_BLOB             KeyId;

FILETIME                    Date;

PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;

} CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO, *PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO;

struct _CMSG_RECIPIENT_ENCODE_INFO {

DWORD   dwRecipientChoice;

union {

PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO   pKeyTrans;

PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO   pKeyAgree;

PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO   pMailList;

} DUMMYUNIONNAME;

};

typedef struct _CMSG_RC2_AUX_INFO {

DWORD                       cbSize;

DWORD                       dwBitLen;

} CMSG_RC2_AUX_INFO, *PCMSG_RC2_AUX_INFO;

typedef struct _CMSG_SP3_COMPATIBLE_AUX_INFO {

DWORD                       cbSize;

DWORD                       dwFlags;

} CMSG_SP3_COMPATIBLE_AUX_INFO, *PCMSG_SP3_COMPATIBLE_AUX_INFO;

typedef struct _CMSG_RC4_AUX_INFO {

DWORD                       cbSize;

DWORD                       dwBitLen;

} CMSG_RC4_AUX_INFO, *PCMSG_RC4_AUX_INFO;

typedef struct _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO {

DWORD                       cbSize;

CMSG_SIGNED_ENCODE_INFO     SignedInfo;

CMSG_ENVELOPED_ENCODE_INFO  EnvelopedInfo;

} CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO, *PCMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO;

typedef struct _CMSG_HASHED_ENCODE_INFO {

DWORD                       cbSize;

HCRYPTPROV_LEGACY           hCryptProv;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

void                        *pvHashAuxInfo;

} CMSG_HASHED_ENCODE_INFO, *PCMSG_HASHED_ENCODE_INFO;

typedef struct _CMSG_ENCRYPTED_ENCODE_INFO {

DWORD                       cbSize;

CRYPT_ALGORITHM_IDENTIFIER  ContentEncryptionAlgorithm;

void                        *pvEncryptionAuxInfo;

} CMSG_ENCRYPTED_ENCODE_INFO, *PCMSG_ENCRYPTED_ENCODE_INFO;

typedef BOOL (__stdcall *PFN_CMSG_STREAM_OUTPUT)(

const void *pvArg,

BYTE *pbData,

DWORD cbData,

BOOL fFinal

);

typedef struct _CMSG_STREAM_INFO {

DWORD                   cbContent;

PFN_CMSG_STREAM_OUTPUT  pfnStreamOutput;

void                    *pvArg;

} CMSG_STREAM_INFO, *PCMSG_STREAM_INFO;

HCRYPTMSG

__stdcall

CryptMsgOpenToEncode(

DWORD dwMsgEncodingType,

DWORD dwFlags,

DWORD dwMsgType,

void const *pvMsgEncodeInfo,

LPSTR pszInnerContentObjID,

PCMSG_STREAM_INFO pStreamInfo

);

DWORD

__stdcall

CryptMsgCalculateEncodedLength(

DWORD dwMsgEncodingType,

DWORD dwFlags,

DWORD dwMsgType,

void const *pvMsgEncodeInfo,

LPSTR pszInnerContentObjID,

DWORD cbData

);

HCRYPTMSG

__stdcall

CryptMsgOpenToDecode(

DWORD dwMsgEncodingType,

DWORD dwFlags,

DWORD dwMsgType,

HCRYPTPROV_LEGACY hCryptProv,

PCERT_INFO pRecipientInfo,

PCMSG_STREAM_INFO pStreamInfo

);

HCRYPTMSG

__stdcall

CryptMsgDuplicate(

HCRYPTMSG hCryptMsg

);

BOOL

__stdcall

CryptMsgClose(

HCRYPTMSG hCryptMsg

);

BOOL

__stdcall

CryptMsgUpdate(

HCRYPTMSG hCryptMsg,

const BYTE *pbData,

DWORD cbData,

BOOL fFinal

);

BOOL

__stdcall

CryptMsgGetParam(

HCRYPTMSG hCryptMsg,

DWORD dwParamType,

DWORD dwIndex,

void *pvData,

DWORD *pcbData

);

typedef struct _CMSG_SIGNER_INFO {

DWORD                       dwVersion;

CERT_NAME_BLOB              Issuer;

CRYPT_INTEGER_BLOB          SerialNumber;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_ALGORITHM_IDENTIFIER  HashEncryptionAlgorithm;

CRYPT_DATA_BLOB             EncryptedHash;

CRYPT_ATTRIBUTES            AuthAttrs;

CRYPT_ATTRIBUTES            UnauthAttrs;

} CMSG_SIGNER_INFO, *PCMSG_SIGNER_INFO;

typedef struct _CMSG_CMS_SIGNER_INFO {

DWORD                       dwVersion;

CERT_ID                     SignerId;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_ALGORITHM_IDENTIFIER  HashEncryptionAlgorithm;

CRYPT_DATA_BLOB             EncryptedHash;

CRYPT_ATTRIBUTES            AuthAttrs;

CRYPT_ATTRIBUTES            UnauthAttrs;

} CMSG_CMS_SIGNER_INFO, *PCMSG_CMS_SIGNER_INFO;

typedef CRYPT_ATTRIBUTES CMSG_ATTR;

typedef CRYPT_ATTRIBUTES *PCMSG_ATTR;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_INFO {

DWORD                       dwVersion;

CERT_ID                     RecipientId;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

CRYPT_DATA_BLOB             EncryptedKey;

} CMSG_KEY_TRANS_RECIPIENT_INFO, *PCMSG_KEY_TRANS_RECIPIENT_INFO;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO {

CERT_ID                     RecipientId;

CRYPT_DATA_BLOB             EncryptedKey;

FILETIME                    Date;

PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;

} CMSG_RECIPIENT_ENCRYPTED_KEY_INFO, *PCMSG_RECIPIENT_ENCRYPTED_KEY_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_INFO {

DWORD                       dwVersion;

DWORD                       dwOriginatorChoice;

union {

CERT_ID                     OriginatorCertId;

CERT_PUBLIC_KEY_INFO        OriginatorPublicKeyInfo;

} DUMMYUNIONNAME;

CRYPT_DATA_BLOB             UserKeyingMaterial;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

DWORD                                cRecipientEncryptedKeys;

PCMSG_RECIPIENT_ENCRYPTED_KEY_INFO   *rgpRecipientEncryptedKeys;

} CMSG_KEY_AGREE_RECIPIENT_INFO, *PCMSG_KEY_AGREE_RECIPIENT_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_INFO {

DWORD                       dwVersion;

CRYPT_DATA_BLOB             KeyId;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

CRYPT_DATA_BLOB             EncryptedKey;

FILETIME                    Date;

PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;

} CMSG_MAIL_LIST_RECIPIENT_INFO, *PCMSG_MAIL_LIST_RECIPIENT_INFO;

typedef struct _CMSG_CMS_RECIPIENT_INFO {

DWORD   dwRecipientChoice;

union {

PCMSG_KEY_TRANS_RECIPIENT_INFO   pKeyTrans;

PCMSG_KEY_AGREE_RECIPIENT_INFO   pKeyAgree;

PCMSG_MAIL_LIST_RECIPIENT_INFO   pMailList;

} DUMMYUNIONNAME;

} CMSG_CMS_RECIPIENT_INFO, *PCMSG_CMS_RECIPIENT_INFO;

BOOL

__stdcall

CryptMsgControl(

HCRYPTMSG hCryptMsg,

DWORD dwFlags,

DWORD dwCtrlType,

void const *pvCtrlPara

);

typedef struct _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA {

DWORD               cbSize;

HCRYPTPROV_LEGACY   hCryptProv;

DWORD               dwSignerIndex;

DWORD               dwSignerType;

void                *pvSigner;

} CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA, *PCMSG_CTRL_VERIFY_SIGNATURE_EX_PARA;

typedef struct _CMSG_CTRL_DECRYPT_PARA {

DWORD       cbSize;

union {

HCRYPTPROV                  hCryptProv;

NCRYPT_KEY_HANDLE           hNCryptKey;

} DUMMYUNIONNAME;

DWORD       dwKeySpec;

DWORD       dwRecipientIndex;

} CMSG_CTRL_DECRYPT_PARA, *PCMSG_CTRL_DECRYPT_PARA;

typedef struct _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA {

DWORD                           cbSize;

union {

HCRYPTPROV                  hCryptProv;

NCRYPT_KEY_HANDLE           hNCryptKey;

} DUMMYUNIONNAME;

DWORD                           dwKeySpec;

PCMSG_KEY_TRANS_RECIPIENT_INFO  pKeyTrans;

DWORD                           dwRecipientIndex;

} CMSG_CTRL_KEY_TRANS_DECRYPT_PARA, *PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA;

typedef struct _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA {

DWORD                           cbSize;

union {

HCRYPTPROV                  hCryptProv;

NCRYPT_KEY_HANDLE           hNCryptKey;

} DUMMYUNIONNAME;

DWORD                           dwKeySpec;

PCMSG_KEY_AGREE_RECIPIENT_INFO  pKeyAgree;

DWORD                           dwRecipientIndex;

DWORD                           dwRecipientEncryptedKeyIndex;

CRYPT_BIT_BLOB                  OriginatorPublicKey;

} CMSG_CTRL_KEY_AGREE_DECRYPT_PARA, *PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA;

typedef struct _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA {

DWORD                           cbSize;

HCRYPTPROV                      hCryptProv;

PCMSG_MAIL_LIST_RECIPIENT_INFO  pMailList;

DWORD                           dwRecipientIndex;

DWORD                           dwKeyChoice;

union {

HCRYPTKEY                       hKeyEncryptionKey;

void                            *pvKeyEncryptionKey;

} DUMMYUNIONNAME;

} CMSG_CTRL_MAIL_LIST_DECRYPT_PARA, *PCMSG_CTRL_MAIL_LIST_DECRYPT_PARA;

typedef struct _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA {

DWORD               cbSize;

DWORD               dwSignerIndex;

CRYPT_DATA_BLOB     blob;

} CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA, *PCMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA;

typedef struct _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA {

DWORD               cbSize;

DWORD               dwSignerIndex;

DWORD               dwUnauthAttrIndex;

} CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA, *PCMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA;

BOOL

__stdcall

CryptMsgVerifyCountersignatureEncoded(

HCRYPTPROV_LEGACY hCryptProv,

DWORD dwEncodingType,

PBYTE pbSignerInfo,

DWORD cbSignerInfo,

PBYTE pbSignerInfoCountersignature,

DWORD cbSignerInfoCountersignature,

PCERT_INFO pciCountersigner

);

BOOL

__stdcall

CryptMsgVerifyCountersignatureEncodedEx(

HCRYPTPROV_LEGACY hCryptProv,

DWORD dwEncodingType,

PBYTE pbSignerInfo,

DWORD cbSignerInfo,

PBYTE pbSignerInfoCountersignature,

DWORD cbSignerInfoCountersignature,

DWORD dwSignerType,

void *pvSigner,

DWORD dwFlags,

void *pvExtra

);

BOOL

__stdcall

CryptMsgCountersign(

HCRYPTMSG hCryptMsg,

DWORD dwIndex,

DWORD cCountersigners,

PCMSG_SIGNER_ENCODE_INFO rgCountersigners

);

BOOL

__stdcall

CryptMsgCountersignEncoded(

DWORD dwEncodingType,

PBYTE pbSignerInfo,

DWORD cbSignerInfo,

DWORD cCountersigners,

PCMSG_SIGNER_ENCODE_INFO rgCountersigners,

PBYTE pbCountersignature,

PDWORD pcbCountersignature

);

typedef void * (__stdcall *PFN_CMSG_ALLOC) (

size_t cb

);

typedef void (__stdcall *PFN_CMSG_FREE)(

void *pv

);

typedef   BOOL (__stdcall *PFN_CMSG_GEN_ENCRYPT_KEY) (

HCRYPTPROV *phCryptProv,

PCRYPT_ALGORITHM_IDENTIFIER paiEncrypt,

PVOID pvEncryptAuxInfo,

PCERT_PUBLIC_KEY_INFO pPublicKeyInfo,

PFN_CMSG_ALLOC pfnAlloc,

HCRYPTKEY *phEncryptKey,

PBYTE *ppbEncryptParameters,

PDWORD pcbEncryptParameters

);

typedef BOOL (__stdcall *PFN_CMSG_EXPORT_ENCRYPT_KEY) (

HCRYPTPROV hCryptProv,

HCRYPTKEY hEncryptKey,

PCERT_PUBLIC_KEY_INFO pPublicKeyInfo,

PBYTE pbData,

PDWORD pcbData

);

typedef BOOL (__stdcall *PFN_CMSG_IMPORT_ENCRYPT_KEY) (

HCRYPTPROV hCryptProv,

DWORD dwKeySpec,

PCRYPT_ALGORITHM_IDENTIFIER paiEncrypt,

PCRYPT_ALGORITHM_IDENTIFIER paiPubKey,

PBYTE pbEncodedKey,

DWORD cbEncodedKey,

HCRYPTKEY *phEncryptKey

);

typedef struct _CMSG_CONTENT_ENCRYPT_INFO {

DWORD                       cbSize;

HCRYPTPROV_LEGACY           hCryptProv;

CRYPT_ALGORITHM_IDENTIFIER  ContentEncryptionAlgorithm;

void                        *pvEncryptionAuxInfo;

DWORD                       cRecipients;

PCMSG_RECIPIENT_ENCODE_INFO rgCmsRecipients;

PFN_CMSG_ALLOC              pfnAlloc;

PFN_CMSG_FREE               pfnFree;

DWORD                       dwEncryptFlags;

union {

HCRYPTKEY                   hContentEncryptKey;

BCRYPT_KEY_HANDLE           hCNGContentEncryptKey;

} DUMMYUNIONNAME;

DWORD                       dwFlags;

BOOL                        fCNG;

BYTE                        *pbCNGContentEncryptKeyObject;

BYTE                        *pbContentEncryptKey;

DWORD                       cbContentEncryptKey;

} CMSG_CONTENT_ENCRYPT_INFO, *PCMSG_CONTENT_ENCRYPT_INFO;

typedef BOOL (__stdcall *PFN_CMSG_GEN_CONTENT_ENCRYPT_KEY) (

PCMSG_CONTENT_ENCRYPT_INFO pContentEncryptInfo,

DWORD dwFlags,

void *pvReserved

);

typedef struct _CMSG_KEY_TRANS_ENCRYPT_INFO {

DWORD                       cbSize;

DWORD                       dwRecipientIndex;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

CRYPT_DATA_BLOB             EncryptedKey;

DWORD                       dwFlags;

} CMSG_KEY_TRANS_ENCRYPT_INFO, *PCMSG_KEY_TRANS_ENCRYPT_INFO;

typedef BOOL (__stdcall *PFN_CMSG_EXPORT_KEY_TRANS) (

PCMSG_CONTENT_ENCRYPT_INFO pContentEncryptInfo,

PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO pKeyTransEncodeInfo,

PCMSG_KEY_TRANS_ENCRYPT_INFO pKeyTransEncryptInfo,

DWORD dwFlags,

void *pvReserved

);

typedef struct _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO {

DWORD                       cbSize;

CRYPT_DATA_BLOB             EncryptedKey;

} CMSG_KEY_AGREE_KEY_ENCRYPT_INFO, *PCMSG_KEY_AGREE_KEY_ENCRYPT_INFO;

typedef struct _CMSG_KEY_AGREE_ENCRYPT_INFO {

DWORD                       cbSize;

DWORD                       dwRecipientIndex;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

CRYPT_DATA_BLOB             UserKeyingMaterial;

DWORD                       dwOriginatorChoice;

union {

CERT_ID                     OriginatorCertId;

CERT_PUBLIC_KEY_INFO        OriginatorPublicKeyInfo;

} DUMMYUNIONNAME;

DWORD                       cKeyAgreeKeyEncryptInfo;

PCMSG_KEY_AGREE_KEY_ENCRYPT_INFO *rgpKeyAgreeKeyEncryptInfo;

DWORD                       dwFlags;

} CMSG_KEY_AGREE_ENCRYPT_INFO, *PCMSG_KEY_AGREE_ENCRYPT_INFO;

typedef BOOL (__stdcall *PFN_CMSG_EXPORT_KEY_AGREE) (

PCMSG_CONTENT_ENCRYPT_INFO pContentEncryptInfo,

PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO pKeyAgreeEncodeInfo,

PCMSG_KEY_AGREE_ENCRYPT_INFO pKeyAgreeEncryptInfo,

DWORD dwFlags,

void *pvReserved

);

typedef struct _CMSG_MAIL_LIST_ENCRYPT_INFO {

DWORD                       cbSize;

DWORD                       dwRecipientIndex;

CRYPT_ALGORITHM_IDENTIFIER  KeyEncryptionAlgorithm;

CRYPT_DATA_BLOB             EncryptedKey;

DWORD                       dwFlags;

} CMSG_MAIL_LIST_ENCRYPT_INFO, *PCMSG_MAIL_LIST_ENCRYPT_INFO;

typedef BOOL (__stdcall *PFN_CMSG_EXPORT_MAIL_LIST) (

PCMSG_CONTENT_ENCRYPT_INFO pContentEncryptInfo,

PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO pMailListEncodeInfo,

PCMSG_MAIL_LIST_ENCRYPT_INFO pMailListEncryptInfo,

DWORD dwFlags,

void *pvReserved

);

typedef BOOL (__stdcall *PFN_CMSG_IMPORT_KEY_TRANS) (

PCRYPT_ALGORITHM_IDENTIFIER pContentEncryptionAlgorithm,

PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA pKeyTransDecryptPara,

DWORD dwFlags,

void *pvReserved,

HCRYPTKEY *phContentEncryptKey

);

typedef BOOL (__stdcall *PFN_CMSG_IMPORT_KEY_AGREE) (

PCRYPT_ALGORITHM_IDENTIFIER pContentEncryptionAlgorithm,

PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA pKeyAgreeDecryptPara,

DWORD dwFlags,

void *pvReserved,

HCRYPTKEY *phContentEncryptKey

);

typedef BOOL (__stdcall *PFN_CMSG_IMPORT_MAIL_LIST) (

PCRYPT_ALGORITHM_IDENTIFIER pContentEncryptionAlgorithm,

PCMSG_CTRL_MAIL_LIST_DECRYPT_PARA pMailListDecryptPara,

DWORD dwFlags,

void *pvReserved,

HCRYPTKEY *phContentEncryptKey

);

typedef struct _CMSG_CNG_CONTENT_DECRYPT_INFO {

DWORD                       cbSize;

CRYPT_ALGORITHM_IDENTIFIER  ContentEncryptionAlgorithm;

PFN_CMSG_ALLOC              pfnAlloc;

PFN_CMSG_FREE               pfnFree;

NCRYPT_KEY_HANDLE           hNCryptKey;

BYTE                        *pbContentEncryptKey;

DWORD                       cbContentEncryptKey;

BCRYPT_KEY_HANDLE           hCNGContentEncryptKey;

BYTE                        *pbCNGContentEncryptKeyObject;

} CMSG_CNG_CONTENT_DECRYPT_INFO, *PCMSG_CNG_CONTENT_DECRYPT_INFO;

typedef BOOL (__stdcall *PFN_CMSG_CNG_IMPORT_KEY_TRANS) (

PCMSG_CNG_CONTENT_DECRYPT_INFO pCNGContentDecryptInfo,

PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA pKeyTransDecryptPara,

DWORD dwFlags,

void *pvReserved

);

typedef BOOL (__stdcall *PFN_CMSG_CNG_IMPORT_KEY_AGREE) (

PCMSG_CNG_CONTENT_DECRYPT_INFO pCNGContentDecryptInfo,

PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA pKeyAgreeDecryptPara,

DWORD dwFlags,

void *pvReserved

);

typedef BOOL (__stdcall *PFN_CMSG_CNG_IMPORT_CONTENT_ENCRYPT_KEY) (

PCMSG_CNG_CONTENT_DECRYPT_INFO pCNGContentDecryptInfo,

DWORD dwFlags,

void *pvReserved

);

typedef void *HCERTSTORE;

typedef struct _CERT_CONTEXT {

DWORD                   dwCertEncodingType;

BYTE                    *pbCertEncoded;

DWORD                   cbCertEncoded;

PCERT_INFO              pCertInfo;

HCERTSTORE              hCertStore;

} CERT_CONTEXT, *PCERT_CONTEXT;

typedef const CERT_CONTEXT *PCCERT_CONTEXT;

typedef struct _CRL_CONTEXT {

DWORD                   dwCertEncodingType;

BYTE                    *pbCrlEncoded;

DWORD                   cbCrlEncoded;

PCRL_INFO               pCrlInfo;

HCERTSTORE              hCertStore;

} CRL_CONTEXT, *PCRL_CONTEXT;

typedef const CRL_CONTEXT *PCCRL_CONTEXT;

typedef struct _CTL_CONTEXT {

DWORD                   dwMsgAndCertEncodingType;

BYTE                    *pbCtlEncoded;

DWORD                   cbCtlEncoded;

PCTL_INFO               pCtlInfo;

HCERTSTORE              hCertStore;

HCRYPTMSG               hCryptMsg;

BYTE                    *pbCtlContent;

DWORD                   cbCtlContent;

} CTL_CONTEXT, *PCTL_CONTEXT;

typedef const CTL_CONTEXT *PCCTL_CONTEXT;

typedef enum CertKeyType 

{

KeyTypeOther             = 0,

KeyTypeVirtualSmartCard  = 1,

KeyTypePhysicalSmartCard = 2,

KeyTypePassport          = 3,

KeyTypePassportRemote    = 4,

KeyTypePassportSmartCard = 5,

KeyTypeHardware          = 6,

KeyTypeSoftware          = 7,

KeyTypeSelfSigned        = 8,

} CertKeyType;

typedef struct _CRYPT_KEY_PROV_PARAM {

DWORD           dwParam;

BYTE            *pbData;

DWORD           cbData;

DWORD           dwFlags;

} CRYPT_KEY_PROV_PARAM, *PCRYPT_KEY_PROV_PARAM;

typedef struct _CRYPT_KEY_PROV_INFO {

LPWSTR                  pwszContainerName;

LPWSTR                  pwszProvName;

DWORD                   dwProvType;

DWORD                   dwFlags;

DWORD                   cProvParam;

PCRYPT_KEY_PROV_PARAM   rgProvParam;

DWORD                   dwKeySpec;

} CRYPT_KEY_PROV_INFO, *PCRYPT_KEY_PROV_INFO;

typedef struct _CERT_KEY_CONTEXT {

DWORD           cbSize;           

union {

HCRYPTPROV          hCryptProv;

NCRYPT_KEY_HANDLE   hNCryptKey;

} DUMMYUNIONNAME;

DWORD           dwKeySpec;

} CERT_KEY_CONTEXT, *PCERT_KEY_CONTEXT;

typedef struct _ROOT_INFO_LUID {

DWORD LowPart;

LONG HighPart;

} ROOT_INFO_LUID, *PROOT_INFO_LUID;

typedef struct _CRYPT_SMART_CARD_ROOT_INFO {

BYTE                rgbCardID [16];

ROOT_INFO_LUID      luid;

} CRYPT_SMART_CARD_ROOT_INFO, *PCRYPT_SMART_CARD_ROOT_INFO;

typedef struct _CERT_SYSTEM_STORE_RELOCATE_PARA {

union {

HKEY                hKeyBase;

void                *pvBase;

} DUMMYUNIONNAME;

union {

void                *pvSystemStore;

LPCSTR              pszSystemStore;

LPCWSTR             pwszSystemStore;

} DUMMYUNIONNAME2;

} CERT_SYSTEM_STORE_RELOCATE_PARA, *PCERT_SYSTEM_STORE_RELOCATE_PARA;

typedef struct _CERT_REGISTRY_STORE_CLIENT_GPT_PARA {

HKEY                hKeyBase;

LPWSTR              pwszRegPath;

} CERT_REGISTRY_STORE_CLIENT_GPT_PARA, *PCERT_REGISTRY_STORE_CLIENT_GPT_PARA;

typedef struct _CERT_REGISTRY_STORE_ROAMING_PARA {

HKEY                hKey;

LPWSTR              pwszStoreDirectory;

} CERT_REGISTRY_STORE_ROAMING_PARA, *PCERT_REGISTRY_STORE_ROAMING_PARA;

typedef struct _CERT_LDAP_STORE_OPENED_PARA {

void        *pvLdapSessionHandle;   

LPCWSTR     pwszLdapUrl;

} CERT_LDAP_STORE_OPENED_PARA, *PCERT_LDAP_STORE_OPENED_PARA;

HCERTSTORE

__stdcall

CertOpenStore(

LPCSTR lpszStoreProvider,

DWORD dwEncodingType,

HCRYPTPROV_LEGACY hCryptProv,

DWORD dwFlags,

const void *pvPara

);

typedef void *HCERTSTOREPROV;

typedef struct _CERT_STORE_PROV_INFO {

DWORD               cbSize;

DWORD               cStoreProvFunc;

void                **rgpvStoreProvFunc;

HCERTSTOREPROV      hStoreProv;

DWORD               dwStoreProvFlags;

HCRYPTOIDFUNCADDR   hStoreProvFuncAddr2;

} CERT_STORE_PROV_INFO, *PCERT_STORE_PROV_INFO;

typedef BOOL (__stdcall *PFN_CERT_DLL_OPEN_STORE_PROV_FUNC)(

LPCSTR lpszStoreProvider,

DWORD dwEncodingType,

HCRYPTPROV_LEGACY hCryptProv,

DWORD dwFlags,

const void *pvPara,

HCERTSTORE hCertStore,

PCERT_STORE_PROV_INFO pStoreProvInfo

);

typedef void (__stdcall *PFN_CERT_STORE_PROV_CLOSE)(

HCERTSTOREPROV hStoreProv,

DWORD dwFlags

);

typedef   BOOL (__stdcall *PFN_CERT_STORE_PROV_READ_CERT)(

HCERTSTOREPROV hStoreProv,

PCCERT_CONTEXT pStoreCertContext,

DWORD dwFlags,

PCCERT_CONTEXT *ppProvCertContext

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_WRITE_CERT)(

HCERTSTOREPROV hStoreProv,

PCCERT_CONTEXT pCertContext,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_DELETE_CERT)(

HCERTSTOREPROV hStoreProv,

PCCERT_CONTEXT pCertContext,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_SET_CERT_PROPERTY)(

HCERTSTOREPROV hStoreProv,

PCCERT_CONTEXT pCertContext,

DWORD dwPropId,

DWORD dwFlags,

const void *pvData

);

typedef   BOOL (__stdcall *PFN_CERT_STORE_PROV_READ_CRL)(

HCERTSTOREPROV hStoreProv,

PCCRL_CONTEXT pStoreCrlContext,

DWORD dwFlags,

PCCRL_CONTEXT *ppProvCrlContext

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_WRITE_CRL)(

HCERTSTOREPROV hStoreProv,

PCCRL_CONTEXT pCrlContext,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_DELETE_CRL)(

HCERTSTOREPROV hStoreProv,

PCCRL_CONTEXT pCrlContext,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_SET_CRL_PROPERTY)(

HCERTSTOREPROV hStoreProv,

PCCRL_CONTEXT pCrlContext,

DWORD dwPropId,

DWORD dwFlags,

const void *pvData

);

typedef   BOOL (__stdcall *PFN_CERT_STORE_PROV_READ_CTL)(

HCERTSTOREPROV hStoreProv,

PCCTL_CONTEXT pStoreCtlContext,

DWORD dwFlags,

PCCTL_CONTEXT *ppProvCtlContext

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_WRITE_CTL)(

HCERTSTOREPROV hStoreProv,

PCCTL_CONTEXT pCtlContext,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_DELETE_CTL)(

HCERTSTOREPROV hStoreProv,

PCCTL_CONTEXT pCtlContext,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_SET_CTL_PROPERTY)(

HCERTSTOREPROV hStoreProv,

PCCTL_CONTEXT pCtlContext,

DWORD dwPropId,

DWORD dwFlags,

const void *pvData

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_CONTROL)(

HCERTSTOREPROV hStoreProv,

DWORD dwFlags,

DWORD dwCtrlType,

void const *pvCtrlPara

);

typedef struct _CERT_STORE_PROV_FIND_INFO {

DWORD               cbSize;

DWORD               dwMsgAndCertEncodingType;

DWORD               dwFindFlags;

DWORD               dwFindType;

const void          *pvFindPara;

} CERT_STORE_PROV_FIND_INFO, *PCERT_STORE_PROV_FIND_INFO;

typedef const CERT_STORE_PROV_FIND_INFO CCERT_STORE_PROV_FIND_INFO,

*PCCERT_STORE_PROV_FIND_INFO;

typedef   BOOL (__stdcall *PFN_CERT_STORE_PROV_FIND_CERT)(

HCERTSTOREPROV hStoreProv,

PCCERT_STORE_PROV_FIND_INFO pFindInfo,

PCCERT_CONTEXT pPrevCertContext,

DWORD dwFlags,

void **ppvStoreProvFindInfo,

PCCERT_CONTEXT *ppProvCertContext

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_FREE_FIND_CERT)(

HCERTSTOREPROV hStoreProv,

PCCERT_CONTEXT pCertContext,

void *pvStoreProvFindInfo,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_GET_CERT_PROPERTY)(

HCERTSTOREPROV hStoreProv,

PCCERT_CONTEXT pCertContext,

DWORD dwPropId,

DWORD dwFlags,

void *pvData,

DWORD *pcbData

);

typedef   BOOL (__stdcall *PFN_CERT_STORE_PROV_FIND_CRL)(

HCERTSTOREPROV hStoreProv,

PCCERT_STORE_PROV_FIND_INFO pFindInfo,

PCCRL_CONTEXT pPrevCrlContext,

DWORD dwFlags,

void **ppvStoreProvFindInfo,

PCCRL_CONTEXT *ppProvCrlContext

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_FREE_FIND_CRL)(

HCERTSTOREPROV hStoreProv,

PCCRL_CONTEXT pCrlContext,

void *pvStoreProvFindInfo,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_GET_CRL_PROPERTY)(

HCERTSTOREPROV hStoreProv,

PCCRL_CONTEXT pCrlContext,

DWORD dwPropId,

DWORD dwFlags,

void *pvData,

DWORD *pcbData

);

typedef   BOOL (__stdcall *PFN_CERT_STORE_PROV_FIND_CTL)(

HCERTSTOREPROV hStoreProv,

PCCERT_STORE_PROV_FIND_INFO pFindInfo,

PCCTL_CONTEXT pPrevCtlContext,

DWORD dwFlags,

void **ppvStoreProvFindInfo,

PCCTL_CONTEXT *ppProvCtlContext

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_FREE_FIND_CTL)(

HCERTSTOREPROV hStoreProv,

PCCTL_CONTEXT pCtlContext,

void *pvStoreProvFindInfo,

DWORD dwFlags

);

typedef BOOL (__stdcall *PFN_CERT_STORE_PROV_GET_CTL_PROPERTY)(

HCERTSTOREPROV hStoreProv,

PCCTL_CONTEXT pCtlContext,

DWORD dwPropId,

DWORD dwFlags,

void *pvData,

DWORD *pcbData

);

HCERTSTORE

__stdcall

CertDuplicateStore(

HCERTSTORE hCertStore

);

BOOL

__stdcall

CertSaveStore(

HCERTSTORE hCertStore,

DWORD dwEncodingType,

DWORD dwSaveAs,

DWORD dwSaveTo,

void *pvSaveToPara,

DWORD dwFlags

);

BOOL

__stdcall

CertCloseStore(

HCERTSTORE hCertStore,

DWORD dwFlags

);

PCCERT_CONTEXT

__stdcall

CertGetSubjectCertificateFromStore(

HCERTSTORE hCertStore,

DWORD dwCertEncodingType,

PCERT_INFO pCertId           

);

PCCERT_CONTEXT

__stdcall

CertEnumCertificatesInStore(

HCERTSTORE hCertStore,

PCCERT_CONTEXT pPrevCertContext

);

PCCERT_CONTEXT

__stdcall

CertFindCertificateInStore(

HCERTSTORE hCertStore,

DWORD dwCertEncodingType,

DWORD dwFindFlags,

DWORD dwFindType,

const void *pvFindPara,

PCCERT_CONTEXT pPrevCertContext

);

PCCERT_CONTEXT

__stdcall

CertGetIssuerCertificateFromStore(

HCERTSTORE hCertStore,

PCCERT_CONTEXT pSubjectContext,

PCCERT_CONTEXT pPrevIssuerContext,

DWORD *pdwFlags

);

BOOL

__stdcall

CertVerifySubjectCertificateContext(

PCCERT_CONTEXT pSubject,

PCCERT_CONTEXT pIssuer,

DWORD *pdwFlags

);

PCCERT_CONTEXT

__stdcall

CertDuplicateCertificateContext(

PCCERT_CONTEXT pCertContext

);

PCCERT_CONTEXT

__stdcall

CertCreateCertificateContext(

DWORD dwCertEncodingType,

const BYTE *pbCertEncoded,

DWORD cbCertEncoded

);

BOOL

__stdcall

CertFreeCertificateContext(

PCCERT_CONTEXT pCertContext

);

BOOL

__stdcall

CertSetCertificateContextProperty(

PCCERT_CONTEXT pCertContext,

DWORD dwPropId,

DWORD dwFlags,

const void *pvData

);

BOOL

__stdcall

CertGetCertificateContextProperty(

PCCERT_CONTEXT pCertContext,

DWORD dwPropId,

void *pvData,

DWORD *pcbData

);

DWORD

__stdcall

CertEnumCertificateContextProperties(

PCCERT_CONTEXT pCertContext,

DWORD dwPropId

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CertCreateCTLEntryFromCertificateContextProperties(

PCCERT_CONTEXT pCertContext,

DWORD cOptAttr,

PCRYPT_ATTRIBUTE rgOptAttr,

DWORD dwFlags,

void *pvReserved,

PCTL_ENTRY pCtlEntry,

DWORD *pcbCtlEntry

);

BOOL

__stdcall

CertSetCertificateContextPropertiesFromCTLEntry(

PCCERT_CONTEXT pCertContext,

PCTL_ENTRY pCtlEntry,

DWORD dwFlags

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

PCCRL_CONTEXT

__stdcall

CertGetCRLFromStore(

HCERTSTORE hCertStore,

PCCERT_CONTEXT pIssuerContext,

PCCRL_CONTEXT pPrevCrlContext,

DWORD *pdwFlags

);

PCCRL_CONTEXT

__stdcall

CertEnumCRLsInStore(

HCERTSTORE hCertStore,

PCCRL_CONTEXT pPrevCrlContext

);

PCCRL_CONTEXT

__stdcall

CertFindCRLInStore(

HCERTSTORE hCertStore,

DWORD dwCertEncodingType,

DWORD dwFindFlags,

DWORD dwFindType,

const void *pvFindPara,

PCCRL_CONTEXT pPrevCrlContext

);

typedef struct _CRL_FIND_ISSUED_FOR_PARA {

PCCERT_CONTEXT              pSubjectCert;

PCCERT_CONTEXT              pIssuerCert;

} CRL_FIND_ISSUED_FOR_PARA, *PCRL_FIND_ISSUED_FOR_PARA;

PCCRL_CONTEXT

__stdcall

CertDuplicateCRLContext(

PCCRL_CONTEXT pCrlContext

);

PCCRL_CONTEXT

__stdcall

CertCreateCRLContext(

DWORD dwCertEncodingType,

const BYTE *pbCrlEncoded,

DWORD cbCrlEncoded

);

BOOL

__stdcall

CertFreeCRLContext(

PCCRL_CONTEXT pCrlContext

);

BOOL

__stdcall

CertSetCRLContextProperty(

PCCRL_CONTEXT pCrlContext,

DWORD dwPropId,

DWORD dwFlags,

const void *pvData

);

BOOL

__stdcall

CertGetCRLContextProperty(

PCCRL_CONTEXT pCrlContext,

DWORD dwPropId,

void *pvData,

DWORD *pcbData

);

DWORD

__stdcall

CertEnumCRLContextProperties(

PCCRL_CONTEXT pCrlContext,

DWORD dwPropId

);

BOOL

__stdcall

CertFindCertificateInCRL(

PCCERT_CONTEXT pCert,

PCCRL_CONTEXT pCrlContext,

DWORD dwFlags,

void *pvReserved,

PCRL_ENTRY *ppCrlEntry

);

BOOL

__stdcall

CertIsValidCRLForCertificate(

PCCERT_CONTEXT pCert,

PCCRL_CONTEXT pCrl,

DWORD dwFlags,

void *pvReserved

);

BOOL

__stdcall

CertAddEncodedCertificateToStore(

HCERTSTORE hCertStore,

DWORD dwCertEncodingType,

const BYTE *pbCertEncoded,

DWORD cbCertEncoded,

DWORD dwAddDisposition,

PCCERT_CONTEXT *ppCertContext

);

BOOL

__stdcall

CertAddCertificateContextToStore(

HCERTSTORE hCertStore,

PCCERT_CONTEXT pCertContext,

DWORD dwAddDisposition,

PCCERT_CONTEXT *ppStoreContext

);

BOOL

__stdcall

CertAddSerializedElementToStore(

HCERTSTORE hCertStore,

const BYTE *pbElement,

DWORD cbElement,

DWORD dwAddDisposition,

DWORD dwFlags,

DWORD dwContextTypeFlags,

DWORD *pdwContextType,

const void **ppvContext

);

BOOL

__stdcall

CertDeleteCertificateFromStore(

PCCERT_CONTEXT pCertContext

);

BOOL

__stdcall

CertAddEncodedCRLToStore(

HCERTSTORE hCertStore,

DWORD dwCertEncodingType,

const BYTE *pbCrlEncoded,

DWORD cbCrlEncoded,

DWORD dwAddDisposition,

PCCRL_CONTEXT *ppCrlContext

);

BOOL

__stdcall

CertAddCRLContextToStore(

HCERTSTORE hCertStore,

PCCRL_CONTEXT pCrlContext,

DWORD dwAddDisposition,

PCCRL_CONTEXT *ppStoreContext

);

BOOL

__stdcall

CertDeleteCRLFromStore(

PCCRL_CONTEXT pCrlContext

);

BOOL

__stdcall

CertSerializeCertificateStoreElement(

PCCERT_CONTEXT pCertContext,

DWORD dwFlags,

BYTE *pbElement,

DWORD *pcbElement

);

BOOL

__stdcall

CertSerializeCRLStoreElement(

PCCRL_CONTEXT pCrlContext,

DWORD dwFlags,

BYTE *pbElement,

DWORD *pcbElement

);

PCCTL_CONTEXT

__stdcall

CertDuplicateCTLContext(

PCCTL_CONTEXT pCtlContext

);

PCCTL_CONTEXT

__stdcall

CertCreateCTLContext(

DWORD dwMsgAndCertEncodingType,

const BYTE *pbCtlEncoded,

DWORD cbCtlEncoded

);

BOOL

__stdcall

CertFreeCTLContext(

PCCTL_CONTEXT pCtlContext

);

BOOL

__stdcall

CertSetCTLContextProperty(

PCCTL_CONTEXT pCtlContext,

DWORD dwPropId,

DWORD dwFlags,

const void *pvData

);

BOOL

__stdcall

CertGetCTLContextProperty(

PCCTL_CONTEXT pCtlContext,

DWORD dwPropId,

void *pvData,

DWORD *pcbData

);

DWORD

__stdcall

CertEnumCTLContextProperties(

PCCTL_CONTEXT pCtlContext,

DWORD dwPropId

);

PCCTL_CONTEXT

__stdcall

CertEnumCTLsInStore(

HCERTSTORE hCertStore,

PCCTL_CONTEXT pPrevCtlContext

);

PCTL_ENTRY

__stdcall

CertFindSubjectInCTL(

DWORD dwEncodingType,

DWORD dwSubjectType,

void *pvSubject,

PCCTL_CONTEXT pCtlContext,

DWORD dwFlags

);

typedef struct _CTL_ANY_SUBJECT_INFO {

CRYPT_ALGORITHM_IDENTIFIER  SubjectAlgorithm;

CRYPT_DATA_BLOB             SubjectIdentifier;

} CTL_ANY_SUBJECT_INFO, *PCTL_ANY_SUBJECT_INFO;

PCCTL_CONTEXT

__stdcall

CertFindCTLInStore(

HCERTSTORE hCertStore,

DWORD dwMsgAndCertEncodingType,

DWORD dwFindFlags,

DWORD dwFindType,

const void *pvFindPara,

PCCTL_CONTEXT pPrevCtlContext

);

typedef struct _CTL_FIND_USAGE_PARA {

DWORD               cbSize;

CTL_USAGE           SubjectUsage;   

CRYPT_DATA_BLOB     ListIdentifier; 

PCERT_INFO          pSigner;        

} CTL_FIND_USAGE_PARA, *PCTL_FIND_USAGE_PARA;

typedef struct _CTL_FIND_SUBJECT_PARA {

DWORD                   cbSize;

PCTL_FIND_USAGE_PARA    pUsagePara; 

DWORD                   dwSubjectType;

void                    *pvSubject;

} CTL_FIND_SUBJECT_PARA, *PCTL_FIND_SUBJECT_PARA;

BOOL

__stdcall

CertAddEncodedCTLToStore(

HCERTSTORE hCertStore,

DWORD dwMsgAndCertEncodingType,

const BYTE *pbCtlEncoded,

DWORD cbCtlEncoded,

DWORD dwAddDisposition,

PCCTL_CONTEXT *ppCtlContext

);

BOOL

__stdcall

CertAddCTLContextToStore(

HCERTSTORE hCertStore,

PCCTL_CONTEXT pCtlContext,

DWORD dwAddDisposition,

PCCTL_CONTEXT *ppStoreContext

);

BOOL

__stdcall

CertSerializeCTLStoreElement(

PCCTL_CONTEXT pCtlContext,

DWORD dwFlags,

BYTE *pbElement,

DWORD *pcbElement

);

BOOL

__stdcall

CertDeleteCTLFromStore(

PCCTL_CONTEXT pCtlContext

);

BOOL

__stdcall

CertAddCertificateLinkToStore(

HCERTSTORE hCertStore,

PCCERT_CONTEXT pCertContext,

DWORD dwAddDisposition,

PCCERT_CONTEXT *ppStoreContext

);

BOOL

__stdcall

CertAddCRLLinkToStore(

HCERTSTORE hCertStore,

PCCRL_CONTEXT pCrlContext,

DWORD dwAddDisposition,

PCCRL_CONTEXT *ppStoreContext

);

BOOL

__stdcall

CertAddCTLLinkToStore(

HCERTSTORE hCertStore,

PCCTL_CONTEXT pCtlContext,

DWORD dwAddDisposition,

PCCTL_CONTEXT *ppStoreContext

);

BOOL

__stdcall

CertAddStoreToCollection(

HCERTSTORE hCollectionStore,

HCERTSTORE hSiblingStore,

DWORD dwUpdateFlags,

DWORD dwPriority

);

void

__stdcall

CertRemoveStoreFromCollection(

HCERTSTORE hCollectionStore,

HCERTSTORE hSiblingStore

);

BOOL

__stdcall

CertControlStore(

HCERTSTORE hCertStore,

DWORD dwFlags,

DWORD dwCtrlType,

void const *pvCtrlPara

);

BOOL

__stdcall

CertSetStoreProperty(

HCERTSTORE hCertStore,

DWORD dwPropId,

DWORD dwFlags,

const void *pvData

);

BOOL

__stdcall

CertGetStoreProperty(

HCERTSTORE hCertStore,

DWORD dwPropId,

void *pvData,

DWORD *pcbData

);

typedef BOOL (__stdcall *PFN_CERT_CREATE_CONTEXT_SORT_FUNC)(

DWORD cbTotalEncoded,

DWORD cbRemainEncoded,

DWORD cEntry,

void *pvSort

);

typedef struct _CERT_CREATE_CONTEXT_PARA {

DWORD                               cbSize;

PFN_CRYPT_FREE                      pfnFree;    

void                                *pvFree;    

PFN_CERT_CREATE_CONTEXT_SORT_FUNC   pfnSort;    

void                                *pvSort;    

} CERT_CREATE_CONTEXT_PARA, *PCERT_CREATE_CONTEXT_PARA;

const void *

__stdcall

CertCreateContext(

DWORD dwContextType,

DWORD dwEncodingType,

const BYTE *pbEncoded,

DWORD cbEncoded,

DWORD dwFlags,

PCERT_CREATE_CONTEXT_PARA pCreatePara

);

typedef struct _CERT_SYSTEM_STORE_INFO {

DWORD   cbSize;

} CERT_SYSTEM_STORE_INFO, *PCERT_SYSTEM_STORE_INFO;

typedef struct _CERT_PHYSICAL_STORE_INFO {

DWORD               cbSize;

LPSTR               pszOpenStoreProvider;   

DWORD               dwOpenEncodingType;     

DWORD               dwOpenFlags;            

CRYPT_DATA_BLOB     OpenParameters;         

DWORD               dwFlags;                

DWORD               dwPriority;             

} CERT_PHYSICAL_STORE_INFO, *PCERT_PHYSICAL_STORE_INFO;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CertRegisterSystemStore(

const void *pvSystemStore,

DWORD dwFlags,

PCERT_SYSTEM_STORE_INFO pStoreInfo,

void *pvReserved

);

BOOL

__stdcall

CertRegisterPhysicalStore(

const void *pvSystemStore,

DWORD dwFlags,

LPCWSTR pwszStoreName,

PCERT_PHYSICAL_STORE_INFO pStoreInfo,

void *pvReserved

);

BOOL

__stdcall

CertUnregisterSystemStore(

const void *pvSystemStore,

DWORD dwFlags

);

BOOL

__stdcall

CertUnregisterPhysicalStore(

const void *pvSystemStore,

DWORD dwFlags,

LPCWSTR pwszStoreName

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef BOOL (__stdcall *PFN_CERT_ENUM_SYSTEM_STORE_LOCATION)(

LPCWSTR pwszStoreLocation,

DWORD dwFlags,

void *pvReserved,

void *pvArg

);

typedef BOOL (__stdcall *PFN_CERT_ENUM_SYSTEM_STORE)(

const void *pvSystemStore,

DWORD dwFlags,

PCERT_SYSTEM_STORE_INFO pStoreInfo,

void *pvReserved,

void *pvArg

);

typedef BOOL (__stdcall *PFN_CERT_ENUM_PHYSICAL_STORE)(

const void *pvSystemStore,

DWORD dwFlags,

LPCWSTR pwszStoreName,

PCERT_PHYSICAL_STORE_INFO pStoreInfo,

void *pvReserved,

void *pvArg

);

BOOL

__stdcall

CertEnumSystemStoreLocation(

DWORD dwFlags,

void *pvArg,

PFN_CERT_ENUM_SYSTEM_STORE_LOCATION pfnEnum

);

BOOL

__stdcall

CertEnumSystemStore(

DWORD dwFlags,

void *pvSystemStoreLocationPara,

void *pvArg,

PFN_CERT_ENUM_SYSTEM_STORE pfnEnum

);

BOOL

__stdcall

CertEnumPhysicalStore(

const void *pvSystemStore,

DWORD dwFlags,

void *pvArg,

PFN_CERT_ENUM_PHYSICAL_STORE pfnEnum

);

BOOL

__stdcall

CertGetEnhancedKeyUsage(

PCCERT_CONTEXT pCertContext,

DWORD dwFlags,

PCERT_ENHKEY_USAGE pUsage,

DWORD *pcbUsage

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CertSetEnhancedKeyUsage(

PCCERT_CONTEXT pCertContext,

PCERT_ENHKEY_USAGE pUsage

);

BOOL

__stdcall

CertAddEnhancedKeyUsageIdentifier(

PCCERT_CONTEXT pCertContext,

LPCSTR pszUsageIdentifier

);

BOOL

__stdcall

CertRemoveEnhancedKeyUsageIdentifier(

PCCERT_CONTEXT pCertContext,

LPCSTR pszUsageIdentifier

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CertGetValidUsages(

DWORD cCerts,

PCCERT_CONTEXT *rghCerts,

int *cNumOIDs,

LPSTR *rghOIDs,

DWORD *pcbOIDs);

BOOL

__stdcall

CryptMsgGetAndVerifySigner(

HCRYPTMSG hCryptMsg,

DWORD cSignerStore,

HCERTSTORE *rghSignerStore,

DWORD dwFlags,

PCCERT_CONTEXT *ppSigner,

DWORD *pdwSignerIndex

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptMsgSignCTL(

DWORD dwMsgEncodingType,

BYTE *pbCtlContent,

DWORD cbCtlContent,

PCMSG_SIGNED_ENCODE_INFO pSignInfo,

DWORD dwFlags,

BYTE *pbEncoded,

DWORD *pcbEncoded

);

BOOL

__stdcall

CryptMsgEncodeAndSignCTL(

DWORD dwMsgEncodingType,

PCTL_INFO pCtlInfo,

PCMSG_SIGNED_ENCODE_INFO pSignInfo,

DWORD dwFlags,

BYTE *pbEncoded,

DWORD *pcbEncoded

);

BOOL

__stdcall

CertFindSubjectInSortedCTL(

PCRYPT_DATA_BLOB pSubjectIdentifier,

PCCTL_CONTEXT pCtlContext,

DWORD dwFlags,

void *pvReserved,

PCRYPT_DER_BLOB pEncodedAttributes

);

BOOL

__stdcall

CertEnumSubjectInSortedCTL(

PCCTL_CONTEXT pCtlContext,

void **ppvNextSubject,

PCRYPT_DER_BLOB pSubjectIdentifier,

PCRYPT_DER_BLOB pEncodedAttributes

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef struct _CTL_VERIFY_USAGE_PARA {

DWORD                   cbSize;

CRYPT_DATA_BLOB         ListIdentifier;     

DWORD                   cCtlStore;

HCERTSTORE              *rghCtlStore;       

DWORD                   cSignerStore;

HCERTSTORE              *rghSignerStore;    

} CTL_VERIFY_USAGE_PARA, *PCTL_VERIFY_USAGE_PARA;

typedef struct _CTL_VERIFY_USAGE_STATUS {

DWORD                   cbSize;

DWORD                   dwError;

DWORD                   dwFlags;

PCCTL_CONTEXT           *ppCtl;             

DWORD                   dwCtlEntryIndex;

PCCERT_CONTEXT          *ppSigner;          

DWORD                   dwSignerIndex;

} CTL_VERIFY_USAGE_STATUS, *PCTL_VERIFY_USAGE_STATUS;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CertVerifyCTLUsage(

DWORD dwEncodingType,

DWORD dwSubjectType,

void *pvSubject,

PCTL_USAGE pSubjectUsage,

DWORD dwFlags,

PCTL_VERIFY_USAGE_PARA pVerifyUsagePara,

PCTL_VERIFY_USAGE_STATUS pVerifyUsageStatus

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef struct _CERT_REVOCATION_CRL_INFO {

DWORD                   cbSize;

PCCRL_CONTEXT           pBaseCrlContext;

PCCRL_CONTEXT           pDeltaCrlContext;

PCRL_ENTRY              pCrlEntry;

BOOL                    fDeltaCrlEntry; 

} CERT_REVOCATION_CRL_INFO, *PCERT_REVOCATION_CRL_INFO;

typedef struct _CERT_REVOCATION_CHAIN_PARA

CERT_REVOCATION_CHAIN_PARA,

*PCERT_REVOCATION_CHAIN_PARA;

typedef struct _CERT_REVOCATION_PARA {

DWORD                       cbSize;

PCCERT_CONTEXT              pIssuerCert;

DWORD                       cCertStore;

HCERTSTORE                  *rgCertStore;

HCERTSTORE                  hCrlStore;

LPFILETIME                  pftTimeToUse;

} CERT_REVOCATION_PARA, *PCERT_REVOCATION_PARA;

typedef struct _CERT_REVOCATION_STATUS {

DWORD                   cbSize;

DWORD                   dwIndex;

DWORD                   dwError;

DWORD                   dwReason;

BOOL                    fHasFreshnessTime;

DWORD                   dwFreshnessTime;    

} CERT_REVOCATION_STATUS, *PCERT_REVOCATION_STATUS;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CertVerifyRevocation(

DWORD dwEncodingType,

DWORD dwRevType,

DWORD cContext,

PVOID rgpvContext[],

DWORD dwFlags,

PCERT_REVOCATION_PARA pRevPara,

PCERT_REVOCATION_STATUS pRevStatus

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CertCompareIntegerBlob(

PCRYPT_INTEGER_BLOB pInt1,

PCRYPT_INTEGER_BLOB pInt2

);

BOOL

__stdcall

CertCompareCertificate(

DWORD dwCertEncodingType,

PCERT_INFO pCertId1,

PCERT_INFO pCertId2

);

BOOL

__stdcall

CertCompareCertificateName(

DWORD dwCertEncodingType,

PCERT_NAME_BLOB pCertName1,

PCERT_NAME_BLOB pCertName2

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CertIsRDNAttrsInCertificateName(

DWORD dwCertEncodingType,

DWORD dwFlags,

PCERT_NAME_BLOB pCertName,

PCERT_RDN pRDN

);

BOOL

__stdcall

CertComparePublicKeyInfo(

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pPublicKey1,

PCERT_PUBLIC_KEY_INFO pPublicKey2

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

DWORD

__stdcall

CertGetPublicKeyLength(

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pPublicKey

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptVerifyCertificateSignature(

HCRYPTPROV_LEGACY hCryptProv,

DWORD dwCertEncodingType,

const BYTE *pbEncoded,

DWORD cbEncoded,

PCERT_PUBLIC_KEY_INFO pPublicKey

);

BOOL

__stdcall

CryptVerifyCertificateSignatureEx(

HCRYPTPROV_LEGACY hCryptProv,

DWORD dwCertEncodingType,

DWORD dwSubjectType,

void *pvSubject,

DWORD dwIssuerType,

void *pvIssuer,

DWORD dwFlags,

void *pvExtra

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef struct _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO {

CRYPT_DATA_BLOB CertSignHashCNGAlgPropData;

CRYPT_DATA_BLOB CertIssuerPubKeyBitLengthPropData;

} CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO,

*PCRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO;

typedef struct _CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO {

DWORD   cCNGHashAlgid;

PCWSTR  *rgpwszCNGHashAlgid;

DWORD   dwWeakIndex;

} CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO,

*PCRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CertIsStrongHashToSign(

PCCERT_STRONG_SIGN_PARA pStrongSignPara,

LPCWSTR pwszCNGHashAlgid,

PCCERT_CONTEXT pSigningCert

);

BOOL

__stdcall

CryptHashToBeSigned(

HCRYPTPROV_LEGACY hCryptProv,

DWORD dwCertEncodingType,

const BYTE *pbEncoded,

DWORD cbEncoded,

BYTE *pbComputedHash,

DWORD *pcbComputedHash

);

BOOL

__stdcall

CryptHashCertificate(

HCRYPTPROV_LEGACY hCryptProv,

ALG_ID Algid,

DWORD dwFlags,

const BYTE *pbEncoded,

DWORD cbEncoded,

BYTE *pbComputedHash,

DWORD *pcbComputedHash

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CryptHashCertificate2(

LPCWSTR pwszCNGHashAlgid,

DWORD dwFlags,

void *pvReserved,

const BYTE *pbEncoded,

DWORD cbEncoded,

BYTE *pbComputedHash,

DWORD *pcbComputedHash

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptSignCertificate(

HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,

DWORD dwKeySpec,       

DWORD dwCertEncodingType,

const BYTE *pbEncodedToBeSigned,

DWORD cbEncodedToBeSigned,

PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,

const void *pvHashAuxInfo,

BYTE *pbSignature,

DWORD *pcbSignature

);

BOOL

__stdcall

CryptSignAndEncodeCertificate(

HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,

DWORD dwKeySpec,       

DWORD dwCertEncodingType,

LPCSTR lpszStructType,       

const void *pvStructInfo,

PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,

const void *pvHashAuxInfo,

BYTE *pbEncoded,

DWORD *pcbEncoded

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef BOOL (__stdcall *PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)(

DWORD dwCertEncodingType,

PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,

void **ppvDecodedSignPara, 

LPWSTR *ppwszCNGHashAlgid      

);

typedef BOOL (__stdcall *PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC)(

NCRYPT_KEY_HANDLE hKey,

DWORD dwCertEncodingType,

PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,

void *pvDecodedSignPara,

LPCWSTR pwszCNGPubKeyAlgid,    

LPCWSTR pwszCNGHashAlgid,

BYTE *pbComputedHash,

DWORD cbComputedHash,

BYTE *pbSignature,

DWORD *pcbSignature

);

typedef BOOL (__stdcall *PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC)(

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pPubKeyInfo,

PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,

void *pvDecodedSignPara,

LPCWSTR pwszCNGPubKeyAlgid,    

LPCWSTR pwszCNGHashAlgid,

BYTE *pbComputedHash,

DWORD cbComputedHash,

BYTE *pbSignature,

DWORD cbSignature

);

LONG

__stdcall

CertVerifyTimeValidity(

LPFILETIME pTimeToVerify,

PCERT_INFO pCertInfo

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

LONG

__stdcall

CertVerifyCRLTimeValidity(

LPFILETIME pTimeToVerify,

PCRL_INFO pCrlInfo

);

BOOL

__stdcall

CertVerifyValidityNesting(

PCERT_INFO pSubjectInfo,

PCERT_INFO pIssuerInfo

);

BOOL

__stdcall

CertVerifyCRLRevocation(

DWORD dwCertEncodingType,

PCERT_INFO pCertId,          

DWORD cCrlInfo,

PCRL_INFO rgpCrlInfo[]

);

LPCSTR

__stdcall

CertAlgIdToOID(

DWORD dwAlgId

);

DWORD

__stdcall

CertOIDToAlgId(

LPCSTR pszObjId

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

PCERT_EXTENSION

__stdcall

CertFindExtension(

LPCSTR pszObjId,

DWORD cExtensions,

CERT_EXTENSION rgExtensions[]

);

PCRYPT_ATTRIBUTE

__stdcall

CertFindAttribute(

LPCSTR pszObjId,

DWORD cAttr,

CRYPT_ATTRIBUTE rgAttr[]

);

PCERT_RDN_ATTR

__stdcall

CertFindRDNAttr(

LPCSTR pszObjId,

PCERT_NAME_INFO pName

);

BOOL

__stdcall

CertGetIntendedKeyUsage(

DWORD dwCertEncodingType,

PCERT_INFO pCertInfo,

BYTE *pbKeyUsage,

DWORD cbKeyUsage

);

typedef void *HCRYPTDEFAULTCONTEXT;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptInstallDefaultContext(

HCRYPTPROV hCryptProv,

DWORD dwDefaultType,

const void *pvDefaultPara,

DWORD dwFlags,

void *pvReserved,

HCRYPTDEFAULTCONTEXT *phDefaultContext

);

typedef struct _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA {

DWORD               cOID;

LPSTR               *rgpszOID;

} CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA, *PCRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA;

BOOL

__stdcall

CryptUninstallDefaultContext(

HCRYPTDEFAULTCONTEXT hDefaultContext,

DWORD dwFlags,

void *pvReserved

);

BOOL

__stdcall

CryptExportPublicKeyInfo(

HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,

DWORD dwKeySpec,       

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pInfo,

DWORD *pcbInfo

);

BOOL

__stdcall

CryptExportPublicKeyInfoEx(

HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,

DWORD dwKeySpec,       

DWORD dwCertEncodingType,

LPSTR pszPublicKeyObjId,

DWORD dwFlags,

void *pvAuxInfo,

PCERT_PUBLIC_KEY_INFO pInfo,

DWORD *pcbInfo

);

typedef BOOL (__stdcall *PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC) (

NCRYPT_KEY_HANDLE hNCryptKey,

DWORD dwCertEncodingType,

LPSTR pszPublicKeyObjId,

DWORD dwFlags,

void *pvAuxInfo,

PCERT_PUBLIC_KEY_INFO pInfo,

DWORD *pcbInfo

);

BOOL

__stdcall

CryptExportPublicKeyInfoFromBCryptKeyHandle(

BCRYPT_KEY_HANDLE hBCryptKey,

DWORD dwCertEncodingType,

LPSTR pszPublicKeyObjId,

DWORD dwFlags,

void *pvAuxInfo,

PCERT_PUBLIC_KEY_INFO pInfo,

DWORD *pcbInfo

);

typedef BOOL (__stdcall *PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC) (

BCRYPT_KEY_HANDLE hBCryptKey,

DWORD dwCertEncodingType,

LPSTR pszPublicKeyObjId,

DWORD dwFlags,

void *pvAuxInfo,

PCERT_PUBLIC_KEY_INFO pInfo,

DWORD *pcbInfo

);

BOOL

__stdcall

CryptImportPublicKeyInfo(

HCRYPTPROV hCryptProv,

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pInfo,

HCRYPTKEY *phKey

);

BOOL

__stdcall

CryptImportPublicKeyInfoEx(

HCRYPTPROV hCryptProv,

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pInfo,

ALG_ID aiKeyAlg,

DWORD dwFlags,

void *pvAuxInfo,

HCRYPTKEY *phKey

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CryptImportPublicKeyInfoEx2(

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pInfo,

DWORD dwFlags,

void *pvAuxInfo,

BCRYPT_KEY_HANDLE *phKey

);

typedef BOOL (__stdcall *PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC) (

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pInfo,

DWORD dwFlags,

void *pvAuxInfo,

BCRYPT_KEY_HANDLE *phKey

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CryptAcquireCertificatePrivateKey(

PCCERT_CONTEXT pCert,

DWORD dwFlags,

void *pvParameters,

HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey,

DWORD *pdwKeySpec,

BOOL *pfCallerFreeProvOrNCryptKey

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptFindCertificateKeyProvInfo(

PCCERT_CONTEXT pCert,

DWORD dwFlags,

void *pvReserved

);

typedef BOOL (__stdcall *PFN_IMPORT_PRIV_KEY_FUNC) (

HCRYPTPROV hCryptProv,                     

CRYPT_PRIVATE_KEY_INFO* pPrivateKeyInfo,   

DWORD dwFlags,                             

void* pvAuxInfo                        

);

BOOL

__stdcall

CryptImportPKCS8(

CRYPT_PKCS8_IMPORT_PARAMS sPrivateKeyAndParams,    

DWORD dwFlags,                                     

HCRYPTPROV *phCryptProv,                      

void* pvAuxInfo                                

);

typedef BOOL (__stdcall *PFN_EXPORT_PRIV_KEY_FUNC) (

HCRYPTPROV hCryptProv,         

DWORD dwKeySpec,               

LPSTR pszPrivateKeyObjId,      

DWORD dwFlags,                 

void* pvAuxInfo,           

CRYPT_PRIVATE_KEY_INFO* pPrivateKeyInfo,  

DWORD* pcbPrivateKeyInfo    

);

BOOL

__stdcall

CryptExportPKCS8(

HCRYPTPROV hCryptProv,                                     

DWORD dwKeySpec,                                           

LPSTR pszPrivateKeyObjId,                                  

DWORD dwFlags,                                             

void* pvAuxInfo,                                       

BYTE* pbPrivateKeyBlob,   

DWORD *pcbPrivateKeyBlob                                

);

#pragma endregion

#pragma region Desktop or Games Family

BOOL

__stdcall

CryptExportPKCS8Ex(

CRYPT_PKCS8_EXPORT_PARAMS* psExportParams,                 

DWORD dwFlags,                                             

void* pvAuxInfo,                                       

BYTE* pbPrivateKeyBlob,   

DWORD* pcbPrivateKeyBlob                                

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CryptHashPublicKeyInfo(

HCRYPTPROV_LEGACY hCryptProv,

ALG_ID Algid,

DWORD dwFlags,

DWORD dwCertEncodingType,

PCERT_PUBLIC_KEY_INFO pInfo,

BYTE *pbComputedHash,

DWORD *pcbComputedHash

);

DWORD

__stdcall

CertRDNValueToStrA(

DWORD dwValueType,

PCERT_RDN_VALUE_BLOB pValue,

LPSTR psz,

DWORD csz

);

DWORD

__stdcall

CertRDNValueToStrW(

DWORD dwValueType,

PCERT_RDN_VALUE_BLOB pValue,

LPWSTR psz,

DWORD csz

);

DWORD

__stdcall

CertNameToStrA(

DWORD dwCertEncodingType,

PCERT_NAME_BLOB pName,

DWORD dwStrType,

LPSTR psz,

DWORD csz

);

DWORD

__stdcall

CertNameToStrW(

DWORD dwCertEncodingType,

PCERT_NAME_BLOB pName,

DWORD dwStrType,

LPWSTR psz,

DWORD csz

);

BOOL

__stdcall

CertStrToNameA(

DWORD dwCertEncodingType,

LPCSTR pszX500,

DWORD dwStrType,

void *pvReserved,

BYTE *pbEncoded,

DWORD *pcbEncoded,

LPCSTR *ppszError

);

BOOL

__stdcall

CertStrToNameW(

DWORD dwCertEncodingType,

LPCWSTR pszX500,

DWORD dwStrType,

void *pvReserved,

BYTE *pbEncoded,

DWORD *pcbEncoded,

LPCWSTR *ppszError

);

DWORD

__stdcall

CertGetNameStringA(

PCCERT_CONTEXT pCertContext,

DWORD dwType,

DWORD dwFlags,

void *pvTypePara,

LPSTR pszNameString,

DWORD cchNameString

);

DWORD

__stdcall

CertGetNameStringW(

PCCERT_CONTEXT pCertContext,

DWORD dwType,

DWORD dwFlags,

void *pvTypePara,

LPWSTR pszNameString,

DWORD cchNameString

);

typedef PCCERT_CONTEXT (__stdcall *PFN_CRYPT_GET_SIGNER_CERTIFICATE)(

void *pvGetArg,

DWORD dwCertEncodingType,

PCERT_INFO pSignerId,    

HCERTSTORE hMsgCertStore

);

typedef struct _CRYPT_SIGN_MESSAGE_PARA {

DWORD                       cbSize;

DWORD                       dwMsgEncodingType;

PCCERT_CONTEXT              pSigningCert;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

void                        *pvHashAuxInfo;

DWORD                       cMsgCert;

PCCERT_CONTEXT              *rgpMsgCert;

DWORD                       cMsgCrl;

PCCRL_CONTEXT               *rgpMsgCrl;

DWORD                       cAuthAttr;

PCRYPT_ATTRIBUTE            rgAuthAttr;

DWORD                       cUnauthAttr;

PCRYPT_ATTRIBUTE            rgUnauthAttr;

DWORD                       dwFlags;

DWORD                       dwInnerContentType;

} CRYPT_SIGN_MESSAGE_PARA, *PCRYPT_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_VERIFY_MESSAGE_PARA {

DWORD                               cbSize;

DWORD                               dwMsgAndCertEncodingType;

HCRYPTPROV_LEGACY                   hCryptProv;

PFN_CRYPT_GET_SIGNER_CERTIFICATE    pfnGetSignerCertificate;

void                                *pvGetArg;

} CRYPT_VERIFY_MESSAGE_PARA, *PCRYPT_VERIFY_MESSAGE_PARA;

typedef struct _CRYPT_ENCRYPT_MESSAGE_PARA {

DWORD                       cbSize;

DWORD                       dwMsgEncodingType;

HCRYPTPROV_LEGACY           hCryptProv;

CRYPT_ALGORITHM_IDENTIFIER  ContentEncryptionAlgorithm;

void                        *pvEncryptionAuxInfo;

DWORD                       dwFlags;

DWORD                       dwInnerContentType;

} CRYPT_ENCRYPT_MESSAGE_PARA, *PCRYPT_ENCRYPT_MESSAGE_PARA;

typedef struct _CRYPT_DECRYPT_MESSAGE_PARA {

DWORD                   cbSize;

DWORD                   dwMsgAndCertEncodingType;

DWORD                   cCertStore;

HCERTSTORE              *rghCertStore;

} CRYPT_DECRYPT_MESSAGE_PARA, *PCRYPT_DECRYPT_MESSAGE_PARA;

typedef struct _CRYPT_HASH_MESSAGE_PARA {

DWORD                       cbSize;

DWORD                       dwMsgEncodingType;

HCRYPTPROV_LEGACY           hCryptProv;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

void                        *pvHashAuxInfo;

} CRYPT_HASH_MESSAGE_PARA, *PCRYPT_HASH_MESSAGE_PARA;

typedef struct _CRYPT_KEY_SIGN_MESSAGE_PARA {

DWORD                       cbSize;

DWORD                       dwMsgAndCertEncodingType;

union {

HCRYPTPROV                  hCryptProv;

NCRYPT_KEY_HANDLE           hNCryptKey;

} DUMMYUNIONNAME;

DWORD                       dwKeySpec;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

void                        *pvHashAuxInfo;

CRYPT_ALGORITHM_IDENTIFIER  PubKeyAlgorithm;

} CRYPT_KEY_SIGN_MESSAGE_PARA, *PCRYPT_KEY_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_KEY_VERIFY_MESSAGE_PARA {

DWORD                   cbSize;

DWORD                   dwMsgEncodingType;

HCRYPTPROV_LEGACY       hCryptProv;

} CRYPT_KEY_VERIFY_MESSAGE_PARA, *PCRYPT_KEY_VERIFY_MESSAGE_PARA;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptSignMessage(

PCRYPT_SIGN_MESSAGE_PARA pSignPara,

BOOL fDetachedSignature,

DWORD cToBeSigned,

const BYTE *rgpbToBeSigned[],

DWORD rgcbToBeSigned[],

BYTE *pbSignedBlob,

DWORD *pcbSignedBlob

);

BOOL

__stdcall

CryptVerifyMessageSignature(

PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,

DWORD dwSignerIndex,

const BYTE *pbSignedBlob,

DWORD cbSignedBlob,

BYTE *pbDecoded,

DWORD *pcbDecoded,

PCCERT_CONTEXT *ppSignerCert

);

LONG

__stdcall

CryptGetMessageSignerCount(

DWORD dwMsgEncodingType,

const BYTE *pbSignedBlob,

DWORD cbSignedBlob

);

HCERTSTORE

__stdcall

CryptGetMessageCertificates(

DWORD dwMsgAndCertEncodingType,

HCRYPTPROV_LEGACY hCryptProv,           

DWORD dwFlags,                   

const BYTE *pbSignedBlob,

DWORD cbSignedBlob

);

BOOL

__stdcall

CryptVerifyDetachedMessageSignature(

PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,

DWORD dwSignerIndex,

const BYTE *pbDetachedSignBlob,

DWORD cbDetachedSignBlob,

DWORD cToBeSigned,

const BYTE *rgpbToBeSigned[],

DWORD rgcbToBeSigned[],

PCCERT_CONTEXT *ppSignerCert

);

BOOL

__stdcall

CryptEncryptMessage(

PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,

DWORD cRecipientCert,

PCCERT_CONTEXT rgpRecipientCert[],

const BYTE *pbToBeEncrypted,

DWORD cbToBeEncrypted,

BYTE *pbEncryptedBlob,

DWORD *pcbEncryptedBlob

);

BOOL

__stdcall

CryptDecryptMessage(

PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,

const BYTE *pbEncryptedBlob,

DWORD cbEncryptedBlob,

BYTE *pbDecrypted,

DWORD *pcbDecrypted,

PCCERT_CONTEXT *ppXchgCert

);

BOOL

__stdcall

CryptSignAndEncryptMessage(

PCRYPT_SIGN_MESSAGE_PARA pSignPara,

PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,

DWORD cRecipientCert,

PCCERT_CONTEXT rgpRecipientCert[],

const BYTE *pbToBeSignedAndEncrypted,

DWORD cbToBeSignedAndEncrypted,

BYTE *pbSignedAndEncryptedBlob,

DWORD *pcbSignedAndEncryptedBlob

);

BOOL

__stdcall

CryptDecryptAndVerifyMessageSignature(

PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,

PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,

DWORD dwSignerIndex,

const BYTE *pbEncryptedBlob,

DWORD cbEncryptedBlob,

BYTE *pbDecrypted,

DWORD *pcbDecrypted,

PCCERT_CONTEXT *ppXchgCert,

PCCERT_CONTEXT *ppSignerCert

);

BOOL

__stdcall

CryptDecodeMessage(

DWORD dwMsgTypeFlags,

PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,

PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,

DWORD dwSignerIndex,

const BYTE *pbEncodedBlob,

DWORD cbEncodedBlob,

DWORD dwPrevInnerContentType,

DWORD *pdwMsgType,

DWORD *pdwInnerContentType,

BYTE *pbDecoded,

DWORD *pcbDecoded,

PCCERT_CONTEXT *ppXchgCert,

PCCERT_CONTEXT *ppSignerCert

);

BOOL

__stdcall

CryptHashMessage(

PCRYPT_HASH_MESSAGE_PARA pHashPara,

BOOL fDetachedHash,

DWORD cToBeHashed,

const BYTE *rgpbToBeHashed[],

DWORD rgcbToBeHashed[],

BYTE *pbHashedBlob,

DWORD *pcbHashedBlob,

BYTE *pbComputedHash,

DWORD *pcbComputedHash

);

BOOL

__stdcall

CryptVerifyMessageHash(

PCRYPT_HASH_MESSAGE_PARA pHashPara,

BYTE *pbHashedBlob,

DWORD cbHashedBlob,

BYTE *pbToBeHashed,

DWORD *pcbToBeHashed,

BYTE *pbComputedHash,

DWORD *pcbComputedHash

);

BOOL

__stdcall

CryptVerifyDetachedMessageHash(

PCRYPT_HASH_MESSAGE_PARA pHashPara,

BYTE *pbDetachedHashBlob,

DWORD cbDetachedHashBlob,

DWORD cToBeHashed,

const BYTE *rgpbToBeHashed[],

DWORD rgcbToBeHashed[],

BYTE *pbComputedHash,

DWORD *pcbComputedHash

);

BOOL

__stdcall

CryptSignMessageWithKey(

PCRYPT_KEY_SIGN_MESSAGE_PARA pSignPara,

const BYTE *pbToBeSigned,

DWORD cbToBeSigned,

BYTE *pbSignedBlob,

DWORD *pcbSignedBlob

);

BOOL

__stdcall

CryptVerifyMessageSignatureWithKey(

PCRYPT_KEY_VERIFY_MESSAGE_PARA pVerifyPara,

PCERT_PUBLIC_KEY_INFO pPublicKeyInfo,

const BYTE *pbSignedBlob,

DWORD cbSignedBlob,

BYTE *pbDecoded,

DWORD *pcbDecoded

);

HCERTSTORE

__stdcall

CertOpenSystemStoreA(

HCRYPTPROV_LEGACY      hProv,

LPCSTR            szSubsystemProtocol

);

HCERTSTORE

__stdcall

CertOpenSystemStoreW(

HCRYPTPROV_LEGACY      hProv,

LPCWSTR            szSubsystemProtocol

);

BOOL

__stdcall

CertAddEncodedCertificateToSystemStoreA(

LPCSTR            szCertStoreName,

const BYTE *    pbCertEncoded,

DWORD           cbCertEncoded

);

BOOL

__stdcall

CertAddEncodedCertificateToSystemStoreW(

LPCWSTR            szCertStoreName,

const BYTE *    pbCertEncoded,

DWORD           cbCertEncoded

);

#pragma endregion

#pragma region Desktop Family or Wintrust Package or Games Family

typedef struct _CERT_CHAIN {

DWORD                   cCerts;     

PCERT_BLOB              certs;      

CRYPT_KEY_PROV_INFO     keyLocatorInfo; 

} CERT_CHAIN, *PCERT_CHAIN;

HRESULT

__stdcall

FindCertsByIssuer(

PCERT_CHAIN pCertChains,

DWORD *pcbCertChains,

DWORD *pcCertChains,        

BYTE* pbEncodedIssuerName,   

DWORD cbEncodedIssuerName,   

LPCWSTR pwszPurpose,     

DWORD dwKeySpec              

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

BOOL

__stdcall

CryptQueryObject(

DWORD                    dwObjectType,

const void               *pvObject,

DWORD                    dwExpectedContentTypeFlags,

DWORD                    dwExpectedFormatTypeFlags,

DWORD                    dwFlags,

DWORD               *pdwMsgAndCertEncodingType,

DWORD               *pdwContentType,

DWORD               *pdwFormatType,

HCERTSTORE          *phCertStore,

HCRYPTMSG           *phMsg,

const void **ppvContext

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

LPVOID

__stdcall

CryptMemAlloc (

ULONG cbSize

);

LPVOID

__stdcall

CryptMemRealloc (

LPVOID pv,

ULONG cbSize

);

VOID

__stdcall

CryptMemFree (

LPVOID pv

);

typedef HANDLE HCRYPTASYNC, *PHCRYPTASYNC;

typedef VOID (__stdcall *PFN_CRYPT_ASYNC_PARAM_FREE_FUNC) (

LPSTR pszParamOid,

LPVOID pvParam

);

BOOL

__stdcall

CryptCreateAsyncHandle (

DWORD dwFlags,

PHCRYPTASYNC phAsync

);

BOOL

__stdcall

CryptSetAsyncParam (

HCRYPTASYNC hAsync,

LPSTR pszParamOid,

LPVOID pvParam,

PFN_CRYPT_ASYNC_PARAM_FREE_FUNC pfnFree

);

BOOL

__stdcall

CryptGetAsyncParam (

HCRYPTASYNC hAsync,

LPSTR pszParamOid,

LPVOID* ppvParam,

PFN_CRYPT_ASYNC_PARAM_FREE_FUNC* ppfnFree

);

BOOL

__stdcall

CryptCloseAsyncHandle (

HCRYPTASYNC hAsync

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef struct _CRYPT_BLOB_ARRAY {

DWORD            cBlob;

PCRYPT_DATA_BLOB rgBlob;

} CRYPT_BLOB_ARRAY, *PCRYPT_BLOB_ARRAY;

typedef struct _CRYPT_CREDENTIALS {

DWORD  cbSize;

LPCSTR pszCredentialsOid;

LPVOID pvCredentials;

} CRYPT_CREDENTIALS, *PCRYPT_CREDENTIALS;

typedef struct _CRYPT_PASSWORD_CREDENTIALSA {

DWORD   cbSize;

LPSTR   pszUsername;

LPSTR   pszPassword;

} CRYPT_PASSWORD_CREDENTIALSA, *PCRYPT_PASSWORD_CREDENTIALSA;

typedef struct _CRYPT_PASSWORD_CREDENTIALSW {

DWORD   cbSize;

LPWSTR  pszUsername;

LPWSTR  pszPassword;

} CRYPT_PASSWORD_CREDENTIALSW, *PCRYPT_PASSWORD_CREDENTIALSW;

typedef CRYPT_PASSWORD_CREDENTIALSA CRYPT_PASSWORD_CREDENTIALS;

typedef PCRYPT_PASSWORD_CREDENTIALSA PCRYPT_PASSWORD_CREDENTIALS;

typedef VOID (__stdcall *PFN_FREE_ENCODED_OBJECT_FUNC) (

LPCSTR pszObjectOid,

PCRYPT_BLOB_ARRAY pObject,

LPVOID pvFreeContext

);

typedef struct _CRYPTNET_URL_CACHE_PRE_FETCH_INFO {

DWORD           cbSize;

DWORD           dwObjectType;

DWORD           dwError;

DWORD           dwReserved;

FILETIME        ThisUpdateTime;

FILETIME        NextUpdateTime;

FILETIME        PublishTime;    

} CRYPTNET_URL_CACHE_PRE_FETCH_INFO, *PCRYPTNET_URL_CACHE_PRE_FETCH_INFO;

typedef struct _CRYPTNET_URL_CACHE_FLUSH_INFO {

DWORD           cbSize;

DWORD           dwExemptSeconds;

FILETIME        ExpireTime;

} CRYPTNET_URL_CACHE_FLUSH_INFO, *PCRYPTNET_URL_CACHE_FLUSH_INFO;

typedef struct _CRYPTNET_URL_CACHE_RESPONSE_INFO {

DWORD           cbSize;

WORD            wResponseType;

WORD            wResponseFlags;

FILETIME        LastModifiedTime;

DWORD           dwMaxAge;

LPCWSTR         pwszETag;

DWORD           dwProxyId;

} CRYPTNET_URL_CACHE_RESPONSE_INFO, *PCRYPTNET_URL_CACHE_RESPONSE_INFO;

typedef struct _CRYPT_RETRIEVE_AUX_INFO {

DWORD                               cbSize;

FILETIME                            *pLastSyncTime;

DWORD                               dwMaxUrlRetrievalByteCount;

PCRYPTNET_URL_CACHE_PRE_FETCH_INFO  pPreFetchInfo;

PCRYPTNET_URL_CACHE_FLUSH_INFO      pFlushInfo;

PCRYPTNET_URL_CACHE_RESPONSE_INFO   *ppResponseInfo;

LPWSTR                              pwszCacheFileNamePrefix;

LPFILETIME                          pftCacheResync;

BOOL                                fProxyCacheRetrieval;

DWORD                               dwHttpStatusCode;

LPWSTR                              *ppwszErrorResponseHeaders;

PCRYPT_DATA_BLOB                    *ppErrorContentBlob;

} CRYPT_RETRIEVE_AUX_INFO, *PCRYPT_RETRIEVE_AUX_INFO;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptRetrieveObjectByUrlA (

LPCSTR pszUrl,

LPCSTR pszObjectOid,

DWORD dwRetrievalFlags,

DWORD dwTimeout,                     

LPVOID* ppvObject,

HCRYPTASYNC hAsyncRetrieve,

PCRYPT_CREDENTIALS pCredentials,

LPVOID pvVerify,

PCRYPT_RETRIEVE_AUX_INFO pAuxInfo

);

BOOL

__stdcall

CryptRetrieveObjectByUrlW (

LPCWSTR pszUrl,

LPCSTR pszObjectOid,

DWORD dwRetrievalFlags,

DWORD dwTimeout,                     

LPVOID* ppvObject,

HCRYPTASYNC hAsyncRetrieve,

PCRYPT_CREDENTIALS pCredentials,

LPVOID pvVerify,

PCRYPT_RETRIEVE_AUX_INFO pAuxInfo

);

typedef BOOL (__stdcall *PFN_CRYPT_CANCEL_RETRIEVAL)(

DWORD dwFlags,

void  *pvArg

);

BOOL

__stdcall

CryptInstallCancelRetrieval(

PFN_CRYPT_CANCEL_RETRIEVAL pfnCancel,

const void *pvArg,

DWORD dwFlags,

void *pvReserved

);

BOOL

__stdcall

CryptUninstallCancelRetrieval(

DWORD dwFlags,

void *pvReserved

);

#pragma endregion

#pragma region Desktop or Games Family

BOOL

__stdcall

CryptCancelAsyncRetrieval (

HCRYPTASYNC hAsyncRetrieval

);

typedef VOID (__stdcall *PFN_CRYPT_ASYNC_RETRIEVAL_COMPLETION_FUNC) (

LPVOID pvCompletion,

DWORD dwCompletionCode,

LPCSTR pszUrl,

LPSTR pszObjectOid,

LPVOID pvObject

);

typedef struct _CRYPT_ASYNC_RETRIEVAL_COMPLETION {

PFN_CRYPT_ASYNC_RETRIEVAL_COMPLETION_FUNC pfnCompletion;

LPVOID pvCompletion;

} CRYPT_ASYNC_RETRIEVAL_COMPLETION, *PCRYPT_ASYNC_RETRIEVAL_COMPLETION;

typedef BOOL (__stdcall *PFN_CANCEL_ASYNC_RETRIEVAL_FUNC) (

HCRYPTASYNC hAsyncRetrieve

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

typedef struct _CRYPT_URL_ARRAY {

DWORD   cUrl;

LPWSTR* rgwszUrl;

} CRYPT_URL_ARRAY, *PCRYPT_URL_ARRAY;

typedef struct _CRYPT_URL_INFO {

DWORD   cbSize;

DWORD   dwSyncDeltaTime;

DWORD   cGroup;

DWORD   *rgcGroupEntry;

} CRYPT_URL_INFO, *PCRYPT_URL_INFO;

BOOL

__stdcall

CryptGetObjectUrl (

LPCSTR pszUrlOid,

LPVOID pvPara,

DWORD dwFlags,

PCRYPT_URL_ARRAY pUrlArray,

DWORD* pcbUrlArray,

PCRYPT_URL_INFO pUrlInfo,

DWORD* pcbUrlInfo,

LPVOID pvReserved

);

typedef struct _CERT_CRL_CONTEXT_PAIR {

PCCERT_CONTEXT          pCertContext;

PCCRL_CONTEXT           pCrlContext;

} CERT_CRL_CONTEXT_PAIR, *PCERT_CRL_CONTEXT_PAIR;

typedef const CERT_CRL_CONTEXT_PAIR *PCCERT_CRL_CONTEXT_PAIR;

#pragma endregion

#pragma region Desktop or Games Family

typedef struct _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO {

DWORD                       cbSize;

int                         iDeltaCrlIndicator;

LPFILETIME                  pftCacheResync;

LPFILETIME                  pLastSyncTime;

LPFILETIME                  pMaxAgeTime;

PCERT_REVOCATION_CHAIN_PARA pChainPara;

PCRYPT_INTEGER_BLOB pDeltaCrlIndicator;

} CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO,

*PCRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO;

BOOL

__stdcall

CryptGetTimeValidObject (

LPCSTR pszTimeValidOid,

LPVOID pvPara,

PCCERT_CONTEXT pIssuer,

LPFILETIME pftValidFor,

DWORD dwFlags,

DWORD dwTimeout,                         

LPVOID* ppvObject,

PCRYPT_CREDENTIALS pCredentials,

PCRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO pExtraInfo

);

BOOL

__stdcall

CryptFlushTimeValidObject (

LPCSTR pszFlushTimeValidOid,

LPVOID pvPara,

PCCERT_CONTEXT pIssuer,

DWORD dwFlags,

LPVOID pvReserved

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

PCCERT_CONTEXT

__stdcall

CertCreateSelfSignCertificate(

HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,

PCERT_NAME_BLOB             pSubjectIssuerBlob,

DWORD                       dwFlags,

PCRYPT_KEY_PROV_INFO        pKeyProvInfo,

PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,

PSYSTEMTIME                 pStartTime,

PSYSTEMTIME                 pEndTime,

PCERT_EXTENSIONS            pExtensions

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptGetKeyIdentifierProperty(

const CRYPT_HASH_BLOB *pKeyIdentifier,

DWORD dwPropId,

DWORD dwFlags,

LPCWSTR pwszComputerName,

void *pvReserved,

void *pvData,

DWORD *pcbData

);

BOOL

__stdcall

CryptSetKeyIdentifierProperty(

const CRYPT_HASH_BLOB *pKeyIdentifier,

DWORD dwPropId,

DWORD dwFlags,

LPCWSTR pwszComputerName,

void *pvReserved,

const void *pvData

);

typedef BOOL (__stdcall *PFN_CRYPT_ENUM_KEYID_PROP)(

const CRYPT_HASH_BLOB *pKeyIdentifier,

DWORD dwFlags,

void *pvReserved,

void *pvArg,

DWORD cProp,

DWORD *rgdwPropId,

void **rgpvData,

DWORD *rgcbData

);

BOOL

__stdcall

CryptEnumKeyIdentifierProperties(

const CRYPT_HASH_BLOB *pKeyIdentifier,

DWORD dwPropId,

DWORD dwFlags,

LPCWSTR pwszComputerName,

void *pvReserved,

void *pvArg,

PFN_CRYPT_ENUM_KEYID_PROP pfnEnum

);

BOOL

__stdcall

CryptCreateKeyIdentifierFromCSP(

DWORD dwCertEncodingType,

LPCSTR pszPubKeyOID,

const PUBLICKEYSTRUC *pPubKeyStruc,

DWORD cbPubKeyStruc,

DWORD dwFlags,

void *pvReserved,

BYTE *pbHash,

DWORD *pcbHash

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef HANDLE HCERTCHAINENGINE;

typedef struct _CERT_CHAIN_ENGINE_CONFIG {

DWORD       cbSize;

HCERTSTORE  hRestrictedRoot;

HCERTSTORE  hRestrictedTrust;

HCERTSTORE  hRestrictedOther;

DWORD       cAdditionalStore;

HCERTSTORE* rghAdditionalStore;

DWORD       dwFlags;

DWORD       dwUrlRetrievalTimeout;      

DWORD       MaximumCachedCertificates;

DWORD       CycleDetectionModulus;

HCERTSTORE  hExclusiveRoot;

HCERTSTORE  hExclusiveTrustedPeople;

DWORD       dwExclusiveFlags;

} CERT_CHAIN_ENGINE_CONFIG, *PCERT_CHAIN_ENGINE_CONFIG;

BOOL

__stdcall

CertCreateCertificateChainEngine (

PCERT_CHAIN_ENGINE_CONFIG pConfig,

HCERTCHAINENGINE* phChainEngine

);

VOID

__stdcall

CertFreeCertificateChainEngine (

HCERTCHAINENGINE hChainEngine

);

BOOL

__stdcall

CertResyncCertificateChainEngine (

HCERTCHAINENGINE hChainEngine

);

typedef struct _CERT_TRUST_STATUS {

DWORD dwErrorStatus;

DWORD dwInfoStatus;

} CERT_TRUST_STATUS, *PCERT_TRUST_STATUS;

typedef struct _CERT_REVOCATION_INFO {

DWORD                       cbSize;

DWORD                       dwRevocationResult;

LPCSTR                      pszRevocationOid;

LPVOID                      pvOidSpecificInfo;

BOOL                        fHasFreshnessTime;

DWORD                       dwFreshnessTime;    

PCERT_REVOCATION_CRL_INFO   pCrlInfo;

} CERT_REVOCATION_INFO, *PCERT_REVOCATION_INFO;

typedef struct _CERT_TRUST_LIST_INFO {

DWORD         cbSize;

PCTL_ENTRY    pCtlEntry;

PCCTL_CONTEXT pCtlContext;

} CERT_TRUST_LIST_INFO, *PCERT_TRUST_LIST_INFO;

typedef struct _CERT_CHAIN_ELEMENT {

DWORD                 cbSize;

PCCERT_CONTEXT        pCertContext;

CERT_TRUST_STATUS     TrustStatus;

PCERT_REVOCATION_INFO pRevocationInfo;

PCERT_ENHKEY_USAGE    pIssuanceUsage;       

PCERT_ENHKEY_USAGE    pApplicationUsage;    

LPCWSTR               pwszExtendedErrorInfo;    

} CERT_CHAIN_ELEMENT, *PCERT_CHAIN_ELEMENT;

typedef const CERT_CHAIN_ELEMENT* PCCERT_CHAIN_ELEMENT;

typedef struct _CERT_SIMPLE_CHAIN {

DWORD                 cbSize;

CERT_TRUST_STATUS     TrustStatus;

DWORD                 cElement;

PCERT_CHAIN_ELEMENT*  rgpElement;

PCERT_TRUST_LIST_INFO pTrustListInfo;

BOOL                   fHasRevocationFreshnessTime;

DWORD                  dwRevocationFreshnessTime;    

} CERT_SIMPLE_CHAIN, *PCERT_SIMPLE_CHAIN;

typedef const CERT_SIMPLE_CHAIN* PCCERT_SIMPLE_CHAIN;

typedef struct _CERT_CHAIN_CONTEXT CERT_CHAIN_CONTEXT, *PCERT_CHAIN_CONTEXT;

typedef const CERT_CHAIN_CONTEXT *PCCERT_CHAIN_CONTEXT;

struct _CERT_CHAIN_CONTEXT {

DWORD                   cbSize;

CERT_TRUST_STATUS       TrustStatus;

DWORD                   cChain;

PCERT_SIMPLE_CHAIN*     rgpChain;

DWORD                   cLowerQualityChainContext;

PCCERT_CHAIN_CONTEXT*   rgpLowerQualityChainContext;

BOOL                    fHasRevocationFreshnessTime;

DWORD                   dwRevocationFreshnessTime;    

DWORD                   dwCreateFlags;

GUID                    ChainId;

};

typedef struct _CERT_USAGE_MATCH {

DWORD             dwType;

CERT_ENHKEY_USAGE Usage;

} CERT_USAGE_MATCH, *PCERT_USAGE_MATCH;

typedef struct _CTL_USAGE_MATCH {

DWORD     dwType;

CTL_USAGE Usage;

} CTL_USAGE_MATCH, *PCTL_USAGE_MATCH;

typedef struct _CERT_CHAIN_PARA {

DWORD            cbSize;

CERT_USAGE_MATCH RequestedUsage;

} CERT_CHAIN_PARA, *PCERT_CHAIN_PARA;

BOOL

__stdcall

CertGetCertificateChain (

HCERTCHAINENGINE hChainEngine,

PCCERT_CONTEXT pCertContext,

LPFILETIME pTime,

HCERTSTORE hAdditionalStore,

PCERT_CHAIN_PARA pChainPara,

DWORD dwFlags,

LPVOID pvReserved,

PCCERT_CHAIN_CONTEXT* ppChainContext

);

VOID

__stdcall

CertFreeCertificateChain (

PCCERT_CHAIN_CONTEXT pChainContext

);

PCCERT_CHAIN_CONTEXT

__stdcall

CertDuplicateCertificateChain (

PCCERT_CHAIN_CONTEXT pChainContext

);

struct _CERT_REVOCATION_CHAIN_PARA {

DWORD                       cbSize;

HCERTCHAINENGINE            hChainEngine;

HCERTSTORE                  hAdditionalStore;

DWORD                       dwChainFlags;

DWORD                       dwUrlRetrievalTimeout;     

LPFILETIME                  pftCurrentTime;

LPFILETIME                  pftCacheResync;

DWORD                       cbMaxUrlRetrievalByteCount;

};

typedef struct _CRL_REVOCATION_INFO {

PCRL_ENTRY           pCrlEntry;

PCCRL_CONTEXT        pCrlContext;

PCCERT_CHAIN_CONTEXT pCrlIssuerChain;

} CRL_REVOCATION_INFO, *PCRL_REVOCATION_INFO;

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

PCCERT_CHAIN_CONTEXT

__stdcall

CertFindChainInStore(

HCERTSTORE hCertStore,

DWORD dwCertEncodingType,

DWORD dwFindFlags,

DWORD dwFindType,

const void *pvFindPara,

PCCERT_CHAIN_CONTEXT pPrevChainContext

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef BOOL (__stdcall *PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK)(

PCCERT_CONTEXT pCert,

void *pvFindArg

);

typedef struct _CERT_CHAIN_FIND_BY_ISSUER_PARA {

DWORD                                   cbSize;

LPCSTR                                  pszUsageIdentifier;

DWORD                                   dwKeySpec;

DWORD                                   dwAcquirePrivateKeyFlags;

DWORD                                   cIssuer;

CERT_NAME_BLOB                          *rgIssuer;

PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK pfnFindCallback;

void                                    *pvFindArg;

} CERT_CHAIN_FIND_ISSUER_PARA, *PCERT_CHAIN_FIND_ISSUER_PARA,

CERT_CHAIN_FIND_BY_ISSUER_PARA, *PCERT_CHAIN_FIND_BY_ISSUER_PARA;

typedef struct _CERT_CHAIN_POLICY_PARA {

DWORD                   cbSize;

DWORD                   dwFlags;

void                    *pvExtraPolicyPara;     

} CERT_CHAIN_POLICY_PARA, *PCERT_CHAIN_POLICY_PARA;

typedef struct _CERT_CHAIN_POLICY_STATUS {

DWORD                   cbSize;

DWORD                   dwError;

LONG                    lChainIndex;

LONG                    lElementIndex;

void                    *pvExtraPolicyStatus;   

} CERT_CHAIN_POLICY_STATUS, *PCERT_CHAIN_POLICY_STATUS;

BOOL

__stdcall

CertVerifyCertificateChainPolicy(

LPCSTR pszPolicyOID,

PCCERT_CHAIN_CONTEXT pChainContext,

PCERT_CHAIN_POLICY_PARA pPolicyPara,

PCERT_CHAIN_POLICY_STATUS pPolicyStatus

);

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA {

DWORD               cbSize;

DWORD               dwRegPolicySettings;

PCMSG_SIGNER_INFO   pSignerInfo;                

} AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA,

*PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS {

DWORD               cbSize;

BOOL                fCommercial;        

} AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS,

*PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA {

DWORD               cbSize;

DWORD               dwRegPolicySettings;

BOOL                fCommercial;

} AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA,

*PAUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _HTTPSPolicyCallbackData

{

union {

DWORD           cbStruct;       

DWORD           cbSize;         

} DUMMYUNIONNAME;

DWORD           dwAuthType;

DWORD           fdwChecks;

WCHAR           *pwszServerName; 

} HTTPSPolicyCallbackData, *PHTTPSPolicyCallbackData,

SSL_EXTRA_CERT_CHAIN_POLICY_PARA, *PSSL_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_PARA {

DWORD               cbSize;

DWORD               dwRootProgramQualifierFlags;

} EV_EXTRA_CERT_CHAIN_POLICY_PARA,

*PEV_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_STATUS {

DWORD   cbSize;

DWORD   dwQualifiers;

DWORD   dwIssuanceUsageIndex;

} EV_EXTRA_CERT_CHAIN_POLICY_STATUS, *PEV_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS {

DWORD   cbSize;

DWORD   dwErrorLevel;

DWORD   dwErrorCategory;

DWORD   dwReserved;

WCHAR   wszErrorText[256];  

} SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS, *PSSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA {

DWORD               cbSize;

DWORD               dwReserved;

LPWSTR              pwszServerName;

LPSTR               rgpszHpkpValue[2];

} SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA,

*PSSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA {

DWORD   cbSize;

DWORD   dwReserved;

PCWSTR  pwszServerName;

} SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA, *PSSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS {

DWORD   cbSize;

LONG    lError;

WCHAR   wszErrorText[512];  

} SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS, *PSSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS;

BOOL

__stdcall

CryptStringToBinaryA(

LPCSTR pszString,

DWORD cchString,

DWORD dwFlags,

BYTE *pbBinary,

DWORD  *pcbBinary,

DWORD *pdwSkip,

DWORD *pdwFlags

);

BOOL

__stdcall

CryptStringToBinaryW(

LPCWSTR pszString,

DWORD cchString,

DWORD dwFlags,

BYTE *pbBinary,

DWORD  *pcbBinary,

DWORD *pdwSkip,

DWORD *pdwFlags

);

BOOL

__stdcall

CryptBinaryToStringA(

const BYTE *pbBinary,

DWORD cbBinary,

DWORD dwFlags,

LPSTR pszString,

DWORD *pcchString

);

BOOL

__stdcall

CryptBinaryToStringW(

const BYTE *pbBinary,

DWORD cbBinary,

DWORD dwFlags,

LPWSTR pszString,

DWORD *pcchString

);

typedef struct _CRYPT_PKCS12_PBE_PARAMS

{

int                 iIterations;        

ULONG               cbSalt;             

}

CRYPT_PKCS12_PBE_PARAMS;

HCERTSTORE

__stdcall

PFXImportCertStore(

CRYPT_DATA_BLOB* pPFX,

LPCWSTR szPassword,

DWORD   dwFlags);

BOOL

__stdcall

PFXIsPFXBlob(

CRYPT_DATA_BLOB* pPFX);

BOOL

__stdcall

PFXVerifyPassword(

CRYPT_DATA_BLOB* pPFX,

LPCWSTR szPassword,

DWORD dwFlags);

BOOL

__stdcall

PFXExportCertStoreEx(

HCERTSTORE hStore,

CRYPT_DATA_BLOB* pPFX,

LPCWSTR szPassword,

void* pvPara,

DWORD dwFlags);

typedef struct _PKCS12_PBES2_EXPORT_PARAMS 

{ 

DWORD dwSize;            

PVOID hNcryptDescriptor;

LPWSTR pwszPbes2Alg; 

} PKCS12_PBES2_EXPORT_PARAMS, *PPKCS12_PBES2_EXPORT_PARAMS; 

BOOL

__stdcall

PFXExportCertStore(

HCERTSTORE hStore,

CRYPT_DATA_BLOB* pPFX,

LPCWSTR szPassword,

DWORD dwFlags);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

typedef VOID *HCERT_SERVER_OCSP_RESPONSE;

typedef struct _CERT_SERVER_OCSP_RESPONSE_CONTEXT

CERT_SERVER_OCSP_RESPONSE_CONTEXT,

*PCERT_SERVER_OCSP_RESPONSE_CONTEXT;

typedef const CERT_SERVER_OCSP_RESPONSE_CONTEXT

*PCCERT_SERVER_OCSP_RESPONSE_CONTEXT;

struct _CERT_SERVER_OCSP_RESPONSE_CONTEXT {

DWORD       cbSize;

BYTE        *pbEncodedOcspResponse;

DWORD       cbEncodedOcspResponse;

};

typedef VOID (__stdcall *PFN_CERT_SERVER_OCSP_RESPONSE_UPDATE_CALLBACK)(

PCCERT_CHAIN_CONTEXT pChainContext,

PCCERT_SERVER_OCSP_RESPONSE_CONTEXT pServerOcspResponseContext,

PCCRL_CONTEXT pNewCrlContext,

PCCRL_CONTEXT pPrevCrlContext,

PVOID pvArg,

DWORD dwWriteOcspFileError

);

typedef struct _CERT_SERVER_OCSP_RESPONSE_OPEN_PARA {

DWORD                                           cbSize;

DWORD                                           dwFlags;

DWORD                                           *pcbUsedSize;

PWSTR                                           pwszOcspDirectory;

PFN_CERT_SERVER_OCSP_RESPONSE_UPDATE_CALLBACK   pfnUpdateCallback;

PVOID                                           pvUpdateCallbackArg;

} CERT_SERVER_OCSP_RESPONSE_OPEN_PARA, *PCERT_SERVER_OCSP_RESPONSE_OPEN_PARA;

HCERT_SERVER_OCSP_RESPONSE

__stdcall

CertOpenServerOcspResponse(

PCCERT_CHAIN_CONTEXT pChainContext,

DWORD dwFlags,

PCERT_SERVER_OCSP_RESPONSE_OPEN_PARA pOpenPara

);

VOID

__stdcall

CertAddRefServerOcspResponse(

HCERT_SERVER_OCSP_RESPONSE hServerOcspResponse

);

VOID

__stdcall

CertCloseServerOcspResponse(

HCERT_SERVER_OCSP_RESPONSE hServerOcspResponse,

DWORD dwFlags

);

PCCERT_SERVER_OCSP_RESPONSE_CONTEXT

__stdcall

CertGetServerOcspResponseContext(

HCERT_SERVER_OCSP_RESPONSE hServerOcspResponse,

DWORD dwFlags,

LPVOID pvReserved

);

VOID

__stdcall

CertAddRefServerOcspResponseContext(

PCCERT_SERVER_OCSP_RESPONSE_CONTEXT pServerOcspResponseContext

);

VOID

__stdcall

CertFreeServerOcspResponseContext(

PCCERT_SERVER_OCSP_RESPONSE_CONTEXT pServerOcspResponseContext

);

BOOL

__stdcall

CertRetrieveLogoOrBiometricInfo(

PCCERT_CONTEXT pCertContext,

LPCSTR lpszLogoOrBiometricType,

DWORD dwRetrievalFlags,

DWORD dwTimeout,                             

DWORD dwFlags,

void *pvReserved,

BYTE **ppbData,      

DWORD *pcbData,

LPWSTR *ppwszMimeType         

);

#pragma endregion

#pragma region Application Family or OneCore or Games Family

typedef struct _CERT_SELECT_CHAIN_PARA

{

HCERTCHAINENGINE    hChainEngine;

PFILETIME           pTime;

HCERTSTORE          hAdditionalStore;

PCERT_CHAIN_PARA    pChainPara;

DWORD               dwFlags;

}

CERT_SELECT_CHAIN_PARA, *PCERT_SELECT_CHAIN_PARA;

typedef const CERT_SELECT_CHAIN_PARA*    PCCERT_SELECT_CHAIN_PARA;

typedef struct _CERT_SELECT_CRITERIA

{

DWORD                           dwType;

DWORD                           cPara;

void**    ppPara;

}

CERT_SELECT_CRITERIA, *PCERT_SELECT_CRITERIA;

typedef const CERT_SELECT_CRITERIA*     PCCERT_SELECT_CRITERIA;

BOOL

__stdcall

CertSelectCertificateChains(

LPCGUID pSelectionContext,

DWORD dwFlags,

PCCERT_SELECT_CHAIN_PARA pChainParameters,

DWORD cCriteria,

PCCERT_SELECT_CRITERIA rgpCriteria,

HCERTSTORE hStore,

PDWORD pcSelection,

PCCERT_CHAIN_CONTEXT** pprgpSelection

);

VOID

__stdcall

CertFreeCertificateChainList(

PCCERT_CHAIN_CONTEXT* prgpSelection

);

typedef struct _CRYPT_TIMESTAMP_REQUEST

{

DWORD                       dwVersion;              

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_DER_BLOB              HashedMessage;

LPSTR                       pszTSAPolicyId;         

CRYPT_INTEGER_BLOB          Nonce;                  

BOOL                        fCertReq;               

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;            

} CRYPT_TIMESTAMP_REQUEST, *PCRYPT_TIMESTAMP_REQUEST;

typedef struct _CRYPT_TIMESTAMP_RESPONSE

{

DWORD                       dwStatus;

DWORD                       cFreeText;              

LPWSTR*                     rgFreeText;

CRYPT_BIT_BLOB              FailureInfo;            

CRYPT_DER_BLOB              ContentInfo;            

} CRYPT_TIMESTAMP_RESPONSE, *PCRYPT_TIMESTAMP_RESPONSE;

typedef struct _CRYPT_TIMESTAMP_ACCURACY

{

DWORD                       dwSeconds;                  

DWORD                       dwMillis;                   

DWORD                       dwMicros;                   

} CRYPT_TIMESTAMP_ACCURACY, *PCRYPT_TIMESTAMP_ACCURACY;

typedef struct _CRYPT_TIMESTAMP_INFO

{

DWORD                       dwVersion;                  

LPSTR                       pszTSAPolicyId;

CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

CRYPT_DER_BLOB              HashedMessage;

CRYPT_INTEGER_BLOB          SerialNumber;

FILETIME                    ftTime;

PCRYPT_TIMESTAMP_ACCURACY   pvAccuracy;                 

BOOL                        fOrdering;                  

CRYPT_DER_BLOB              Nonce;                      

CRYPT_DER_BLOB              Tsa;                        

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;                

} CRYPT_TIMESTAMP_INFO, *PCRYPT_TIMESTAMP_INFO;

typedef struct _CRYPT_TIMESTAMP_CONTEXT

{

DWORD                       cbEncoded;

BYTE                        *pbEncoded;

PCRYPT_TIMESTAMP_INFO       pTimeStamp;

} CRYPT_TIMESTAMP_CONTEXT, *PCRYPT_TIMESTAMP_CONTEXT;

typedef struct _CRYPT_TIMESTAMP_PARA

{

LPCSTR                      pszTSAPolicyId;             

BOOL                        fRequestCerts;              

CRYPT_INTEGER_BLOB          Nonce;                      

DWORD                       cExtension;

PCERT_EXTENSION             rgExtension;                

} CRYPT_TIMESTAMP_PARA, *PCRYPT_TIMESTAMP_PARA;

BOOL

__stdcall

CryptRetrieveTimeStamp(

LPCWSTR     wszUrl,

DWORD       dwRetrievalFlags,

DWORD       dwTimeout,

LPCSTR      pszHashId,

const CRYPT_TIMESTAMP_PARA *pPara,

const BYTE  *pbData,

DWORD       cbData,

PCRYPT_TIMESTAMP_CONTEXT *ppTsContext,

PCCERT_CONTEXT *ppTsSigner,

HCERTSTORE  *phStore

);

BOOL

__stdcall

CryptVerifyTimeStampSignature (

const BYTE  *pbTSContentInfo,

DWORD       cbTSContentInfo,

const BYTE  *pbData,

DWORD    cbData,

HCERTSTORE  hAdditionalStore,

PCRYPT_TIMESTAMP_CONTEXT   *ppTsContext,

PCCERT_CONTEXT *ppTsSigner,

HCERTSTORE  *phStore

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

typedef BOOL (__stdcall *PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FLUSH)(

LPVOID pContext,

PCERT_NAME_BLOB *rgIdentifierOrNameList,

DWORD dwIdentifierOrNameListCount); 

typedef BOOL (__stdcall *PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET)(

LPVOID pPluginContext,

PCRYPT_DATA_BLOB pIdentifier,

DWORD dwNameType,

PCERT_NAME_BLOB pNameBlob,

PBYTE *ppbContent,

DWORD *pcbContent,

PCWSTR *ppwszPassword,

PCRYPT_DATA_BLOB *ppIdentifier);

typedef void (__stdcall * PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_RELEASE)(

DWORD dwReason,

LPVOID pPluginContext);

typedef void (__stdcall *PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_PASSWORD)(

LPVOID pPluginContext,

PCWSTR pwszPassword

);

typedef void (__stdcall *PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE)(

LPVOID pPluginContext,

PBYTE pbData

);

typedef void (__stdcall *PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_IDENTIFIER)(

LPVOID pPluginContext,

PCRYPT_DATA_BLOB pIdentifier);

typedef struct _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE

{

DWORD cbSize;

PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET pfnGet;

PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_RELEASE pfnRelease;

PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_PASSWORD pfnFreePassword;

PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE pfnFree;

PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_IDENTIFIER pfnFreeIdentifier;

} CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE, *PCRYPT_OBJECT_LOCATOR_PROVIDER_TABLE;

typedef BOOL (__stdcall *PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_INITIALIZE)(

PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FLUSH pfnFlush,

LPVOID pContext,

DWORD *pdwExpectedObjectCount,

PCRYPT_OBJECT_LOCATOR_PROVIDER_TABLE *ppFuncTable,

void **ppPluginContext);

BOOL

__stdcall

CertIsWeakHash(

DWORD dwHashUseType,

LPCWSTR pwszCNGHashAlgid,

DWORD dwChainFlags,

PCCERT_CHAIN_CONTEXT pSignerChainContext,

LPFILETIME pTimeStamp,

LPCWSTR pwszFileName

);

typedef  BOOL (__stdcall *PFN_CERT_IS_WEAK_HASH)(

DWORD dwHashUseType,

LPCWSTR pwszCNGHashAlgid,

DWORD dwChainFlags,

PCCERT_CHAIN_CONTEXT pSignerChainContext,

LPFILETIME pTimeStamp,

LPCWSTR pwszFileName

);

#pragma endregion

#pragma warning(pop)

#pragma region Desktop Family or OneCore or Games Family

#pragma once

#pragma region App Family or OneCore or Games Family

#pragma endregion

#pragma region App Family or OneCore or Games Family

typedef struct  _CRYPTPROTECT_PROMPTSTRUCT

{

DWORD cbSize;

DWORD dwPromptFlags;

HWND  hwndApp;

LPCWSTR szPrompt;

} CRYPTPROTECT_PROMPTSTRUCT, *PCRYPTPROTECT_PROMPTSTRUCT;

#pragma endregion

#pragma region App Family or OneCore or Games Family

#pragma endregion

#pragma region App Family or OneCore or Games Family

BOOL

__stdcall

CryptProtectData(

DATA_BLOB*      pDataIn,

LPCWSTR         szDataDescr,

DATA_BLOB*      pOptionalEntropy,

PVOID           pvReserved,

CRYPTPROTECT_PROMPTSTRUCT*  pPromptStruct,

DWORD           dwFlags,

DATA_BLOB*      pDataOut            

);

BOOL

__stdcall

CryptUnprotectData(

DATA_BLOB*      pDataIn,             

LPWSTR*     ppszDataDescr,       

DATA_BLOB*      pOptionalEntropy,

PVOID           pvReserved,

CRYPTPROTECT_PROMPTSTRUCT*  pPromptStruct,

DWORD           dwFlags,

DATA_BLOB*      pDataOut

);

#pragma endregion

#pragma region Desktop Family

BOOL

__stdcall

CryptProtectDataNoUI(

DATA_BLOB*      pDataIn,

LPCWSTR         szDataDescr,

DATA_BLOB*      pOptionalEntropy,

PVOID           pvReserved,

CRYPTPROTECT_PROMPTSTRUCT*  pPromptStruct,

DWORD           dwFlags,

const BYTE      *pbOptionalPassword,

DWORD           cbOptionalPassword,

DATA_BLOB*      pDataOut            

);

BOOL

__stdcall

CryptUnprotectDataNoUI(

DATA_BLOB*      pDataIn,             

LPWSTR*     ppszDataDescr,       

DATA_BLOB*      pOptionalEntropy,

PVOID           pvReserved,

CRYPTPROTECT_PROMPTSTRUCT*  pPromptStruct,

DWORD           dwFlags,

const BYTE      *pbOptionalPassword,

DWORD           cbOptionalPassword,

DATA_BLOB*      pDataOut

);

#pragma endregion

#pragma region Desktop Family or OneCore or Games Family

BOOL

__stdcall

CryptUpdateProtectedState(

PSID            pOldSid,

LPCWSTR         pwszOldPassword,

DWORD           dwFlags,

DWORD           *pdwSuccessCount,

DWORD           *pdwFailureCount);

#pragma endregion

#pragma region App Family or OneCore or Games Family

#pragma endregion

#pragma region App Family or OneCore or Games Family

BOOL

__stdcall

CryptProtectMemory(

LPVOID          pDataIn,             

DWORD           cbDataIn,            

DWORD           dwFlags

);

BOOL

__stdcall

CryptUnprotectMemory(

LPVOID          pDataIn,             

DWORD           cbDataIn,            

DWORD           dwFlags

);

#pragma endregion

#pragma endregion

typedef const BYTE *PCBYTE;

typedef struct _FVE_UEFI_VARIABLE_INFO { 

PBYTE UEFIVariableValue;          

ULONG UEFIVariableSizeBytes;     

} FVE_UEFI_VARIABLE_INFO, *PFVE_UEFI_VARIABLE_INFO;

typedef struct _FVE_TPM_PCR7_INFO { 

PFVE_UEFI_VARIABLE_INFO PlatformKeyVariableInfo;              

PFVE_UEFI_VARIABLE_INFO KekDatabaseVariableInfo;              

PFVE_UEFI_VARIABLE_INFO AllowedDatabaseVariableInfo;          

PFVE_UEFI_VARIABLE_INFO ForbiddenDatabaseVariableInfo;        

PBYTE                   OsLoaderAuthoritySignature;           

ULONG                   OsLoaderAuthoritySignatureSizeBytes;  

ULONG                   CountSeparatorEvents;                 

} FVE_TPM_PCR7_INFO, *PFVE_TPM_PCR7_INFO;

typedef struct _FVE_TPM_PCR4_INFO { 

WCHAR BootMgrFilePath[MAX_PATH];  

} FVE_TPM_PCR4_INFO, *PFVE_TPM_PCR4_INFO;

typedef struct _FVE_TPM_PROTECTOR_INFO { 

UINT32 TpmPcrIndex;                     

union {

PFVE_TPM_PCR7_INFO FveTpmPcr7Info; 

PFVE_TPM_PCR4_INFO FveTpmPcr4Info; 

} PredictiveSealInfo; 

} FVE_TPM_PROTECTOR_INFO, *PFVE_TPM_PROTECTOR_INFO;

typedef struct _FVE_TPM_STATE_ {

PVOID TpmContext;

ULONG FveTpmProtectorInfoCount;

PFVE_TPM_PROTECTOR_INFO FveTpmProtectorInfo;

} FVE_TPM_STATE, *PFVE_TPM_STATE;

typedef struct _FVE_TPM_INFO_ {

ULONG FveTpmInfoVersion;

PFVE_TPM_STATE TpmStateInfo;

} FVE_TPM_INFO, *PFVE_TPM_INFO;

typedef HRESULT (__stdcall *PFVE_TPM_API_CALLBACK)(

PVOID hContext,

UINT32 cbCmd,

PCBYTE pabCmd,

PUINT32 pcbResult,

PBYTE pabResult);

STDAPI

FveAddPredictiveTpmProtector(

PCWSTR FveVolumePath,

PFVE_TPM_INFO FveTpmInfo

);

STDAPI

FveSetupTpmCallback(

PFVE_TPM_API_CALLBACK TpmCallback,

UINT32 TpmVersion

);

typedef enum _FVE_DEVICE_TYPE {

FVE_DEVICE_UNKNOWN = -1,

FVE_DEVICE_UNSUPPORTED = 0,

FVE_DEVICE_VOLUME,

FVE_DEVICE_CSV_VOLUME,

FVE_DEVICE_MAX

} FVE_DEVICE_TYPE, *PFVE_DEVICE_TYPE;

typedef enum _FVE_INTERFACE_TYPE {

FVE_INTERFACE_UNKNOWN = -1,

FVE_INTERFACE_SEI = 0,

FVE_INTERFACE_SYS,

FVE_INTERFACE_HEI,

FVE_INTERFACE_MAX

} FVE_INTERFACE_TYPE, *PFVE_INTERFACE_TYPE;

typedef enum _FVE_HANDLE_TYPE {

FVE_HANDLE_UNKNOWN = -1,

FVE_HANDLE_FVE = 0,

FVE_HANDLE_NONFVE,

FVE_HANDLE_MAX

} FVE_HANDLE_TYPE, *PFVE_HANDLE_TYPE;

typedef enum _FVE_SCENARIO_TYPE {

FVE_SCENARIO_UNKNOWN  = -1,

FVE_SCENARIO_DEFAULT  = 0,

FVE_SCENARIO_KEY_ROLL = 1,

FVE_SCENARIO_BOOT_COMPONENT_UPDATE = 2,

FVE_SCENARIO_UNDEFINED_SKIP_CHECKS = 3

} FVE_SCENARIO_TYPE, *PFVE_SCENARIO_TYPE;

typedef struct _FVE_STATUS_V1 {

ULONG  StructureSize;

ULONG  StructureVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

} FVE_STATUS_V1, *PFVE_STATUS_V1;

typedef const FVE_STATUS_V1 * PCFVE_STATUS_V1;

typedef struct _FVE_STATUS_V2 {

ULONG  StructureSize;

ULONG  StructureVersion;

USHORT FveVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

} FVE_STATUS_V2, *PFVE_STATUS_V2;

typedef const FVE_STATUS_V2 * PCFVE_STATUS_V2;

typedef struct _FVE_STATUS_V3 {

ULONG  StructureSize;

ULONG  StructureVersion;

USHORT FveVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

LONGLONG VolArriveTime;  

} FVE_STATUS_V3, *PFVE_STATUS_V3;

typedef const FVE_STATUS_V3 * PCFVE_STATUS_V3;

typedef struct _FVE_STATUS_V4 {

ULONG  StructureSize;

ULONG  StructureVersion;

USHORT FveVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

LONGLONG VolArriveTime;  

double WipedPercent;     

ULONG WipeState;         

ULONG WipeCount;         

ULONGLONG ExtendedFlags; 

} FVE_STATUS_V4, *PFVE_STATUS_V4;

typedef const FVE_STATUS_V4 * PCFVE_STATUS_V4;

#pragma warning(push)

#pragma warning(disable:4201)   

#pragma warning(disable:4214)   

typedef struct _FVE_STATUS_V5 {

ULONG  StructureSize;

ULONG  StructureVersion;

USHORT FveVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

LONGLONG VolArriveTime;  

double WipedPercent;     

ULONG WipeState;         

ULONG WipeCount;         

ULONGLONG ExtendedFlags; 

ULONGLONG WimBootHashedSizeRequired;    

ULONGLONG WimBootHashedSizeActual;  

union {

ULONGLONG ExtendedFlags2;

struct {

BOOLEAN WimBootVolume : 1;  

BOOLEAN WimBootHashCompleted : 1;   

};

};

} FVE_STATUS_V5, *PFVE_STATUS_V5;

typedef const FVE_STATUS_V5 * PCFVE_STATUS_V5;

#pragma warning(pop)

#pragma warning(push)

#pragma warning(disable:4201)   

#pragma warning(disable:4214)   

typedef struct _FVE_STATUS_V6 {

ULONG  StructureSize;

ULONG  StructureVersion;

USHORT FveVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

LONGLONG VolArriveTime;  

double WipedPercent;     

ULONG WipeState;         

ULONG WipeCount;         

ULONGLONG ExtendedFlags; 

ULONGLONG WimBootHashedSizeRequired;    

ULONGLONG WimBootHashedSizeActual;  

union {

ULONGLONG ExtendedFlags2;

struct {

BOOLEAN WimBootVolume : 1;  

BOOLEAN WimBootHashCompleted : 1;   

BOOLEAN IceIsUsedForFve : 1;    

BOOLEAN IsEfiEsp : 1;           

BOOLEAN IsRecovery : 1;         

BOOLEAN WcosDePolicy : 1;       

BOOLEAN WcosOsData : 1;         

BOOLEAN WcosPreInstalled : 1;   

BOOLEAN WcosUserData : 1;       

BOOLEAN WcosMainOs : 1;         

BOOLEAN WcosEfiEsp : 1;         

BOOLEAN WcosBsp : 1;            

};

};

ULONG WcosOsMainProtectLevel;

ULONG WcosOsDataProtectLevel;

ULONG WcosPreInstalledProtectLevel;

ULONG WcosUserDataProtectLevel;

} FVE_STATUS_V6, *PFVE_STATUS_V6;

typedef const FVE_STATUS_V6 * PCFVE_STATUS_V6;

#pragma warning(pop)

#pragma warning(push)

#pragma warning(disable:4201)   

#pragma warning(disable:4214)   

typedef struct _FVE_STATUS_V7 {

ULONG  StructureSize;

ULONG  StructureVersion;

USHORT FveVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

LONGLONG VolArriveTime;  

double WipedPercent;     

ULONG WipeState;         

ULONG WipeCount;         

ULONGLONG ExtendedFlags; 

ULONGLONG WimBootHashedSizeRequired;    

ULONGLONG WimBootHashedSizeActual;  

union {

ULONGLONG ExtendedFlags2;

struct {

BOOLEAN WimBootVolume : 1;  

BOOLEAN WimBootHashCompleted : 1;   

BOOLEAN IceIsUsedForFve : 1;    

BOOLEAN IsEfiEsp : 1;           

BOOLEAN IsRecovery : 1;         

BOOLEAN WcosDePolicy : 1;       

BOOLEAN WcosOsData : 1;         

BOOLEAN WcosPreInstalled : 1;   

BOOLEAN WcosUserData : 1;       

BOOLEAN WcosMainOs : 1;         

BOOLEAN WcosEfiEsp : 1;         

BOOLEAN WcosBsp : 1;            

BOOLEAN WcosWsp : 1;            

};

};

ULONG WcosOsMainProtectLevel;

ULONG WcosOsDataProtectLevel;

ULONG WcosPreInstalledProtectLevel;

ULONG WcosUserDataProtectLevel;

ULONG WcosBspProtectLevel;

ULONG WcosWspProtectLevel;

} FVE_STATUS_V7, *PFVE_STATUS_V7;

typedef const FVE_STATUS_V7 * PCFVE_STATUS_V7;

#pragma warning(pop)

#pragma warning(push)

#pragma warning(disable:4201)   

#pragma warning(disable:4214)   

typedef struct _FVE_STATUS_V8 {

ULONG  StructureSize;

ULONG  StructureVersion;

USHORT FveVersion;

ULONG  Flags;            

double ConvertedPercent; 

HRESULT LastConvertStatus; 

LONGLONG VolArriveTime;  

double WipedPercent;     

ULONG WipeState;         

ULONG WipeCount;         

ULONGLONG ExtendedFlags; 

ULONGLONG WimBootHashedSizeRequired;    

ULONGLONG WimBootHashedSizeActual;  

union {

ULONGLONG ExtendedFlags2;

struct {

BOOLEAN WimBootVolume : 1;  

BOOLEAN WimBootHashCompleted : 1;   

BOOLEAN IceIsUsedForFve : 1;    

BOOLEAN IsEfiEsp : 1;           

BOOLEAN IsRecovery : 1;         

BOOLEAN WcosDePolicy : 1;       

BOOLEAN WcosOsData : 1;         

BOOLEAN WcosPreInstalled : 1;   

BOOLEAN WcosUserData : 1;       

BOOLEAN WcosMainOs : 1;         

BOOLEAN WcosEfiEsp : 1;         

BOOLEAN WcosBsp : 1;            

BOOLEAN WcosWsp : 1;            

BOOLEAN WcosDpp : 1;            

};

};

ULONG WcosOsMainProtectLevel;

ULONG WcosOsDataProtectLevel;

ULONG WcosPreInstalledProtectLevel;

ULONG WcosUserDataProtectLevel;

ULONG WcosBspProtectLevel;

ULONG WcosWspProtectLevel;

ULONG WcosDppProtectLevel;

} FVE_STATUS_V8, *PFVE_STATUS_V8;

typedef const FVE_STATUS_V8 * PCFVE_STATUS_V8;

#pragma warning(pop)

typedef enum _FVE_WIPING_STATE {

FVE_WIPING_STATE_UNSPECIFIED = 0,

FVE_WIPING_STATE_INACTIVE = 1,   

FVE_WIPING_STATE_PENDING = 2,    

FVE_WIPING_STATE_STOPPED = 3,    

FVE_WIPING_STATE_INPROGRESS = 4, 

} FVE_WIPING_STATE, *PFVE_WIPING_STATE;

typedef struct _FVE_TPM_CAPS {

ULONG  StructureSize;

ULONG  StructureVersion;

HRESULT TpmStatus;    

ULONG  Flags;         

} FVE_TPM_CAPS, *PFVE_TPM_CAPS;

typedef const FVE_TPM_CAPS * PCFVE_TPM_CAPS;

typedef struct _FVE_TPM_CAPS_TPM_PRESENCE {

ULONG StructureSize;

ULONG StructureVersion;

HRESULT NotUsed;

ULONG NotUsed2;

BOOL TpmPresent;

} FVE_TPM_CAPS_TPM_PRESENCE, *PFVE_TPM_CAPS_TPM_PRESENCE;

typedef const FVE_TPM_CAPS_TPM_PRESENCE * PCFVE_TPM_CAPS_TPM_PRESENCE;

typedef struct _FVE_AUTH_RECOVERY_PASSWORD {

USHORT Block[(8)];

} FVE_AUTH_RECOVERY_PASSWORD, *PFVE_AUTH_RECOVERY_PASSWORD;

typedef const FVE_AUTH_RECOVERY_PASSWORD * PCFVE_AUTH_RECOVERY_PASSWORD;

typedef struct _FVE_AUTH_PIN {

BYTE HashedPin[32];

} FVE_AUTH_PIN, *PFVE_AUTH_PIN;

typedef const FVE_AUTH_PIN * PCFVE_AUTH_PIN;

typedef struct _FVE_AUTH_TPM {

ULONG PcrBitmap;

} FVE_AUTH_TPM, *PFVE_AUTH_TPM;

typedef const FVE_AUTH_TPM * PCFVE_AUTH_TPM;

typedef struct _FVE_AUTH_PREDICTED_TPM_INFO {

PFVE_TPM_STATE FveTpmState;

} FVE_AUTH_PREDICTED_TPM_INFO, *PFVE_AUTH_PREDICTED_TPM_INFO;

typedef const FVE_AUTH_PREDICTED_TPM_INFO * PCFVE_AUTH_PREDICTED_TPM_INFO;

typedef struct _FVE_AUTH_EXTERNAL_KEY {

BYTE Key[32];

} FVE_AUTH_EXTERNAL_KEY, *PFVE_AUTH_EXTERNAL_KEY;

typedef const FVE_AUTH_EXTERNAL_KEY * PCFVE_AUTH_EXTERNAL_KEY;

typedef struct _FVE_AUTH_PUBLIC_KEY {

BCRYPT_KEY_HANDLE Handle;

ULONG BlobSize;

PBYTE Blob;         

} FVE_AUTH_PUBLIC_KEY, *PFVE_AUTH_PUBLIC_KEY;

typedef const FVE_AUTH_PUBLIC_KEY * PCFVE_AUTH_PUBLIC_KEY;

typedef struct _FVE_AUTH_PRIVATE_KEY {

NCRYPT_KEY_HANDLE KspKeyHandle;

HCRYPTPROV CspProviderHandle;

HCRYPTKEY CspKeyHandle;

DWORD KeySpec;

} FVE_AUTH_PRIVATE_KEY, *PFVE_AUTH_PRIVATE_KEY;

typedef const FVE_AUTH_PRIVATE_KEY * PCFVE_AUTH_PRIVATE_KEY;

typedef struct _FVE_AUTH_INFO_PUBLIC_KEY {

ULONG ExportedPublicKeySize;

ULONG ExportedPublicKeyOffset;

ULONG BlobSize;

ULONG BlobOffset;

} FVE_AUTH_INFO_PUBLIC_KEY, *PFVE_AUTH_INFO_PUBLIC_KEY;

typedef const FVE_AUTH_INFO_PUBLIC_KEY * PCFVE_AUTH_INFO_PUBLIC_KEY;

typedef struct _FVE_AUTH_PASSPHRASE

{

WCHAR ClearPassPhrase[256 + 1];

BYTE HashedPassPhrase[32];

BYTE Salt[16];

} FVE_AUTH_PASSPHRASE, *PFVE_AUTH_PASSPHRASE;

typedef const FVE_AUTH_PASSPHRASE * PCFVE_AUTH_PASSPHRASE;

typedef struct _FVE_AUTH_INFO_CLEAR_KEY {

UCHAR Count;

} FVE_AUTH_INFO_CLEAR_KEY, *PFVE_AUTH_INFO_CLEAR_KEY;

typedef struct _FVE_AUTH_DPAPI_NG

{

USHORT DpapiNgFlags;        

USHORT DescriptorLength;

WCHAR DpapiNgDescriptor[ANYSIZE_ARRAY];

} FVE_AUTH_DPAPI_NG, *PFVE_AUTH_DPAPI_NG;

typedef const FVE_AUTH_DPAPI_NG *PCFVE_AUTH_DPAPI_NG;

typedef struct _FVE_AUTH_ELEMENT {

ULONG StructureSize;     

ULONG StructureVersion;  

ULONG ElementFlags;

ULONG ElementType;

union {

BYTE Nothing[1];

FVE_AUTH_RECOVERY_PASSWORD RecoveryPassword;

FVE_AUTH_PIN Pin;

FVE_AUTH_TPM Tpm;

FVE_AUTH_EXTERNAL_KEY ExternalKey;

FVE_AUTH_PUBLIC_KEY PublicKey;

FVE_AUTH_PRIVATE_KEY PrivateKey;

FVE_AUTH_INFO_PUBLIC_KEY PublicKeyInfo;

FVE_AUTH_PASSPHRASE PassPhrase;

FVE_AUTH_INFO_CLEAR_KEY ClearKeyInfo;

FVE_AUTH_DPAPI_NG DpapiNgInfo;

FVE_AUTH_PREDICTED_TPM_INFO PredictedTpmInfo;

} Data;

} FVE_AUTH_ELEMENT, *PFVE_AUTH_ELEMENT;

typedef const FVE_AUTH_ELEMENT *PCFVE_AUTH_ELEMENT;

typedef struct _FVE_AUTH_INFORMATION {

ULONG StructureSize;

ULONG StructureVersion;

ULONG AuthFlags;

ULONG ElementsCount;

PFVE_AUTH_ELEMENT * Elements;

PCWSTR Description;

FILETIME CreationTime;

GUID Identifier;

} FVE_AUTH_INFORMATION, *PFVE_AUTH_INFORMATION;

typedef const FVE_AUTH_INFORMATION *PCFVE_AUTH_INFORMATION;

typedef struct _ADA_GP_OPTIONS {

BOOL BackupEnabled;

BOOL BackupKeyPackage;

BOOL BackupRequired;

} ADA_GP_OPTIONS, *PADA_GP_OPTIONS;

typedef enum _FVE_PROTECTOR_TYPE {

FveKeyProtTypeUnknown = 0,

FveKeyProtTypeTpm,

FveKeyProtTypeKey,

FveKeyProtTypePassword,

FveKeyProtTypeTpmAndPin,

FveKeyProtTypeTpmAndKey,

FveKeyProtTypeTpmAndPinAndKey,

FveKeyProtTypeCertificate,

FveKeyProtTypePassPhrase,

FveKeyProtTypeTpmAndCertificate,

FveKeyProtTypeDpapiNg,

} FVE_PROTECTOR_TYPE, *PFVE_PROTECTOR_TYPE;


BOOL

FveIsTpmProtectorType(

FVE_PROTECTOR_TYPE ProtectorType

)

{

return ProtectorType == FveKeyProtTypeTpm ||

ProtectorType == FveKeyProtTypeTpmAndPin ||

ProtectorType == FveKeyProtTypeTpmAndKey ||

ProtectorType == FveKeyProtTypeTpmAndPinAndKey ||

ProtectorType == FveKeyProtTypeTpmAndCertificate;

}

NTSYSAPI

HRESULT

NTAPI

FveOpenVolumeW(

PCWSTR VolumeName,

BOOL bNeedWriteAccess,

HANDLE * phVolume

);

NTSYSAPI

HRESULT

NTAPI

FveOpenVolumeExW(

PCWSTR VolumeName,

ULONG NameFlags,

BOOL bNeedWriteAccess,

FVE_INTERFACE_TYPE IfcType,

ULONG HandleFlags,

HANDLE * phVolume

);

NTSYSAPI

HRESULT

NTAPI

FveOpenVolumeByHandle(

HANDLE Handle,

FVE_HANDLE_TYPE HandleType,

BOOL bNeedWriteAccess,

FVE_INTERFACE_TYPE IfcType,

ULONG HandleFlags,

HANDLE * phVolume

);

NTSYSAPI

HRESULT

NTAPI

FveCloseHandle(

HANDLE FveHandle

);

NTSYSAPI

HRESULT

NTAPI

FveCloseVolume(

HANDLE FveVolumeHandle

);

HRESULT

NTAPI

FveApplyGroupPolicy(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveCommitChanges(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveDiscardChanges(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveGetStatus(

HANDLE FveVolumeHandle,

PFVE_STATUS_V8 Status

);

NTSYSAPI

HRESULT

NTAPI

FveGetStatusW(

PCWSTR VolumeName,

PFVE_STATUS_V8 Status

);

NTSYSAPI

HRESULT

NTAPI

FveGetUserFlags(

HANDLE FveVolumeHandle,

PULONG UserFlags

);

NTSYSAPI

HRESULT

NTAPI

FveSetUserFlags(

HANDLE FveVolumeHandle,

ULONG UserFlags

);

NTSYSAPI

HRESULT

NTAPI

FveClearUserFlags(

HANDLE FveVolumeHandle,

ULONG UserFlags

);

NTSYSAPI

HRESULT

NTAPI

FveGetAuthMethodGuids(

HANDLE FveVolumeHandle,

LPGUID AuthMethodGuids,

UINT MaxNumGuids,

PUINT NumGuids

);

NTSYSAPI

HRESULT

NTAPI

FveGetAuthMethodInformation(

HANDLE FveVolumeHandle,

PFVE_AUTH_INFORMATION Information,

SIZE_T BufferSize,

SIZE_T * RequiredSize

);

NTSYSAPI

HRESULT

NTAPI

FveProtectorTypeToFlags(

FVE_PROTECTOR_TYPE ProtectorType,

PULONG TypeFlags

);

NTSYSAPI

HRESULT

NTAPI

FveFlagsToProtectorType(

ULONG TypeFlags,

PFVE_PROTECTOR_TYPE ProtectorType

);

NTSYSAPI

HRESULT

NTAPI

FveDeleteAuthMethod(

HANDLE FveVolumeHandle,

LPCGUID AuthMethodGuid

);

NTSYSAPI

HRESULT

NTAPI

FveAddAuthMethodInformation(

HANDLE FveVolumeHandle,

PCFVE_AUTH_INFORMATION Information,

LPGUID AuthMethodGuid

);

NTSYSAPI

HRESULT

NTAPI

FveUpdatePinW (

HANDLE hFveVolume,

LPCWSTR NewPin,

LPCGUID ProtectorGuid

);

NTSYSAPI

HRESULT

NTAPI

FveValidateExistingPinW(

HANDLE hFveVolume,

PCWSTR ExistingPin,

PBOOL ExistingPinValidates,

LPGUID GUIDProtector

);

NTSYSAPI

HRESULT

NTAPI

FveValidateExistingPassphraseW(

HANDLE hFveVolume,

PCWSTR ExistingPassphrase,

PBOOL ExistingPassphraseValidates,

LPGUID ProtectorGuid

);

NTSYSAPI

HRESULT

NTAPI

FveEraseDrive(

HANDLE FveVolumeHandle,

BOOL ForceDismount

);

NTSYSAPI

HRESULT

NTAPI

FveUpgradeVolume(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveEraseDriveExW(

PCWSTR   VolumeName,

BOOL     ForceDismount

);

NTSYSAPI

HRESULT

NTAPI

FveUnlockVolume(

HANDLE FveVolumeHandle,

PCFVE_AUTH_INFORMATION Information

);

HRESULT

NTAPI

FveUnlockVolumeWithAccessMode(

HANDLE hFveVolume,

PCFVE_AUTH_INFORMATION Information,

PBOOL ReadOnly

);

NTSYSAPI

HRESULT

NTAPI

FveAttemptAutoUnlock(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveLockVolume(

HANDLE FveVolumeHandle,

BOOLEAN ForceDismount

);

NTSYSAPI

HRESULT

NTAPI

FveCheckBootFileW(

PCWSTR   Path

);

NTSYSAPI

HRESULT

NTAPI

FveGetIdentity(

HANDLE FveVolumeHandle,

LPGUID IdentityGuid

);

NTSYSAPI

HRESULT

NTAPI

FveGetRecoveryPasswordBackupInformation(

HANDLE FveVolumeHandle,

LPCGUID ProtectorGuid,

PUSHORT BackupInfoTypeMask

);

NTSYSAPI

HRESULT

NTAPI

FveSetRecoveryPasswordBackupInformation(

HANDLE FveVolumeHandle,

LPCGUID ProtectorGuid,

USHORT BackupInfoType,

USHORT SetFlags,

USHORT ClearFlags,

PBOOLEAN DatasetWasUpdated

);

NTSYSAPI

HRESULT

NTAPI

FveSelectBestRecoveryPasswordByBackupInformation (

HANDLE FveVolumeHandle,

LPGUID ProtectorGuid

);

NTSYSAPI

HRESULT

NTAPI

FveAuthElementToRecoveryPasswordW(

PCFVE_AUTH_ELEMENT AuthElement,

PWSTR Passphrase,

SIZE_T PassphraseLength

);

NTSYSAPI

HRESULT

NTAPI

FveAuthElementFromPinW(

PCWSTR Pin,

PFVE_AUTH_ELEMENT AuthElement

);

NTSYSAPI

HRESULT

NTAPI

FveAuthElementFromPassPhraseW(

PCWSTR PassPhrase,

PFVE_AUTH_ELEMENT AuthElement

);

NTSYSAPI

HRESULT

NTAPI

FveAuthElementFromRecoveryPasswordW(

PCWSTR Passphrase,

PFVE_AUTH_ELEMENT AuthElement

);

NTSYSAPI

HRESULT

NTAPI

FveIsRecoveryPasswordGroupValidW(

PCWSTR PassphraseGroup,

BOOLEAN * IsValid

);

NTSYSAPI

HRESULT

NTAPI

FveIsRecoveryPasswordValidW(

PCWSTR Passphrase,

BOOLEAN * IsValid

);

NTSYSAPI

HRESULT

NTAPI

FveIsPassphraseCompatibleW(

PCWSTR Passphrase,

BOOL *IsCompatible

);

NTSYSAPI

HRESULT

NTAPI

FveAuthElementReadExternalKeyW(

PCWSTR KeyFullFilePath,

PFVE_AUTH_INFORMATION Information,

SIZE_T BufferSize,

SIZE_T * RequiredSize

);

NTSYSAPI

HRESULT

NTAPI

FveAuthElementWriteExternalKeyW(

PCWSTR KeyFullFilePath,

PCFVE_AUTH_INFORMATION Information

);

NTSYSAPI

HRESULT

NTAPI

FveAuthElementGetKeyFileNameW(

PCFVE_AUTH_INFORMATION Information,

PWSTR KeyFileName,

SIZE_T BufferLength

);

NTSYSAPI

HRESULT

NTAPI

FveInitVolumeEx(

HANDLE hFveVolume,

PCWSTR pcwszDiscoveryVolumeType,

ULONG InitializationFlags

);

NTSYSAPI

HRESULT

NTAPI

FveInitVolume(

HANDLE FveVolumeHandle,

PCWSTR DiscoveryVolumeType

);

NTSYSAPI

HRESULT

NTAPI

FveInitializeDeviceEncryption(

VOID

);

NTSYSAPI

HRESULT

NTAPI

FveInitializeDeviceEncryption2(

HANDLE FveVolumeHandle,

ULONG DEInitializationFlags

);

typedef struct _FVE_DE_SUPPORT {

ULONG StructureSize;

ULONG StructureVersion;

ULONG QueryFlags;

HRESULT SupportStatus;

ULONG SupportFlags;

} FVE_DE_SUPPORT, *PFVE_DE_SUPPORT;

typedef const FVE_DE_SUPPORT * PCFVE_DE_SUPPORT;

NTSYSAPI

HRESULT

NTAPI

FveQueryDeviceEncryptionSupport(

PFVE_DE_SUPPORT DeviceEncryptionSupport

);

NTSYSAPI

HRESULT

NTAPI

FveRevertVolume(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveKeyManagement(

HANDLE FveVolumeHandle,

ULONG FlagsIn,

PULONG FlagsOut

);

NTSYSAPI

HRESULT

NTAPI

FveConversionDecrypt(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveConversionDecryptEx(

HANDLE FveVolumeHandle,

ULONG ConversionFlags

);

NTSYSAPI

HRESULT

NTAPI

FveConversionEncrypt(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveConversionEncryptEx(

HANDLE FveVolumeHandle,

ULONG ConversionFlags

);

NTSYSAPI

HRESULT

NTAPI

FveConversionEncryptPendingReboot(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveConversionEncryptPendingRebootEx(

HANDLE FveVolumeHandle,

ULONG ConversionFlags

);

NTSYSAPI

HRESULT

NTAPI

FveConversionStop(

HANDLE FveVolumeHandle

);

HRESULT

NTAPI

FveConversionStopEx(

HANDLE FveVolumeHandle,

BOOLEAN AutoStartOnReinsertion

);

NTSYSAPI

HRESULT

NTAPI

FveConversionPause(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveConversionResume(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveIsVolumeEncryptable(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveGetFveMethod(

HANDLE FveVolumeHandle,

PINT FveMethod

);

NTSYSAPI

HRESULT

NTAPI

FveGetFveMethodEDrv(

HANDLE FveVolumeHandle,

PINT FveMethod,

LPWSTR

SelfEncryptionDriveEncryptionMethod);

NTSYSAPI

HRESULT

NTAPI

FveGetFveMethodEx(

HANDLE hFveVolume,

PINT FveMethod,

LPWSTR eDriveMethod,

PULONG FveMethodFlags

);

NTSYSAPI

HRESULT

NTAPI

FveSetFveMethod(

HANDLE FveVolumeHandle,

INT FveMethod

);

NTSYSAPI

HRESULT

NTAPI

FveCheckTpmCapability(

PFVE_TPM_CAPS Capability

);

NTSYSAPI

HRESULT

NTAPI

FveBindDataVolume(

HANDLE FveVolumeHandle,

LPCGUID AuthMethodGUID

);

NTSYSAPI

HRESULT

NTAPI

FveUnbindDataVolume(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveIsBoundDataVolume(

HANDLE FveVolumeHandle,

PBOOL IsAutoUnlockEnabled,

LPGUID UnlockGUID

);

NTSYSAPI

HRESULT

NTAPI

FveIsBoundDataVolumeToOSVolume(

HANDLE FveVolumeHandle,

PBOOL IsAutoUnlockEnabled,

LPGUID UnlockGUID

);

NTSYSAPI

HRESULT

NTAPI

FveIsAnyDataVolumeBoundToOSVolume(

HANDLE FveVolumeHandle,

PULONG Count

);

NTSYSAPI

HRESULT

NTAPI

FveUnbindAllDataVolumeFromOSVolume(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveSetDescriptionW(

HANDLE FveVolumeHandle,

PCWSTR VolumeDescription

);

NTSYSAPI

HRESULT

NTAPI

FveGetDescriptionW(

HANDLE FveVolumeHandle,

PWSTR VolumeDescription,

SIZE_T BufferLength,

SIZE_T * RequiredSize

);

NTSYSAPI

HRESULT

NTAPI

FveSetIdentificationFieldW(

HANDLE FveVolumeHandle,

PCWSTR IdentificationField

);

NTSYSAPI

HRESULT

NTAPI

FveGetIdentificationFieldW(

HANDLE FveVolumeHandle,

PWSTR IdentificationField,

SIZE_T BufferLength,

SIZE_T * RequiredSize

);

NTSYSAPI

HRESULT

NTAPI

FveSetAllowKeyExport(

BOOL Allow

);

NTSYSAPI

HRESULT

NTAPI

FveGetAllowKeyExport(

BOOL *Allow

);

NTSYSAPI

HRESULT

NTAPI

FveSetFipsAllowDisabled(

BOOL Allow

);

NTSYSAPI

HRESULT

NTAPI

FveGetFipsAllowDisabled(

BOOL *Allow

);

NTSYSAPI

HRESULT

NTAPI

FveIsHardwareReadyForConversion(

VOID

);

NTSYSAPI

HRESULT

NTAPI

FveGetKeyPackage(

HANDLE FveVolumeHandle,

LPCGUID Identifier,

PUCHAR Buffer,

SIZE_T BufferSize,

SIZE_T * DataSize

);

NTSYSAPI

HRESULT

NTAPI

FveEnableRawAccessW(

PCWSTR VolumeName,

BOOL Enabled

);

NTSYSAPI

HRESULT

NTAPI

FveEnableRawAccess(

HANDLE FveVolumeHandle,

BOOL Enabled

);

NTSYSAPI

HRESULT

NTAPI

FveEnableRawAccessEx(

HANDLE FveVolumeHandle,

BOOL Enabled,

BOOL ForceDismount

);

NTSYSAPI

HRESULT

NTAPI

FveBackupRecoveryInformationToAD(

HANDLE FveVolumeHandle,

LPCGUID AuthMethodGUID

);

NTSYSAPI

HRESULT

NTAPI

FveBackupRecoveryInformationToADEx(

HANDLE hFveVolume,

LPCGUID AuthMethodGUID,

ULONG FveBackupFlags

);

NTSYSAPI

HRESULT

NTAPI

FveCheckADRecoveryInfoBackupPolicy(

HANDLE hFveVolume,

ADA_GP_OPTIONS * ADPolicy

);

NTSYSAPI

HRESULT

NTAPI

FveCheckADRecoveryInfoBackupPolicyEx(

ADA_GP_OPTIONS * ADPolicyOs,

ADA_GP_OPTIONS * ADPolicyFdv,

ADA_GP_OPTIONS * ADPolicyRdv

);

NTSYSAPI

HRESULT

NTAPI

FveGetDataSet(

HANDLE FveVolumeHandle,

PUCHAR DataSetBuffer,

SIZE_T DataSetBufferSize,

SIZE_T * ActualDataSetBufferSize

);

NTSYSAPI

HRESULT

NTAPI

FveIsHybridVolume(

HANDLE FveVolumeHandle,

PBOOL IsHybrid

);

NTSYSAPI

HRESULT

NTAPI

FveIsHybridVolumeW(

PCWSTR VolumeName,

PBOOL IsHybrid

);

NTSYSAPI

HRESULT

NTAPI

FveNeedsDiscoveryVolumeUpdate(

HANDLE FveVolumeHandle,

PBOOL NeedsUpdate

);

NTSYSAPI

HRESULT

NTAPI

FveServiceDiscoveryVolume(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveNotifyVolumeAfterFormat(

HANDLE FveVolumeHandle

);

NTSYSAPI

HRESULT

NTAPI

FveSaveRecoveryPasswordBackupFlag(

HANDLE FveVolumeHandle,

LPCGUID pRecoveryPasswordGuid,

PCFVE_AUTH_ELEMENT pRecoveryPassword

);

NTSYSAPI

HRESULT

NTAPI

FveDraCertPresentInRegistry(

PBOOL ptCertPresent

);

NTSYSAPI

HRESULT

NTAPI

FveSysOpenVolumeW(

PCWSTR VolumeName,

HANDLE * phFveSys

);

NTSYSAPI

HRESULT

NTAPI

FveSysCloseVolume(

HANDLE FveSys

);

NTSYSAPI

HRESULT

NTAPI

FveSysGetUserFlags(

HANDLE FveSysHandle,

PULONG UserFlags

);

NTSYSAPI

HRESULT

NTAPI

FveSysSetUserFlags(

HANDLE FveSysHandle,

ULONG UserFlags

);

NTSYSAPI

HRESULT

NTAPI

FveSysClearUserFlags(

HANDLE FveSysHandle,

ULONG UserFlags

);

typedef enum _FVE_QUERY_TYPE {

FVE_QUERY_UNKNOWN = 0,

FVE_QUERY_UNSUPPORTED,

FVE_QUERY_VOLUMES,

FVE_QUERY_CSV_VOLUMES,

FVE_QUERY_DE_NOT_INITIALIZED,

FVE_QUERY_WCOS_SECURITY_INFO,

FVE_QUERY_MAX

} FVE_QUERY_TYPE, *PFVE_QUERY_TYPE;

typedef struct _FVE_WCOS_SEQURITY_INFO_REQUEST {

USHORT Version;

USHORT Size;

ULONG CompletionWaitTime;

} FVE_WCOS_SEQURITY_INFO_REQUEST, *PFVE_WCOS_SEQURITY_INFO_REQUEST;

typedef struct _FVE_WCOS_SEQURITY_INFO_RESPONSE {

USHORT Version;

USHORT Size;

UCHAR Secure;

UCHAR SecureBootBinding;

UCHAR ProvisioningStarted;

UCHAR ProvisioningComplete;

ULONGLONG EncryptionRequiredMask;

ULONGLONG EncryptionEnabledMask;

ULONGLONG EncryptionCompleteMask;

ULONGLONG ProtectionArmedMask;

ULONGLONG RecoveryPasswordAbsentMask;

ULONGLONG ReadOnlyRequiredMask;

ULONGLONG ReadOnlyEnabledMask;

} FVE_WCOS_SEQURITY_INFO_RESPONSE, *PFVE_WCOS_SEQURITY_INFO_RESPONSE;

NTSYSAPI

HRESULT

NTAPI

FveQuery(

FVE_QUERY_TYPE FveQueryType,

PBYTE InputBuffer,

ULONG InputSize,

PBYTE OutputBuffer,

ULONG *OutputSize

);

HRESULT

NTAPI

FveApplyNkpCertChanges(

HANDLE FveVolumeHandle

);

HRESULT

NTAPI

FveGenerateNkpSessionKeys(

HANDLE FveVolumeHandle

);

HRESULT

NTAPI

FveGenerateNbp(

HANDLE FveVolumeHandle,

DWORD CertThumbprintSize,

BYTE* CertThumbprint

);

HRESULT

NTAPI

FveRegenerateNbpSessionKey(

HANDLE FveVolumeHandle

);

HRESULT

NTAPI

FveCanStandardUsersChangePin(

PBOOL ptStandardUsersCanChangePin

);

HRESULT

NTAPI

FveCanStandardUsersChangePassphraseByProxy(

HANDLE FveVolumeHandle,

PBOOL ptStandardUsersCanChangePassphraseByProxy

);

HRESULT

NTAPI

FveCheckPassphrasePolicy(

HANDLE FveVolumeHandle,

PCWSTR Passphrase

);

HRESULT

NTAPI

FveDecrementClearKeyCounter(

HANDLE FveVolumeHandle

);

HRESULT

NTAPI

FveGetClearKeyCounter(

HANDLE FveVolumeHandle,

PULONG ClearKeyCounter

);

NTSYSAPI

HRESULT

NTAPI

FveAddAuthMethodSid(

HANDLE FveVolumeHandle,

PCWSTR FriendlyName,

PSID Sid,

USHORT Flags,

LPGUID AuthMethodGuid

);

NTSYSAPI

HRESULT

NTAPI

FveGetAuthMethodSid(

HANDLE FveVolumeHandle,

PSID Sid,

LPGUID AuthMethodGuidArray,

PULONG AuthMethodCount

);

NTSYSAPI

HRESULT

NTAPI

FveUnlockVolumeAuthMethodSid(

HANDLE FveVolumeHandle,

LPCGUID AuthMethodGuid

);

NTSYSAPI

HRESULT

NTAPI

FveGetAuthMethodSidInformation(

HANDLE FveVolumeHandle,

LPCGUID AuthMethodGuid,

PUSHORT Flags,

PSID Sid,

PULONG SidBufferSize

);

typedef struct _FVE_FIND_DATA_V1 {

ULONG FveFindVersion;

FVE_DEVICE_TYPE DevType;

} FVE_FIND_DATA_V1, *PFVE_FIND_DATA_V1;

NTSYSAPI

HRESULT

NTAPI

FveFindFirstVolume(

PHANDLE FveFindHandle,

PFVE_FIND_DATA_V1 FindData

);

NTSYSAPI

HRESULT

NTAPI

FveFindNextVolume(

HANDLE FveFindHandle,

PFVE_FIND_DATA_V1 FindData

);

NTSYSAPI

HRESULT

NTAPI

FveGetVolumeNameW(

HANDLE FveHandle,

PULONG VolumeNameBufferCchLen,

LPWSTR VolumeName

);

HRESULT

NTAPI

FveUpdateBandIdBcd(

HANDLE FveVolumeHandle

);

HRESULT

NTAPI

FveLogRecoveryReason(

HANDLE FveVolumeHandle,

DWORD RecoveryReason,

PCWSTR ApplicationPath,

DWORD ChangedBcd

);

HRESULT

NTAPI

FveIsSchemaExtInstalled(

PBOOL SchemExtInstalled

);

typedef

enum _FVE_SECUREBOOT_BINDING_STATE {

FVE_SECUREBOOT_BINDING_UNKNOWN = -1,

FVE_SECUREBOOT_BINDING_NOT_POSSIBLE = 0,

FVE_SECUREBOOT_BINDING_DISABLED_BY_POLICY,

FVE_SECUREBOOT_BINDING_POSSIBLE,

FVE_SECUREBOOT_BINDING_BOUND

} FVE_SECUREBOOT_BINDING_STATE, *PFVE_SECUREBOOT_BINDING_STATE;

HRESULT

NTAPI

FveGetSecureBootBindingState(

PFVE_SECUREBOOT_BINDING_STATE SecureBootBindingState

);

HRESULT

NTAPI

FveIsDeviceLockable(

HANDLE hFveVolume

);

HRESULT

NTAPI

FveLockDevice(

HANDLE hFveVolume

);

HRESULT

NTAPI

FveIsDeviceLockedOut(

HANDLE hFveVolume,

BOOL *IsDeviceLocked

);

HRESULT

NTAPI

FveValidateDeviceLockoutState(

HANDLE hFveVolume

);

HRESULT

NTAPI

FveGetDeviceLockoutData(

HANDLE hFveVolume,

PBYTE PerUserData,

ULONG *PerUserSize

);

HRESULT

NTAPI

FveUpdateDeviceLockoutState(

HANDLE hFveVolume,

PBYTE PerUserData,

ULONG PerUserSize

);

HRESULT

NTAPI

FveUpdateDeviceLockoutStateEx(

HANDLE hFveVolume,

PBYTE PerUserData,

ULONG PerUserSize,

ULONG Flags

);

HRESULT

NTAPI

FveDisableDeviceLockoutState(

HANDLE hFveVolume

);

HRESULT

NTAPI

FveRecalculateOffsetsAndMoveMetadata(

HANDLE hFveVolume

);

HRESULT

NTAPI

FveDeleteDeviceEncryptionOptOutForVolumeW(

PCWSTR VolumePath

);

NTSYSAPI

HRESULT

NTAPI

FveGetExternalKeyBlob(

PBYTE* Buffer,

DWORD* BufferSize

);

NTSYSAPI

HRESULT

NTAPI

FveEscrowEncryptedRecoveryKeyForRetailUnlock(

PBYTE Buffer,

DWORD BufferSize

);

HRESULT

NTAPI

FvepCanPinExceptionPolicyBeApplied(

PBOOL Result

);

NTSYSAPI

HRESULT

NTAPI

FveCanPinExceptionPolicyBeApplied(

PBOOL Result

);

NTSYSAPI

HRESULT

NTAPI

FveResetTpmDictionaryAttackParameters(

);

NTSYSAPI

HRESULT

NTAPI

FveCommitChangesEx(

HANDLE FveVolumeHandle,

FVE_SCENARIO_TYPE FveScenario

);
