typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef pointer64 ImageBaseOffset64;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned int    uint3;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef enum _ACCESS_MODE {
    NOT_USED_ACCESS=0,
    GRANT_ACCESS=1,
    SET_ACCESS=2,
    DENY_ACCESS=3,
    REVOKE_ACCESS=4,
    SET_AUDIT_SUCCESS=5,
    SET_AUDIT_FAILURE=6
} _ACCESS_MODE;

typedef struct _EXPLICIT_ACCESS_W _EXPLICIT_ACCESS_W, *P_EXPLICIT_ACCESS_W;

typedef ulong DWORD;

typedef enum _ACCESS_MODE ACCESS_MODE;

typedef struct _TRUSTEE_W _TRUSTEE_W, *P_TRUSTEE_W;

typedef struct _TRUSTEE_W TRUSTEE_W;

typedef enum _MULTIPLE_TRUSTEE_OPERATION {
    NO_MULTIPLE_TRUSTEE=0,
    TRUSTEE_IS_IMPERSONATE=1
} _MULTIPLE_TRUSTEE_OPERATION;

typedef enum _MULTIPLE_TRUSTEE_OPERATION MULTIPLE_TRUSTEE_OPERATION;

typedef enum _TRUSTEE_FORM {
    TRUSTEE_IS_SID=0,
    TRUSTEE_IS_NAME=1,
    TRUSTEE_BAD_FORM=2,
    TRUSTEE_IS_OBJECTS_AND_SID=3,
    TRUSTEE_IS_OBJECTS_AND_NAME=4
} _TRUSTEE_FORM;

typedef enum _TRUSTEE_FORM TRUSTEE_FORM;

typedef enum _TRUSTEE_TYPE {
    TRUSTEE_IS_UNKNOWN=0,
    TRUSTEE_IS_USER=1,
    TRUSTEE_IS_GROUP=2,
    TRUSTEE_IS_DOMAIN=3,
    TRUSTEE_IS_ALIAS=4,
    TRUSTEE_IS_WELL_KNOWN_GROUP=5,
    TRUSTEE_IS_DELETED=6,
    TRUSTEE_IS_INVALID=7,
    TRUSTEE_IS_COMPUTER=8
} _TRUSTEE_TYPE;

typedef enum _TRUSTEE_TYPE TRUSTEE_TYPE;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

struct _TRUSTEE_W {
    struct _TRUSTEE_W *pMultipleTrustee;
    MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
    TRUSTEE_FORM TrusteeForm;
    TRUSTEE_TYPE TrusteeType;
    LPWSTR ptstrName;
};

struct _EXPLICIT_ACCESS_W {
    DWORD grfAccessPermissions;
    ACCESS_MODE grfAccessMode;
    DWORD grfInheritance;
    TRUSTEE_W Trustee;
};

typedef enum _SE_OBJECT_TYPE {
    SE_UNKNOWN_OBJECT_TYPE=0,
    SE_FILE_OBJECT=1,
    SE_SERVICE=2,
    SE_PRINTER=3,
    SE_REGISTRY_KEY=4,
    SE_LMSHARE=5,
    SE_KERNEL_OBJECT=6,
    SE_WINDOW_OBJECT=7,
    SE_DS_OBJECT=8,
    SE_DS_OBJECT_ALL=9,
    SE_PROVIDER_DEFINED_OBJECT=10,
    SE_WMIGUID_OBJECT=11,
    SE_REGISTRY_WOW64_32KEY=12
} _SE_OBJECT_TYPE;

typedef struct _EXPLICIT_ACCESS_W *PEXPLICIT_ACCESS_W;

typedef enum _SE_OBJECT_TYPE SE_OBJECT_TYPE;

typedef struct astruct astruct, *Pastruct;

typedef struct _FVE_DATUM_KEY _FVE_DATUM_KEY, *P_FVE_DATUM_KEY;

typedef struct _FVE_DATUM_KEY FVE_DATUM_KEY;

typedef struct Nonce Nonce, *PNonce;

typedef struct FVE_DATUM_TEMPLATE FVE_DATUM_TEMPLATE, *PFVE_DATUM_TEMPLATE;

typedef struct _FVE_DATUM _FVE_DATUM, *P_FVE_DATUM;

typedef struct _FVE_DATUM FVE_DATUM;

typedef enum KEY_TYPES {
    STRETCH_KEY=4096,
    AES_CCM_256_0=8192,
    AES_CCM_256_1=8193,
    AES_CCM_256_EXTERN_KEY=8194,
    AES_CCM_256_VMK=8195,
    AES_CCM_256_PIN=8196,
    AES_CCM_256_CONCAT_HASH=8197,
    AES_CCM_256_PUBLIC_KEY=8198,
    AES_CCM_256_PASSPHRASE=8199,
    AES_CCM_256_REOCVERY_PASSWORD=8200,
    AES_128_DIFFUSER=32768,
    AES_256_DIFFUSER=32769,
    AES_128_NO_DIFFUSER=32770,
    AES_256_NO_DIFFUSER=32771,
    AES_XTS_128=32772,
    AES_XTS_256=32773
} KEY_TYPES;

typedef ushort WORD;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef uchar BYTE;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct Nonce {
    FILETIME nonceTime;
    int nonceCounter;
};

struct _FVE_DATUM {
    WORD StructureSize;
    WORD Role;
    WORD Type;
    WORD Flags;
};

struct FVE_DATUM_TEMPLATE {
    FVE_DATUM h;
    BYTE DatumData[1];
};

struct astruct {
    FVE_DATUM_KEY *AuthDataDatum;
    ushort DatumCount;
    undefined field2_0xa;
    undefined field3_0xb;
    undefined field4_0xc;
    undefined field5_0xd;
    undefined field6_0xe;
    undefined field7_0xf;
    struct Nonce *Nonce;
    struct FVE_DATUM_TEMPLATE **DaumArr;
};

struct _FVE_DATUM_KEY {
    FVE_DATUM h;
    enum KEY_TYPES KeyType;
    WORD KeyFlags;
    WORD KeyData[1];
};

typedef struct astruct_2 astruct_2, *Pastruct_2;

struct astruct_2 {
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    undefined field8_0x8;
    undefined field9_0x9;
    undefined field10_0xa;
    undefined field11_0xb;
    undefined field12_0xc;
    undefined field13_0xd;
    undefined field14_0xe;
    undefined field15_0xf;
    undefined field16_0x10;
    undefined field17_0x11;
    undefined field18_0x12;
    undefined field19_0x13;
    undefined field20_0x14;
    undefined field21_0x15;
    undefined field22_0x16;
    undefined field23_0x17;
    undefined field24_0x18;
    undefined field25_0x19;
    undefined field26_0x1a;
    undefined field27_0x1b;
    undefined field28_0x1c;
    undefined field29_0x1d;
    undefined field30_0x1e;
    undefined field31_0x1f;
    undefined field32_0x20;
    undefined field33_0x21;
    undefined field34_0x22;
    undefined field35_0x23;
    undefined field36_0x24;
    undefined field37_0x25;
    undefined field38_0x26;
    undefined field39_0x27;
    undefined field40_0x28;
    undefined field41_0x29;
    undefined field42_0x2a;
    undefined field43_0x2b;
    undefined field44_0x2c;
    undefined field45_0x2d;
    undefined field46_0x2e;
    undefined field47_0x2f;
    undefined field48_0x30;
    undefined field49_0x31;
    undefined field50_0x32;
    undefined field51_0x33;
    undefined field52_0x34;
    undefined field53_0x35;
    undefined field54_0x36;
    undefined field55_0x37;
    undefined field56_0x38;
    undefined field57_0x39;
    undefined field58_0x3a;
    undefined field59_0x3b;
    undefined field60_0x3c;
    undefined field61_0x3d;
    undefined field62_0x3e;
    undefined field63_0x3f;
    undefined field64_0x40;
    undefined field65_0x41;
    undefined field66_0x42;
    undefined field67_0x43;
    undefined field68_0x44;
    undefined field69_0x45;
    undefined field70_0x46;
    undefined field71_0x47;
    undefined field72_0x48;
    undefined field73_0x49;
    undefined field74_0x4a;
    undefined field75_0x4b;
    undefined field76_0x4c;
    undefined field77_0x4d;
    undefined field78_0x4e;
    undefined field79_0x4f;
    undefined field80_0x50;
    undefined field81_0x51;
    undefined field82_0x52;
    undefined field83_0x53;
    undefined field84_0x54;
    undefined field85_0x55;
    undefined field86_0x56;
    undefined field87_0x57;
    undefined field88_0x58;
    undefined field89_0x59;
    undefined field90_0x5a;
    undefined field91_0x5b;
    undefined field92_0x5c;
    undefined field93_0x5d;
    undefined field94_0x5e;
    undefined field95_0x5f;
    undefined field96_0x60;
    undefined field97_0x61;
    undefined field98_0x62;
    undefined field99_0x63;
    undefined field100_0x64;
    undefined field101_0x65;
    undefined field102_0x66;
    undefined field103_0x67;
    undefined field104_0x68;
    undefined field105_0x69;
    undefined field106_0x6a;
    undefined field107_0x6b;
    undefined field108_0x6c;
    undefined field109_0x6d;
    undefined field110_0x6e;
    undefined field111_0x6f;
    undefined field112_0x70;
    undefined field113_0x71;
    undefined field114_0x72;
    undefined field115_0x73;
    undefined field116_0x74;
    undefined field117_0x75;
    undefined field118_0x76;
    undefined field119_0x77;
    ushort AuthDataSize;
    undefined field121_0x7a;
    undefined field122_0x7b;
    undefined field123_0x7c;
    undefined field124_0x7d;
    undefined field125_0x7e;
    undefined field126_0x7f;
    void *AuthData;
    undefined field128_0x88;
    undefined field129_0x89;
    undefined field130_0x8a;
    undefined field131_0x8b;
    undefined field132_0x8c;
    undefined field133_0x8d;
    undefined field134_0x8e;
    undefined field135_0x8f;
    undefined field136_0x90;
    undefined field137_0x91;
    undefined field138_0x92;
    undefined field139_0x93;
    undefined field140_0x94;
    undefined field141_0x95;
    undefined field142_0x96;
    undefined field143_0x97;
    undefined field144_0x98;
    undefined field145_0x99;
    undefined field146_0x9a;
    undefined field147_0x9b;
    undefined field148_0x9c;
    undefined field149_0x9d;
    undefined field150_0x9e;
    undefined field151_0x9f;
    undefined field152_0xa0;
    undefined field153_0xa1;
    undefined field154_0xa2;
    undefined field155_0xa3;
    undefined field156_0xa4;
    undefined field157_0xa5;
    undefined field158_0xa6;
    undefined field159_0xa7;
    undefined field160_0xa8;
    undefined field161_0xa9;
    undefined field162_0xaa;
    undefined field163_0xab;
    undefined field164_0xac;
    undefined field165_0xad;
    undefined field166_0xae;
    undefined field167_0xaf;
    undefined field168_0xb0;
    undefined field169_0xb1;
    undefined field170_0xb2;
    undefined field171_0xb3;
    undefined field172_0xb4;
    undefined field173_0xb5;
    undefined field174_0xb6;
    undefined field175_0xb7;
    undefined field176_0xb8;
    undefined field177_0xb9;
    undefined field178_0xba;
    undefined field179_0xbb;
    undefined field180_0xbc;
    undefined field181_0xbd;
    undefined field182_0xbe;
    undefined field183_0xbf;
    ushort AesLen;
    undefined field185_0xc2;
    undefined field186_0xc3;
    undefined field187_0xc4;
    undefined field188_0xc5;
    undefined field189_0xc6;
    undefined field190_0xc7;
    void *AESIn;
};

typedef struct astruct_3 astruct_3, *Pastruct_3;

struct astruct_3 {
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    undefined field8_0x8;
    undefined field9_0x9;
    undefined field10_0xa;
    undefined field11_0xb;
    undefined field12_0xc;
    undefined field13_0xd;
    undefined field14_0xe;
    undefined field15_0xf;
    undefined field16_0x10;
    undefined field17_0x11;
    undefined field18_0x12;
    undefined field19_0x13;
    undefined field20_0x14;
    undefined field21_0x15;
    undefined field22_0x16;
    undefined field23_0x17;
    undefined field24_0x18;
    undefined field25_0x19;
    undefined field26_0x1a;
    undefined field27_0x1b;
    undefined field28_0x1c;
    undefined field29_0x1d;
    undefined field30_0x1e;
    undefined field31_0x1f;
    undefined field32_0x20;
    undefined field33_0x21;
    undefined field34_0x22;
    undefined field35_0x23;
    undefined field36_0x24;
    undefined field37_0x25;
    undefined field38_0x26;
    undefined field39_0x27;
    undefined field40_0x28;
    undefined field41_0x29;
    undefined field42_0x2a;
    undefined field43_0x2b;
    undefined field44_0x2c;
    undefined field45_0x2d;
    undefined field46_0x2e;
    undefined field47_0x2f;
    undefined field48_0x30;
    undefined field49_0x31;
    undefined field50_0x32;
    undefined field51_0x33;
    undefined field52_0x34;
    undefined field53_0x35;
    undefined field54_0x36;
    undefined field55_0x37;
    undefined2 field56_0x38;
    short field57_0x3a;
    uint field58_0x3c;
    undefined field59_0x40;
    undefined field60_0x41;
    undefined field61_0x42;
    undefined field62_0x43;
    undefined field63_0x44;
    undefined field64_0x45;
    undefined field65_0x46;
    undefined field66_0x47;
    undefined field67_0x48;
    undefined field68_0x49;
    undefined field69_0x4a;
    undefined field70_0x4b;
    undefined field71_0x4c;
    undefined field72_0x4d;
    undefined field73_0x4e;
    undefined field74_0x4f;
    undefined field75_0x50;
    undefined field76_0x51;
    undefined field77_0x52;
    undefined field78_0x53;
    undefined field79_0x54;
    undefined field80_0x55;
    undefined field81_0x56;
    undefined field82_0x57;
    undefined field83_0x58;
    undefined field84_0x59;
    undefined field85_0x5a;
    undefined field86_0x5b;
    undefined field87_0x5c;
    undefined field88_0x5d;
    undefined field89_0x5e;
    undefined field90_0x5f;
    undefined field91_0x60;
    undefined field92_0x61;
    undefined field93_0x62;
    undefined field94_0x63;
    undefined field95_0x64;
    undefined field96_0x65;
    undefined field97_0x66;
    undefined field98_0x67;
    undefined field99_0x68;
    undefined field100_0x69;
    undefined field101_0x6a;
    undefined field102_0x6b;
    undefined field103_0x6c;
    undefined field104_0x6d;
    undefined field105_0x6e;
    undefined field106_0x6f;
    undefined field107_0x70;
    undefined field108_0x71;
    undefined field109_0x72;
    undefined field110_0x73;
    undefined field111_0x74;
    undefined field112_0x75;
    undefined field113_0x76;
    undefined field114_0x77;
    undefined field115_0x78;
    undefined field116_0x79;
    undefined field117_0x7a;
    undefined field118_0x7b;
    undefined field119_0x7c;
    undefined field120_0x7d;
    undefined field121_0x7e;
    undefined field122_0x7f;
    undefined field123_0x80;
    undefined field124_0x81;
    undefined field125_0x82;
    undefined field126_0x83;
    undefined field127_0x84;
    undefined field128_0x85;
    undefined field129_0x86;
    undefined field130_0x87;
    undefined field131_0x88;
    undefined field132_0x89;
    undefined field133_0x8a;
    undefined field134_0x8b;
    undefined field135_0x8c;
    undefined field136_0x8d;
    undefined field137_0x8e;
    undefined field138_0x8f;
    undefined field139_0x90;
    undefined field140_0x91;
    undefined field141_0x92;
    undefined field142_0x93;
    undefined field143_0x94;
    undefined field144_0x95;
    undefined field145_0x96;
    undefined field146_0x97;
    undefined field147_0x98;
    undefined field148_0x99;
    undefined field149_0x9a;
    undefined field150_0x9b;
    undefined field151_0x9c;
    undefined field152_0x9d;
    undefined field153_0x9e;
    undefined field154_0x9f;
    undefined field155_0xa0;
    undefined field156_0xa1;
    undefined field157_0xa2;
    undefined field158_0xa3;
    undefined field159_0xa4;
    undefined field160_0xa5;
    undefined field161_0xa6;
    undefined field162_0xa7;
    undefined field163_0xa8;
    undefined field164_0xa9;
    undefined field165_0xaa;
    undefined field166_0xab;
    undefined field167_0xac;
    undefined field168_0xad;
    undefined field169_0xae;
    undefined field170_0xaf;
    undefined field171_0xb0;
    undefined field172_0xb1;
    undefined field173_0xb2;
    undefined field174_0xb3;
    undefined field175_0xb4;
    undefined field176_0xb5;
    undefined field177_0xb6;
    undefined field178_0xb7;
    undefined field179_0xb8;
    undefined field180_0xb9;
    undefined field181_0xba;
    undefined field182_0xbb;
    undefined field183_0xbc;
    undefined field184_0xbd;
    undefined field185_0xbe;
    undefined field186_0xbf;
    undefined field187_0xc0;
    undefined field188_0xc1;
    undefined field189_0xc2;
    undefined field190_0xc3;
    undefined field191_0xc4;
    undefined field192_0xc5;
    undefined field193_0xc6;
    undefined field194_0xc7;
    undefined field195_0xc8;
    undefined field196_0xc9;
    undefined field197_0xca;
    undefined field198_0xcb;
    undefined field199_0xcc;
    undefined field200_0xcd;
    undefined field201_0xce;
    undefined field202_0xcf;
    undefined field203_0xd0;
    undefined field204_0xd1;
    undefined field205_0xd2;
    undefined field206_0xd3;
    undefined field207_0xd4;
    undefined field208_0xd5;
    undefined field209_0xd6;
    undefined field210_0xd7;
    undefined field211_0xd8;
    undefined field212_0xd9;
    undefined field213_0xda;
    undefined field214_0xdb;
    undefined field215_0xdc;
    undefined field216_0xdd;
    undefined field217_0xde;
    undefined field218_0xdf;
    undefined field219_0xe0;
    undefined field220_0xe1;
    undefined field221_0xe2;
    undefined field222_0xe3;
    undefined field223_0xe4;
    undefined field224_0xe5;
    undefined field225_0xe6;
    undefined field226_0xe7;
    undefined field227_0xe8;
    undefined field228_0xe9;
    undefined field229_0xea;
    undefined field230_0xeb;
    undefined field231_0xec;
    undefined field232_0xed;
    undefined field233_0xee;
    undefined field234_0xef;
    undefined field235_0xf0;
    undefined field236_0xf1;
    undefined field237_0xf2;
    undefined field238_0xf3;
    undefined field239_0xf4;
    undefined field240_0xf5;
    undefined field241_0xf6;
    undefined field242_0xf7;
    undefined field243_0xf8;
    undefined field244_0xf9;
    undefined field245_0xfa;
    undefined field246_0xfb;
    undefined field247_0xfc;
    undefined field248_0xfd;
    undefined field249_0xfe;
    undefined field250_0xff;
    undefined field251_0x100;
    undefined field252_0x101;
    undefined field253_0x102;
    undefined field254_0x103;
    undefined field255_0x104;
    undefined field256_0x105;
    undefined field257_0x106;
    undefined field258_0x107;
    undefined field259_0x108;
    undefined field260_0x109;
    undefined field261_0x10a;
    undefined field262_0x10b;
    undefined field263_0x10c;
    undefined field264_0x10d;
    undefined field265_0x10e;
    undefined field266_0x10f;
    undefined field267_0x110;
    undefined field268_0x111;
    undefined field269_0x112;
    undefined field270_0x113;
    undefined field271_0x114;
    undefined field272_0x115;
    undefined field273_0x116;
    undefined field274_0x117;
    undefined field275_0x118;
    undefined field276_0x119;
    undefined field277_0x11a;
    undefined field278_0x11b;
    undefined field279_0x11c;
    undefined field280_0x11d;
    undefined field281_0x11e;
    undefined field282_0x11f;
    undefined field283_0x120;
    undefined field284_0x121;
    undefined field285_0x122;
    undefined field286_0x123;
    undefined field287_0x124;
    undefined field288_0x125;
    undefined field289_0x126;
    undefined field290_0x127;
    undefined field291_0x128;
    undefined field292_0x129;
    undefined field293_0x12a;
    undefined field294_0x12b;
    undefined field295_0x12c;
    undefined field296_0x12d;
    undefined field297_0x12e;
    undefined field298_0x12f;
    undefined field299_0x130;
    undefined field300_0x131;
    undefined field301_0x132;
    undefined field302_0x133;
    undefined field303_0x134;
    undefined field304_0x135;
    undefined field305_0x136;
    undefined field306_0x137;
    undefined field307_0x138;
    undefined field308_0x139;
    undefined field309_0x13a;
    undefined field310_0x13b;
    undefined field311_0x13c;
    undefined field312_0x13d;
    undefined field313_0x13e;
    undefined field314_0x13f;
    undefined field315_0x140;
    undefined field316_0x141;
    undefined field317_0x142;
    undefined field318_0x143;
    undefined field319_0x144;
    undefined field320_0x145;
    undefined field321_0x146;
    undefined field322_0x147;
    undefined field323_0x148;
    undefined field324_0x149;
    undefined field325_0x14a;
    undefined field326_0x14b;
    undefined field327_0x14c;
    undefined field328_0x14d;
    undefined field329_0x14e;
    undefined field330_0x14f;
    undefined field331_0x150;
    undefined field332_0x151;
    undefined field333_0x152;
    undefined field334_0x153;
    undefined field335_0x154;
    undefined field336_0x155;
    undefined field337_0x156;
    undefined field338_0x157;
    undefined field339_0x158;
    undefined field340_0x159;
    undefined field341_0x15a;
    undefined field342_0x15b;
    undefined field343_0x15c;
    undefined field344_0x15d;
    undefined field345_0x15e;
    undefined field346_0x15f;
    undefined field347_0x160;
    undefined field348_0x161;
    undefined field349_0x162;
    undefined field350_0x163;
    undefined field351_0x164;
    undefined field352_0x165;
    undefined field353_0x166;
    undefined field354_0x167;
    undefined field355_0x168;
    undefined field356_0x169;
    undefined field357_0x16a;
    undefined field358_0x16b;
    undefined field359_0x16c;
    undefined field360_0x16d;
    undefined field361_0x16e;
    undefined field362_0x16f;
    undefined field363_0x170;
    undefined field364_0x171;
    undefined field365_0x172;
    undefined field366_0x173;
    undefined field367_0x174;
    undefined field368_0x175;
    undefined field369_0x176;
    undefined field370_0x177;
    undefined field371_0x178;
    undefined field372_0x179;
    undefined field373_0x17a;
    undefined field374_0x17b;
    undefined field375_0x17c;
    undefined field376_0x17d;
    undefined field377_0x17e;
    undefined field378_0x17f;
    undefined field379_0x180;
    undefined field380_0x181;
    undefined field381_0x182;
    undefined field382_0x183;
    undefined field383_0x184;
    undefined field384_0x185;
    undefined field385_0x186;
    undefined field386_0x187;
    undefined field387_0x188;
    undefined field388_0x189;
    undefined field389_0x18a;
    undefined field390_0x18b;
    undefined field391_0x18c;
    undefined field392_0x18d;
    undefined field393_0x18e;
    undefined field394_0x18f;
    undefined field395_0x190;
    undefined field396_0x191;
    undefined field397_0x192;
    undefined field398_0x193;
    undefined field399_0x194;
    undefined field400_0x195;
    undefined field401_0x196;
    undefined field402_0x197;
    undefined field403_0x198;
    undefined field404_0x199;
    undefined field405_0x19a;
    undefined field406_0x19b;
    undefined field407_0x19c;
    undefined field408_0x19d;
    undefined field409_0x19e;
    undefined field410_0x19f;
    undefined field411_0x1a0;
    undefined field412_0x1a1;
    undefined field413_0x1a2;
    undefined field414_0x1a3;
    undefined field415_0x1a4;
    undefined field416_0x1a5;
    undefined field417_0x1a6;
    undefined field418_0x1a7;
    undefined field419_0x1a8;
    undefined field420_0x1a9;
    undefined field421_0x1aa;
    undefined field422_0x1ab;
    undefined field423_0x1ac;
    undefined field424_0x1ad;
    undefined field425_0x1ae;
    undefined field426_0x1af;
    undefined field427_0x1b0;
    undefined field428_0x1b1;
    undefined field429_0x1b2;
    undefined field430_0x1b3;
    undefined field431_0x1b4;
    undefined field432_0x1b5;
    undefined field433_0x1b6;
    undefined field434_0x1b7;
    undefined field435_0x1b8;
    undefined field436_0x1b9;
    undefined field437_0x1ba;
    undefined field438_0x1bb;
    undefined field439_0x1bc;
    undefined field440_0x1bd;
    undefined field441_0x1be;
    undefined field442_0x1bf;
    undefined field443_0x1c0;
    undefined field444_0x1c1;
    undefined field445_0x1c2;
    undefined field446_0x1c3;
    undefined field447_0x1c4;
    undefined field448_0x1c5;
    undefined field449_0x1c6;
    undefined field450_0x1c7;
    undefined field451_0x1c8;
    undefined field452_0x1c9;
    undefined field453_0x1ca;
    undefined field454_0x1cb;
    undefined field455_0x1cc;
    undefined field456_0x1cd;
    undefined field457_0x1ce;
    undefined field458_0x1cf;
    undefined field459_0x1d0;
    undefined field460_0x1d1;
    undefined field461_0x1d2;
    undefined field462_0x1d3;
    undefined field463_0x1d4;
    undefined field464_0x1d5;
    undefined field465_0x1d6;
    undefined field466_0x1d7;
    undefined field467_0x1d8;
    undefined field468_0x1d9;
    undefined field469_0x1da;
    undefined field470_0x1db;
    undefined field471_0x1dc;
    undefined field472_0x1dd;
    undefined field473_0x1de;
    undefined field474_0x1df;
    undefined field475_0x1e0;
    undefined field476_0x1e1;
    undefined field477_0x1e2;
    undefined field478_0x1e3;
    undefined field479_0x1e4;
    undefined field480_0x1e5;
    undefined field481_0x1e6;
    undefined field482_0x1e7;
    undefined field483_0x1e8;
    undefined field484_0x1e9;
    undefined field485_0x1ea;
    undefined field486_0x1eb;
    undefined field487_0x1ec;
    undefined field488_0x1ed;
    undefined field489_0x1ee;
    undefined field490_0x1ef;
    undefined field491_0x1f0;
    undefined field492_0x1f1;
    undefined field493_0x1f2;
    undefined field494_0x1f3;
    undefined field495_0x1f4;
    undefined field496_0x1f5;
    undefined field497_0x1f6;
    undefined field498_0x1f7;
    undefined field499_0x1f8;
    undefined field500_0x1f9;
    undefined field501_0x1fa;
    undefined field502_0x1fb;
    undefined field503_0x1fc;
    undefined field504_0x1fd;
    undefined field505_0x1fe;
    undefined field506_0x1ff;
    undefined field507_0x200;
    undefined field508_0x201;
    undefined field509_0x202;
    undefined field510_0x203;
    undefined field511_0x204;
    undefined field512_0x205;
    undefined field513_0x206;
    undefined field514_0x207;
    undefined field515_0x208;
    undefined field516_0x209;
    undefined field517_0x20a;
    undefined field518_0x20b;
    undefined field519_0x20c;
    undefined field520_0x20d;
    undefined field521_0x20e;
    undefined field522_0x20f;
    undefined field523_0x210;
    undefined field524_0x211;
    undefined field525_0x212;
    undefined field526_0x213;
    undefined field527_0x214;
    undefined field528_0x215;
    undefined field529_0x216;
    undefined field530_0x217;
    undefined field531_0x218;
    undefined field532_0x219;
    undefined field533_0x21a;
    undefined field534_0x21b;
    undefined field535_0x21c;
    undefined field536_0x21d;
    undefined field537_0x21e;
    undefined field538_0x21f;
    undefined field539_0x220;
    undefined field540_0x221;
    undefined field541_0x222;
    undefined field542_0x223;
    undefined field543_0x224;
    undefined field544_0x225;
    undefined field545_0x226;
    undefined field546_0x227;
    undefined field547_0x228;
    undefined field548_0x229;
    undefined field549_0x22a;
    undefined field550_0x22b;
    undefined field551_0x22c;
    undefined field552_0x22d;
    undefined field553_0x22e;
    undefined field554_0x22f;
    undefined field555_0x230;
    undefined field556_0x231;
    undefined field557_0x232;
    undefined field558_0x233;
    undefined field559_0x234;
    undefined field560_0x235;
    undefined field561_0x236;
    undefined field562_0x237;
    undefined field563_0x238;
    undefined field564_0x239;
    undefined field565_0x23a;
    undefined field566_0x23b;
    undefined field567_0x23c;
    undefined field568_0x23d;
    undefined field569_0x23e;
    undefined field570_0x23f;
    undefined field571_0x240;
    undefined field572_0x241;
    undefined field573_0x242;
    undefined field574_0x243;
    undefined field575_0x244;
    undefined field576_0x245;
    undefined field577_0x246;
    undefined field578_0x247;
    undefined field579_0x248;
    undefined field580_0x249;
    undefined field581_0x24a;
    undefined field582_0x24b;
    undefined field583_0x24c;
    undefined field584_0x24d;
    undefined field585_0x24e;
    undefined field586_0x24f;
    undefined field587_0x250;
    undefined field588_0x251;
    undefined field589_0x252;
    undefined field590_0x253;
    undefined field591_0x254;
    undefined field592_0x255;
    undefined field593_0x256;
    undefined field594_0x257;
    undefined field595_0x258;
    undefined field596_0x259;
    undefined field597_0x25a;
    undefined field598_0x25b;
    undefined field599_0x25c;
    undefined field600_0x25d;
    undefined field601_0x25e;
    undefined field602_0x25f;
    undefined field603_0x260;
    undefined field604_0x261;
    undefined field605_0x262;
    undefined field606_0x263;
    undefined field607_0x264;
    undefined field608_0x265;
    undefined field609_0x266;
    undefined field610_0x267;
    undefined field611_0x268;
    undefined field612_0x269;
    undefined field613_0x26a;
    undefined field614_0x26b;
    undefined field615_0x26c;
    undefined field616_0x26d;
    undefined field617_0x26e;
    undefined field618_0x26f;
    undefined field619_0x270;
    undefined field620_0x271;
    undefined field621_0x272;
    undefined field622_0x273;
    undefined field623_0x274;
    undefined field624_0x275;
    undefined field625_0x276;
    undefined field626_0x277;
    undefined field627_0x278;
    undefined field628_0x279;
    undefined field629_0x27a;
    undefined field630_0x27b;
    undefined field631_0x27c;
    undefined field632_0x27d;
    undefined field633_0x27e;
    undefined field634_0x27f;
    undefined field635_0x280;
    undefined field636_0x281;
    undefined field637_0x282;
    undefined field638_0x283;
    undefined field639_0x284;
    undefined field640_0x285;
    undefined field641_0x286;
    undefined field642_0x287;
    undefined field643_0x288;
    undefined field644_0x289;
    undefined field645_0x28a;
    undefined field646_0x28b;
    undefined field647_0x28c;
    undefined field648_0x28d;
    undefined field649_0x28e;
    undefined field650_0x28f;
    undefined field651_0x290;
    undefined field652_0x291;
    undefined field653_0x292;
    undefined field654_0x293;
    undefined field655_0x294;
    undefined field656_0x295;
    undefined field657_0x296;
    undefined field658_0x297;
    undefined field659_0x298;
    undefined field660_0x299;
    undefined field661_0x29a;
    undefined field662_0x29b;
    undefined field663_0x29c;
    undefined field664_0x29d;
    undefined field665_0x29e;
    undefined field666_0x29f;
    undefined field667_0x2a0;
    undefined field668_0x2a1;
    undefined field669_0x2a2;
    undefined field670_0x2a3;
    undefined field671_0x2a4;
    undefined field672_0x2a5;
    undefined field673_0x2a6;
    undefined field674_0x2a7;
    undefined field675_0x2a8;
    undefined field676_0x2a9;
    undefined field677_0x2aa;
    undefined field678_0x2ab;
    undefined field679_0x2ac;
    undefined field680_0x2ad;
    undefined field681_0x2ae;
    undefined field682_0x2af;
    undefined2 field683_0x2b0;
    undefined field684_0x2b2;
    undefined field685_0x2b3;
    undefined field686_0x2b4;
    undefined field687_0x2b5;
    undefined field688_0x2b6;
    undefined field689_0x2b7;
    undefined field690_0x2b8;
    undefined field691_0x2b9;
    undefined field692_0x2ba;
    undefined field693_0x2bb;
    undefined field694_0x2bc;
    undefined field695_0x2bd;
    undefined field696_0x2be;
    undefined field697_0x2bf;
    undefined field698_0x2c0;
    undefined field699_0x2c1;
    undefined field700_0x2c2;
    undefined field701_0x2c3;
    undefined field702_0x2c4;
    undefined field703_0x2c5;
    undefined field704_0x2c6;
    undefined field705_0x2c7;
    undefined field706_0x2c8;
    undefined field707_0x2c9;
    undefined field708_0x2ca;
    undefined field709_0x2cb;
    undefined field710_0x2cc;
    undefined field711_0x2cd;
    undefined field712_0x2ce;
    undefined field713_0x2cf;
    undefined field714_0x2d0;
    undefined field715_0x2d1;
    undefined field716_0x2d2;
    undefined field717_0x2d3;
    undefined field718_0x2d4;
    undefined field719_0x2d5;
    undefined field720_0x2d6;
    undefined field721_0x2d7;
    undefined field722_0x2d8;
    undefined field723_0x2d9;
    undefined field724_0x2da;
    undefined field725_0x2db;
    undefined field726_0x2dc;
    undefined field727_0x2dd;
    undefined field728_0x2de;
    undefined field729_0x2df;
    undefined field730_0x2e0;
    undefined field731_0x2e1;
    undefined field732_0x2e2;
    undefined field733_0x2e3;
    undefined field734_0x2e4;
    undefined field735_0x2e5;
    undefined field736_0x2e6;
    undefined field737_0x2e7;
    undefined field738_0x2e8;
    undefined field739_0x2e9;
    undefined field740_0x2ea;
    undefined field741_0x2eb;
    undefined field742_0x2ec;
    undefined field743_0x2ed;
    undefined field744_0x2ee;
    undefined field745_0x2ef;
    undefined field746_0x2f0;
    undefined field747_0x2f1;
    undefined field748_0x2f2;
    undefined field749_0x2f3;
    undefined field750_0x2f4;
    undefined field751_0x2f5;
    undefined field752_0x2f6;
    undefined field753_0x2f7;
    undefined field754_0x2f8;
    undefined field755_0x2f9;
    undefined field756_0x2fa;
    undefined field757_0x2fb;
    undefined field758_0x2fc;
    undefined field759_0x2fd;
    undefined field760_0x2fe;
    undefined field761_0x2ff;
    undefined field762_0x300;
    undefined field763_0x301;
    undefined field764_0x302;
    undefined field765_0x303;
    undefined field766_0x304;
    undefined field767_0x305;
    undefined field768_0x306;
    undefined field769_0x307;
    undefined field770_0x308;
    undefined field771_0x309;
    undefined field772_0x30a;
    undefined field773_0x30b;
    undefined field774_0x30c;
    undefined field775_0x30d;
    undefined field776_0x30e;
    undefined field777_0x30f;
    undefined field778_0x310;
    undefined field779_0x311;
    undefined field780_0x312;
    undefined field781_0x313;
    undefined field782_0x314;
    undefined field783_0x315;
    undefined field784_0x316;
    undefined field785_0x317;
    undefined field786_0x318;
    undefined field787_0x319;
    undefined field788_0x31a;
    undefined field789_0x31b;
    undefined field790_0x31c;
    undefined field791_0x31d;
    undefined field792_0x31e;
    undefined field793_0x31f;
    undefined field794_0x320;
    undefined field795_0x321;
    undefined field796_0x322;
    undefined field797_0x323;
    undefined field798_0x324;
    undefined field799_0x325;
    undefined field800_0x326;
    undefined field801_0x327;
    undefined field802_0x328;
    undefined field803_0x329;
    undefined field804_0x32a;
    undefined field805_0x32b;
    undefined field806_0x32c;
    undefined field807_0x32d;
    undefined field808_0x32e;
    undefined field809_0x32f;
    ushort field810_0x330;
    undefined field811_0x332;
    undefined field812_0x333;
    undefined field813_0x334;
    undefined field814_0x335;
    undefined field815_0x336;
    undefined field816_0x337;
    void *AuthData;
};

typedef struct astruct_4 astruct_4, *Pastruct_4;

typedef struct FVE_DATUM_CONCAT_HASH FVE_DATUM_CONCAT_HASH, *PFVE_DATUM_CONCAT_HASH;

typedef struct FVE_DATUM_TPM_ENC FVE_DATUM_TPM_ENC, *PFVE_DATUM_TPM_ENC;

typedef enum ProtectorTypes {
    TPMBit=256,
    EXTERNAL_KEYBit=512,
    PINBit=1024,
    RECOVERY_PASSWORDBit=2048,
    PUBLIC_KEYBit=4096,
    PASSPHRASEBit=8192,
    EXTERNLY_MGDBit=16384
} ProtectorTypes;

struct FVE_DATUM_CONCAT_HASH {
    FVE_DATUM h;
    char *ConcatData;
};

struct FVE_DATUM_TPM_ENC {
    FVE_DATUM h;
    uchar PCRs[3];
    byte zero;
    short PrivateLen;
    short PrivateHMACLen;
    byte HMAC[32];
    short PrivateIVLen;
    byte PrivateIV[16];
    byte TPM_Sensitive[1];
};

struct astruct_4 {
    FVE_DATUM_KEY *AuthDataOrIK;
    ushort DatumCount;
    undefined field2_0xa;
    undefined field3_0xb;
    undefined field4_0xc;
    undefined field5_0xd;
    undefined field6_0xe;
    undefined field7_0xf;
    struct Nonce *Nonce;
    struct FVE_DATUM_TEMPLATE **DatumArr; /* Created by retype action */
    struct FVE_DATUM_CONCAT_HASH *ConcatHash; /* Created by retype action */
    struct FVE_DATUM_TPM_ENC *TPMEnc; /* Created by retype action */
    struct FVE_DATUM_TEMPLATE *Simple2; /* Created by retype action */
    struct FVE_DATUM_TEMPLATE *Simple3; /* Created by retype action */
    undefined field14_0x40;
    undefined field15_0x41;
    undefined field16_0x42;
    undefined field17_0x43;
    undefined field18_0x44;
    undefined field19_0x45;
    undefined field20_0x46;
    undefined field21_0x47;
    undefined field22_0x48;
    undefined field23_0x49;
    undefined field24_0x4a;
    undefined field25_0x4b;
    undefined field26_0x4c;
    undefined field27_0x4d;
    undefined field28_0x4e;
    undefined field29_0x4f;
    undefined field30_0x50;
    undefined field31_0x51;
    undefined field32_0x52;
    undefined field33_0x53;
    undefined field34_0x54;
    undefined field35_0x55;
    undefined field36_0x56;
    undefined field37_0x57;
    undefined field38_0x58;
    undefined field39_0x59;
    undefined field40_0x5a;
    undefined field41_0x5b;
    undefined field42_0x5c;
    undefined field43_0x5d;
    undefined field44_0x5e;
    undefined field45_0x5f;
    enum ProtectorTypes ProtectorType;
};

typedef struct VMKCreateRequest VMKCreateRequest, *PVMKCreateRequest;

typedef struct VMkInfoStruct VMkInfoStruct, *PVMkInfoStruct;

typedef enum VMKInfoEnum {
    ExternalKey=2,
    PassPhrase=3,
    PIN=4,
    PublicKey=5,
    RecoveryPassword=6,
    TPM=7,
    SID?=8
} VMKInfoEnum;

struct VMKCreateRequest {
    uint VMKCount;
    undefined field1_0x4;
    undefined field2_0x5;
    undefined field3_0x6;
    undefined field4_0x7;
    struct VMkInfoStruct (*VMKStructs)[1];
    FVE_DATUM_KEY *VMKDatum;
    undefined8 Time;
    undefined1 FixVMKTime; /* Created by retype action */
    undefined field9_0x21;
    undefined field10_0x22;
    undefined field11_0x23;
    undefined field12_0x24;
    undefined field13_0x25;
    undefined field14_0x26;
    undefined field15_0x27;
    struct FVE_DATUM_TEMPLATE *preambleDatum;
    GUID *GUID;
    struct Nonce *Nonce;
    undefined2 OverriddenProtType;
    bool OverrideProtectorType; /* Created by retype action */
    undefined field21_0x43;
    ushort VMKHints;
    undefined1 DetermineVMKHints; /* Created by retype action */
};

struct VMkInfoStruct {
    FVE_DATUM_KEY *CurrProtKey;
    FVE_DATUM *field1_0x8;
    FVE_DATUM *UseEnhancedAuthData;
    FVE_DATUM *field3_0x18;
    FVE_DATUM *field4_0x20;
    enum VMKInfoEnum VMKInfoType;
    undefined field6_0x2c;
    undefined field7_0x2d;
    undefined field8_0x2e;
    undefined field9_0x2f;
};

#define MAXDWORD32 -1

#define MAXDWORD64 -1

#define MAXHALF_PTR -1

#define MAXINT -1

#define MAXINT16 -1

#define MAXINT32 -1

#define MAXINT64 -1

#define MAXINT8 -1

#define MAXINT_PTR -1

#define MAXLONG32 -1

#define MAXLONG64 -1

#define MAXLONG_PTR -1

#define MAXSIZE_T -1

#define MAXSSIZE_T -1

#define MAXUHALF_PTR -1

#define MAXUINT -1

#define MAXUINT16 -1

#define MAXUINT32 -1

#define MAXUINT64 -1

#define MAXUINT8 -1

#define MAXUINT_PTR -1

#define MAXULONG32 -1

#define MAXULONG64 -1

#define MAXULONG_PTR -1

#define MAXULONGLONG -1

#define MINHALF_PTR 0

#define MININT 0

#define MININT16 0

#define MININT32 0

#define MININT64 0

#define MININT8 0

#define MININT_PTR 0

#define MINLONG32 0

#define MINLONG64 0

#define MINLONG_PTR 0

#define MINLONGLONG -9223372036854775808

#define MINSSIZE_T 0

typedef uint DWORD32;

typedef ulonglong DWORD64;

typedef ulonglong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef int HALF_PTR;

typedef ulonglong HANDLE_PTR;

typedef short INT16;

typedef int INT32;

typedef longlong INT64;

typedef char INT8;

typedef longlong INT_PTR;

typedef ULONG_PTR KAFFINITY;

typedef int LONG32;

typedef longlong LONG64;

typedef longlong LONG_PTR;

typedef uint *PDWORD32;

typedef ulonglong *PDWORD64;

typedef ULONG_PTR *PDWORD_PTR;

typedef int *PHALF_PTR;

typedef short *PINT16;

typedef int *PINT32;

typedef longlong *PINT64;

typedef char *PINT8;

typedef longlong *PINT_PTR;

typedef KAFFINITY *PKAFFINITY;

typedef int *PLONG32;

typedef longlong *PLONG64;

typedef longlong *PLONG_PTR;

typedef ulonglong POINTER_64_INT;

typedef ULONG_PTR *PSIZE_T;

typedef LONG_PTR *PSSIZE_T;

typedef uint *PUHALF_PTR;

typedef ushort *PUINT16;

typedef uint *PUINT32;

typedef ulonglong *PUINT64;

typedef uchar *PUINT8;

typedef ulonglong *PUINT_PTR;

typedef uint *PULONG32;

typedef ulonglong *PULONG64;

typedef ulonglong *PULONG_PTR;

typedef longlong SHANDLE_PTR;

typedef ULONG_PTR SIZE_T;

typedef LONG_PTR SSIZE_T;

typedef uint UHALF_PTR;

typedef ushort UINT16;

typedef uint UINT32;

typedef ulonglong UINT64;

typedef uchar UINT8;

typedef ulonglong UINT_PTR;

typedef uint ULONG32;

typedef ulonglong ULONG64;

typedef struct __BCRYPT_KEY_LENGTHS_STRUCT __BCRYPT_KEY_LENGTHS_STRUCT, *P__BCRYPT_KEY_LENGTHS_STRUCT;

typedef ulong ULONG;

struct __BCRYPT_KEY_LENGTHS_STRUCT {
    ULONG dwMinLength;
    ULONG dwMaxLength;
    ULONG dwIncrement;
};

typedef struct _BCRYPT_ALGORITHM_IDENTIFIER _BCRYPT_ALGORITHM_IDENTIFIER, *P_BCRYPT_ALGORITHM_IDENTIFIER;

struct _BCRYPT_ALGORITHM_IDENTIFIER {
    LPWSTR pszName;
    ULONG dwClass;
    ULONG dwFlags;
};

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, *P_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef uchar UCHAR;

typedef UCHAR *PUCHAR;

typedef ulonglong ULONGLONG;

struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG cbNonce;
    PUCHAR pbAuthData;
    ULONG cbAuthData;
    PUCHAR pbTag;
    ULONG cbTag;
    PUCHAR pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONGLONG cbData;
    ULONG dwFlags;
};

typedef struct _BCRYPT_DH_KEY_BLOB _BCRYPT_DH_KEY_BLOB, *P_BCRYPT_DH_KEY_BLOB;

struct _BCRYPT_DH_KEY_BLOB {
    ULONG dwMagic;
    ULONG cbKey;
};

typedef struct _BCRYPT_DH_PARAMETER_HEADER _BCRYPT_DH_PARAMETER_HEADER, *P_BCRYPT_DH_PARAMETER_HEADER;

struct _BCRYPT_DH_PARAMETER_HEADER {
    ULONG cbLength;
    ULONG dwMagic;
    ULONG cbKeyLength;
};

typedef struct _BCRYPT_DSA_KEY_BLOB _BCRYPT_DSA_KEY_BLOB, *P_BCRYPT_DSA_KEY_BLOB;

struct _BCRYPT_DSA_KEY_BLOB {
    ULONG dwMagic;
    ULONG cbKey;
    UCHAR Count[4];
    UCHAR Seed[20];
    UCHAR q[20];
};

typedef struct _BCRYPT_DSA_PARAMETER_HEADER _BCRYPT_DSA_PARAMETER_HEADER, *P_BCRYPT_DSA_PARAMETER_HEADER;

struct _BCRYPT_DSA_PARAMETER_HEADER {
    ULONG cbLength;
    ULONG dwMagic;
    ULONG cbKeyLength;
    UCHAR Count[4];
    UCHAR Seed[20];
    UCHAR q[20];
};

typedef struct _BCRYPT_ECCKEY_BLOB _BCRYPT_ECCKEY_BLOB, *P_BCRYPT_ECCKEY_BLOB;

struct _BCRYPT_ECCKEY_BLOB {
    ULONG dwMagic;
    ULONG cbKey;
};

typedef struct _BCRYPT_INTERFACE_VERSION _BCRYPT_INTERFACE_VERSION, *P_BCRYPT_INTERFACE_VERSION;

typedef ushort USHORT;

struct _BCRYPT_INTERFACE_VERSION {
    USHORT MajorVersion;
    USHORT MinorVersion;
};

typedef struct _BCRYPT_KEY_BLOB _BCRYPT_KEY_BLOB, *P_BCRYPT_KEY_BLOB;

struct _BCRYPT_KEY_BLOB {
    ULONG Magic;
};

typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER _BCRYPT_KEY_DATA_BLOB_HEADER, *P_BCRYPT_KEY_DATA_BLOB_HEADER;

struct _BCRYPT_KEY_DATA_BLOB_HEADER {
    ULONG dwMagic;
    ULONG dwVersion;
    ULONG cbKeyData;
};

typedef struct _BCRYPT_OAEP_PADDING_INFO _BCRYPT_OAEP_PADDING_INFO, *P_BCRYPT_OAEP_PADDING_INFO;

typedef WCHAR *LPCWSTR;

struct _BCRYPT_OAEP_PADDING_INFO {
    LPCWSTR pszAlgId;
    PUCHAR pbLabel;
    ULONG cbLabel;
};

typedef struct _BCRYPT_OID _BCRYPT_OID, *P_BCRYPT_OID;

struct _BCRYPT_OID {
    ULONG cbOID;
    PUCHAR pbOID;
};

typedef struct _BCRYPT_OID_LIST _BCRYPT_OID_LIST, *P_BCRYPT_OID_LIST;

typedef struct _BCRYPT_OID BCRYPT_OID;

struct _BCRYPT_OID_LIST {
    ULONG dwOIDCount;
    BCRYPT_OID *pOIDs;
};

typedef struct _BCRYPT_PKCS1_PADDING_INFO _BCRYPT_PKCS1_PADDING_INFO, *P_BCRYPT_PKCS1_PADDING_INFO;

struct _BCRYPT_PKCS1_PADDING_INFO {
    LPCWSTR pszAlgId;
};

typedef struct _BCRYPT_PROVIDER_NAME _BCRYPT_PROVIDER_NAME, *P_BCRYPT_PROVIDER_NAME;

struct _BCRYPT_PROVIDER_NAME {
    LPWSTR pszProviderName;
};

typedef struct _BCRYPT_PSS_PADDING_INFO _BCRYPT_PSS_PADDING_INFO, *P_BCRYPT_PSS_PADDING_INFO;

struct _BCRYPT_PSS_PADDING_INFO {
    LPCWSTR pszAlgId;
    ULONG cbSalt;
};

typedef struct _BCRYPT_RSAKEY_BLOB _BCRYPT_RSAKEY_BLOB, *P_BCRYPT_RSAKEY_BLOB;

struct _BCRYPT_RSAKEY_BLOB {
    ULONG Magic;
    ULONG BitLength;
    ULONG cbPublicExp;
    ULONG cbModulus;
    ULONG cbPrime1;
    ULONG cbPrime2;
};

typedef struct _BCryptBuffer _BCryptBuffer, *P_BCryptBuffer;

typedef void *PVOID;

struct _BCryptBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    PVOID pvBuffer;
};

typedef struct _BCryptBufferDesc _BCryptBufferDesc, *P_BCryptBufferDesc;

typedef struct _BCryptBuffer *PBCryptBuffer;

struct _BCryptBufferDesc {
    ULONG ulVersion;
    ULONG cBuffers;
    PBCryptBuffer pBuffers;
};

typedef struct _CRYPT_CONTEXT_CONFIG _CRYPT_CONTEXT_CONFIG, *P_CRYPT_CONTEXT_CONFIG;

struct _CRYPT_CONTEXT_CONFIG {
    ULONG dwFlags;
    ULONG dwReserved;
};

typedef struct _CRYPT_CONTEXT_FUNCTION_CONFIG _CRYPT_CONTEXT_FUNCTION_CONFIG, *P_CRYPT_CONTEXT_FUNCTION_CONFIG;

struct _CRYPT_CONTEXT_FUNCTION_CONFIG {
    ULONG dwFlags;
    ULONG dwReserved;
};

typedef struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS _CRYPT_CONTEXT_FUNCTION_PROVIDERS, *P_CRYPT_CONTEXT_FUNCTION_PROVIDERS;

typedef WCHAR *PWSTR;

struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS {
    ULONG cProviders;
    PWSTR *rgpszProviders;
};

typedef struct _CRYPT_CONTEXT_FUNCTIONS _CRYPT_CONTEXT_FUNCTIONS, *P_CRYPT_CONTEXT_FUNCTIONS;

struct _CRYPT_CONTEXT_FUNCTIONS {
    ULONG cFunctions;
    PWSTR *rgpszFunctions;
};

typedef struct _CRYPT_CONTEXTS _CRYPT_CONTEXTS, *P_CRYPT_CONTEXTS;

struct _CRYPT_CONTEXTS {
    ULONG cContexts;
    PWSTR *rgpszContexts;
};

typedef struct _CRYPT_IMAGE_REF _CRYPT_IMAGE_REF, *P_CRYPT_IMAGE_REF;

struct _CRYPT_IMAGE_REF {
    PWSTR pszImage;
    ULONG dwFlags;
};

typedef struct _CRYPT_INTERFACE_REG _CRYPT_INTERFACE_REG, *P_CRYPT_INTERFACE_REG;

struct _CRYPT_INTERFACE_REG {
    ULONG dwInterface;
    ULONG dwFlags;
    ULONG cFunctions;
    PWSTR *rgpszFunctions;
};

typedef struct _CRYPT_PROPERTY_REF _CRYPT_PROPERTY_REF, *P_CRYPT_PROPERTY_REF;

struct _CRYPT_PROPERTY_REF {
    PWSTR pszProperty;
    ULONG cbValue;
    PUCHAR pbValue;
};

typedef struct _CRYPT_PROVIDERS _CRYPT_PROVIDERS, *P_CRYPT_PROVIDERS;

struct _CRYPT_PROVIDERS {
    ULONG cProviders;
    PWSTR *rgpszProviders;
};

typedef PVOID BCRYPT_ALG_HANDLE;

typedef struct _BCRYPT_ALGORITHM_IDENTIFIER BCRYPT_ALGORITHM_IDENTIFIER;

typedef struct __BCRYPT_KEY_LENGTHS_STRUCT BCRYPT_KEY_LENGTHS_STRUCT;

typedef BCRYPT_KEY_LENGTHS_STRUCT BCRYPT_AUTH_TAG_LENGTHS_STRUCT;

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef struct _BCRYPT_DH_KEY_BLOB BCRYPT_DH_KEY_BLOB;

typedef struct _BCRYPT_DH_PARAMETER_HEADER BCRYPT_DH_PARAMETER_HEADER;

typedef struct _BCRYPT_DSA_KEY_BLOB BCRYPT_DSA_KEY_BLOB;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER BCRYPT_DSA_PARAMETER_HEADER;

typedef struct _BCRYPT_ECCKEY_BLOB BCRYPT_ECCKEY_BLOB;

typedef PVOID BCRYPT_HANDLE;

typedef PVOID BCRYPT_HASH_HANDLE;

typedef struct _BCRYPT_INTERFACE_VERSION BCRYPT_INTERFACE_VERSION;

typedef struct _BCRYPT_KEY_BLOB BCRYPT_KEY_BLOB;

typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER BCRYPT_KEY_DATA_BLOB_HEADER;

typedef PVOID BCRYPT_KEY_HANDLE;

typedef struct _BCRYPT_OAEP_PADDING_INFO BCRYPT_OAEP_PADDING_INFO;

typedef struct _BCRYPT_OID_LIST BCRYPT_OID_LIST;

typedef struct _BCRYPT_PKCS1_PADDING_INFO BCRYPT_PKCS1_PADDING_INFO;

typedef struct _BCRYPT_PROVIDER_NAME BCRYPT_PROVIDER_NAME;

typedef struct _BCRYPT_PSS_PADDING_INFO BCRYPT_PSS_PADDING_INFO;

typedef struct _BCRYPT_RSAKEY_BLOB BCRYPT_RSAKEY_BLOB;

typedef PVOID BCRYPT_SECRET_HANDLE;

typedef struct _BCryptBuffer BCryptBuffer;

typedef struct _BCryptBufferDesc BCryptBufferDesc;

typedef struct _CRYPT_CONTEXT_CONFIG CRYPT_CONTEXT_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_CONFIG CRYPT_CONTEXT_FUNCTION_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS CRYPT_CONTEXT_FUNCTION_PROVIDERS;

typedef struct _CRYPT_CONTEXT_FUNCTIONS CRYPT_CONTEXT_FUNCTIONS;

typedef struct _CRYPT_CONTEXTS CRYPT_CONTEXTS;

typedef struct _CRYPT_IMAGE_REF CRYPT_IMAGE_REF;

typedef struct _CRYPT_INTERFACE_REG CRYPT_INTERFACE_REG;

typedef struct _CRYPT_PROPERTY_REF CRYPT_PROPERTY_REF;

typedef struct _CRYPT_PROVIDERS CRYPT_PROVIDERS;

typedef long LONG;

typedef LONG NTSTATUS;

typedef NTSTATUS *PNTSTATUS;

typedef struct bde_metadata_block_header_v1 bde_metadata_block_header_v1, *Pbde_metadata_block_header_v1;

typedef uchar uint8_t;

struct bde_metadata_block_header_v1 {
    uint8_t signature[8];
    uint8_t size[2];
    uint8_t version[2];
    uint8_t unknown1[2];
    uint8_t unknown2[2];
    uint8_t unknown3[16];
    uint8_t first_metadata_offset[8];
    uint8_t second_metadata_offset[8];
    uint8_t third_metadata_offset[8];
    uint8_t mft_mirror_cluster_block[8];
};

typedef struct bde_metadata_block_header_v1 bde_metadata_block_header_v1_t;

typedef struct bde_metadata_block_header_v2 bde_metadata_block_header_v2, *Pbde_metadata_block_header_v2;

struct bde_metadata_block_header_v2 {
    uint8_t signature[8];
    uint8_t size[2];
    uint8_t version[2];
    uint8_t unknown1[2];
    uint8_t unknown2[2];
    uint8_t encrypted_volume_size[8];
    uint8_t unknown3[4];
    uint8_t number_of_volume_header_sectors[4];
    uint8_t first_metadata_offset[8];
    uint8_t second_metadata_offset[8];
    uint8_t third_metadata_offset[8];
    uint8_t volume_header_offset[8];
};

typedef struct bde_metadata_block_header_v2 bde_metadata_block_header_v2_t;

typedef struct bde_metadata_entry_aes_ccm_encrypted_key_header bde_metadata_entry_aes_ccm_encrypted_key_header, *Pbde_metadata_entry_aes_ccm_encrypted_key_header;

struct bde_metadata_entry_aes_ccm_encrypted_key_header {
    uint8_t nonce_time[8];
    uint8_t nonce_counter[4];
};

typedef struct bde_metadata_entry_aes_ccm_encrypted_key_header bde_metadata_entry_aes_ccm_encrypted_key_header_t;

typedef struct bde_metadata_entry_external_key_header bde_metadata_entry_external_key_header, *Pbde_metadata_entry_external_key_header;

struct bde_metadata_entry_external_key_header {
    uint8_t identifier[16];
    uint8_t modification_time[8];
};

typedef struct bde_metadata_entry_external_key_header bde_metadata_entry_external_key_header_t;

typedef struct bde_metadata_entry_key_header bde_metadata_entry_key_header, *Pbde_metadata_entry_key_header;

struct bde_metadata_entry_key_header {
    uint8_t encryption_method[4];
};

typedef struct bde_metadata_entry_key_header bde_metadata_entry_key_header_t;

typedef struct bde_metadata_entry_stretch_key_header bde_metadata_entry_stretch_key_header, *Pbde_metadata_entry_stretch_key_header;

struct bde_metadata_entry_stretch_key_header {
    uint8_t encryption_method[4];
    uint8_t salt[16];
};

typedef struct bde_metadata_entry_stretch_key_header bde_metadata_entry_stretch_key_header_t;

typedef struct bde_metadata_entry_v1 bde_metadata_entry_v1, *Pbde_metadata_entry_v1;

struct bde_metadata_entry_v1 {
    uint8_t size[2];
    uint8_t type[2];
    uint8_t value_type[2];
    uint8_t version[2];
};

typedef struct bde_metadata_entry_v1 bde_metadata_entry_v1_t;

typedef struct bde_metadata_entry_volume_master_key_header bde_metadata_entry_volume_master_key_header, *Pbde_metadata_entry_volume_master_key_header;

struct bde_metadata_entry_volume_master_key_header {
    uint8_t identifier[16];
    uint8_t modification_time[8];
    uint8_t unknown1[2];
    uint8_t protection_type[2];
};

typedef struct bde_metadata_entry_volume_master_key_header bde_metadata_entry_volume_master_key_header_t;

typedef struct bde_metadata_header_v1 bde_metadata_header_v1, *Pbde_metadata_header_v1;

struct bde_metadata_header_v1 {
    uint8_t metadata_size[4];
    uint8_t version[4];
    uint8_t metadata_header_size[4];
    uint8_t metadata_size_copy[4];
    uint8_t volume_identifier[16];
    uint8_t next_nonce_counter[4];
    uint8_t encryption_method[2];
    uint8_t encryption_method_copy[2];
    uint8_t creation_time[8];
};

typedef struct bde_metadata_header_v1 bde_metadata_header_v1_t;

typedef struct GuardCfgTableEntry GuardCfgTableEntry, *PGuardCfgTableEntry;

struct GuardCfgTableEntry {
    ImageBaseOffset32 Offset;
    byte Pad[1];
};

typedef struct __NCRYPT_KEY_ACCESS_POLICY_BLOB __NCRYPT_KEY_ACCESS_POLICY_BLOB, *P__NCRYPT_KEY_ACCESS_POLICY_BLOB;

struct __NCRYPT_KEY_ACCESS_POLICY_BLOB {
    DWORD dwVersion;
    DWORD dwPolicyFlags;
    DWORD cbUserSid;
    DWORD cbApplicationSid;
};

typedef struct __NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO __NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO, *P__NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO;

struct __NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO {
    DWORD dwVersion;
    INT32 iExpiration;
    BYTE pabNonce[32];
    BYTE pabPolicyRef[32];
    BYTE pabHMAC[32];
};

typedef struct __NCRYPT_PCP_RAW_POLICYDIGEST __NCRYPT_PCP_RAW_POLICYDIGEST, *P__NCRYPT_PCP_RAW_POLICYDIGEST;

struct __NCRYPT_PCP_RAW_POLICYDIGEST {
    DWORD dwVersion;
    DWORD cbDigest;
};

typedef struct __NCRYPT_PCP_TPM_FW_VERSION_INFO __NCRYPT_PCP_TPM_FW_VERSION_INFO, *P__NCRYPT_PCP_TPM_FW_VERSION_INFO;

struct __NCRYPT_PCP_TPM_FW_VERSION_INFO {
    UINT16 major1;
    UINT16 major2;
    UINT16 minor1;
    UINT16 minor2;
};

typedef struct __NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT __NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT, *P__NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT;

struct __NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT {
    UINT32 Magic;
    UINT32 Version;
    UINT32 HeaderSize;
    UINT32 cbCertifyInfo;
    UINT32 cbSignature;
    UINT32 cbTpmPublic;
};

typedef struct __NCRYPT_SUPPORTED_LENGTHS __NCRYPT_SUPPORTED_LENGTHS, *P__NCRYPT_SUPPORTED_LENGTHS;

struct __NCRYPT_SUPPORTED_LENGTHS {
    DWORD dwMinLength;
    DWORD dwMaxLength;
    DWORD dwIncrement;
    DWORD dwDefaultLength;
};

typedef struct __NCRYPT_UI_POLICY __NCRYPT_UI_POLICY, *P__NCRYPT_UI_POLICY;

struct __NCRYPT_UI_POLICY {
    DWORD dwVersion;
    DWORD dwFlags;
    LPCWSTR pszCreationTitle;
    LPCWSTR pszFriendlyName;
    LPCWSTR pszDescription;
};

typedef struct _ADA_GP_OPTIONS _ADA_GP_OPTIONS, *P_ADA_GP_OPTIONS;

typedef int BOOL;

struct _ADA_GP_OPTIONS {
    BOOL BackupEnabled;
    BOOL BackupKeyPackage;
    BOOL BackupRequired;
};

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA, *P_AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _CMSG_SIGNER_INFO _CMSG_SIGNER_INFO, *P_CMSG_SIGNER_INFO;

typedef struct _CMSG_SIGNER_INFO *PCMSG_SIGNER_INFO;

typedef struct _CRYPTOAPI_BLOB _CRYPTOAPI_BLOB, *P_CRYPTOAPI_BLOB;

typedef struct _CRYPTOAPI_BLOB CERT_NAME_BLOB;

typedef struct _CRYPTOAPI_BLOB CRYPT_INTEGER_BLOB;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER _CRYPT_ALGORITHM_IDENTIFIER, *P_CRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER CRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CRYPTOAPI_BLOB CRYPT_DATA_BLOB;

typedef struct _CRYPT_ATTRIBUTES _CRYPT_ATTRIBUTES, *P_CRYPT_ATTRIBUTES;

typedef struct _CRYPT_ATTRIBUTES CRYPT_ATTRIBUTES;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef struct _CRYPTOAPI_BLOB CRYPT_OBJID_BLOB;

typedef struct _CRYPT_ATTRIBUTE _CRYPT_ATTRIBUTE, *P_CRYPT_ATTRIBUTE;

typedef struct _CRYPT_ATTRIBUTE *PCRYPT_ATTRIBUTE;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_ATTR_BLOB;

struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
};

struct _CRYPT_ALGORITHM_IDENTIFIER {
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Parameters;
};

struct _CRYPT_ATTRIBUTES {
    DWORD cAttr;
    PCRYPT_ATTRIBUTE rgAttr;
};

struct _CMSG_SIGNER_INFO {
    DWORD dwVersion;
    CERT_NAME_BLOB Issuer;
    CRYPT_INTEGER_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedHash;
    CRYPT_ATTRIBUTES AuthAttrs;
    CRYPT_ATTRIBUTES UnauthAttrs;
};

struct _CRYPT_ATTRIBUTE {
    LPSTR pszObjId;
    DWORD cValue;
    PCRYPT_ATTR_BLOB rgValue;
};

struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    DWORD dwRegPolicySettings;
    PCMSG_SIGNER_INFO pSignerInfo;
};

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS, *P_AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS;

struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    BOOL fCommercial;
};

typedef struct _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA, *P_AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA;

struct _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    DWORD dwRegPolicySettings;
    BOOL fCommercial;
};

typedef struct _BCRYPT_DSA_KEY_BLOB_V2 _BCRYPT_DSA_KEY_BLOB_V2, *P_BCRYPT_DSA_KEY_BLOB_V2;

typedef enum enum_80 {
    DSA_HASH_ALGORITHM_SHA1=0,
    DSA_HASH_ALGORITHM_SHA256=1,
    DSA_HASH_ALGORITHM_SHA512=2
} enum_80;

typedef enum enum_80 HASHALGORITHM_ENUM;

typedef enum enum_81 {
    DSA_FIPS186_2=0,
    DSA_FIPS186_3=1
} enum_81;

typedef enum enum_81 DSAFIPSVERSION_ENUM;

struct _BCRYPT_DSA_KEY_BLOB_V2 {
    ULONG dwMagic;
    ULONG cbKey;
    HASHALGORITHM_ENUM hashAlgorithm;
    DSAFIPSVERSION_ENUM standardVersion;
    ULONG cbSeedLength;
    ULONG cbGroupSize;
    UCHAR Count[4];
};

typedef struct _BCRYPT_DSA_PARAMETER_HEADER_V2 _BCRYPT_DSA_PARAMETER_HEADER_V2, *P_BCRYPT_DSA_PARAMETER_HEADER_V2;

struct _BCRYPT_DSA_PARAMETER_HEADER_V2 {
    ULONG cbLength;
    ULONG dwMagic;
    ULONG cbKeyLength;
    HASHALGORITHM_ENUM hashAlgorithm;
    DSAFIPSVERSION_ENUM standardVersion;
    ULONG cbSeedLength;
    ULONG cbGroupSize;
    UCHAR Count[4];
};

typedef struct _BCRYPT_ECC_CURVE_NAMES _BCRYPT_ECC_CURVE_NAMES, *P_BCRYPT_ECC_CURVE_NAMES;

struct _BCRYPT_ECC_CURVE_NAMES {
    ULONG dwEccCurveNames;
    LPWSTR *pEccCurveNames;
};

typedef struct _BCRYPT_ECCFULLKEY_BLOB _BCRYPT_ECCFULLKEY_BLOB, *P_BCRYPT_ECCFULLKEY_BLOB;

typedef enum enum_74 {
    BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE=1,
    BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE=2,
    BCRYPT_ECC_PRIME_MONTGOMERY_CURVE=3
} enum_74;

typedef enum enum_74 ECC_CURVE_TYPE_ENUM;

typedef enum enum_75 {
    BCRYPT_NO_CURVE_GENERATION_ALG_ID=0
} enum_75;

typedef enum enum_75 ECC_CURVE_ALG_ID_ENUM;

struct _BCRYPT_ECCFULLKEY_BLOB {
    ULONG dwMagic;
    ULONG dwVersion;
    ECC_CURVE_TYPE_ENUM dwCurveType;
    ECC_CURVE_ALG_ID_ENUM dwCurveGenerationAlgId;
    ULONG cbFieldLength;
    ULONG cbSubgroupOrder;
    ULONG cbCofactor;
    ULONG cbSeed;
};

typedef struct _BCRYPT_MULTI_HASH_OPERATION _BCRYPT_MULTI_HASH_OPERATION, *P_BCRYPT_MULTI_HASH_OPERATION;

typedef enum enum_87 {
    BCRYPT_HASH_OPERATION_HASH_DATA=1,
    BCRYPT_HASH_OPERATION_FINISH_HASH=2
} enum_87;

typedef enum enum_87 BCRYPT_HASH_OPERATION_TYPE;

struct _BCRYPT_MULTI_HASH_OPERATION {
    ULONG iHash;
    BCRYPT_HASH_OPERATION_TYPE hashOperation;
    PUCHAR pbBuffer;
    ULONG cbBuffer;
};

typedef struct _BCRYPT_MULTI_OBJECT_LENGTH_STRUCT _BCRYPT_MULTI_OBJECT_LENGTH_STRUCT, *P_BCRYPT_MULTI_OBJECT_LENGTH_STRUCT;

struct _BCRYPT_MULTI_OBJECT_LENGTH_STRUCT {
    ULONG cbPerObject;
    ULONG cbPerElement;
};


/* WARNING! conflicting data type names: /CONFLICTS python2.h/_BCryptBufferDesc - /bcrypt.h/_BCryptBufferDesc */

typedef struct _CERT_ACCESS_DESCRIPTION _CERT_ACCESS_DESCRIPTION, *P_CERT_ACCESS_DESCRIPTION;

typedef struct _CERT_ALT_NAME_ENTRY _CERT_ALT_NAME_ENTRY, *P_CERT_ALT_NAME_ENTRY;

typedef struct _CERT_ALT_NAME_ENTRY CERT_ALT_NAME_ENTRY;

typedef union _union_171 _union_171, *P_union_171;

typedef struct _CERT_OTHER_NAME _CERT_OTHER_NAME, *P_CERT_OTHER_NAME;

typedef struct _CERT_OTHER_NAME *PCERT_OTHER_NAME;

struct _CERT_OTHER_NAME {
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Value;
};

union _union_171 {
    PCERT_OTHER_NAME pOtherName;
    LPWSTR pwszRfc822Name;
    LPWSTR pwszDNSName;
    CERT_NAME_BLOB DirectoryName;
    LPWSTR pwszURL;
    CRYPT_DATA_BLOB IPAddress;
    LPSTR pszRegisteredID;
};

struct _CERT_ALT_NAME_ENTRY {
    DWORD dwAltNameChoice;
    union _union_171 u;
};

struct _CERT_ACCESS_DESCRIPTION {
    LPSTR pszAccessMethod;
    CERT_ALT_NAME_ENTRY AccessLocation;
};

typedef struct _CERT_ALT_NAME_INFO _CERT_ALT_NAME_INFO, *P_CERT_ALT_NAME_INFO;

typedef struct _CERT_ALT_NAME_ENTRY *PCERT_ALT_NAME_ENTRY;

struct _CERT_ALT_NAME_INFO {
    DWORD cAltEntry;
    PCERT_ALT_NAME_ENTRY rgAltEntry;
};

typedef struct _CERT_AUTHORITY_INFO_ACCESS _CERT_AUTHORITY_INFO_ACCESS, *P_CERT_AUTHORITY_INFO_ACCESS;

typedef struct _CERT_ACCESS_DESCRIPTION *PCERT_ACCESS_DESCRIPTION;

struct _CERT_AUTHORITY_INFO_ACCESS {
    DWORD cAccDescr;
    PCERT_ACCESS_DESCRIPTION rgAccDescr;
};

typedef struct _CERT_AUTHORITY_KEY_ID2_INFO _CERT_AUTHORITY_KEY_ID2_INFO, *P_CERT_AUTHORITY_KEY_ID2_INFO;

typedef struct _CERT_ALT_NAME_INFO CERT_ALT_NAME_INFO;

struct _CERT_AUTHORITY_KEY_ID2_INFO {
    CRYPT_DATA_BLOB KeyId;
    CERT_ALT_NAME_INFO AuthorityCertIssuer;
    CRYPT_INTEGER_BLOB AuthorityCertSerialNumber;
};

typedef struct _CERT_AUTHORITY_KEY_ID_INFO _CERT_AUTHORITY_KEY_ID_INFO, *P_CERT_AUTHORITY_KEY_ID_INFO;

struct _CERT_AUTHORITY_KEY_ID_INFO {
    CRYPT_DATA_BLOB KeyId;
    CERT_NAME_BLOB CertIssuer;
    CRYPT_INTEGER_BLOB CertSerialNumber;
};

typedef struct _CERT_BASIC_CONSTRAINTS2_INFO _CERT_BASIC_CONSTRAINTS2_INFO, *P_CERT_BASIC_CONSTRAINTS2_INFO;

struct _CERT_BASIC_CONSTRAINTS2_INFO {
    BOOL fCA;
    BOOL fPathLenConstraint;
    DWORD dwPathLenConstraint;
};

typedef struct _CERT_BASIC_CONSTRAINTS_INFO _CERT_BASIC_CONSTRAINTS_INFO, *P_CERT_BASIC_CONSTRAINTS_INFO;

typedef struct _CRYPT_BIT_BLOB _CRYPT_BIT_BLOB, *P_CRYPT_BIT_BLOB;

typedef struct _CRYPT_BIT_BLOB CRYPT_BIT_BLOB;

struct _CRYPT_BIT_BLOB {
    DWORD cbData;
    BYTE *pbData;
    DWORD cUnusedBits;
};

struct _CERT_BASIC_CONSTRAINTS_INFO {
    CRYPT_BIT_BLOB SubjectType;
    BOOL fPathLenConstraint;
    DWORD dwPathLenConstraint;
    DWORD cSubtreesConstraint;
    CERT_NAME_BLOB *rgSubtreesConstraint;
};

typedef struct _CERT_BIOMETRIC_DATA _CERT_BIOMETRIC_DATA, *P_CERT_BIOMETRIC_DATA;

typedef union _union_244 _union_244, *P_union_244;

typedef struct _CERT_HASHED_URL _CERT_HASHED_URL, *P_CERT_HASHED_URL;

typedef struct _CERT_HASHED_URL CERT_HASHED_URL;

typedef struct _CRYPTOAPI_BLOB CRYPT_HASH_BLOB;

struct _CERT_HASHED_URL {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_HASH_BLOB Hash;
    LPWSTR pwszUrl;
};

union _union_244 {
    DWORD dwPredefined;
    LPSTR pszObjId;
};

struct _CERT_BIOMETRIC_DATA {
    DWORD dwTypeOfBiometricDataChoice;
    union _union_244 u;
    CERT_HASHED_URL HashedUrl;
};

typedef struct _CERT_BIOMETRIC_EXT_INFO _CERT_BIOMETRIC_EXT_INFO, *P_CERT_BIOMETRIC_EXT_INFO;

typedef struct _CERT_BIOMETRIC_DATA *PCERT_BIOMETRIC_DATA;

struct _CERT_BIOMETRIC_EXT_INFO {
    DWORD cBiometricData;
    PCERT_BIOMETRIC_DATA rgBiometricData;
};

typedef struct _CERT_CHAIN _CERT_CHAIN, *P_CERT_CHAIN;

typedef struct _CRYPTOAPI_BLOB *PCERT_BLOB;

typedef struct _CRYPT_KEY_PROV_INFO _CRYPT_KEY_PROV_INFO, *P_CRYPT_KEY_PROV_INFO;

typedef struct _CRYPT_KEY_PROV_INFO CRYPT_KEY_PROV_INFO;

typedef struct _CRYPT_KEY_PROV_PARAM _CRYPT_KEY_PROV_PARAM, *P_CRYPT_KEY_PROV_PARAM;

typedef struct _CRYPT_KEY_PROV_PARAM *PCRYPT_KEY_PROV_PARAM;

struct _CRYPT_KEY_PROV_INFO {
    LPWSTR pwszContainerName;
    LPWSTR pwszProvName;
    DWORD dwProvType;
    DWORD dwFlags;
    DWORD cProvParam;
    PCRYPT_KEY_PROV_PARAM rgProvParam;
    DWORD dwKeySpec;
};

struct _CERT_CHAIN {
    DWORD cCerts;
    PCERT_BLOB certs;
    CRYPT_KEY_PROV_INFO keyLocatorInfo;
};

struct _CRYPT_KEY_PROV_PARAM {
    DWORD dwParam;
    BYTE *pbData;
    DWORD cbData;
    DWORD dwFlags;
};

typedef struct _CERT_CHAIN_CONTEXT _CERT_CHAIN_CONTEXT, *P_CERT_CHAIN_CONTEXT;

typedef struct _CERT_TRUST_STATUS _CERT_TRUST_STATUS, *P_CERT_TRUST_STATUS;

typedef struct _CERT_TRUST_STATUS CERT_TRUST_STATUS;

typedef struct _CERT_SIMPLE_CHAIN _CERT_SIMPLE_CHAIN, *P_CERT_SIMPLE_CHAIN;

typedef struct _CERT_SIMPLE_CHAIN *PCERT_SIMPLE_CHAIN;

typedef struct _CERT_CHAIN_CONTEXT CERT_CHAIN_CONTEXT;

typedef CERT_CHAIN_CONTEXT *PCCERT_CHAIN_CONTEXT;


/* WARNING! conflicting data type names: /guiddef.h/GUID - /GUID */

typedef struct _CERT_CHAIN_ELEMENT _CERT_CHAIN_ELEMENT, *P_CERT_CHAIN_ELEMENT;

typedef struct _CERT_CHAIN_ELEMENT *PCERT_CHAIN_ELEMENT;

typedef struct _CERT_TRUST_LIST_INFO _CERT_TRUST_LIST_INFO, *P_CERT_TRUST_LIST_INFO;

typedef struct _CERT_TRUST_LIST_INFO *PCERT_TRUST_LIST_INFO;

typedef struct _CERT_CONTEXT _CERT_CONTEXT, *P_CERT_CONTEXT;

typedef struct _CERT_CONTEXT CERT_CONTEXT;

typedef CERT_CONTEXT *PCCERT_CONTEXT;

typedef struct _CERT_REVOCATION_INFO _CERT_REVOCATION_INFO, *P_CERT_REVOCATION_INFO;

typedef struct _CERT_REVOCATION_INFO *PCERT_REVOCATION_INFO;

typedef struct _CTL_USAGE _CTL_USAGE, *P_CTL_USAGE;

typedef struct _CTL_USAGE *PCERT_ENHKEY_USAGE;

typedef struct _CTL_ENTRY _CTL_ENTRY, *P_CTL_ENTRY;

typedef struct _CTL_ENTRY *PCTL_ENTRY;

typedef struct _CTL_CONTEXT _CTL_CONTEXT, *P_CTL_CONTEXT;

typedef struct _CTL_CONTEXT CTL_CONTEXT;

typedef CTL_CONTEXT *PCCTL_CONTEXT;

typedef struct _CERT_INFO _CERT_INFO, *P_CERT_INFO;

typedef struct _CERT_INFO *PCERT_INFO;

typedef void *HCERTSTORE;

typedef CHAR *LPCSTR;

typedef void *LPVOID;

typedef struct _CERT_REVOCATION_CRL_INFO _CERT_REVOCATION_CRL_INFO, *P_CERT_REVOCATION_CRL_INFO;

typedef struct _CERT_REVOCATION_CRL_INFO *PCERT_REVOCATION_CRL_INFO;

typedef struct _CTL_INFO _CTL_INFO, *P_CTL_INFO;

typedef struct _CTL_INFO *PCTL_INFO;

typedef void *HCRYPTMSG;

typedef struct _CERT_PUBLIC_KEY_INFO _CERT_PUBLIC_KEY_INFO, *P_CERT_PUBLIC_KEY_INFO;

typedef struct _CERT_PUBLIC_KEY_INFO CERT_PUBLIC_KEY_INFO;

typedef struct _CERT_EXTENSION _CERT_EXTENSION, *P_CERT_EXTENSION;

typedef struct _CERT_EXTENSION *PCERT_EXTENSION;

typedef struct _CRL_CONTEXT _CRL_CONTEXT, *P_CRL_CONTEXT;

typedef struct _CRL_CONTEXT CRL_CONTEXT;

typedef CRL_CONTEXT *PCCRL_CONTEXT;

typedef struct _CRL_ENTRY _CRL_ENTRY, *P_CRL_ENTRY;

typedef struct _CRL_ENTRY *PCRL_ENTRY;

typedef struct _CTL_USAGE CTL_USAGE;

typedef struct _CRL_INFO _CRL_INFO, *P_CRL_INFO;

typedef struct _CRL_INFO *PCRL_INFO;

struct _CRL_ENTRY {
    CRYPT_INTEGER_BLOB SerialNumber;
    FILETIME RevocationDate;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

struct _CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_BIT_BLOB PublicKey;
};

struct _CERT_INFO {
    DWORD dwVersion;
    CRYPT_INTEGER_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CERT_NAME_BLOB Issuer;
    FILETIME NotBefore;
    FILETIME NotAfter;
    CERT_NAME_BLOB Subject;
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
    CRYPT_BIT_BLOB IssuerUniqueId;
    CRYPT_BIT_BLOB SubjectUniqueId;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

struct _CERT_TRUST_STATUS {
    DWORD dwErrorStatus;
    DWORD dwInfoStatus;
};

struct _CERT_SIMPLE_CHAIN {
    DWORD cbSize;
    CERT_TRUST_STATUS TrustStatus;
    DWORD cElement;
    PCERT_CHAIN_ELEMENT *rgpElement;
    PCERT_TRUST_LIST_INFO pTrustListInfo;
    BOOL fHasRevocationFreshnessTime;
    DWORD dwRevocationFreshnessTime;
};

struct _CERT_REVOCATION_INFO {
    DWORD cbSize;
    DWORD dwRevocationResult;
    LPCSTR pszRevocationOid;
    LPVOID pvOidSpecificInfo;
    BOOL fHasFreshnessTime;
    DWORD dwFreshnessTime;
    PCERT_REVOCATION_CRL_INFO pCrlInfo;
};

struct _CTL_USAGE {
    DWORD cUsageIdentifier;
    LPSTR *rgpszUsageIdentifier;
};

struct _CERT_REVOCATION_CRL_INFO {
    DWORD cbSize;
    PCCRL_CONTEXT pBaseCrlContext;
    PCCRL_CONTEXT pDeltaCrlContext;
    PCRL_ENTRY pCrlEntry;
    BOOL fDeltaCrlEntry;
};

struct _CTL_CONTEXT {
    DWORD dwMsgAndCertEncodingType;
    BYTE *pbCtlEncoded;
    DWORD cbCtlEncoded;
    PCTL_INFO pCtlInfo;
    HCERTSTORE hCertStore;
    HCRYPTMSG hCryptMsg;
    BYTE *pbCtlContent;
    DWORD cbCtlContent;
};

struct _CRL_INFO {
    DWORD dwVersion;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CERT_NAME_BLOB Issuer;
    FILETIME ThisUpdate;
    FILETIME NextUpdate;
    DWORD cCRLEntry;
    PCRL_ENTRY rgCRLEntry;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

struct _CERT_CHAIN_ELEMENT {
    DWORD cbSize;
    PCCERT_CONTEXT pCertContext;
    CERT_TRUST_STATUS TrustStatus;
    PCERT_REVOCATION_INFO pRevocationInfo;
    PCERT_ENHKEY_USAGE pIssuanceUsage;
    PCERT_ENHKEY_USAGE pApplicationUsage;
    LPCWSTR pwszExtendedErrorInfo;
};

struct _CERT_CHAIN_CONTEXT {
    DWORD cbSize;
    CERT_TRUST_STATUS TrustStatus;
    DWORD cChain;
    PCERT_SIMPLE_CHAIN *rgpChain;
    DWORD cLowerQualityChainContext;
    PCCERT_CHAIN_CONTEXT *rgpLowerQualityChainContext;
    BOOL fHasRevocationFreshnessTime;
    DWORD dwRevocationFreshnessTime;
    DWORD dwCreateFlags;
    GUID ChainId;
};

struct _CERT_EXTENSION {
    LPSTR pszObjId;
    BOOL fCritical;
    CRYPT_OBJID_BLOB Value;
};

struct _CTL_ENTRY {
    CRYPT_DATA_BLOB SubjectIdentifier;
    DWORD cAttribute;
    PCRYPT_ATTRIBUTE rgAttribute;
};

struct _CERT_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCertEncoded;
    DWORD cbCertEncoded;
    PCERT_INFO pCertInfo;
    HCERTSTORE hCertStore;
};

struct _CTL_INFO {
    DWORD dwVersion;
    CTL_USAGE SubjectUsage;
    CRYPT_DATA_BLOB ListIdentifier;
    CRYPT_INTEGER_BLOB SequenceNumber;
    FILETIME ThisUpdate;
    FILETIME NextUpdate;
    CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
    DWORD cCTLEntry;
    PCTL_ENTRY rgCTLEntry;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

struct _CERT_TRUST_LIST_INFO {
    DWORD cbSize;
    PCTL_ENTRY pCtlEntry;
    PCCTL_CONTEXT pCtlContext;
};

struct _CRL_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCrlEncoded;
    DWORD cbCrlEncoded;
    PCRL_INFO pCrlInfo;
    HCERTSTORE hCertStore;
};

typedef struct _CERT_CHAIN_ENGINE_CONFIG _CERT_CHAIN_ENGINE_CONFIG, *P_CERT_CHAIN_ENGINE_CONFIG;

struct _CERT_CHAIN_ENGINE_CONFIG {
    DWORD cbSize;
    HCERTSTORE hRestrictedRoot;
    HCERTSTORE hRestrictedTrust;
    HCERTSTORE hRestrictedOther;
    DWORD cAdditionalStore;
    HCERTSTORE *rghAdditionalStore;
    DWORD dwFlags;
    DWORD dwUrlRetrievalTimeout;
    DWORD MaximumCachedCertificates;
    DWORD CycleDetectionModulus;
    HCERTSTORE hExclusiveRoot;
    HCERTSTORE hExclusiveTrustedPeople;
    DWORD dwExclusiveFlags;
};

typedef struct _CERT_CHAIN_FIND_BY_ISSUER_PARA _CERT_CHAIN_FIND_BY_ISSUER_PARA, *P_CERT_CHAIN_FIND_BY_ISSUER_PARA;

typedef BOOL (*PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK)(PCCERT_CONTEXT, void *);

struct _CERT_CHAIN_FIND_BY_ISSUER_PARA {
    DWORD cbSize;
    LPCSTR pszUsageIdentifier;
    DWORD dwKeySpec;
    DWORD dwAcquirePrivateKeyFlags;
    DWORD cIssuer;
    CERT_NAME_BLOB *rgIssuer;
    PFN_CERT_CHAIN_FIND_BY_ISSUER_CALLBACK pfnFindCallback;
    void *pvFindArg;
};

typedef struct _CERT_CHAIN_PARA _CERT_CHAIN_PARA, *P_CERT_CHAIN_PARA;

typedef struct _CERT_USAGE_MATCH _CERT_USAGE_MATCH, *P_CERT_USAGE_MATCH;

typedef struct _CERT_USAGE_MATCH CERT_USAGE_MATCH;

typedef struct _CTL_USAGE CERT_ENHKEY_USAGE;

struct _CERT_USAGE_MATCH {
    DWORD dwType;
    CERT_ENHKEY_USAGE Usage;
};

struct _CERT_CHAIN_PARA {
    DWORD cbSize;
    CERT_USAGE_MATCH RequestedUsage;
};

typedef struct _CERT_CHAIN_POLICY_PARA _CERT_CHAIN_POLICY_PARA, *P_CERT_CHAIN_POLICY_PARA;

struct _CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    DWORD dwFlags;
    void *pvExtraPolicyPara;
};

typedef struct _CERT_CHAIN_POLICY_STATUS _CERT_CHAIN_POLICY_STATUS, *P_CERT_CHAIN_POLICY_STATUS;

struct _CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    void *pvExtraPolicyStatus;
};

typedef struct _CERT_CREATE_CONTEXT_PARA _CERT_CREATE_CONTEXT_PARA, *P_CERT_CREATE_CONTEXT_PARA;

typedef void (*PFN_CRYPT_FREE)(LPVOID);

typedef BOOL (*PFN_CERT_CREATE_CONTEXT_SORT_FUNC)(DWORD, DWORD, DWORD, void *);

struct _CERT_CREATE_CONTEXT_PARA {
    DWORD cbSize;
    PFN_CRYPT_FREE pfnFree;
    void *pvFree;
    PFN_CERT_CREATE_CONTEXT_SORT_FUNC pfnSort;
    void *pvSort;
};

typedef struct _CERT_CRL_CONTEXT_PAIR _CERT_CRL_CONTEXT_PAIR, *P_CERT_CRL_CONTEXT_PAIR;

struct _CERT_CRL_CONTEXT_PAIR {
    PCCERT_CONTEXT pCertContext;
    PCCRL_CONTEXT pCrlContext;
};

typedef struct _CERT_DH_PARAMETERS _CERT_DH_PARAMETERS, *P_CERT_DH_PARAMETERS;

typedef struct _CRYPTOAPI_BLOB CRYPT_UINT_BLOB;

struct _CERT_DH_PARAMETERS {
    CRYPT_UINT_BLOB p;
    CRYPT_UINT_BLOB g;
};

typedef struct _CERT_DSS_PARAMETERS _CERT_DSS_PARAMETERS, *P_CERT_DSS_PARAMETERS;

struct _CERT_DSS_PARAMETERS {
    CRYPT_UINT_BLOB p;
    CRYPT_UINT_BLOB q;
    CRYPT_UINT_BLOB g;
};

typedef struct _CERT_ECC_SIGNATURE _CERT_ECC_SIGNATURE, *P_CERT_ECC_SIGNATURE;

struct _CERT_ECC_SIGNATURE {
    CRYPT_UINT_BLOB r;
    CRYPT_UINT_BLOB s;
};

typedef struct _CERT_EXTENSIONS _CERT_EXTENSIONS, *P_CERT_EXTENSIONS;

struct _CERT_EXTENSIONS {
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _CERT_FORTEZZA_DATA_PROP _CERT_FORTEZZA_DATA_PROP, *P_CERT_FORTEZZA_DATA_PROP;

struct _CERT_FORTEZZA_DATA_PROP {
    uchar SerialNumber[8];
    int CertIndex;
    uchar CertLabel[36];
};

typedef struct _CERT_GENERAL_SUBTREE _CERT_GENERAL_SUBTREE, *P_CERT_GENERAL_SUBTREE;

struct _CERT_GENERAL_SUBTREE {
    CERT_ALT_NAME_ENTRY Base;
    DWORD dwMinimum;
    BOOL fMaximum;
    DWORD dwMaximum;
};

typedef struct _CERT_ID _CERT_ID, *P_CERT_ID;

typedef union _union_268 _union_268, *P_union_268;

typedef struct _CERT_ISSUER_SERIAL_NUMBER _CERT_ISSUER_SERIAL_NUMBER, *P_CERT_ISSUER_SERIAL_NUMBER;

typedef struct _CERT_ISSUER_SERIAL_NUMBER CERT_ISSUER_SERIAL_NUMBER;

struct _CERT_ISSUER_SERIAL_NUMBER {
    CERT_NAME_BLOB Issuer;
    CRYPT_INTEGER_BLOB SerialNumber;
};

union _union_268 {
    CERT_ISSUER_SERIAL_NUMBER IssuerSerialNumber;
    CRYPT_HASH_BLOB KeyId;
    CRYPT_HASH_BLOB HashId;
};

struct _CERT_ID {
    DWORD dwIdChoice;
    union _union_268 u;
};

typedef struct _CERT_KEY_ATTRIBUTES_INFO _CERT_KEY_ATTRIBUTES_INFO, *P_CERT_KEY_ATTRIBUTES_INFO;

typedef struct _CERT_PRIVATE_KEY_VALIDITY _CERT_PRIVATE_KEY_VALIDITY, *P_CERT_PRIVATE_KEY_VALIDITY;

typedef struct _CERT_PRIVATE_KEY_VALIDITY *PCERT_PRIVATE_KEY_VALIDITY;

struct _CERT_PRIVATE_KEY_VALIDITY {
    FILETIME NotBefore;
    FILETIME NotAfter;
};

struct _CERT_KEY_ATTRIBUTES_INFO {
    CRYPT_DATA_BLOB KeyId;
    CRYPT_BIT_BLOB IntendedKeyUsage;
    PCERT_PRIVATE_KEY_VALIDITY pPrivateKeyUsagePeriod;
};

typedef struct _CERT_KEY_CONTEXT _CERT_KEY_CONTEXT, *P_CERT_KEY_CONTEXT;

typedef union _union_323 _union_323, *P_union_323;

typedef ULONG_PTR HCRYPTPROV;

typedef ULONG_PTR NCRYPT_KEY_HANDLE;

union _union_323 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

struct _CERT_KEY_CONTEXT {
    DWORD cbSize;
    union _union_323 u;
    DWORD dwKeySpec;
};

typedef struct _CERT_KEY_USAGE_RESTRICTION_INFO _CERT_KEY_USAGE_RESTRICTION_INFO, *P_CERT_KEY_USAGE_RESTRICTION_INFO;

typedef struct _CERT_POLICY_ID _CERT_POLICY_ID, *P_CERT_POLICY_ID;

typedef struct _CERT_POLICY_ID *PCERT_POLICY_ID;

struct _CERT_KEY_USAGE_RESTRICTION_INFO {
    DWORD cCertPolicyId;
    PCERT_POLICY_ID rgCertPolicyId;
    CRYPT_BIT_BLOB RestrictedKeyUsage;
};

struct _CERT_POLICY_ID {
    DWORD cCertPolicyElementId;
    LPSTR *rgpszCertPolicyElementId;
};

typedef struct _CERT_KEYGEN_REQUEST_INFO _CERT_KEYGEN_REQUEST_INFO, *P_CERT_KEYGEN_REQUEST_INFO;

struct _CERT_KEYGEN_REQUEST_INFO {
    DWORD dwVersion;
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
    LPWSTR pwszChallengeString;
};

typedef struct _CERT_LDAP_STORE_OPENED_PARA _CERT_LDAP_STORE_OPENED_PARA, *P_CERT_LDAP_STORE_OPENED_PARA;

struct _CERT_LDAP_STORE_OPENED_PARA {
    void *pvLdapSessionHandle;
    LPCWSTR pwszLdapUrl;
};

typedef struct _CERT_LOGOTYPE_AUDIO _CERT_LOGOTYPE_AUDIO, *P_CERT_LOGOTYPE_AUDIO;

typedef struct _CERT_LOGOTYPE_DETAILS _CERT_LOGOTYPE_DETAILS, *P_CERT_LOGOTYPE_DETAILS;

typedef struct _CERT_LOGOTYPE_DETAILS CERT_LOGOTYPE_DETAILS;

typedef struct _CERT_LOGOTYPE_AUDIO_INFO _CERT_LOGOTYPE_AUDIO_INFO, *P_CERT_LOGOTYPE_AUDIO_INFO;

typedef struct _CERT_LOGOTYPE_AUDIO_INFO *PCERT_LOGOTYPE_AUDIO_INFO;

typedef struct _CERT_HASHED_URL *PCERT_HASHED_URL;

struct _CERT_LOGOTYPE_DETAILS {
    LPWSTR pwszMimeType;
    DWORD cHashedUrl;
    PCERT_HASHED_URL rgHashedUrl;
};

struct _CERT_LOGOTYPE_AUDIO {
    CERT_LOGOTYPE_DETAILS LogotypeDetails;
    PCERT_LOGOTYPE_AUDIO_INFO pLogotypeAudioInfo;
};

struct _CERT_LOGOTYPE_AUDIO_INFO {
    DWORD dwFileSize;
    DWORD dwPlayTime;
    DWORD dwChannels;
    DWORD dwSampleRate;
    LPWSTR pwszLanguage;
};

typedef struct _CERT_LOGOTYPE_DATA _CERT_LOGOTYPE_DATA, *P_CERT_LOGOTYPE_DATA;

typedef struct _CERT_LOGOTYPE_IMAGE _CERT_LOGOTYPE_IMAGE, *P_CERT_LOGOTYPE_IMAGE;

typedef struct _CERT_LOGOTYPE_IMAGE *PCERT_LOGOTYPE_IMAGE;

typedef struct _CERT_LOGOTYPE_AUDIO *PCERT_LOGOTYPE_AUDIO;

typedef struct _CERT_LOGOTYPE_IMAGE_INFO _CERT_LOGOTYPE_IMAGE_INFO, *P_CERT_LOGOTYPE_IMAGE_INFO;

typedef struct _CERT_LOGOTYPE_IMAGE_INFO *PCERT_LOGOTYPE_IMAGE_INFO;

typedef union _union_234 _union_234, *P_union_234;

struct _CERT_LOGOTYPE_IMAGE {
    CERT_LOGOTYPE_DETAILS LogotypeDetails;
    PCERT_LOGOTYPE_IMAGE_INFO pLogotypeImageInfo;
};

union _union_234 {
    DWORD dwNumBits;
    DWORD dwTableSize;
};

struct _CERT_LOGOTYPE_IMAGE_INFO {
    DWORD dwLogotypeImageInfoChoice;
    DWORD dwFileSize;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwLogotypeImageResolutionChoice;
    union _union_234 u;
    LPWSTR pwszLanguage;
};

struct _CERT_LOGOTYPE_DATA {
    DWORD cLogotypeImage;
    PCERT_LOGOTYPE_IMAGE rgLogotypeImage;
    DWORD cLogotypeAudio;
    PCERT_LOGOTYPE_AUDIO rgLogotypeAudio;
};

typedef struct _CERT_LOGOTYPE_EXT_INFO _CERT_LOGOTYPE_EXT_INFO, *P_CERT_LOGOTYPE_EXT_INFO;

typedef struct _CERT_LOGOTYPE_INFO _CERT_LOGOTYPE_INFO, *P_CERT_LOGOTYPE_INFO;

typedef struct _CERT_LOGOTYPE_INFO *PCERT_LOGOTYPE_INFO;

typedef struct _CERT_OTHER_LOGOTYPE_INFO _CERT_OTHER_LOGOTYPE_INFO, *P_CERT_OTHER_LOGOTYPE_INFO;

typedef struct _CERT_OTHER_LOGOTYPE_INFO *PCERT_OTHER_LOGOTYPE_INFO;

typedef union _union_240 _union_240, *P_union_240;

typedef struct _CERT_LOGOTYPE_INFO CERT_LOGOTYPE_INFO;

typedef struct _CERT_LOGOTYPE_DATA *PCERT_LOGOTYPE_DATA;

typedef struct _CERT_LOGOTYPE_REFERENCE _CERT_LOGOTYPE_REFERENCE, *P_CERT_LOGOTYPE_REFERENCE;

typedef struct _CERT_LOGOTYPE_REFERENCE *PCERT_LOGOTYPE_REFERENCE;

union _union_240 {
    PCERT_LOGOTYPE_DATA pLogotypeDirectInfo;
    PCERT_LOGOTYPE_REFERENCE pLogotypeIndirectInfo;
};

struct _CERT_LOGOTYPE_REFERENCE {
    DWORD cHashedUrl;
    PCERT_HASHED_URL rgHashedUrl;
};

struct _CERT_LOGOTYPE_EXT_INFO {
    DWORD cCommunityLogo;
    PCERT_LOGOTYPE_INFO rgCommunityLogo;
    PCERT_LOGOTYPE_INFO pIssuerLogo;
    PCERT_LOGOTYPE_INFO pSubjectLogo;
    DWORD cOtherLogo;
    PCERT_OTHER_LOGOTYPE_INFO rgOtherLogo;
};

struct _CERT_LOGOTYPE_INFO {
    DWORD dwLogotypeInfoChoice;
    union _union_240 u;
};

struct _CERT_OTHER_LOGOTYPE_INFO {
    LPSTR pszObjId;
    CERT_LOGOTYPE_INFO LogotypeInfo;
};

typedef struct _CERT_NAME_CONSTRAINTS_INFO _CERT_NAME_CONSTRAINTS_INFO, *P_CERT_NAME_CONSTRAINTS_INFO;

typedef struct _CERT_GENERAL_SUBTREE *PCERT_GENERAL_SUBTREE;

struct _CERT_NAME_CONSTRAINTS_INFO {
    DWORD cPermittedSubtree;
    PCERT_GENERAL_SUBTREE rgPermittedSubtree;
    DWORD cExcludedSubtree;
    PCERT_GENERAL_SUBTREE rgExcludedSubtree;
};

typedef struct _CERT_NAME_INFO _CERT_NAME_INFO, *P_CERT_NAME_INFO;

typedef struct _CERT_RDN _CERT_RDN, *P_CERT_RDN;

typedef struct _CERT_RDN *PCERT_RDN;

typedef struct _CERT_RDN_ATTR _CERT_RDN_ATTR, *P_CERT_RDN_ATTR;

typedef struct _CERT_RDN_ATTR *PCERT_RDN_ATTR;

typedef struct _CRYPTOAPI_BLOB CERT_RDN_VALUE_BLOB;

struct _CERT_RDN_ATTR {
    LPSTR pszObjId;
    DWORD dwValueType;
    CERT_RDN_VALUE_BLOB Value;
};

struct _CERT_NAME_INFO {
    DWORD cRDN;
    PCERT_RDN rgRDN;
};

struct _CERT_RDN {
    DWORD cRDNAttr;
    PCERT_RDN_ATTR rgRDNAttr;
};

typedef struct _CERT_NAME_VALUE _CERT_NAME_VALUE, *P_CERT_NAME_VALUE;

struct _CERT_NAME_VALUE {
    DWORD dwValueType;
    CERT_RDN_VALUE_BLOB Value;
};

typedef struct _CERT_OR_CRL_BLOB _CERT_OR_CRL_BLOB, *P_CERT_OR_CRL_BLOB;

struct _CERT_OR_CRL_BLOB {
    DWORD dwChoice;
    DWORD cbEncoded;
    BYTE *pbEncoded;
};

typedef struct _CERT_OR_CRL_BUNDLE _CERT_OR_CRL_BUNDLE, *P_CERT_OR_CRL_BUNDLE;

typedef struct _CERT_OR_CRL_BLOB *PCERT_OR_CRL_BLOB;

struct _CERT_OR_CRL_BUNDLE {
    DWORD cItem;
    PCERT_OR_CRL_BLOB rgItem;
};

typedef struct _CERT_PAIR _CERT_PAIR, *P_CERT_PAIR;

typedef struct _CRYPTOAPI_BLOB CERT_BLOB;

struct _CERT_PAIR {
    CERT_BLOB Forward;
    CERT_BLOB Reverse;
};

typedef struct _CERT_PHYSICAL_STORE_INFO _CERT_PHYSICAL_STORE_INFO, *P_CERT_PHYSICAL_STORE_INFO;

struct _CERT_PHYSICAL_STORE_INFO {
    DWORD cbSize;
    LPSTR pszOpenStoreProvider;
    DWORD dwOpenEncodingType;
    DWORD dwOpenFlags;
    CRYPT_DATA_BLOB OpenParameters;
    DWORD dwFlags;
    DWORD dwPriority;
};

typedef struct _CERT_POLICIES_INFO _CERT_POLICIES_INFO, *P_CERT_POLICIES_INFO;

typedef struct _CERT_POLICY_INFO _CERT_POLICY_INFO, *P_CERT_POLICY_INFO;

typedef struct _CERT_POLICY_INFO CERT_POLICY_INFO;

typedef struct _CERT_POLICY_QUALIFIER_INFO _CERT_POLICY_QUALIFIER_INFO, *P_CERT_POLICY_QUALIFIER_INFO;

typedef struct _CERT_POLICY_QUALIFIER_INFO CERT_POLICY_QUALIFIER_INFO;

struct _CERT_POLICY_INFO {
    LPSTR pszPolicyIdentifier;
    DWORD cPolicyQualifier;
    CERT_POLICY_QUALIFIER_INFO *rgPolicyQualifier;
};

struct _CERT_POLICIES_INFO {
    DWORD cPolicyInfo;
    CERT_POLICY_INFO *rgPolicyInfo;
};

struct _CERT_POLICY_QUALIFIER_INFO {
    LPSTR pszPolicyQualifierId;
    CRYPT_OBJID_BLOB Qualifier;
};

typedef struct _CERT_POLICY95_QUALIFIER1 _CERT_POLICY95_QUALIFIER1, *P_CERT_POLICY95_QUALIFIER1;

typedef struct _CPS_URLS _CPS_URLS, *P_CPS_URLS;

typedef struct _CPS_URLS CPS_URLS;

struct _CERT_POLICY95_QUALIFIER1 {
    LPWSTR pszPracticesReference;
    LPSTR pszNoticeIdentifier;
    LPSTR pszNSINoticeIdentifier;
    DWORD cCPSURLs;
    CPS_URLS *rgCPSURLs;
};

struct _CPS_URLS {
    LPWSTR pszURL;
    CRYPT_ALGORITHM_IDENTIFIER *pAlgorithm;
    CRYPT_DATA_BLOB *pDigest;
};

typedef struct _CERT_POLICY_CONSTRAINTS_INFO _CERT_POLICY_CONSTRAINTS_INFO, *P_CERT_POLICY_CONSTRAINTS_INFO;

struct _CERT_POLICY_CONSTRAINTS_INFO {
    BOOL fRequireExplicitPolicy;
    DWORD dwRequireExplicitPolicySkipCerts;
    BOOL fInhibitPolicyMapping;
    DWORD dwInhibitPolicyMappingSkipCerts;
};

typedef struct _CERT_POLICY_MAPPING _CERT_POLICY_MAPPING, *P_CERT_POLICY_MAPPING;

struct _CERT_POLICY_MAPPING {
    LPSTR pszIssuerDomainPolicy;
    LPSTR pszSubjectDomainPolicy;
};

typedef struct _CERT_POLICY_MAPPINGS_INFO _CERT_POLICY_MAPPINGS_INFO, *P_CERT_POLICY_MAPPINGS_INFO;

typedef struct _CERT_POLICY_MAPPING *PCERT_POLICY_MAPPING;

struct _CERT_POLICY_MAPPINGS_INFO {
    DWORD cPolicyMapping;
    PCERT_POLICY_MAPPING rgPolicyMapping;
};

typedef struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE, *P_CERT_POLICY_QUALIFIER_NOTICE_REFERENCE;

struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE {
    LPSTR pszOrganization;
    DWORD cNoticeNumbers;
    int *rgNoticeNumbers;
};

typedef struct _CERT_POLICY_QUALIFIER_USER_NOTICE _CERT_POLICY_QUALIFIER_USER_NOTICE, *P_CERT_POLICY_QUALIFIER_USER_NOTICE;

typedef struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE CERT_POLICY_QUALIFIER_NOTICE_REFERENCE;

struct _CERT_POLICY_QUALIFIER_USER_NOTICE {
    CERT_POLICY_QUALIFIER_NOTICE_REFERENCE *pNoticeReference;
    LPWSTR pszDisplayText;
};

typedef struct _CERT_QC_STATEMENT _CERT_QC_STATEMENT, *P_CERT_QC_STATEMENT;

struct _CERT_QC_STATEMENT {
    LPSTR pszStatementId;
    CRYPT_OBJID_BLOB StatementInfo;
};

typedef struct _CERT_QC_STATEMENTS_EXT_INFO _CERT_QC_STATEMENTS_EXT_INFO, *P_CERT_QC_STATEMENTS_EXT_INFO;

typedef struct _CERT_QC_STATEMENT *PCERT_QC_STATEMENT;

struct _CERT_QC_STATEMENTS_EXT_INFO {
    DWORD cStatement;
    PCERT_QC_STATEMENT rgStatement;
};

typedef struct _CERT_REGISTRY_STORE_CLIENT_GPT_PARA _CERT_REGISTRY_STORE_CLIENT_GPT_PARA, *P_CERT_REGISTRY_STORE_CLIENT_GPT_PARA;

typedef struct HKEY__ HKEY__, *PHKEY__;

typedef struct HKEY__ *HKEY;

struct _CERT_REGISTRY_STORE_CLIENT_GPT_PARA {
    HKEY hKeyBase;
    LPWSTR pwszRegPath;
};

struct HKEY__ {
    int unused;
};

typedef struct _CERT_REGISTRY_STORE_ROAMING_PARA _CERT_REGISTRY_STORE_ROAMING_PARA, *P_CERT_REGISTRY_STORE_ROAMING_PARA;

struct _CERT_REGISTRY_STORE_ROAMING_PARA {
    HKEY hKey;
    LPWSTR pwszStoreDirectory;
};

typedef struct _CERT_REQUEST_INFO _CERT_REQUEST_INFO, *P_CERT_REQUEST_INFO;

struct _CERT_REQUEST_INFO {
    DWORD dwVersion;
    CERT_NAME_BLOB Subject;
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
    DWORD cAttribute;
    PCRYPT_ATTRIBUTE rgAttribute;
};

typedef struct _CERT_REVOCATION_CHAIN_PARA _CERT_REVOCATION_CHAIN_PARA, *P_CERT_REVOCATION_CHAIN_PARA;

typedef void *HANDLE;

typedef HANDLE HCERTCHAINENGINE;

typedef struct _FILETIME *LPFILETIME;

struct _CERT_REVOCATION_CHAIN_PARA {
    DWORD cbSize;
    HCERTCHAINENGINE hChainEngine;
    HCERTSTORE hAdditionalStore;
    DWORD dwChainFlags;
    DWORD dwUrlRetrievalTimeout;
    LPFILETIME pftCurrentTime;
    LPFILETIME pftCacheResync;
    DWORD cbMaxUrlRetrievalByteCount;
};

typedef struct _CERT_REVOCATION_PARA _CERT_REVOCATION_PARA, *P_CERT_REVOCATION_PARA;

struct _CERT_REVOCATION_PARA {
    DWORD cbSize;
    PCCERT_CONTEXT pIssuerCert;
    DWORD cCertStore;
    HCERTSTORE *rgCertStore;
    HCERTSTORE hCrlStore;
    LPFILETIME pftTimeToUse;
};

typedef struct _CERT_REVOCATION_STATUS _CERT_REVOCATION_STATUS, *P_CERT_REVOCATION_STATUS;

struct _CERT_REVOCATION_STATUS {
    DWORD cbSize;
    DWORD dwIndex;
    DWORD dwError;
    DWORD dwReason;
    BOOL fHasFreshnessTime;
    DWORD dwFreshnessTime;
};

typedef struct _CERT_SELECT_CHAIN_PARA _CERT_SELECT_CHAIN_PARA, *P_CERT_SELECT_CHAIN_PARA;

typedef struct _FILETIME *PFILETIME;

typedef struct _CERT_CHAIN_PARA *PCERT_CHAIN_PARA;

struct _CERT_SELECT_CHAIN_PARA {
    HCERTCHAINENGINE hChainEngine;
    PFILETIME pTime;
    HCERTSTORE hAdditionalStore;
    PCERT_CHAIN_PARA pChainPara;
    DWORD dwFlags;
};

typedef struct _CERT_SELECT_CRITERIA _CERT_SELECT_CRITERIA, *P_CERT_SELECT_CRITERIA;

struct _CERT_SELECT_CRITERIA {
    DWORD dwType;
    DWORD cPara;
    void **ppPara;
};

typedef struct _CERT_SERVER_OCSP_RESPONSE_CONTEXT _CERT_SERVER_OCSP_RESPONSE_CONTEXT, *P_CERT_SERVER_OCSP_RESPONSE_CONTEXT;

struct _CERT_SERVER_OCSP_RESPONSE_CONTEXT {
    DWORD cbSize;
    BYTE *pbEncodedOcspResponse;
    DWORD cbEncodedOcspResponse;
};

typedef struct _CERT_SERVER_OCSP_RESPONSE_OPEN_PARA _CERT_SERVER_OCSP_RESPONSE_OPEN_PARA, *P_CERT_SERVER_OCSP_RESPONSE_OPEN_PARA;

typedef struct _CERT_SERVER_OCSP_RESPONSE_CONTEXT CERT_SERVER_OCSP_RESPONSE_CONTEXT;

typedef CERT_SERVER_OCSP_RESPONSE_CONTEXT *PCCERT_SERVER_OCSP_RESPONSE_CONTEXT;

typedef void (*PFN_CERT_SERVER_OCSP_RESPONSE_UPDATE_CALLBACK)(PCCERT_CHAIN_CONTEXT, PCCERT_SERVER_OCSP_RESPONSE_CONTEXT, PCCRL_CONTEXT, PCCRL_CONTEXT, PVOID, DWORD);

struct _CERT_SERVER_OCSP_RESPONSE_OPEN_PARA {
    DWORD cbSize;
    DWORD dwFlags;
    DWORD *pcbUsedSize;
    PWSTR pwszOcspDirectory;
    PFN_CERT_SERVER_OCSP_RESPONSE_UPDATE_CALLBACK pfnUpdateCallback;
    PVOID pvUpdateCallbackArg;
};

typedef struct _CERT_SIGNED_CONTENT_INFO _CERT_SIGNED_CONTENT_INFO, *P_CERT_SIGNED_CONTENT_INFO;

typedef struct _CRYPTOAPI_BLOB CRYPT_DER_BLOB;

struct _CERT_SIGNED_CONTENT_INFO {
    CRYPT_DER_BLOB ToBeSigned;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CRYPT_BIT_BLOB Signature;
};

typedef struct _CERT_STORE_PROV_FIND_INFO _CERT_STORE_PROV_FIND_INFO, *P_CERT_STORE_PROV_FIND_INFO;

struct _CERT_STORE_PROV_FIND_INFO {
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    DWORD dwFindFlags;
    DWORD dwFindType;
    void *pvFindPara;
};

typedef struct _CERT_STORE_PROV_INFO _CERT_STORE_PROV_INFO, *P_CERT_STORE_PROV_INFO;

typedef void *HCERTSTOREPROV;

typedef void *HCRYPTOIDFUNCADDR;

struct _CERT_STORE_PROV_INFO {
    DWORD cbSize;
    DWORD cStoreProvFunc;
    void **rgpvStoreProvFunc;
    HCERTSTOREPROV hStoreProv;
    DWORD dwStoreProvFlags;
    HCRYPTOIDFUNCADDR hStoreProvFuncAddr2;
};

typedef struct _CERT_STRONG_SIGN_PARA _CERT_STRONG_SIGN_PARA, *P_CERT_STRONG_SIGN_PARA;

typedef union _union_265 _union_265, *P_union_265;

typedef struct _CERT_STRONG_SIGN_SERIALIZED_INFO _CERT_STRONG_SIGN_SERIALIZED_INFO, *P_CERT_STRONG_SIGN_SERIALIZED_INFO;

typedef struct _CERT_STRONG_SIGN_SERIALIZED_INFO *PCERT_STRONG_SIGN_SERIALIZED_INFO;

struct _CERT_STRONG_SIGN_SERIALIZED_INFO {
    DWORD dwFlags;
    LPWSTR pwszCNGSignHashAlgids;
    LPWSTR pwszCNGPubKeyMinBitLengths;
};

union _union_265 {
    void *pvInfo;
    PCERT_STRONG_SIGN_SERIALIZED_INFO pSerializedInfo;
    LPSTR pszOID;
};

struct _CERT_STRONG_SIGN_PARA {
    DWORD cbSize;
    DWORD dwInfoChoice;
    union _union_265 u;
};

typedef struct _CERT_SUPPORTED_ALGORITHM_INFO _CERT_SUPPORTED_ALGORITHM_INFO, *P_CERT_SUPPORTED_ALGORITHM_INFO;

typedef struct _CERT_POLICIES_INFO CERT_POLICIES_INFO;

struct _CERT_SUPPORTED_ALGORITHM_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_BIT_BLOB IntendedKeyUsage;
    CERT_POLICIES_INFO IntendedCertPolicies;
};

typedef struct _CERT_SYSTEM_STORE_INFO _CERT_SYSTEM_STORE_INFO, *P_CERT_SYSTEM_STORE_INFO;

struct _CERT_SYSTEM_STORE_INFO {
    DWORD cbSize;
};

typedef struct _CERT_SYSTEM_STORE_RELOCATE_PARA _CERT_SYSTEM_STORE_RELOCATE_PARA, *P_CERT_SYSTEM_STORE_RELOCATE_PARA;

typedef union _union_327 _union_327, *P_union_327;

typedef union _union_328 _union_328, *P_union_328;

union _union_328 {
    void *pvSystemStore;
    LPCSTR pszSystemStore;
    LPCWSTR pwszSystemStore;
};

union _union_327 {
    HKEY hKeyBase;
    void *pvBase;
};

struct _CERT_SYSTEM_STORE_RELOCATE_PARA {
    union _union_327 u;
    union _union_328 u2;
};

typedef struct _CERT_TEMPLATE_EXT _CERT_TEMPLATE_EXT, *P_CERT_TEMPLATE_EXT;

struct _CERT_TEMPLATE_EXT {
    LPSTR pszObjId;
    DWORD dwMajorVersion;
    BOOL fMinorVersion;
    DWORD dwMinorVersion;
};

typedef struct _CERT_TPM_SPECIFICATION_INFO _CERT_TPM_SPECIFICATION_INFO, *P_CERT_TPM_SPECIFICATION_INFO;

struct _CERT_TPM_SPECIFICATION_INFO {
    LPWSTR pwszFamily;
    DWORD dwLevel;
    DWORD dwRevision;
};

typedef struct _CERT_X942_DH_PARAMETERS _CERT_X942_DH_PARAMETERS, *P_CERT_X942_DH_PARAMETERS;

typedef struct _CERT_X942_DH_VALIDATION_PARAMS _CERT_X942_DH_VALIDATION_PARAMS, *P_CERT_X942_DH_VALIDATION_PARAMS;

typedef struct _CERT_X942_DH_VALIDATION_PARAMS *PCERT_X942_DH_VALIDATION_PARAMS;

struct _CERT_X942_DH_PARAMETERS {
    CRYPT_UINT_BLOB p;
    CRYPT_UINT_BLOB g;
    CRYPT_UINT_BLOB q;
    CRYPT_UINT_BLOB j;
    PCERT_X942_DH_VALIDATION_PARAMS pValidationParams;
};

struct _CERT_X942_DH_VALIDATION_PARAMS {
    CRYPT_BIT_BLOB seed;
    DWORD pgenCounter;
};

typedef struct _CMC_ADD_ATTRIBUTES_INFO _CMC_ADD_ATTRIBUTES_INFO, *P_CMC_ADD_ATTRIBUTES_INFO;

struct _CMC_ADD_ATTRIBUTES_INFO {
    DWORD dwCmcDataReference;
    DWORD cCertReference;
    DWORD *rgdwCertReference;
    DWORD cAttribute;
    PCRYPT_ATTRIBUTE rgAttribute;
};

typedef struct _CMC_ADD_EXTENSIONS_INFO _CMC_ADD_EXTENSIONS_INFO, *P_CMC_ADD_EXTENSIONS_INFO;

struct _CMC_ADD_EXTENSIONS_INFO {
    DWORD dwCmcDataReference;
    DWORD cCertReference;
    DWORD *rgdwCertReference;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _CMC_DATA_INFO _CMC_DATA_INFO, *P_CMC_DATA_INFO;

typedef struct _CMC_TAGGED_ATTRIBUTE _CMC_TAGGED_ATTRIBUTE, *P_CMC_TAGGED_ATTRIBUTE;

typedef struct _CMC_TAGGED_ATTRIBUTE *PCMC_TAGGED_ATTRIBUTE;

typedef struct _CMC_TAGGED_REQUEST _CMC_TAGGED_REQUEST, *P_CMC_TAGGED_REQUEST;

typedef struct _CMC_TAGGED_REQUEST *PCMC_TAGGED_REQUEST;

typedef struct _CMC_TAGGED_CONTENT_INFO _CMC_TAGGED_CONTENT_INFO, *P_CMC_TAGGED_CONTENT_INFO;

typedef struct _CMC_TAGGED_CONTENT_INFO *PCMC_TAGGED_CONTENT_INFO;

typedef struct _CMC_TAGGED_OTHER_MSG _CMC_TAGGED_OTHER_MSG, *P_CMC_TAGGED_OTHER_MSG;

typedef struct _CMC_TAGGED_OTHER_MSG *PCMC_TAGGED_OTHER_MSG;

typedef struct _CRYPT_ATTRIBUTE CRYPT_ATTRIBUTE;

typedef union _union_219 _union_219, *P_union_219;

typedef struct _CMC_TAGGED_CERT_REQUEST _CMC_TAGGED_CERT_REQUEST, *P_CMC_TAGGED_CERT_REQUEST;

typedef struct _CMC_TAGGED_CERT_REQUEST *PCMC_TAGGED_CERT_REQUEST;

struct _CMC_TAGGED_CONTENT_INFO {
    DWORD dwBodyPartID;
    CRYPT_DER_BLOB EncodedContentInfo;
};

struct _CMC_TAGGED_ATTRIBUTE {
    DWORD dwBodyPartID;
    CRYPT_ATTRIBUTE Attribute;
};

struct _CMC_DATA_INFO {
    DWORD cTaggedAttribute;
    PCMC_TAGGED_ATTRIBUTE rgTaggedAttribute;
    DWORD cTaggedRequest;
    PCMC_TAGGED_REQUEST rgTaggedRequest;
    DWORD cTaggedContentInfo;
    PCMC_TAGGED_CONTENT_INFO rgTaggedContentInfo;
    DWORD cTaggedOtherMsg;
    PCMC_TAGGED_OTHER_MSG rgTaggedOtherMsg;
};

union _union_219 {
    PCMC_TAGGED_CERT_REQUEST pTaggedCertRequest;
};

struct _CMC_TAGGED_CERT_REQUEST {
    DWORD dwBodyPartID;
    CRYPT_DER_BLOB SignedCertRequest;
};

struct _CMC_TAGGED_OTHER_MSG {
    DWORD dwBodyPartID;
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Value;
};

struct _CMC_TAGGED_REQUEST {
    DWORD dwTaggedRequestChoice;
    union _union_219 u;
};

typedef struct _CMC_PEND_INFO _CMC_PEND_INFO, *P_CMC_PEND_INFO;

struct _CMC_PEND_INFO {
    CRYPT_DATA_BLOB PendToken;
    FILETIME PendTime;
};

typedef struct _CMC_RESPONSE_INFO _CMC_RESPONSE_INFO, *P_CMC_RESPONSE_INFO;

struct _CMC_RESPONSE_INFO {
    DWORD cTaggedAttribute;
    PCMC_TAGGED_ATTRIBUTE rgTaggedAttribute;
    DWORD cTaggedContentInfo;
    PCMC_TAGGED_CONTENT_INFO rgTaggedContentInfo;
    DWORD cTaggedOtherMsg;
    PCMC_TAGGED_OTHER_MSG rgTaggedOtherMsg;
};

typedef struct _CMC_STATUS_INFO _CMC_STATUS_INFO, *P_CMC_STATUS_INFO;

typedef union _union_226 _union_226, *P_union_226;

typedef struct _CMC_PEND_INFO *PCMC_PEND_INFO;

union _union_226 {
    DWORD dwFailInfo;
    PCMC_PEND_INFO pPendInfo;
};

struct _CMC_STATUS_INFO {
    DWORD dwStatus;
    DWORD cBodyList;
    DWORD *rgdwBodyList;
    LPWSTR pwszStatusString;
    DWORD dwOtherInfoChoice;
    union _union_226 u;
};

typedef struct _CMS_DH_KEY_INFO _CMS_DH_KEY_INFO, *P_CMS_DH_KEY_INFO;

typedef uint ALG_ID;

struct _CMS_DH_KEY_INFO {
    DWORD dwVersion;
    ALG_ID Algid;
    LPSTR pszContentEncObjId;
    CRYPT_DATA_BLOB PubInfo;
    void *pReserved;
};

typedef struct _CMS_KEY_INFO _CMS_KEY_INFO, *P_CMS_KEY_INFO;

struct _CMS_KEY_INFO {
    DWORD dwVersion;
    ALG_ID Algid;
    BYTE *pbOID;
    DWORD cbOID;
};

typedef struct _CMSG_CMS_RECIPIENT_INFO _CMSG_CMS_RECIPIENT_INFO, *P_CMSG_CMS_RECIPIENT_INFO;

typedef union _union_297 _union_297, *P_union_297;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_INFO _CMSG_KEY_TRANS_RECIPIENT_INFO, *P_CMSG_KEY_TRANS_RECIPIENT_INFO;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_INFO *PCMSG_KEY_TRANS_RECIPIENT_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_INFO _CMSG_KEY_AGREE_RECIPIENT_INFO, *P_CMSG_KEY_AGREE_RECIPIENT_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_INFO *PCMSG_KEY_AGREE_RECIPIENT_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_INFO _CMSG_MAIL_LIST_RECIPIENT_INFO, *P_CMSG_MAIL_LIST_RECIPIENT_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_INFO *PCMSG_MAIL_LIST_RECIPIENT_INFO;

typedef struct _CERT_ID CERT_ID;

typedef union _union_294 _union_294, *P_union_294;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO, *P_CMSG_RECIPIENT_ENCRYPTED_KEY_INFO;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO *PCMSG_RECIPIENT_ENCRYPTED_KEY_INFO;

typedef struct _CRYPT_ATTRIBUTE_TYPE_VALUE _CRYPT_ATTRIBUTE_TYPE_VALUE, *P_CRYPT_ATTRIBUTE_TYPE_VALUE;

typedef struct _CRYPT_ATTRIBUTE_TYPE_VALUE *PCRYPT_ATTRIBUTE_TYPE_VALUE;

union _union_297 {
    PCMSG_KEY_TRANS_RECIPIENT_INFO pKeyTrans;
    PCMSG_KEY_AGREE_RECIPIENT_INFO pKeyAgree;
    PCMSG_MAIL_LIST_RECIPIENT_INFO pMailList;
};

struct _CMSG_CMS_RECIPIENT_INFO {
    DWORD dwRecipientChoice;
    union _union_297 u;
};

struct _CMSG_KEY_TRANS_RECIPIENT_INFO {
    DWORD dwVersion;
    CERT_ID RecipientId;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedKey;
};

union _union_294 {
    CERT_ID OriginatorCertId;
    CERT_PUBLIC_KEY_INFO OriginatorPublicKeyInfo;
};

struct _CRYPT_ATTRIBUTE_TYPE_VALUE {
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Value;
};

struct _CMSG_MAIL_LIST_RECIPIENT_INFO {
    DWORD dwVersion;
    CRYPT_DATA_BLOB KeyId;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedKey;
    FILETIME Date;
    PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;
};

struct _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO {
    CERT_ID RecipientId;
    CRYPT_DATA_BLOB EncryptedKey;
    FILETIME Date;
    PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;
};

struct _CMSG_KEY_AGREE_RECIPIENT_INFO {
    DWORD dwVersion;
    DWORD dwOriginatorChoice;
    union _union_294 u;
    CRYPT_DATA_BLOB UserKeyingMaterial;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    DWORD cRecipientEncryptedKeys;
    PCMSG_RECIPIENT_ENCRYPTED_KEY_INFO *rgpRecipientEncryptedKeys;
};

typedef struct _CMSG_CMS_SIGNER_INFO _CMSG_CMS_SIGNER_INFO, *P_CMSG_CMS_SIGNER_INFO;

struct _CMSG_CMS_SIGNER_INFO {
    DWORD dwVersion;
    CERT_ID SignerId;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedHash;
    CRYPT_ATTRIBUTES AuthAttrs;
    CRYPT_ATTRIBUTES UnauthAttrs;
};

typedef struct _CMSG_CNG_CONTENT_DECRYPT_INFO _CMSG_CNG_CONTENT_DECRYPT_INFO, *P_CMSG_CNG_CONTENT_DECRYPT_INFO;

typedef ulonglong size_t;

typedef void * (*PFN_CMSG_ALLOC)(size_t);

typedef void (*PFN_CMSG_FREE)(void *);

struct _CMSG_CNG_CONTENT_DECRYPT_INFO {
    DWORD cbSize;
    CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;
    PFN_CMSG_ALLOC pfnAlloc;
    PFN_CMSG_FREE pfnFree;
    NCRYPT_KEY_HANDLE hNCryptKey;
    BYTE *pbContentEncryptKey;
    DWORD cbContentEncryptKey;
    BCRYPT_KEY_HANDLE hCNGContentEncryptKey;
    BYTE *pbCNGContentEncryptKeyObject;
};

typedef struct _CMSG_CONTENT_ENCRYPT_INFO _CMSG_CONTENT_ENCRYPT_INFO, *P_CMSG_CONTENT_ENCRYPT_INFO;

typedef ULONG_PTR HCRYPTPROV_LEGACY;

typedef struct _CMSG_RECIPIENT_ENCODE_INFO _CMSG_RECIPIENT_ENCODE_INFO, *P_CMSG_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_RECIPIENT_ENCODE_INFO *PCMSG_RECIPIENT_ENCODE_INFO;

typedef union _union_310 _union_310, *P_union_310;

typedef union _union_281 _union_281, *P_union_281;

typedef ULONG_PTR HCRYPTKEY;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO, *P_CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO *PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO, *P_CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO *PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO, *P_CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO *PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO;

typedef union _union_277 _union_277, *P_union_277;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO, *P_CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO *PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO;

typedef union _union_279 _union_279, *P_union_279;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER *PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CERT_ID *PCERT_ID;

union _union_281 {
    PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO pKeyTrans;
    PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO pKeyAgree;
    PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO pMailList;
};

struct _CMSG_RECIPIENT_ENCODE_INFO {
    DWORD dwRecipientChoice;
    union _union_281 u;
};

union _union_279 {
    HCRYPTKEY hKeyEncryptionKey;
    void *pvKeyEncryptionKey;
};

struct _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO {
    DWORD cbSize;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    void *pvKeyEncryptionAuxInfo;
    HCRYPTPROV hCryptProv;
    DWORD dwKeyChoice;
    union _union_279 u;
    CRYPT_DATA_BLOB KeyId;
    FILETIME Date;
    PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;
};

struct _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO {
    DWORD cbSize;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    void *pvKeyEncryptionAuxInfo;
    HCRYPTPROV_LEGACY hCryptProv;
    CRYPT_BIT_BLOB RecipientPublicKey;
    CERT_ID RecipientId;
};

union _union_277 {
    PCRYPT_ALGORITHM_IDENTIFIER pEphemeralAlgorithm;
    PCERT_ID pSenderId;
};

struct _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO {
    DWORD cbSize;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    void *pvKeyEncryptionAuxInfo;
    CRYPT_ALGORITHM_IDENTIFIER KeyWrapAlgorithm;
    void *pvKeyWrapAuxInfo;
    HCRYPTPROV_LEGACY hCryptProv;
    DWORD dwKeySpec;
    DWORD dwKeyChoice;
    union _union_277 u;
    CRYPT_DATA_BLOB UserKeyingMaterial;
    DWORD cRecipientEncryptedKeys;
    PCMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO *rgpRecipientEncryptedKeys;
};

struct _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO {
    DWORD cbSize;
    CRYPT_BIT_BLOB RecipientPublicKey;
    CERT_ID RecipientId;
    FILETIME Date;
    PCRYPT_ATTRIBUTE_TYPE_VALUE pOtherAttr;
};

union _union_310 {
    HCRYPTKEY hContentEncryptKey;
    BCRYPT_KEY_HANDLE hCNGContentEncryptKey;
};

struct _CMSG_CONTENT_ENCRYPT_INFO {
    DWORD cbSize;
    HCRYPTPROV_LEGACY hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;
    void *pvEncryptionAuxInfo;
    DWORD cRecipients;
    PCMSG_RECIPIENT_ENCODE_INFO rgCmsRecipients;
    PFN_CMSG_ALLOC pfnAlloc;
    PFN_CMSG_FREE pfnFree;
    DWORD dwEncryptFlags;
    union _union_310 u;
    DWORD dwFlags;
    BOOL fCNG;
    BYTE *pbCNGContentEncryptKeyObject;
    BYTE *pbContentEncryptKey;
    DWORD cbContentEncryptKey;
};

typedef struct _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA, *P_CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA;

struct _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA {
    DWORD cbSize;
    DWORD dwSignerIndex;
    CRYPT_DATA_BLOB blob;
};

typedef struct _CMSG_CTRL_DECRYPT_PARA _CMSG_CTRL_DECRYPT_PARA, *P_CMSG_CTRL_DECRYPT_PARA;

typedef union _union_300 _union_300, *P_union_300;

union _union_300 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

struct _CMSG_CTRL_DECRYPT_PARA {
    DWORD cbSize;
    union _union_300 u;
    DWORD dwKeySpec;
    DWORD dwRecipientIndex;
};

typedef struct _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA, *P_CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA;

struct _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA {
    DWORD cbSize;
    DWORD dwSignerIndex;
    DWORD dwUnauthAttrIndex;
};

typedef struct _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA, *P_CMSG_CTRL_KEY_AGREE_DECRYPT_PARA;

typedef union _union_304 _union_304, *P_union_304;

union _union_304 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

struct _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA {
    DWORD cbSize;
    union _union_304 u;
    DWORD dwKeySpec;
    PCMSG_KEY_AGREE_RECIPIENT_INFO pKeyAgree;
    DWORD dwRecipientIndex;
    DWORD dwRecipientEncryptedKeyIndex;
    CRYPT_BIT_BLOB OriginatorPublicKey;
};

typedef struct _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA, *P_CMSG_CTRL_KEY_TRANS_DECRYPT_PARA;

typedef union _union_302 _union_302, *P_union_302;

union _union_302 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

struct _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA {
    DWORD cbSize;
    union _union_302 u;
    DWORD dwKeySpec;
    PCMSG_KEY_TRANS_RECIPIENT_INFO pKeyTrans;
    DWORD dwRecipientIndex;
};

typedef struct _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA, *P_CMSG_CTRL_MAIL_LIST_DECRYPT_PARA;

typedef union _union_306 _union_306, *P_union_306;

union _union_306 {
    HCRYPTKEY hKeyEncryptionKey;
    void *pvKeyEncryptionKey;
};

struct _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA {
    DWORD cbSize;
    HCRYPTPROV hCryptProv;
    PCMSG_MAIL_LIST_RECIPIENT_INFO pMailList;
    DWORD dwRecipientIndex;
    DWORD dwKeyChoice;
    union _union_306 u;
};

typedef struct _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA, *P_CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA;

struct _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA {
    DWORD cbSize;
    HCRYPTPROV_LEGACY hCryptProv;
    DWORD dwSignerIndex;
    DWORD dwSignerType;
    void *pvSigner;
};

typedef struct _CMSG_ENCRYPTED_ENCODE_INFO _CMSG_ENCRYPTED_ENCODE_INFO, *P_CMSG_ENCRYPTED_ENCODE_INFO;

struct _CMSG_ENCRYPTED_ENCODE_INFO {
    DWORD cbSize;
    CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;
    void *pvEncryptionAuxInfo;
};

typedef struct _CMSG_ENVELOPED_ENCODE_INFO _CMSG_ENVELOPED_ENCODE_INFO, *P_CMSG_ENVELOPED_ENCODE_INFO;

struct _CMSG_ENVELOPED_ENCODE_INFO {
    DWORD cbSize;
    HCRYPTPROV_LEGACY hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;
    void *pvEncryptionAuxInfo;
    DWORD cRecipients;
    PCERT_INFO *rgpRecipients;
};

typedef struct _CMSG_HASHED_ENCODE_INFO _CMSG_HASHED_ENCODE_INFO, *P_CMSG_HASHED_ENCODE_INFO;

struct _CMSG_HASHED_ENCODE_INFO {
    DWORD cbSize;
    HCRYPTPROV_LEGACY hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    void *pvHashAuxInfo;
};

typedef struct _CMSG_KEY_AGREE_ENCRYPT_INFO _CMSG_KEY_AGREE_ENCRYPT_INFO, *P_CMSG_KEY_AGREE_ENCRYPT_INFO;

typedef union _union_314 _union_314, *P_union_314;

typedef struct _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO, *P_CMSG_KEY_AGREE_KEY_ENCRYPT_INFO;

typedef struct _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO *PCMSG_KEY_AGREE_KEY_ENCRYPT_INFO;

struct _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO {
    DWORD cbSize;
    CRYPT_DATA_BLOB EncryptedKey;
};

union _union_314 {
    CERT_ID OriginatorCertId;
    CERT_PUBLIC_KEY_INFO OriginatorPublicKeyInfo;
};

struct _CMSG_KEY_AGREE_ENCRYPT_INFO {
    DWORD cbSize;
    DWORD dwRecipientIndex;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    CRYPT_DATA_BLOB UserKeyingMaterial;
    DWORD dwOriginatorChoice;
    union _union_314 u;
    DWORD cKeyAgreeKeyEncryptInfo;
    PCMSG_KEY_AGREE_KEY_ENCRYPT_INFO *rgpKeyAgreeKeyEncryptInfo;
    DWORD dwFlags;
};

typedef struct _CMSG_KEY_TRANS_ENCRYPT_INFO _CMSG_KEY_TRANS_ENCRYPT_INFO, *P_CMSG_KEY_TRANS_ENCRYPT_INFO;

struct _CMSG_KEY_TRANS_ENCRYPT_INFO {
    DWORD cbSize;
    DWORD dwRecipientIndex;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedKey;
    DWORD dwFlags;
};

typedef struct _CMSG_MAIL_LIST_ENCRYPT_INFO _CMSG_MAIL_LIST_ENCRYPT_INFO, *P_CMSG_MAIL_LIST_ENCRYPT_INFO;

struct _CMSG_MAIL_LIST_ENCRYPT_INFO {
    DWORD cbSize;
    DWORD dwRecipientIndex;
    CRYPT_ALGORITHM_IDENTIFIER KeyEncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedKey;
    DWORD dwFlags;
};

typedef struct _CMSG_RC2_AUX_INFO _CMSG_RC2_AUX_INFO, *P_CMSG_RC2_AUX_INFO;

struct _CMSG_RC2_AUX_INFO {
    DWORD cbSize;
    DWORD dwBitLen;
};

typedef struct _CMSG_RC4_AUX_INFO _CMSG_RC4_AUX_INFO, *P_CMSG_RC4_AUX_INFO;

struct _CMSG_RC4_AUX_INFO {
    DWORD cbSize;
    DWORD dwBitLen;
};

typedef struct _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO, *P_CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO;

typedef struct _CMSG_SIGNED_ENCODE_INFO _CMSG_SIGNED_ENCODE_INFO, *P_CMSG_SIGNED_ENCODE_INFO;

typedef struct _CMSG_SIGNED_ENCODE_INFO CMSG_SIGNED_ENCODE_INFO;

typedef struct _CMSG_ENVELOPED_ENCODE_INFO CMSG_ENVELOPED_ENCODE_INFO;

typedef struct _CMSG_SIGNER_ENCODE_INFO _CMSG_SIGNER_ENCODE_INFO, *P_CMSG_SIGNER_ENCODE_INFO;

typedef struct _CMSG_SIGNER_ENCODE_INFO *PCMSG_SIGNER_ENCODE_INFO;

typedef struct _CRYPTOAPI_BLOB *PCRL_BLOB;

typedef union _union_270 _union_270, *P_union_270;

struct _CMSG_SIGNED_ENCODE_INFO {
    DWORD cbSize;
    DWORD cSigners;
    PCMSG_SIGNER_ENCODE_INFO rgSigners;
    DWORD cCertEncoded;
    PCERT_BLOB rgCertEncoded;
    DWORD cCrlEncoded;
    PCRL_BLOB rgCrlEncoded;
};

union _union_270 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

struct _CMSG_SIGNER_ENCODE_INFO {
    DWORD cbSize;
    PCERT_INFO pCertInfo;
    union _union_270 u;
    DWORD dwKeySpec;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    void *pvHashAuxInfo;
    DWORD cAuthAttr;
    PCRYPT_ATTRIBUTE rgAuthAttr;
    DWORD cUnauthAttr;
    PCRYPT_ATTRIBUTE rgUnauthAttr;
};

struct _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO {
    DWORD cbSize;
    CMSG_SIGNED_ENCODE_INFO SignedInfo;
    CMSG_ENVELOPED_ENCODE_INFO EnvelopedInfo;
};

typedef struct _CMSG_SP3_COMPATIBLE_AUX_INFO _CMSG_SP3_COMPATIBLE_AUX_INFO, *P_CMSG_SP3_COMPATIBLE_AUX_INFO;

struct _CMSG_SP3_COMPATIBLE_AUX_INFO {
    DWORD cbSize;
    DWORD dwFlags;
};

typedef struct _CMSG_STREAM_INFO _CMSG_STREAM_INFO, *P_CMSG_STREAM_INFO;

typedef BOOL (*PFN_CMSG_STREAM_OUTPUT)(void *, BYTE *, DWORD, BOOL);

struct _CMSG_STREAM_INFO {
    DWORD cbContent;
    PFN_CMSG_STREAM_OUTPUT pfnStreamOutput;
    void *pvArg;
};

typedef struct _CRL_DIST_POINT _CRL_DIST_POINT, *P_CRL_DIST_POINT;

typedef struct _CRL_DIST_POINT_NAME _CRL_DIST_POINT_NAME, *P_CRL_DIST_POINT_NAME;

typedef struct _CRL_DIST_POINT_NAME CRL_DIST_POINT_NAME;

typedef union _union_192 _union_192, *P_union_192;

union _union_192 {
    CERT_ALT_NAME_INFO FullName;
};

struct _CRL_DIST_POINT_NAME {
    DWORD dwDistPointNameChoice;
    union _union_192 u;
};

struct _CRL_DIST_POINT {
    CRL_DIST_POINT_NAME DistPointName;
    CRYPT_BIT_BLOB ReasonFlags;
    CERT_ALT_NAME_INFO CRLIssuer;
};

typedef struct _CRL_DIST_POINTS_INFO _CRL_DIST_POINTS_INFO, *P_CRL_DIST_POINTS_INFO;

typedef struct _CRL_DIST_POINT *PCRL_DIST_POINT;

struct _CRL_DIST_POINTS_INFO {
    DWORD cDistPoint;
    PCRL_DIST_POINT rgDistPoint;
};

typedef struct _CRL_FIND_ISSUED_FOR_PARA _CRL_FIND_ISSUED_FOR_PARA, *P_CRL_FIND_ISSUED_FOR_PARA;

struct _CRL_FIND_ISSUED_FOR_PARA {
    PCCERT_CONTEXT pSubjectCert;
    PCCERT_CONTEXT pIssuerCert;
};

typedef struct _CRL_ISSUING_DIST_POINT _CRL_ISSUING_DIST_POINT, *P_CRL_ISSUING_DIST_POINT;

struct _CRL_ISSUING_DIST_POINT {
    CRL_DIST_POINT_NAME DistPointName;
    BOOL fOnlyContainsUserCerts;
    BOOL fOnlyContainsCACerts;
    CRYPT_BIT_BLOB OnlySomeReasonFlags;
    BOOL fIndirectCRL;
};

typedef struct _CRL_REVOCATION_INFO _CRL_REVOCATION_INFO, *P_CRL_REVOCATION_INFO;

struct _CRL_REVOCATION_INFO {
    PCRL_ENTRY pCrlEntry;
    PCCRL_CONTEXT pCrlContext;
    PCCERT_CHAIN_CONTEXT pCrlIssuerChain;
};

typedef struct _CROSS_CERT_DIST_POINTS_INFO _CROSS_CERT_DIST_POINTS_INFO, *P_CROSS_CERT_DIST_POINTS_INFO;

typedef struct _CERT_ALT_NAME_INFO *PCERT_ALT_NAME_INFO;

struct _CROSS_CERT_DIST_POINTS_INFO {
    DWORD dwSyncDeltaTime;
    DWORD cDistPoint;
    PCERT_ALT_NAME_INFO rgDistPoint;
};

typedef struct _CRYPT_3DES_KEY_STATE _CRYPT_3DES_KEY_STATE, *P_CRYPT_3DES_KEY_STATE;

struct _CRYPT_3DES_KEY_STATE {
    uchar Key[24];
    uchar IV[8];
    uchar Feedback[8];
};

typedef struct _CRYPT_AES_128_KEY_STATE _CRYPT_AES_128_KEY_STATE, *P_CRYPT_AES_128_KEY_STATE;

struct _CRYPT_AES_128_KEY_STATE {
    uchar Key[16];
    uchar IV[16];
    uchar EncryptionState[11][16];
    uchar DecryptionState[11][16];
    uchar Feedback[16];
};

typedef struct _CRYPT_AES_256_KEY_STATE _CRYPT_AES_256_KEY_STATE, *P_CRYPT_AES_256_KEY_STATE;

struct _CRYPT_AES_256_KEY_STATE {
    uchar Key[32];
    uchar IV[16];
    uchar EncryptionState[15][16];
    uchar DecryptionState[15][16];
    uchar Feedback[16];
};

typedef struct _CRYPT_ASYNC_RETRIEVAL_COMPLETION _CRYPT_ASYNC_RETRIEVAL_COMPLETION, *P_CRYPT_ASYNC_RETRIEVAL_COMPLETION;

typedef void (*PFN_CRYPT_ASYNC_RETRIEVAL_COMPLETION_FUNC)(LPVOID, DWORD, LPCSTR, LPSTR, LPVOID);

struct _CRYPT_ASYNC_RETRIEVAL_COMPLETION {
    PFN_CRYPT_ASYNC_RETRIEVAL_COMPLETION_FUNC pfnCompletion;
    LPVOID pvCompletion;
};

typedef struct _CRYPT_BLOB_ARRAY _CRYPT_BLOB_ARRAY, *P_CRYPT_BLOB_ARRAY;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_DATA_BLOB;

struct _CRYPT_BLOB_ARRAY {
    DWORD cBlob;
    PCRYPT_DATA_BLOB rgBlob;
};

typedef struct _CRYPT_CONTENT_INFO _CRYPT_CONTENT_INFO, *P_CRYPT_CONTENT_INFO;

struct _CRYPT_CONTENT_INFO {
    LPSTR pszObjId;
    CRYPT_DER_BLOB Content;
};

typedef struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY, *P_CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_DER_BLOB;

struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY {
    LPSTR pszObjId;
    DWORD cValue;
    PCRYPT_DER_BLOB rgValue;
};

typedef struct _CRYPT_CREDENTIALS _CRYPT_CREDENTIALS, *P_CRYPT_CREDENTIALS;

struct _CRYPT_CREDENTIALS {
    DWORD cbSize;
    LPCSTR pszCredentialsOid;
    LPVOID pvCredentials;
};

typedef struct _CRYPT_CSP_PROVIDER _CRYPT_CSP_PROVIDER, *P_CRYPT_CSP_PROVIDER;

struct _CRYPT_CSP_PROVIDER {
    DWORD dwKeySpec;
    LPWSTR pwszProviderName;
    CRYPT_BIT_BLOB Signature;
};

typedef struct _CRYPT_DECODE_PARA _CRYPT_DECODE_PARA, *P_CRYPT_DECODE_PARA;

typedef LPVOID (*PFN_CRYPT_ALLOC)(size_t);

struct _CRYPT_DECODE_PARA {
    DWORD cbSize;
    PFN_CRYPT_ALLOC pfnAlloc;
    PFN_CRYPT_FREE pfnFree;
};

typedef struct _CRYPT_DECRYPT_MESSAGE_PARA _CRYPT_DECRYPT_MESSAGE_PARA, *P_CRYPT_DECRYPT_MESSAGE_PARA;

struct _CRYPT_DECRYPT_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    DWORD cCertStore;
    HCERTSTORE *rghCertStore;
};

typedef struct _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA, *P_CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA;

struct _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA {
    DWORD cOID;
    LPSTR *rgpszOID;
};

typedef struct _CRYPT_DES_KEY_STATE _CRYPT_DES_KEY_STATE, *P_CRYPT_DES_KEY_STATE;

struct _CRYPT_DES_KEY_STATE {
    uchar Key[8];
    uchar IV[8];
    uchar Feedback[8];
};

typedef struct _CRYPT_ECC_CMS_SHARED_INFO _CRYPT_ECC_CMS_SHARED_INFO, *P_CRYPT_ECC_CMS_SHARED_INFO;

struct _CRYPT_ECC_CMS_SHARED_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_DATA_BLOB EntityUInfo;
    BYTE rgbSuppPubInfo[4];
};

typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO _CRYPT_ECC_PRIVATE_KEY_INFO, *P_CRYPT_ECC_PRIVATE_KEY_INFO;

struct _CRYPT_ECC_PRIVATE_KEY_INFO {
    DWORD dwVersion;
    CRYPT_DER_BLOB PrivateKey;
    LPSTR szCurveOid;
    CRYPT_BIT_BLOB PublicKey;
};

typedef struct _CRYPT_ENCODE_PARA _CRYPT_ENCODE_PARA, *P_CRYPT_ENCODE_PARA;

struct _CRYPT_ENCODE_PARA {
    DWORD cbSize;
    PFN_CRYPT_ALLOC pfnAlloc;
    PFN_CRYPT_FREE pfnFree;
};

typedef struct _CRYPT_ENCRYPT_MESSAGE_PARA _CRYPT_ENCRYPT_MESSAGE_PARA, *P_CRYPT_ENCRYPT_MESSAGE_PARA;

struct _CRYPT_ENCRYPT_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    HCRYPTPROV_LEGACY hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;
    void *pvEncryptionAuxInfo;
    DWORD dwFlags;
    DWORD dwInnerContentType;
};

typedef struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO, *P_CRYPT_ENCRYPTED_PRIVATE_KEY_INFO;

struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER EncryptionAlgorithm;
    CRYPT_DATA_BLOB EncryptedPrivateKey;
};

typedef struct _CRYPT_ENROLLMENT_NAME_VALUE_PAIR _CRYPT_ENROLLMENT_NAME_VALUE_PAIR, *P_CRYPT_ENROLLMENT_NAME_VALUE_PAIR;

struct _CRYPT_ENROLLMENT_NAME_VALUE_PAIR {
    LPWSTR pwszName;
    LPWSTR pwszValue;
};

typedef struct _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO, *P_CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO;

typedef struct _CERT_REVOCATION_CHAIN_PARA *PCERT_REVOCATION_CHAIN_PARA;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_INTEGER_BLOB;

struct _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO {
    DWORD cbSize;
    int iDeltaCrlIndicator;
    LPFILETIME pftCacheResync;
    LPFILETIME pLastSyncTime;
    LPFILETIME pMaxAgeTime;
    PCERT_REVOCATION_CHAIN_PARA pChainPara;
    PCRYPT_INTEGER_BLOB pDeltaCrlIndicator;
};

typedef struct _CRYPT_HASH_INFO _CRYPT_HASH_INFO, *P_CRYPT_HASH_INFO;

struct _CRYPT_HASH_INFO {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_HASH_BLOB Hash;
};

typedef struct _CRYPT_HASH_MESSAGE_PARA _CRYPT_HASH_MESSAGE_PARA, *P_CRYPT_HASH_MESSAGE_PARA;

struct _CRYPT_HASH_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    HCRYPTPROV_LEGACY hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    void *pvHashAuxInfo;
};

typedef struct _CRYPT_IMAGE_REG _CRYPT_IMAGE_REG, *P_CRYPT_IMAGE_REG;

typedef struct _CRYPT_INTERFACE_REG *PCRYPT_INTERFACE_REG;

struct _CRYPT_IMAGE_REG {
    PWSTR pszImage;
    ULONG cInterfaces;
    PCRYPT_INTERFACE_REG *rgpInterfaces;
};

typedef struct _CRYPT_KEY_SIGN_MESSAGE_PARA _CRYPT_KEY_SIGN_MESSAGE_PARA, *P_CRYPT_KEY_SIGN_MESSAGE_PARA;

typedef union _union_356 _union_356, *P_union_356;

union _union_356 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

struct _CRYPT_KEY_SIGN_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    union _union_356 u;
    DWORD dwKeySpec;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    void *pvHashAuxInfo;
    CRYPT_ALGORITHM_IDENTIFIER PubKeyAlgorithm;
};

typedef struct _CRYPT_KEY_VERIFY_MESSAGE_PARA _CRYPT_KEY_VERIFY_MESSAGE_PARA, *P_CRYPT_KEY_VERIFY_MESSAGE_PARA;

struct _CRYPT_KEY_VERIFY_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    HCRYPTPROV_LEGACY hCryptProv;
};

typedef struct _CRYPT_MASK_GEN_ALGORITHM _CRYPT_MASK_GEN_ALGORITHM, *P_CRYPT_MASK_GEN_ALGORITHM;

struct _CRYPT_MASK_GEN_ALGORITHM {
    LPSTR pszObjId;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
};

typedef struct _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE, *P_CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE;

typedef struct _CRYPTOAPI_BLOB *PCERT_NAME_BLOB;

typedef BYTE *PBYTE;

typedef WCHAR *PCWSTR;

typedef BOOL (*PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET)(LPVOID, PCRYPT_DATA_BLOB, DWORD, PCERT_NAME_BLOB, PBYTE *, DWORD *, PCWSTR *, PCRYPT_DATA_BLOB *);

typedef void (*PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_RELEASE)(DWORD, LPVOID);

typedef void (*PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_PASSWORD)(LPVOID, PCWSTR);

typedef void (*PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE)(LPVOID, PBYTE);

typedef void (*PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_IDENTIFIER)(LPVOID, PCRYPT_DATA_BLOB);

struct _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE {
    DWORD cbSize;
    PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_GET pfnGet;
    PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_RELEASE pfnRelease;
    PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_PASSWORD pfnFreePassword;
    PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE pfnFree;
    PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FREE_IDENTIFIER pfnFreeIdentifier;
};

typedef struct _CRYPT_OBJID_TABLE _CRYPT_OBJID_TABLE, *P_CRYPT_OBJID_TABLE;

struct _CRYPT_OBJID_TABLE {
    DWORD dwAlgId;
    LPCSTR pszObjId;
};

typedef struct _CRYPT_OID_FUNC_ENTRY _CRYPT_OID_FUNC_ENTRY, *P_CRYPT_OID_FUNC_ENTRY;

struct _CRYPT_OID_FUNC_ENTRY {
    LPCSTR pszOID;
    void *pvFuncAddr;
};

typedef struct _CRYPT_OID_INFO _CRYPT_OID_INFO, *P_CRYPT_OID_INFO;

typedef union _union_262 _union_262, *P_union_262;

union _union_262 {
    DWORD dwValue;
    ALG_ID Algid;
    DWORD dwLength;
};

struct _CRYPT_OID_INFO {
    DWORD cbSize;
    LPCSTR pszOID;
    LPCWSTR pwszName;
    DWORD dwGroupId;
    union _union_262 u;
    CRYPT_DATA_BLOB ExtraInfo;
};

typedef struct _CRYPT_PASSWORD_CREDENTIALSA _CRYPT_PASSWORD_CREDENTIALSA, *P_CRYPT_PASSWORD_CREDENTIALSA;

struct _CRYPT_PASSWORD_CREDENTIALSA {
    DWORD cbSize;
    LPSTR pszUsername;
    LPSTR pszPassword;
};

typedef struct _CRYPT_PASSWORD_CREDENTIALSW _CRYPT_PASSWORD_CREDENTIALSW, *P_CRYPT_PASSWORD_CREDENTIALSW;

struct _CRYPT_PASSWORD_CREDENTIALSW {
    DWORD cbSize;
    LPWSTR pszUsername;
    LPWSTR pszPassword;
};

typedef struct _CRYPT_PKCS12_PBE_PARAMS _CRYPT_PKCS12_PBE_PARAMS, *P_CRYPT_PKCS12_PBE_PARAMS;

struct _CRYPT_PKCS12_PBE_PARAMS {
    int iIterations;
    ULONG cbSalt;
};

typedef struct _CRYPT_PKCS8_EXPORT_PARAMS _CRYPT_PKCS8_EXPORT_PARAMS, *P_CRYPT_PKCS8_EXPORT_PARAMS;

typedef BOOL (*PCRYPT_ENCRYPT_PRIVATE_KEY_FUNC)(CRYPT_ALGORITHM_IDENTIFIER *, CRYPT_DATA_BLOB *, BYTE *, DWORD *, LPVOID);

struct _CRYPT_PKCS8_EXPORT_PARAMS {
    HCRYPTPROV hCryptProv;
    DWORD dwKeySpec;
    LPSTR pszPrivateKeyObjId;
    PCRYPT_ENCRYPT_PRIVATE_KEY_FUNC pEncryptPrivateKeyFunc;
    LPVOID pVoidEncryptFunc;
};

typedef struct _CRYPT_PKCS8_IMPORT_PARAMS _CRYPT_PKCS8_IMPORT_PARAMS, *P_CRYPT_PKCS8_IMPORT_PARAMS;

typedef struct _CRYPTOAPI_BLOB CRYPT_DIGEST_BLOB;

typedef struct _CRYPT_PRIVATE_KEY_INFO _CRYPT_PRIVATE_KEY_INFO, *P_CRYPT_PRIVATE_KEY_INFO;

typedef struct _CRYPT_PRIVATE_KEY_INFO CRYPT_PRIVATE_KEY_INFO;

typedef BOOL (*PCRYPT_RESOLVE_HCRYPTPROV_FUNC)(CRYPT_PRIVATE_KEY_INFO *, HCRYPTPROV *, LPVOID);

typedef BOOL (*PCRYPT_DECRYPT_PRIVATE_KEY_FUNC)(CRYPT_ALGORITHM_IDENTIFIER, CRYPT_DATA_BLOB, BYTE *, DWORD *, LPVOID);

typedef struct _CRYPT_ATTRIBUTES *PCRYPT_ATTRIBUTES;

struct _CRYPT_PRIVATE_KEY_INFO {
    DWORD Version;
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_DER_BLOB PrivateKey;
    PCRYPT_ATTRIBUTES pAttributes;
};

struct _CRYPT_PKCS8_IMPORT_PARAMS {
    CRYPT_DIGEST_BLOB PrivateKey;
    PCRYPT_RESOLVE_HCRYPTPROV_FUNC pResolvehCryptProvFunc;
    LPVOID pVoidResolveFunc;
    PCRYPT_DECRYPT_PRIVATE_KEY_FUNC pDecryptPrivateKeyFunc;
    LPVOID pVoidDecryptFunc;
};

typedef struct _CRYPT_PROVIDER_REF _CRYPT_PROVIDER_REF, *P_CRYPT_PROVIDER_REF;

typedef struct _CRYPT_PROPERTY_REF *PCRYPT_PROPERTY_REF;

typedef struct _CRYPT_IMAGE_REF *PCRYPT_IMAGE_REF;

struct _CRYPT_PROVIDER_REF {
    ULONG dwInterface;
    PWSTR pszFunction;
    PWSTR pszProvider;
    ULONG cProperties;
    PCRYPT_PROPERTY_REF *rgpProperties;
    PCRYPT_IMAGE_REF pUM;
    PCRYPT_IMAGE_REF pKM;
};

typedef struct _CRYPT_PROVIDER_REFS _CRYPT_PROVIDER_REFS, *P_CRYPT_PROVIDER_REFS;

typedef struct _CRYPT_PROVIDER_REF *PCRYPT_PROVIDER_REF;

struct _CRYPT_PROVIDER_REFS {
    ULONG cProviders;
    PCRYPT_PROVIDER_REF *rgpProviders;
};

typedef struct _CRYPT_PROVIDER_REG _CRYPT_PROVIDER_REG, *P_CRYPT_PROVIDER_REG;

typedef struct _CRYPT_IMAGE_REG *PCRYPT_IMAGE_REG;

struct _CRYPT_PROVIDER_REG {
    ULONG cAliases;
    PWSTR *rgpszAliases;
    PCRYPT_IMAGE_REG pUM;
    PCRYPT_IMAGE_REG pKM;
};

typedef struct _CRYPT_PSOURCE_ALGORITHM _CRYPT_PSOURCE_ALGORITHM, *P_CRYPT_PSOURCE_ALGORITHM;

struct _CRYPT_PSOURCE_ALGORITHM {
    LPSTR pszObjId;
    CRYPT_DATA_BLOB EncodingParameters;
};

typedef struct _CRYPT_RC2_CBC_PARAMETERS _CRYPT_RC2_CBC_PARAMETERS, *P_CRYPT_RC2_CBC_PARAMETERS;

struct _CRYPT_RC2_CBC_PARAMETERS {
    DWORD dwVersion;
    BOOL fIV;
    BYTE rgbIV[8];
};

typedef struct _CRYPT_RC4_KEY_STATE _CRYPT_RC4_KEY_STATE, *P_CRYPT_RC4_KEY_STATE;

struct _CRYPT_RC4_KEY_STATE {
    uchar Key[16];
    uchar SBox[256];
    uchar i;
    uchar j;
};

typedef struct _CRYPT_RETRIEVE_AUX_INFO _CRYPT_RETRIEVE_AUX_INFO, *P_CRYPT_RETRIEVE_AUX_INFO;

typedef struct _CRYPTNET_URL_CACHE_PRE_FETCH_INFO _CRYPTNET_URL_CACHE_PRE_FETCH_INFO, *P_CRYPTNET_URL_CACHE_PRE_FETCH_INFO;

typedef struct _CRYPTNET_URL_CACHE_PRE_FETCH_INFO *PCRYPTNET_URL_CACHE_PRE_FETCH_INFO;

typedef struct _CRYPTNET_URL_CACHE_FLUSH_INFO _CRYPTNET_URL_CACHE_FLUSH_INFO, *P_CRYPTNET_URL_CACHE_FLUSH_INFO;

typedef struct _CRYPTNET_URL_CACHE_FLUSH_INFO *PCRYPTNET_URL_CACHE_FLUSH_INFO;

typedef struct _CRYPTNET_URL_CACHE_RESPONSE_INFO _CRYPTNET_URL_CACHE_RESPONSE_INFO, *P_CRYPTNET_URL_CACHE_RESPONSE_INFO;

typedef struct _CRYPTNET_URL_CACHE_RESPONSE_INFO *PCRYPTNET_URL_CACHE_RESPONSE_INFO;

struct _CRYPT_RETRIEVE_AUX_INFO {
    DWORD cbSize;
    FILETIME *pLastSyncTime;
    DWORD dwMaxUrlRetrievalByteCount;
    PCRYPTNET_URL_CACHE_PRE_FETCH_INFO pPreFetchInfo;
    PCRYPTNET_URL_CACHE_FLUSH_INFO pFlushInfo;
    PCRYPTNET_URL_CACHE_RESPONSE_INFO *ppResponseInfo;
    LPWSTR pwszCacheFileNamePrefix;
    LPFILETIME pftCacheResync;
    BOOL fProxyCacheRetrieval;
    DWORD dwHttpStatusCode;
    LPWSTR *ppwszErrorResponseHeaders;
    PCRYPT_DATA_BLOB *ppErrorContentBlob;
};

struct _CRYPTNET_URL_CACHE_PRE_FETCH_INFO {
    DWORD cbSize;
    DWORD dwObjectType;
    DWORD dwError;
    DWORD dwReserved;
    FILETIME ThisUpdateTime;
    FILETIME NextUpdateTime;
    FILETIME PublishTime;
};

struct _CRYPTNET_URL_CACHE_RESPONSE_INFO {
    DWORD cbSize;
    WORD wResponseType;
    WORD wResponseFlags;
    FILETIME LastModifiedTime;
    DWORD dwMaxAge;
    LPCWSTR pwszETag;
    DWORD dwProxyId;
};

struct _CRYPTNET_URL_CACHE_FLUSH_INFO {
    DWORD cbSize;
    DWORD dwExemptSeconds;
    FILETIME ExpireTime;
};

typedef struct _CRYPT_RSA_SSA_PSS_PARAMETERS _CRYPT_RSA_SSA_PSS_PARAMETERS, *P_CRYPT_RSA_SSA_PSS_PARAMETERS;

typedef struct _CRYPT_MASK_GEN_ALGORITHM CRYPT_MASK_GEN_ALGORITHM;

struct _CRYPT_RSA_SSA_PSS_PARAMETERS {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_MASK_GEN_ALGORITHM MaskGenAlgorithm;
    DWORD dwSaltLength;
    DWORD dwTrailerField;
};

typedef struct _CRYPT_RSAES_OAEP_PARAMETERS _CRYPT_RSAES_OAEP_PARAMETERS, *P_CRYPT_RSAES_OAEP_PARAMETERS;

typedef struct _CRYPT_PSOURCE_ALGORITHM CRYPT_PSOURCE_ALGORITHM;

struct _CRYPT_RSAES_OAEP_PARAMETERS {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_MASK_GEN_ALGORITHM MaskGenAlgorithm;
    CRYPT_PSOURCE_ALGORITHM PSourceAlgorithm;
};

typedef struct _CRYPT_SEQUENCE_OF_ANY _CRYPT_SEQUENCE_OF_ANY, *P_CRYPT_SEQUENCE_OF_ANY;

struct _CRYPT_SEQUENCE_OF_ANY {
    DWORD cValue;
    PCRYPT_DER_BLOB rgValue;
};

typedef struct _CRYPT_SIGN_MESSAGE_PARA _CRYPT_SIGN_MESSAGE_PARA, *P_CRYPT_SIGN_MESSAGE_PARA;

struct _CRYPT_SIGN_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgEncodingType;
    PCCERT_CONTEXT pSigningCert;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    void *pvHashAuxInfo;
    DWORD cMsgCert;
    PCCERT_CONTEXT *rgpMsgCert;
    DWORD cMsgCrl;
    PCCRL_CONTEXT *rgpMsgCrl;
    DWORD cAuthAttr;
    PCRYPT_ATTRIBUTE rgAuthAttr;
    DWORD cUnauthAttr;
    PCRYPT_ATTRIBUTE rgUnauthAttr;
    DWORD dwFlags;
    DWORD dwInnerContentType;
};

typedef struct _CRYPT_SMART_CARD_ROOT_INFO _CRYPT_SMART_CARD_ROOT_INFO, *P_CRYPT_SMART_CARD_ROOT_INFO;

typedef struct _ROOT_INFO_LUID _ROOT_INFO_LUID, *P_ROOT_INFO_LUID;

typedef struct _ROOT_INFO_LUID ROOT_INFO_LUID;

struct _ROOT_INFO_LUID {
    DWORD LowPart;
    LONG HighPart;
};

struct _CRYPT_SMART_CARD_ROOT_INFO {
    BYTE rgbCardID[16];
    ROOT_INFO_LUID luid;
};

typedef struct _CRYPT_SMIME_CAPABILITIES _CRYPT_SMIME_CAPABILITIES, *P_CRYPT_SMIME_CAPABILITIES;

typedef struct _CRYPT_SMIME_CAPABILITY _CRYPT_SMIME_CAPABILITY, *P_CRYPT_SMIME_CAPABILITY;

typedef struct _CRYPT_SMIME_CAPABILITY *PCRYPT_SMIME_CAPABILITY;

struct _CRYPT_SMIME_CAPABILITIES {
    DWORD cCapability;
    PCRYPT_SMIME_CAPABILITY rgCapability;
};

struct _CRYPT_SMIME_CAPABILITY {
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Parameters;
};

typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO _CRYPT_TIME_STAMP_REQUEST_INFO, *P_CRYPT_TIME_STAMP_REQUEST_INFO;

struct _CRYPT_TIME_STAMP_REQUEST_INFO {
    LPSTR pszTimeStampAlgorithm;
    LPSTR pszContentType;
    CRYPT_OBJID_BLOB Content;
    DWORD cAttribute;
    PCRYPT_ATTRIBUTE rgAttribute;
};

typedef struct _CRYPT_TIMESTAMP_ACCURACY _CRYPT_TIMESTAMP_ACCURACY, *P_CRYPT_TIMESTAMP_ACCURACY;

struct _CRYPT_TIMESTAMP_ACCURACY {
    DWORD dwSeconds;
    DWORD dwMillis;
    DWORD dwMicros;
};

typedef struct _CRYPT_TIMESTAMP_CONTEXT _CRYPT_TIMESTAMP_CONTEXT, *P_CRYPT_TIMESTAMP_CONTEXT;

typedef struct _CRYPT_TIMESTAMP_INFO _CRYPT_TIMESTAMP_INFO, *P_CRYPT_TIMESTAMP_INFO;

typedef struct _CRYPT_TIMESTAMP_INFO *PCRYPT_TIMESTAMP_INFO;

typedef struct _CRYPT_TIMESTAMP_ACCURACY *PCRYPT_TIMESTAMP_ACCURACY;

struct _CRYPT_TIMESTAMP_INFO {
    DWORD dwVersion;
    LPSTR pszTSAPolicyId;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_DER_BLOB HashedMessage;
    CRYPT_INTEGER_BLOB SerialNumber;
    FILETIME ftTime;
    PCRYPT_TIMESTAMP_ACCURACY pvAccuracy;
    BOOL fOrdering;
    CRYPT_DER_BLOB Nonce;
    CRYPT_DER_BLOB Tsa;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

struct _CRYPT_TIMESTAMP_CONTEXT {
    DWORD cbEncoded;
    BYTE *pbEncoded;
    PCRYPT_TIMESTAMP_INFO pTimeStamp;
};

typedef struct _CRYPT_TIMESTAMP_PARA _CRYPT_TIMESTAMP_PARA, *P_CRYPT_TIMESTAMP_PARA;

struct _CRYPT_TIMESTAMP_PARA {
    LPCSTR pszTSAPolicyId;
    BOOL fRequestCerts;
    CRYPT_INTEGER_BLOB Nonce;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _CRYPT_TIMESTAMP_REQUEST _CRYPT_TIMESTAMP_REQUEST, *P_CRYPT_TIMESTAMP_REQUEST;

struct _CRYPT_TIMESTAMP_REQUEST {
    DWORD dwVersion;
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_DER_BLOB HashedMessage;
    LPSTR pszTSAPolicyId;
    CRYPT_INTEGER_BLOB Nonce;
    BOOL fCertReq;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _CRYPT_TIMESTAMP_RESPONSE _CRYPT_TIMESTAMP_RESPONSE, *P_CRYPT_TIMESTAMP_RESPONSE;

struct _CRYPT_TIMESTAMP_RESPONSE {
    DWORD dwStatus;
    DWORD cFreeText;
    LPWSTR *rgFreeText;
    CRYPT_BIT_BLOB FailureInfo;
    CRYPT_DER_BLOB ContentInfo;
};

typedef struct _CRYPT_URL_ARRAY _CRYPT_URL_ARRAY, *P_CRYPT_URL_ARRAY;

struct _CRYPT_URL_ARRAY {
    DWORD cUrl;
    LPWSTR *rgwszUrl;
};

typedef struct _CRYPT_URL_INFO _CRYPT_URL_INFO, *P_CRYPT_URL_INFO;

struct _CRYPT_URL_INFO {
    DWORD cbSize;
    DWORD dwSyncDeltaTime;
    DWORD cGroup;
    DWORD *rgcGroupEntry;
};

typedef struct _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO, *P_CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO;

struct _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO {
    CRYPT_DATA_BLOB CertSignHashCNGAlgPropData;
    CRYPT_DATA_BLOB CertIssuerPubKeyBitLengthPropData;
};

typedef struct _CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO _CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO, *P_CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO;

struct _CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO {
    DWORD cCNGHashAlgid;
    PCWSTR *rgpwszCNGHashAlgid;
    DWORD dwWeakIndex;
};

typedef struct _CRYPT_VERIFY_MESSAGE_PARA _CRYPT_VERIFY_MESSAGE_PARA, *P_CRYPT_VERIFY_MESSAGE_PARA;

typedef PCCERT_CONTEXT (*PFN_CRYPT_GET_SIGNER_CERTIFICATE)(void *, DWORD, PCERT_INFO, HCERTSTORE);

struct _CRYPT_VERIFY_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    HCRYPTPROV_LEGACY hCryptProv;
    PFN_CRYPT_GET_SIGNER_CERTIFICATE pfnGetSignerCertificate;
    void *pvGetArg;
};

typedef struct _CRYPT_X942_OTHER_INFO _CRYPT_X942_OTHER_INFO, *P_CRYPT_X942_OTHER_INFO;

struct _CRYPT_X942_OTHER_INFO {
    LPSTR pszContentEncryptionObjId;
    BYTE rgbCounter[4];
    BYTE rgbKeyLength[4];
    CRYPT_DATA_BLOB PubInfo;
};

typedef struct _CRYPTPROTECT_PROMPTSTRUCT _CRYPTPROTECT_PROMPTSTRUCT, *P_CRYPTPROTECT_PROMPTSTRUCT;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

struct _CRYPTPROTECT_PROMPTSTRUCT {
    DWORD cbSize;
    DWORD dwPromptFlags;
    HWND hwndApp;
    LPCWSTR szPrompt;
};

typedef struct _CTL_ANY_SUBJECT_INFO _CTL_ANY_SUBJECT_INFO, *P_CTL_ANY_SUBJECT_INFO;

struct _CTL_ANY_SUBJECT_INFO {
    CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
    CRYPT_DATA_BLOB SubjectIdentifier;
};

typedef struct _CTL_FIND_SUBJECT_PARA _CTL_FIND_SUBJECT_PARA, *P_CTL_FIND_SUBJECT_PARA;

typedef struct _CTL_FIND_USAGE_PARA _CTL_FIND_USAGE_PARA, *P_CTL_FIND_USAGE_PARA;

typedef struct _CTL_FIND_USAGE_PARA *PCTL_FIND_USAGE_PARA;

struct _CTL_FIND_USAGE_PARA {
    DWORD cbSize;
    CTL_USAGE SubjectUsage;
    CRYPT_DATA_BLOB ListIdentifier;
    PCERT_INFO pSigner;
};

struct _CTL_FIND_SUBJECT_PARA {
    DWORD cbSize;
    PCTL_FIND_USAGE_PARA pUsagePara;
    DWORD dwSubjectType;
    void *pvSubject;
};

typedef struct _CTL_USAGE_MATCH _CTL_USAGE_MATCH, *P_CTL_USAGE_MATCH;

struct _CTL_USAGE_MATCH {
    DWORD dwType;
    CTL_USAGE Usage;
};

typedef struct _CTL_VERIFY_USAGE_PARA _CTL_VERIFY_USAGE_PARA, *P_CTL_VERIFY_USAGE_PARA;

struct _CTL_VERIFY_USAGE_PARA {
    DWORD cbSize;
    CRYPT_DATA_BLOB ListIdentifier;
    DWORD cCtlStore;
    HCERTSTORE *rghCtlStore;
    DWORD cSignerStore;
    HCERTSTORE *rghSignerStore;
};

typedef struct _CTL_VERIFY_USAGE_STATUS _CTL_VERIFY_USAGE_STATUS, *P_CTL_VERIFY_USAGE_STATUS;

struct _CTL_VERIFY_USAGE_STATUS {
    DWORD cbSize;
    DWORD dwError;
    DWORD dwFlags;
    PCCTL_CONTEXT *ppCtl;
    DWORD dwCtlEntryIndex;
    PCCERT_CONTEXT *ppSigner;
    DWORD dwSignerIndex;
};

typedef struct _DSSSEED _DSSSEED, *P_DSSSEED;

struct _DSSSEED {
    DWORD counter;
    BYTE seed[20];
};

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_PARA _EV_EXTRA_CERT_CHAIN_POLICY_PARA, *P_EV_EXTRA_CERT_CHAIN_POLICY_PARA;

struct _EV_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    DWORD dwRootProgramQualifierFlags;
};

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_STATUS _EV_EXTRA_CERT_CHAIN_POLICY_STATUS, *P_EV_EXTRA_CERT_CHAIN_POLICY_STATUS;

struct _EV_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    DWORD dwQualifiers;
    DWORD dwIssuanceUsageIndex;
};

typedef struct _FVE_AUTH_DPAPI_NG _FVE_AUTH_DPAPI_NG, *P_FVE_AUTH_DPAPI_NG;

struct _FVE_AUTH_DPAPI_NG {
    USHORT DpapiNgFlags;
    USHORT DescriptorLength;
    WCHAR DpapiNgDescriptor[1];
};

typedef struct _FVE_AUTH_ELEMENT _FVE_AUTH_ELEMENT, *P_FVE_AUTH_ELEMENT;

typedef union _union_451 _union_451, *P_union_451;

typedef struct _FVE_AUTH_RECOVERY_PASSWORD _FVE_AUTH_RECOVERY_PASSWORD, *P_FVE_AUTH_RECOVERY_PASSWORD;

typedef struct _FVE_AUTH_RECOVERY_PASSWORD FVE_AUTH_RECOVERY_PASSWORD;

typedef struct _FVE_AUTH_PIN _FVE_AUTH_PIN, *P_FVE_AUTH_PIN;

typedef struct _FVE_AUTH_PIN FVE_AUTH_PIN;

typedef struct _FVE_AUTH_TPM _FVE_AUTH_TPM, *P_FVE_AUTH_TPM;

typedef struct _FVE_AUTH_TPM FVE_AUTH_TPM;

typedef struct _FVE_AUTH_EXTERNAL_KEY _FVE_AUTH_EXTERNAL_KEY, *P_FVE_AUTH_EXTERNAL_KEY;

typedef struct _FVE_AUTH_EXTERNAL_KEY FVE_AUTH_EXTERNAL_KEY;

typedef struct _FVE_AUTH_PUBLIC_KEY _FVE_AUTH_PUBLIC_KEY, *P_FVE_AUTH_PUBLIC_KEY;

typedef struct _FVE_AUTH_PUBLIC_KEY FVE_AUTH_PUBLIC_KEY;

typedef struct _FVE_AUTH_PRIVATE_KEY _FVE_AUTH_PRIVATE_KEY, *P_FVE_AUTH_PRIVATE_KEY;

typedef struct _FVE_AUTH_PRIVATE_KEY FVE_AUTH_PRIVATE_KEY;

typedef struct _FVE_AUTH_INFO_PUBLIC_KEY _FVE_AUTH_INFO_PUBLIC_KEY, *P_FVE_AUTH_INFO_PUBLIC_KEY;

typedef struct _FVE_AUTH_INFO_PUBLIC_KEY FVE_AUTH_INFO_PUBLIC_KEY;

typedef struct _FVE_AUTH_PASSPHRASE _FVE_AUTH_PASSPHRASE, *P_FVE_AUTH_PASSPHRASE;

typedef struct _FVE_AUTH_PASSPHRASE FVE_AUTH_PASSPHRASE;

typedef struct _FVE_AUTH_INFO_CLEAR_KEY _FVE_AUTH_INFO_CLEAR_KEY, *P_FVE_AUTH_INFO_CLEAR_KEY;

typedef struct _FVE_AUTH_INFO_CLEAR_KEY FVE_AUTH_INFO_CLEAR_KEY;

typedef struct _FVE_AUTH_DPAPI_NG FVE_AUTH_DPAPI_NG;

typedef struct _FVE_AUTH_PREDICTED_TPM_INFO _FVE_AUTH_PREDICTED_TPM_INFO, *P_FVE_AUTH_PREDICTED_TPM_INFO;

typedef struct _FVE_AUTH_PREDICTED_TPM_INFO FVE_AUTH_PREDICTED_TPM_INFO;

typedef struct _FVE_TPM_STATE_ _FVE_TPM_STATE_, *P_FVE_TPM_STATE_;

typedef struct _FVE_TPM_STATE_ *PFVE_TPM_STATE;

typedef struct _FVE_TPM_PROTECTOR_INFO _FVE_TPM_PROTECTOR_INFO, *P_FVE_TPM_PROTECTOR_INFO;

typedef struct _FVE_TPM_PROTECTOR_INFO *PFVE_TPM_PROTECTOR_INFO;

typedef union _union_418 _union_418, *P_union_418;

typedef struct _FVE_TPM_PCR7_INFO _FVE_TPM_PCR7_INFO, *P_FVE_TPM_PCR7_INFO;

typedef struct _FVE_TPM_PCR7_INFO *PFVE_TPM_PCR7_INFO;

typedef struct _FVE_TPM_PCR4_INFO _FVE_TPM_PCR4_INFO, *P_FVE_TPM_PCR4_INFO;

typedef struct _FVE_TPM_PCR4_INFO *PFVE_TPM_PCR4_INFO;

typedef struct _FVE_UEFI_VARIABLE_INFO _FVE_UEFI_VARIABLE_INFO, *P_FVE_UEFI_VARIABLE_INFO;

typedef struct _FVE_UEFI_VARIABLE_INFO *PFVE_UEFI_VARIABLE_INFO;

struct _FVE_AUTH_PASSPHRASE {
    WCHAR ClearPassPhrase[257];
    BYTE HashedPassPhrase[32];
    BYTE Salt[16];
};

struct _FVE_AUTH_PRIVATE_KEY {
    NCRYPT_KEY_HANDLE KspKeyHandle;
    HCRYPTPROV CspProviderHandle;
    HCRYPTKEY CspKeyHandle;
    DWORD KeySpec;
};

struct _FVE_TPM_PCR7_INFO {
    PFVE_UEFI_VARIABLE_INFO PlatformKeyVariableInfo;
    PFVE_UEFI_VARIABLE_INFO KekDatabaseVariableInfo;
    PFVE_UEFI_VARIABLE_INFO AllowedDatabaseVariableInfo;
    PFVE_UEFI_VARIABLE_INFO ForbiddenDatabaseVariableInfo;
    PBYTE OsLoaderAuthoritySignature;
    ULONG OsLoaderAuthoritySignatureSizeBytes;
    ULONG CountSeparatorEvents;
};

struct _FVE_AUTH_PREDICTED_TPM_INFO {
    PFVE_TPM_STATE FveTpmState;
};

struct _FVE_AUTH_RECOVERY_PASSWORD {
    USHORT Block[8];
};

struct _FVE_AUTH_INFO_CLEAR_KEY {
    UCHAR Count;
};

struct _FVE_AUTH_TPM {
    ULONG PcrBitmap;
};

struct _FVE_AUTH_PIN {
    BYTE HashedPin[32];
};

struct _FVE_AUTH_EXTERNAL_KEY {
    BYTE Key[32];
};

struct _FVE_AUTH_PUBLIC_KEY {
    BCRYPT_KEY_HANDLE Handle;
    ULONG BlobSize;
    PBYTE Blob;
};

struct _FVE_AUTH_INFO_PUBLIC_KEY {
    ULONG ExportedPublicKeySize;
    ULONG ExportedPublicKeyOffset;
    ULONG BlobSize;
    ULONG BlobOffset;
};

union _union_451 {
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
};

struct _FVE_AUTH_ELEMENT {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG ElementFlags;
    ULONG ElementType;
    union _union_451 Data;
};

struct _FVE_UEFI_VARIABLE_INFO {
    PBYTE UEFIVariableValue;
    ULONG UEFIVariableSizeBytes;
};

union _union_418 {
    PFVE_TPM_PCR7_INFO FveTpmPcr7Info;
    PFVE_TPM_PCR4_INFO FveTpmPcr4Info;
};

struct _FVE_TPM_PROTECTOR_INFO {
    UINT32 TpmPcrIndex;
    union _union_418 PredictiveSealInfo;
};

struct _FVE_TPM_STATE_ {
    PVOID TpmContext;
    ULONG FveTpmProtectorInfoCount;
    PFVE_TPM_PROTECTOR_INFO FveTpmProtectorInfo;
};

struct _FVE_TPM_PCR4_INFO {
    WCHAR BootMgrFilePath[0];
};

typedef struct _FVE_AUTH_INFORMATION _FVE_AUTH_INFORMATION, *P_FVE_AUTH_INFORMATION;

typedef struct _FVE_AUTH_ELEMENT *PFVE_AUTH_ELEMENT;

struct _FVE_AUTH_INFORMATION {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG AuthFlags;
    ULONG ElementsCount;
    PFVE_AUTH_ELEMENT *Elements;
    PCWSTR Description;
    FILETIME CreationTime;
    GUID Identifier;
};

typedef struct _FVE_DATUM_STRETCH_KEY _FVE_DATUM_STRETCH_KEY, *P_FVE_DATUM_STRETCH_KEY;

struct _FVE_DATUM_STRETCH_KEY {
    FVE_DATUM h;
    enum KEY_TYPES EncryptionMethod;
    short KeyFlags;
    byte Salt[16];
    FVE_DATUM_KEY **Datums;
};

typedef struct _FVE_DE_SUPPORT _FVE_DE_SUPPORT, *P_FVE_DE_SUPPORT;

typedef long HRESULT;

struct _FVE_DE_SUPPORT {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG QueryFlags;
    HRESULT SupportStatus;
    ULONG SupportFlags;
};

typedef enum _FVE_DEVICE_TYPE {
    FVE_DEVICE_UNKNOWN=-1,
    FVE_DEVICE_UNSUPPORTED=0,
    FVE_DEVICE_VOLUME=1,
    FVE_DEVICE_CSV_VOLUME=2,
    FVE_DEVICE_MAX=3
} _FVE_DEVICE_TYPE;

typedef struct _FVE_FIND_DATA_V1 _FVE_FIND_DATA_V1, *P_FVE_FIND_DATA_V1;

typedef enum _FVE_DEVICE_TYPE FVE_DEVICE_TYPE;

struct _FVE_FIND_DATA_V1 {
    ULONG FveFindVersion;
    FVE_DEVICE_TYPE DevType;
};

typedef enum _FVE_HANDLE_TYPE {
    FVE_HANDLE_UNKNOWN=-1,
    FVE_HANDLE_FVE=0,
    FVE_HANDLE_NONFVE=1,
    FVE_HANDLE_MAX=2
} _FVE_HANDLE_TYPE;

typedef enum _FVE_INTERFACE_TYPE {
    FVE_INTERFACE_UNKNOWN=-1,
    FVE_INTERFACE_SEI=0,
    FVE_INTERFACE_SYS=1,
    FVE_INTERFACE_HEI=2,
    FVE_INTERFACE_MAX=3
} _FVE_INTERFACE_TYPE;

typedef enum _FVE_PROTECTOR_TYPE {
    FveKeyProtTypeUnknown=0,
    FveKeyProtTypeTpm=1,
    FveKeyProtTypeKey=2,
    FveKeyProtTypePassword=3,
    FveKeyProtTypeTpmAndPin=4,
    FveKeyProtTypeTpmAndKey=5,
    FveKeyProtTypeTpmAndPinAndKey=6,
    FveKeyProtTypeCertificate=7,
    FveKeyProtTypePassPhrase=8,
    FveKeyProtTypeTpmAndCertificate=9,
    FveKeyProtTypeDpapiNg=10
} _FVE_PROTECTOR_TYPE;

typedef enum _FVE_QUERY_TYPE {
    FVE_QUERY_UNKNOWN=0,
    FVE_QUERY_UNSUPPORTED=1,
    FVE_QUERY_VOLUMES=2,
    FVE_QUERY_CSV_VOLUMES=3,
    FVE_QUERY_DE_NOT_INITIALIZED=4,
    FVE_QUERY_WCOS_SECURITY_INFO=5,
    FVE_QUERY_MAX=6
} _FVE_QUERY_TYPE;

typedef enum _FVE_SCENARIO_TYPE {
    FVE_SCENARIO_UNKNOWN=-1,
    FVE_SCENARIO_DEFAULT=0,
    FVE_SCENARIO_KEY_ROLL=1,
    FVE_SCENARIO_BOOT_COMPONENT_UPDATE=2,
    FVE_SCENARIO_UNDEFINED_SKIP_CHECKS=3
} _FVE_SCENARIO_TYPE;

typedef enum _FVE_SECUREBOOT_BINDING_STATE {
    FVE_SECUREBOOT_BINDING_UNKNOWN=-1,
    FVE_SECUREBOOT_BINDING_NOT_POSSIBLE=0,
    FVE_SECUREBOOT_BINDING_DISABLED_BY_POLICY=1,
    FVE_SECUREBOOT_BINDING_POSSIBLE=2,
    FVE_SECUREBOOT_BINDING_BOUND=3
} _FVE_SECUREBOOT_BINDING_STATE;

typedef struct _FVE_STATUS_V1 _FVE_STATUS_V1, *P_FVE_STATUS_V1;

struct _FVE_STATUS_V1 {
    ULONG StructureSize;
    ULONG StructureVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
};

typedef struct _FVE_STATUS_V2 _FVE_STATUS_V2, *P_FVE_STATUS_V2;

struct _FVE_STATUS_V2 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
};

typedef struct _FVE_STATUS_V3 _FVE_STATUS_V3, *P_FVE_STATUS_V3;

typedef longlong LONGLONG;

struct _FVE_STATUS_V3 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
};

typedef struct _FVE_STATUS_V4 _FVE_STATUS_V4, *P_FVE_STATUS_V4;

struct _FVE_STATUS_V4 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
};

typedef struct _FVE_STATUS_V5 _FVE_STATUS_V5, *P_FVE_STATUS_V5;

typedef union _union_426 _union_426, *P_union_426;

typedef struct _struct_427 _struct_427, *P_struct_427;

typedef UCHAR BOOLEAN;

struct _struct_427 {
    BOOLEAN WimBootVolume:1;
    BOOLEAN WimBootHashCompleted:1;
};

union _union_426 {
    ULONGLONG ExtendedFlags2;
    struct _struct_427 field1;
};

struct _FVE_STATUS_V5 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union _union_426 field13_0x50;
};

typedef struct _FVE_STATUS_V6 _FVE_STATUS_V6, *P_FVE_STATUS_V6;

typedef union _union_429 _union_429, *P_union_429;

typedef struct _struct_430 _struct_430, *P_struct_430;

struct _struct_430 {
    BOOLEAN WimBootVolume:1;
    BOOLEAN WimBootHashCompleted:1;
    BOOLEAN IceIsUsedForFve:1;
    BOOLEAN IsEfiEsp:1;
    BOOLEAN IsRecovery:1;
    BOOLEAN WcosDePolicy:1;
    BOOLEAN WcosOsData:1;
    BOOLEAN WcosPreInstalled:1;
    BOOLEAN WcosUserData:1;
    BOOLEAN WcosMainOs:1;
    BOOLEAN WcosEfiEsp:1;
    BOOLEAN WcosBsp:1;
};

union _union_429 {
    ULONGLONG ExtendedFlags2;
    struct _struct_430 field1;
};

struct _FVE_STATUS_V6 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union _union_429 field13_0x50;
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
};

typedef struct _FVE_STATUS_V7 _FVE_STATUS_V7, *P_FVE_STATUS_V7;

typedef union _union_432 _union_432, *P_union_432;

typedef struct _struct_433 _struct_433, *P_struct_433;

struct _struct_433 {
    BOOLEAN WimBootVolume:1;
    BOOLEAN WimBootHashCompleted:1;
    BOOLEAN IceIsUsedForFve:1;
    BOOLEAN IsEfiEsp:1;
    BOOLEAN IsRecovery:1;
    BOOLEAN WcosDePolicy:1;
    BOOLEAN WcosOsData:1;
    BOOLEAN WcosPreInstalled:1;
    BOOLEAN WcosUserData:1;
    BOOLEAN WcosMainOs:1;
    BOOLEAN WcosEfiEsp:1;
    BOOLEAN WcosBsp:1;
    BOOLEAN WcosWsp:1;
};

union _union_432 {
    ULONGLONG ExtendedFlags2;
    struct _struct_433 field1;
};

struct _FVE_STATUS_V7 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union _union_432 field13_0x50;
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
    ULONG WcosBspProtectLevel;
    ULONG WcosWspProtectLevel;
};

typedef struct _FVE_STATUS_V8 _FVE_STATUS_V8, *P_FVE_STATUS_V8;

typedef union _union_435 _union_435, *P_union_435;

typedef struct _struct_436 _struct_436, *P_struct_436;

struct _struct_436 {
    BOOLEAN WimBootVolume:1;
    BOOLEAN WimBootHashCompleted:1;
    BOOLEAN IceIsUsedForFve:1;
    BOOLEAN IsEfiEsp:1;
    BOOLEAN IsRecovery:1;
    BOOLEAN WcosDePolicy:1;
    BOOLEAN WcosOsData:1;
    BOOLEAN WcosPreInstalled:1;
    BOOLEAN WcosUserData:1;
    BOOLEAN WcosMainOs:1;
    BOOLEAN WcosEfiEsp:1;
    BOOLEAN WcosBsp:1;
    BOOLEAN WcosWsp:1;
    BOOLEAN WcosDpp:1;
};

union _union_435 {
    ULONGLONG ExtendedFlags2;
    struct _struct_436 field1;
};

struct _FVE_STATUS_V8 {
    ULONG StructureSize;
    ULONG StructureVersion;
    USHORT FveVersion;
    ULONG Flags;
    double ConvertedPercent;
    HRESULT LastConvertStatus;
    LONGLONG VolArriveTime;
    double WipedPercent;
    ULONG WipeState;
    ULONG WipeCount;
    ULONGLONG ExtendedFlags;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    union _union_435 field13_0x50;
    ULONG WcosOsMainProtectLevel;
    ULONG WcosOsDataProtectLevel;
    ULONG WcosPreInstalledProtectLevel;
    ULONG WcosUserDataProtectLevel;
    ULONG WcosBspProtectLevel;
    ULONG WcosWspProtectLevel;
    ULONG WcosDppProtectLevel;
};

typedef struct _FVE_TPM_CAPS _FVE_TPM_CAPS, *P_FVE_TPM_CAPS;

struct _FVE_TPM_CAPS {
    ULONG StructureSize;
    ULONG StructureVersion;
    HRESULT TpmStatus;
    ULONG Flags;
};

typedef struct _FVE_TPM_CAPS_TPM_PRESENCE _FVE_TPM_CAPS_TPM_PRESENCE, *P_FVE_TPM_CAPS_TPM_PRESENCE;

struct _FVE_TPM_CAPS_TPM_PRESENCE {
    ULONG StructureSize;
    ULONG StructureVersion;
    HRESULT NotUsed;
    ULONG NotUsed2;
    BOOL TpmPresent;
};

typedef struct _FVE_TPM_INFO_ _FVE_TPM_INFO_, *P_FVE_TPM_INFO_;

struct _FVE_TPM_INFO_ {
    ULONG FveTpmInfoVersion;
    PFVE_TPM_STATE TpmStateInfo;
};

typedef struct _FVE_WCOS_SEQURITY_INFO_REQUEST _FVE_WCOS_SEQURITY_INFO_REQUEST, *P_FVE_WCOS_SEQURITY_INFO_REQUEST;

struct _FVE_WCOS_SEQURITY_INFO_REQUEST {
    USHORT Version;
    USHORT Size;
    ULONG CompletionWaitTime;
};

typedef struct _FVE_WCOS_SEQURITY_INFO_RESPONSE _FVE_WCOS_SEQURITY_INFO_RESPONSE, *P_FVE_WCOS_SEQURITY_INFO_RESPONSE;

struct _FVE_WCOS_SEQURITY_INFO_RESPONSE {
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
};

typedef enum _FVE_WIPING_STATE {
    FVE_WIPING_STATE_UNSPECIFIED=0,
    FVE_WIPING_STATE_INACTIVE=1,
    FVE_WIPING_STATE_PENDING=2,
    FVE_WIPING_STATE_STOPPED=3,
    FVE_WIPING_STATE_INPROGRESS=4
} _FVE_WIPING_STATE;

typedef struct _HMAC_Info _HMAC_Info, *P_HMAC_Info;

struct _HMAC_Info {
    ALG_ID HashAlgid;
    BYTE *pbInnerString;
    DWORD cbInnerString;
    BYTE *pbOuterString;
    DWORD cbOuterString;
};

typedef struct _HTTPSPolicyCallbackData _HTTPSPolicyCallbackData, *P_HTTPSPolicyCallbackData;

typedef union _union_392 _union_392, *P_union_392;

union _union_392 {
    DWORD cbStruct;
    DWORD cbSize;
};

struct _HTTPSPolicyCallbackData {
    union _union_392 u;
    DWORD dwAuthType;
    DWORD fdwChecks;
    WCHAR *pwszServerName;
};

typedef struct _KEY_TYPE_SUBTYPE _KEY_TYPE_SUBTYPE, *P_KEY_TYPE_SUBTYPE;

struct _KEY_TYPE_SUBTYPE {
    DWORD dwKeySpec;
    GUID Type;
    GUID Subtype;
};

typedef struct _NCRYPT_CIPHER_PADDING_INFO _NCRYPT_CIPHER_PADDING_INFO, *P_NCRYPT_CIPHER_PADDING_INFO;

struct _NCRYPT_CIPHER_PADDING_INFO {
    ULONG cbSize;
    DWORD dwFlags;
    PUCHAR pbIV;
    ULONG cbIV;
    PUCHAR pbOtherInfo;
    ULONG cbOtherInfo;
};

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE _NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE, *P_NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE;

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_HEADER _NCRYPT_EXPORTED_ISOLATED_KEY_HEADER, *P_NCRYPT_EXPORTED_ISOLATED_KEY_HEADER;

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_HEADER NCRYPT_EXPORTED_ISOLATED_KEY_HEADER;

struct _NCRYPT_EXPORTED_ISOLATED_KEY_HEADER {
    ULONG Version;
    ULONG KeyUsage;
    ULONG PerBootKey:1;
    ULONG Reserved:31;
    ULONG cbAlgName;
    ULONG cbNonce;
    ULONG cbAuthTag;
    ULONG cbWrappingKey;
    ULONG cbIsolatedKey;
};

struct _NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE {
    NCRYPT_EXPORTED_ISOLATED_KEY_HEADER Header;
};

typedef struct _NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES _NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES, *P_NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES;

struct _NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES {
    ULONG Version;
    ULONG Flags;
    ULONG cbPublicKeyBlob;
};

typedef struct _NCRYPT_KEY_ATTEST_PADDING_INFO _NCRYPT_KEY_ATTEST_PADDING_INFO, *P_NCRYPT_KEY_ATTEST_PADDING_INFO;

struct _NCRYPT_KEY_ATTEST_PADDING_INFO {
    ULONG magic;
    PUCHAR pbKeyBlob;
    ULONG cbKeyBlob;
    PUCHAR pbKeyAuth;
    ULONG cbKeyAuth;
};

typedef struct _NCRYPT_KEY_BLOB_HEADER _NCRYPT_KEY_BLOB_HEADER, *P_NCRYPT_KEY_BLOB_HEADER;

struct _NCRYPT_KEY_BLOB_HEADER {
    ULONG cbSize;
    ULONG dwMagic;
    ULONG cbAlgName;
    ULONG cbKeyData;
};

typedef struct _NCRYPT_PLATFORM_ATTEST_PADDING_INFO _NCRYPT_PLATFORM_ATTEST_PADDING_INFO, *P_NCRYPT_PLATFORM_ATTEST_PADDING_INFO;

struct _NCRYPT_PLATFORM_ATTEST_PADDING_INFO {
    ULONG magic;
    ULONG pcrMask;
};

typedef struct _NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT _NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT, *P_NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT;

struct _NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT {
    ULONG Magic;
    ULONG Version;
    ULONG pcrAlg;
    ULONG cbSignature;
    ULONG cbQuote;
    ULONG cbPcrs;
};

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS _NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS, *P_NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS;

struct _NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS {
    ULONG Version;
    ULONGLONG TrustletId;
    ULONG MinSvn;
    ULONG FlagsMask;
    ULONG FlagsExpected;
    ULONG AllowDebugging:1;
    ULONG Reserved:31;
};

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_STATEMENT _NCRYPT_VSM_KEY_ATTESTATION_STATEMENT, *P_NCRYPT_VSM_KEY_ATTESTATION_STATEMENT;

struct _NCRYPT_VSM_KEY_ATTESTATION_STATEMENT {
    ULONG Magic;
    ULONG Version;
    ULONG cbSignature;
    ULONG cbReport;
    ULONG cbAttributes;
};

typedef struct _NCryptAlgorithmName _NCryptAlgorithmName, *P_NCryptAlgorithmName;

struct _NCryptAlgorithmName {
    LPWSTR pszName;
    DWORD dwClass;
    DWORD dwAlgOperations;
    DWORD dwFlags;
};

typedef struct _OCSP_BASIC_RESPONSE_ENTRY _OCSP_BASIC_RESPONSE_ENTRY, *P_OCSP_BASIC_RESPONSE_ENTRY;

typedef struct _OCSP_CERT_ID _OCSP_CERT_ID, *P_OCSP_CERT_ID;

typedef struct _OCSP_CERT_ID OCSP_CERT_ID;

typedef union _union_255 _union_255, *P_union_255;

typedef struct _OCSP_BASIC_REVOKED_INFO _OCSP_BASIC_REVOKED_INFO, *P_OCSP_BASIC_REVOKED_INFO;

typedef struct _OCSP_BASIC_REVOKED_INFO *POCSP_BASIC_REVOKED_INFO;

struct _OCSP_BASIC_REVOKED_INFO {
    FILETIME RevocationDate;
    DWORD dwCrlReasonCode;
};

struct _OCSP_CERT_ID {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_HASH_BLOB IssuerNameHash;
    CRYPT_HASH_BLOB IssuerKeyHash;
    CRYPT_INTEGER_BLOB SerialNumber;
};

union _union_255 {
    POCSP_BASIC_REVOKED_INFO pRevokedInfo;
};

struct _OCSP_BASIC_RESPONSE_ENTRY {
    OCSP_CERT_ID CertId;
    DWORD dwCertStatus;
    union _union_255 u;
    FILETIME ThisUpdate;
    FILETIME NextUpdate;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _OCSP_BASIC_RESPONSE_INFO _OCSP_BASIC_RESPONSE_INFO, *P_OCSP_BASIC_RESPONSE_INFO;

typedef union _union_257 _union_257, *P_union_257;

typedef struct _OCSP_BASIC_RESPONSE_ENTRY *POCSP_BASIC_RESPONSE_ENTRY;

union _union_257 {
    CERT_NAME_BLOB ByNameResponderId;
    CRYPT_HASH_BLOB ByKeyResponderId;
};

struct _OCSP_BASIC_RESPONSE_INFO {
    DWORD dwVersion;
    DWORD dwResponderIdChoice;
    union _union_257 u;
    FILETIME ProducedAt;
    DWORD cResponseEntry;
    POCSP_BASIC_RESPONSE_ENTRY rgResponseEntry;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _OCSP_BASIC_SIGNED_RESPONSE_INFO _OCSP_BASIC_SIGNED_RESPONSE_INFO, *P_OCSP_BASIC_SIGNED_RESPONSE_INFO;

typedef struct _OCSP_SIGNATURE_INFO _OCSP_SIGNATURE_INFO, *P_OCSP_SIGNATURE_INFO;

typedef struct _OCSP_SIGNATURE_INFO OCSP_SIGNATURE_INFO;

struct _OCSP_SIGNATURE_INFO {
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CRYPT_BIT_BLOB Signature;
    DWORD cCertEncoded;
    PCERT_BLOB rgCertEncoded;
};

struct _OCSP_BASIC_SIGNED_RESPONSE_INFO {
    CRYPT_DER_BLOB ToBeSigned;
    OCSP_SIGNATURE_INFO SignatureInfo;
};

typedef struct _OCSP_REQUEST_ENTRY _OCSP_REQUEST_ENTRY, *P_OCSP_REQUEST_ENTRY;

struct _OCSP_REQUEST_ENTRY {
    OCSP_CERT_ID CertId;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _OCSP_REQUEST_INFO _OCSP_REQUEST_INFO, *P_OCSP_REQUEST_INFO;

typedef struct _OCSP_REQUEST_ENTRY *POCSP_REQUEST_ENTRY;

struct _OCSP_REQUEST_INFO {
    DWORD dwVersion;
    PCERT_ALT_NAME_ENTRY pRequestorName;
    DWORD cRequestEntry;
    POCSP_REQUEST_ENTRY rgRequestEntry;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _OCSP_RESPONSE_INFO _OCSP_RESPONSE_INFO, *P_OCSP_RESPONSE_INFO;

struct _OCSP_RESPONSE_INFO {
    DWORD dwStatus;
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Value;
};

typedef struct _OCSP_SIGNED_REQUEST_INFO _OCSP_SIGNED_REQUEST_INFO, *P_OCSP_SIGNED_REQUEST_INFO;

typedef struct _OCSP_SIGNATURE_INFO *POCSP_SIGNATURE_INFO;

struct _OCSP_SIGNED_REQUEST_INFO {
    CRYPT_DER_BLOB ToBeSigned;
    POCSP_SIGNATURE_INFO pOptionalSignatureInfo;
};

typedef struct _PKCS12_PBES2_EXPORT_PARAMS _PKCS12_PBES2_EXPORT_PARAMS, *P_PKCS12_PBES2_EXPORT_PARAMS;

struct _PKCS12_PBES2_EXPORT_PARAMS {
    DWORD dwSize;
    PVOID hNcryptDescriptor;
    LPWSTR pwszPbes2Alg;
};

typedef struct _PRIVKEYVER3 _PRIVKEYVER3, *P_PRIVKEYVER3;

typedef struct _DSSSEED DSSSEED;

struct _PRIVKEYVER3 {
    DWORD magic;
    DWORD bitlenP;
    DWORD bitlenQ;
    DWORD bitlenJ;
    DWORD bitlenX;
    DSSSEED DSSSeed;
};

typedef struct _PROV_ENUMALGS _PROV_ENUMALGS, *P_PROV_ENUMALGS;

struct _PROV_ENUMALGS {
    ALG_ID aiAlgid;
    DWORD dwBitLen;
    DWORD dwNameLen;
    CHAR szName[20];
};

typedef struct _PROV_ENUMALGS_EX _PROV_ENUMALGS_EX, *P_PROV_ENUMALGS_EX;

struct _PROV_ENUMALGS_EX {
    ALG_ID aiAlgid;
    DWORD dwDefaultLen;
    DWORD dwMinLen;
    DWORD dwMaxLen;
    DWORD dwProtocols;
    DWORD dwNameLen;
    CHAR szName[20];
    DWORD dwLongNameLen;
    CHAR szLongName[40];
};

typedef struct _PUBKEY _PUBKEY, *P_PUBKEY;

struct _PUBKEY {
    DWORD magic;
    DWORD bitlen;
};

typedef struct _PUBKEYVER3 _PUBKEYVER3, *P_PUBKEYVER3;

struct _PUBKEYVER3 {
    DWORD magic;
    DWORD bitlenP;
    DWORD bitlenQ;
    DWORD bitlenJ;
    DSSSEED DSSSeed;
};

typedef struct _PUBLICKEYSTRUC _PUBLICKEYSTRUC, *P_PUBLICKEYSTRUC;

struct _PUBLICKEYSTRUC {
    BYTE bType;
    BYTE bVersion;
    WORD reserved;
    ALG_ID aiKeyAlg;
};

typedef struct _RSAPUBKEY _RSAPUBKEY, *P_RSAPUBKEY;

struct _RSAPUBKEY {
    DWORD magic;
    DWORD bitlen;
    DWORD pubexp;
};

typedef struct _SCHANNEL_ALG _SCHANNEL_ALG, *P_SCHANNEL_ALG;

struct _SCHANNEL_ALG {
    DWORD dwUse;
    ALG_ID Algid;
    DWORD cBits;
    DWORD dwFlags;
    DWORD dwReserved;
};

typedef struct _SSL_ECCKEY_BLOB _SSL_ECCKEY_BLOB, *P_SSL_ECCKEY_BLOB;

struct _SSL_ECCKEY_BLOB {
    ULONG dwCurveType;
    ULONG cbKey;
};

typedef struct _SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS _SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS, *P_SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS;

struct _SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    DWORD dwErrorLevel;
    DWORD dwErrorCategory;
    DWORD dwReserved;
    WCHAR wszErrorText[256];
};

typedef struct _SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA _SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA, *P_SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA;

struct _SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    DWORD dwReserved;
    LPWSTR pwszServerName;
    LPSTR rgpszHpkpValue[2];
};

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA, *P_SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA;

struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    DWORD dwReserved;
    PCWSTR pwszServerName;
};

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS, *P_SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS;

struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    LONG lError;
    WCHAR wszErrorText[512];
};

typedef struct _ADA_GP_OPTIONS ADA_GP_OPTIONS;

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef enum AuthFlagsEnum {
    N/AFlag1=65536,
    TPMFlag=131072,
    USBFlag=262144,
    RecoveryPasswordFlag=524288,
    PINFlag=1048576,
    CertificateFlag=2097152,
    N/AFlag2=4194304,
    PassPhraseFlag=8388608
} AuthFlagsEnum;

typedef enum AuthFlagShifts {
    TPMShift=17,
    USBShift=18,
    PasswordShift=19,
    PINShift=20,
    CertificateShift=21,
    N/AShift=22,
    PassPhraseShift=23
} AuthFlagShifts;

typedef struct _BCRYPT_DSA_KEY_BLOB_V2 BCRYPT_DSA_KEY_BLOB_V2;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER_V2 BCRYPT_DSA_PARAMETER_HEADER_V2;

typedef struct _BCRYPT_ECC_CURVE_NAMES BCRYPT_ECC_CURVE_NAMES;

typedef struct _BCRYPT_ECCFULLKEY_BLOB BCRYPT_ECCFULLKEY_BLOB;

typedef struct _BCRYPT_MULTI_HASH_OPERATION BCRYPT_MULTI_HASH_OPERATION;

typedef struct _BCRYPT_MULTI_OBJECT_LENGTH_STRUCT BCRYPT_MULTI_OBJECT_LENGTH_STRUCT;

typedef enum enum_89 {
    BCRYPT_OPERATION_TYPE_HASH=1
} enum_89;

typedef enum enum_89 BCRYPT_MULTI_OPERATION_TYPE;


/* WARNING! conflicting data type names: /CONFLICTS python2.h/BCryptBufferDesc - /bcrypt.h/BCryptBufferDesc */

typedef struct _CERT_ACCESS_DESCRIPTION CERT_ACCESS_DESCRIPTION;

typedef struct _CERT_AUTHORITY_INFO_ACCESS CERT_AUTHORITY_INFO_ACCESS;

typedef struct _CERT_AUTHORITY_KEY_ID2_INFO CERT_AUTHORITY_KEY_ID2_INFO;

typedef struct _CERT_BIOMETRIC_EXT_INFO CERT_BIOMETRIC_EXT_INFO;

typedef struct _CERT_CHAIN CERT_CHAIN;

typedef struct _CERT_CHAIN_ELEMENT CERT_CHAIN_ELEMENT;

typedef struct _CERT_CHAIN_ENGINE_CONFIG CERT_CHAIN_ENGINE_CONFIG;

typedef struct _CERT_CHAIN_FIND_BY_ISSUER_PARA CERT_CHAIN_FIND_BY_ISSUER_PARA;

typedef struct _CERT_CHAIN_FIND_BY_ISSUER_PARA CERT_CHAIN_FIND_ISSUER_PARA;

typedef struct _CERT_CRL_CONTEXT_PAIR CERT_CRL_CONTEXT_PAIR;

typedef struct _CERT_EXTENSIONS CERT_EXTENSIONS;

typedef struct _CERT_GENERAL_SUBTREE CERT_GENERAL_SUBTREE;

typedef struct _CERT_INFO CERT_INFO;

typedef struct _CERT_KEY_ATTRIBUTES_INFO CERT_KEY_ATTRIBUTES_INFO;

typedef struct _CERT_KEY_USAGE_RESTRICTION_INFO CERT_KEY_USAGE_RESTRICTION_INFO;

typedef struct _CERT_LOGOTYPE_AUDIO CERT_LOGOTYPE_AUDIO;

typedef struct _CERT_LOGOTYPE_DATA CERT_LOGOTYPE_DATA;

typedef struct _CERT_LOGOTYPE_EXT_INFO CERT_LOGOTYPE_EXT_INFO;

typedef struct _CERT_LOGOTYPE_IMAGE CERT_LOGOTYPE_IMAGE;

typedef struct _CERT_LOGOTYPE_REFERENCE CERT_LOGOTYPE_REFERENCE;

typedef struct _CERT_NAME_CONSTRAINTS_INFO CERT_NAME_CONSTRAINTS_INFO;

typedef struct _CERT_NAME_INFO CERT_NAME_INFO;

typedef struct _CERT_OR_CRL_BUNDLE CERT_OR_CRL_BUNDLE;

typedef struct _CERT_OTHER_LOGOTYPE_INFO CERT_OTHER_LOGOTYPE_INFO;

typedef struct _CERT_POLICY_MAPPINGS_INFO CERT_POLICY_MAPPINGS_INFO;

typedef struct _CERT_QC_STATEMENTS_EXT_INFO CERT_QC_STATEMENTS_EXT_INFO;

typedef struct _CERT_RDN CERT_RDN;

typedef struct _CERT_REQUEST_INFO CERT_REQUEST_INFO;

typedef struct _CERT_REVOCATION_CHAIN_PARA CERT_REVOCATION_CHAIN_PARA;

typedef struct _CERT_REVOCATION_CRL_INFO CERT_REVOCATION_CRL_INFO;

typedef struct _CERT_REVOCATION_INFO CERT_REVOCATION_INFO;

typedef struct _CERT_REVOCATION_PARA CERT_REVOCATION_PARA;

typedef struct _CERT_SELECT_CHAIN_PARA CERT_SELECT_CHAIN_PARA;

typedef struct _CERT_SELECT_CRITERIA CERT_SELECT_CRITERIA;

typedef struct _CERT_SERVER_OCSP_RESPONSE_OPEN_PARA CERT_SERVER_OCSP_RESPONSE_OPEN_PARA;

typedef struct _CERT_SIMPLE_CHAIN CERT_SIMPLE_CHAIN;

typedef struct _CERT_STRONG_SIGN_PARA CERT_STRONG_SIGN_PARA;

typedef struct _CERT_STRONG_SIGN_SERIALIZED_INFO CERT_STRONG_SIGN_SERIALIZED_INFO;

typedef struct _CERT_AUTHORITY_INFO_ACCESS CERT_SUBJECT_INFO_ACCESS;

typedef struct _CERT_SUPPORTED_ALGORITHM_INFO CERT_SUPPORTED_ALGORITHM_INFO;

typedef struct _CERT_TPM_SPECIFICATION_INFO CERT_TPM_SPECIFICATION_INFO;

typedef struct _CERT_TRUST_LIST_INFO CERT_TRUST_LIST_INFO;

typedef struct _CERT_X942_DH_PARAMETERS CERT_X942_DH_PARAMETERS;

typedef enum CertKeyType {
    KeyTypeOther=0,
    KeyTypeVirtualSmartCard=1,
    KeyTypePhysicalSmartCard=2,
    KeyTypePassport=3,
    KeyTypePassportRemote=4,
    KeyTypePassportSmartCard=5,
    KeyTypeHardware=6,
    KeyTypeSoftware=7,
    KeyTypeSelfSigned=8
} CertKeyType;

typedef struct _CMC_ADD_ATTRIBUTES_INFO CMC_ADD_ATTRIBUTES_INFO;

typedef struct _CMC_ADD_EXTENSIONS_INFO CMC_ADD_EXTENSIONS_INFO;

typedef struct _CMC_DATA_INFO CMC_DATA_INFO;

typedef struct _CMC_RESPONSE_INFO CMC_RESPONSE_INFO;

typedef struct _CMC_STATUS_INFO CMC_STATUS_INFO;

typedef struct _CMC_TAGGED_ATTRIBUTE CMC_TAGGED_ATTRIBUTE;

typedef struct _CMC_TAGGED_REQUEST CMC_TAGGED_REQUEST;

typedef CRYPT_ATTRIBUTES CMSG_ATTR;

typedef struct _CMSG_CMS_RECIPIENT_INFO CMSG_CMS_RECIPIENT_INFO;

typedef struct _CMSG_CMS_SIGNER_INFO CMSG_CMS_SIGNER_INFO;

typedef struct _CMSG_CONTENT_ENCRYPT_INFO CMSG_CONTENT_ENCRYPT_INFO;

typedef struct _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA CMSG_CTRL_KEY_AGREE_DECRYPT_PARA;

typedef struct _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA CMSG_CTRL_KEY_TRANS_DECRYPT_PARA;

typedef struct _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA CMSG_CTRL_MAIL_LIST_DECRYPT_PARA;

typedef struct _CMSG_KEY_AGREE_ENCRYPT_INFO CMSG_KEY_AGREE_ENCRYPT_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO CMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_KEY_AGREE_RECIPIENT_INFO CMSG_KEY_AGREE_RECIPIENT_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO CMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_MAIL_LIST_RECIPIENT_INFO CMSG_MAIL_LIST_RECIPIENT_INFO;

typedef struct _CMSG_RECIPIENT_ENCODE_INFO CMSG_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO CMSG_RECIPIENT_ENCRYPTED_KEY_ENCODE_INFO;

typedef struct _CMSG_RECIPIENT_ENCRYPTED_KEY_INFO CMSG_RECIPIENT_ENCRYPTED_KEY_INFO;

typedef struct _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO;

typedef struct _CMSG_SIGNER_ENCODE_INFO CMSG_SIGNER_ENCODE_INFO;

typedef struct _CMSG_SIGNER_INFO CMSG_SIGNER_INFO;

typedef struct _CRL_DIST_POINT CRL_DIST_POINT;

typedef struct _CRL_DIST_POINTS_INFO CRL_DIST_POINTS_INFO;

typedef struct _CRL_ENTRY CRL_ENTRY;

typedef struct _CRL_FIND_ISSUED_FOR_PARA CRL_FIND_ISSUED_FOR_PARA;

typedef struct _CRL_INFO CRL_INFO;

typedef struct _CRL_ISSUING_DIST_POINT CRL_ISSUING_DIST_POINT;

typedef struct _CRL_REVOCATION_INFO CRL_REVOCATION_INFO;

typedef struct _CROSS_CERT_DIST_POINTS_INFO CROSS_CERT_DIST_POINTS_INFO;

typedef struct _CRYPT_3DES_KEY_STATE CRYPT_3DES_KEY_STATE;

typedef struct _CRYPT_BLOB_ARRAY CRYPT_BLOB_ARRAY;

typedef struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;

typedef struct _CRYPT_DES_KEY_STATE CRYPT_DES_KEY_STATE;

typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO CRYPT_ECC_PRIVATE_KEY_INFO;

typedef struct _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO;

typedef struct _CRYPT_IMAGE_REG CRYPT_IMAGE_REG;

typedef struct _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE;

typedef struct _CRYPT_PKCS8_IMPORT_PARAMS CRYPT_PKCS8_IMPORT_PARAMS;

typedef struct _CRYPT_PKCS8_IMPORT_PARAMS CRYPT_PRIVATE_KEY_BLOB_AND_PARAMS;

typedef struct _CRYPT_PROVIDER_REF CRYPT_PROVIDER_REF;

typedef struct _CRYPT_PROVIDER_REFS CRYPT_PROVIDER_REFS;

typedef struct _CRYPT_PROVIDER_REG CRYPT_PROVIDER_REG;

typedef struct _CRYPT_RC4_KEY_STATE CRYPT_RC4_KEY_STATE;

typedef struct _CRYPT_RETRIEVE_AUX_INFO CRYPT_RETRIEVE_AUX_INFO;

typedef struct _CRYPT_SEQUENCE_OF_ANY CRYPT_SEQUENCE_OF_ANY;

typedef struct _CRYPT_SIGN_MESSAGE_PARA CRYPT_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_SMIME_CAPABILITIES CRYPT_SMIME_CAPABILITIES;

typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO CRYPT_TIME_STAMP_REQUEST_INFO;

typedef struct _CRYPT_TIMESTAMP_ACCURACY CRYPT_TIMESTAMP_ACCURACY;

typedef struct _CRYPT_TIMESTAMP_CONTEXT CRYPT_TIMESTAMP_CONTEXT;

typedef struct _CRYPT_TIMESTAMP_INFO CRYPT_TIMESTAMP_INFO;

typedef struct _CRYPT_TIMESTAMP_PARA CRYPT_TIMESTAMP_PARA;

typedef struct _CRYPT_TIMESTAMP_REQUEST CRYPT_TIMESTAMP_REQUEST;

typedef struct _CRYPT_TIMESTAMP_RESPONSE CRYPT_TIMESTAMP_RESPONSE;

typedef struct _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO;

typedef struct _CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO;

typedef struct _CRYPT_VERIFY_MESSAGE_PARA CRYPT_VERIFY_MESSAGE_PARA;

typedef struct _CTL_ENTRY CTL_ENTRY;

typedef struct _CTL_FIND_SUBJECT_PARA CTL_FIND_SUBJECT_PARA;

typedef struct _CTL_FIND_USAGE_PARA CTL_FIND_USAGE_PARA;

typedef struct _CTL_INFO CTL_INFO;

typedef struct _CTL_VERIFY_USAGE_STATUS CTL_VERIFY_USAGE_STATUS;

typedef enum ElementType {
    RecoveryPassword=1,
    PIN=2,
    TPM=3,
    USB=4,
    Certificate=5,
    N/A=6,
    NetworkCertificate?=7,
    PassPhrase=8,
    DpapiNg/Sid?=10,
    PredictiveTPM?=12
} ElementType;

typedef enum ENC_TYPES {
    STRETCH_KEY=4096,
    AES_CCM_256_0=8192,
    AES_CCM_256_1=8193,
    EXTERN_KEY_CIPHER=8194,
    VMK_CIPHER=8195,
    AES_CCM_256_2=8196,
    HASH_256=8197,
    AES_128_DIFFUSER=32768,
    AES_256_DIFFUSER=32769,
    AES_128_NO_DIFFUSER=32770,
    AES_256_NO_DIFFUSER=32771,
    AES_XTS_128=32772,
    AES_XTS_256=32773
} ENC_TYPES;

typedef enum enum_34 {
    BCRYPT_ECC_PRIME_SHORT_WEIERSTRASS_CURVE=1,
    BCRYPT_ECC_PRIME_TWISTED_EDWARDS_CURVE=2,
    BCRYPT_ECC_PRIME_MONTGOMERY_CURVE=3
} enum_34;

typedef enum enum_35 {
    BCRYPT_NO_CURVE_GENERATION_ALG_ID=0
} enum_35;

typedef enum enum_40 {
    DSA_HASH_ALGORITHM_SHA1=0,
    DSA_HASH_ALGORITHM_SHA256=1,
    DSA_HASH_ALGORITHM_SHA512=2
} enum_40;

typedef enum enum_41 {
    DSA_FIPS186_2=0,
    DSA_FIPS186_3=1
} enum_41;

typedef enum enum_47 {
    BCRYPT_HASH_OPERATION_HASH_DATA=1,
    BCRYPT_HASH_OPERATION_FINISH_HASH=2
} enum_47;

typedef enum enum_49 {
    BCRYPT_OPERATION_TYPE_HASH=1
} enum_49;

typedef struct _FVE_AUTH_ELEMENT FVE_AUTH_ELEMENT;

typedef struct _FVE_AUTH_INFORMATION FVE_AUTH_INFORMATION;

typedef struct _FVE_DE_SUPPORT FVE_DE_SUPPORT;

typedef struct _FVE_FIND_DATA_V1 FVE_FIND_DATA_V1;

typedef enum _FVE_HANDLE_TYPE FVE_HANDLE_TYPE;

typedef enum _FVE_INTERFACE_TYPE FVE_INTERFACE_TYPE;

typedef enum _FVE_PROTECTOR_TYPE FVE_PROTECTOR_TYPE;

typedef enum _FVE_QUERY_TYPE FVE_QUERY_TYPE;

typedef enum _FVE_SCENARIO_TYPE FVE_SCENARIO_TYPE;

typedef enum _FVE_SECUREBOOT_BINDING_STATE FVE_SECUREBOOT_BINDING_STATE;

typedef struct _FVE_STATUS_V1 FVE_STATUS_V1;

typedef struct _FVE_STATUS_V2 FVE_STATUS_V2;

typedef struct _FVE_STATUS_V3 FVE_STATUS_V3;

typedef struct _FVE_STATUS_V4 FVE_STATUS_V4;

typedef struct _FVE_STATUS_V5 FVE_STATUS_V5;

typedef struct _FVE_STATUS_V6 FVE_STATUS_V6;

typedef struct _FVE_STATUS_V7 FVE_STATUS_V7;

typedef struct _FVE_STATUS_V8 FVE_STATUS_V8;

typedef struct _FVE_TPM_CAPS FVE_TPM_CAPS;

typedef struct _FVE_TPM_CAPS_TPM_PRESENCE FVE_TPM_CAPS_TPM_PRESENCE;

typedef struct _FVE_TPM_INFO_ FVE_TPM_INFO;

typedef struct _FVE_TPM_PCR4_INFO FVE_TPM_PCR4_INFO;

typedef struct _FVE_TPM_PCR7_INFO FVE_TPM_PCR7_INFO;

typedef struct _FVE_TPM_PROTECTOR_INFO FVE_TPM_PROTECTOR_INFO;

typedef struct _FVE_TPM_STATE_ FVE_TPM_STATE;

typedef struct _FVE_UEFI_VARIABLE_INFO FVE_UEFI_VARIABLE_INFO;

typedef struct _FVE_WCOS_SEQURITY_INFO_REQUEST FVE_WCOS_SEQURITY_INFO_REQUEST;

typedef struct _FVE_WCOS_SEQURITY_INFO_RESPONSE FVE_WCOS_SEQURITY_INFO_RESPONSE;

typedef enum _FVE_WIPING_STATE FVE_WIPING_STATE;

typedef struct HashIterStruct HashIterStruct, *PHashIterStruct;

typedef longlong int64_t;

struct HashIterStruct {
    byte updateHash[32]; /* Last Hash Calculated */
    byte inputHash[32];
    byte salt[16];
    int64_t hashCount;
};

typedef struct _KEY_TYPE_SUBTYPE KEY_TYPE_SUBTYPE;

typedef struct KeyStretchData KeyStretchData, *PKeyStretchData;

struct KeyStretchData {
    FVE_DATUM_KEY *PBKDF2InputDatum; /* Pointer to a datum PBKDF2 key computation data. */
    FVE_DATUM_KEY *InputHashDatum; /* Pointer to a datum containing the hash to be stretched. */
    FVE_DATUM_KEY *SaltDatum; /* Pointer to a datum containing the salt to be used in key stretching algorithm. */
    int *HashIterations; /* Number of iterations performed by the stretch key algorithm. */
};

typedef struct NCRYPT_ALLOC_PARA NCRYPT_ALLOC_PARA, *PNCRYPT_ALLOC_PARA;

typedef LPVOID (*PFN_NCRYPT_ALLOC)(SIZE_T);

typedef void (*PFN_NCRYPT_FREE)(LPVOID);

struct NCRYPT_ALLOC_PARA {
    DWORD cbSize;
    PFN_NCRYPT_ALLOC pfnAlloc;
    PFN_NCRYPT_FREE pfnFree;
};

typedef struct _NCRYPT_CIPHER_PADDING_INFO NCRYPT_CIPHER_PADDING_INFO;

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE;

typedef struct _NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES;

typedef struct __NCRYPT_KEY_ACCESS_POLICY_BLOB NCRYPT_KEY_ACCESS_POLICY_BLOB;

typedef struct _NCRYPT_KEY_ATTEST_PADDING_INFO NCRYPT_KEY_ATTEST_PADDING_INFO;

typedef struct _NCRYPT_KEY_BLOB_HEADER NCRYPT_KEY_BLOB_HEADER;

typedef struct __NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO;

typedef struct __NCRYPT_PCP_RAW_POLICYDIGEST NCRYPT_PCP_RAW_POLICYDIGEST_INFO;

typedef struct __NCRYPT_PCP_TPM_FW_VERSION_INFO NCRYPT_PCP_TPM_FW_VERSION_INFO;

typedef struct __NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_PLATFORM_ATTEST_PADDING_INFO NCRYPT_PLATFORM_ATTEST_PADDING_INFO;

typedef struct NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER, *PNCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER;

struct NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER {
    DWORD magic;
    DWORD cbHeader;
    DWORD cbPublic;
    DWORD cbPrivate;
    DWORD cbName;
};

typedef struct _NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS;

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_STATEMENT NCRYPT_VSM_KEY_ATTESTATION_STATEMENT;

typedef BCryptBufferDesc NCryptBufferDesc;

typedef struct NCryptKeyName NCryptKeyName, *PNCryptKeyName;

struct NCryptKeyName {
    LPWSTR pszName;
    LPWSTR pszAlgid;
    DWORD dwLegacyKeySpec;
    DWORD dwFlags;
};

typedef struct NCryptProviderName NCryptProviderName, *PNCryptProviderName;

struct NCryptProviderName {
    LPWSTR pszName;
    LPWSTR pszComment;
};

typedef struct _OCSP_BASIC_RESPONSE_ENTRY OCSP_BASIC_RESPONSE_ENTRY;

typedef struct _OCSP_BASIC_RESPONSE_INFO OCSP_BASIC_RESPONSE_INFO;

typedef struct _OCSP_BASIC_SIGNED_RESPONSE_INFO OCSP_BASIC_SIGNED_RESPONSE_INFO;

typedef struct _OCSP_REQUEST_ENTRY OCSP_REQUEST_ENTRY;

typedef struct _OCSP_REQUEST_INFO OCSP_REQUEST_INFO;

typedef struct _OCSP_SIGNED_REQUEST_INFO OCSP_SIGNED_REQUEST_INFO;

typedef struct _ADA_GP_OPTIONS *PADA_GP_OPTIONS;

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA *PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS *PAUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA *PAUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

typedef struct _BCRYPT_DH_KEY_BLOB *PBCRYPT_DH_KEY_BLOB;

typedef struct _BCRYPT_DSA_KEY_BLOB *PBCRYPT_DSA_KEY_BLOB;

typedef struct _BCRYPT_DSA_KEY_BLOB_V2 *PBCRYPT_DSA_KEY_BLOB_V2;

typedef struct _BCRYPT_ECCFULLKEY_BLOB *PBCRYPT_ECCFULLKEY_BLOB;

typedef struct _BCRYPT_ECCKEY_BLOB *PBCRYPT_ECCKEY_BLOB;

typedef struct _BCRYPT_INTERFACE_VERSION *PBCRYPT_INTERFACE_VERSION;

typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER *PBCRYPT_KEY_DATA_BLOB_HEADER;


/* WARNING! conflicting data type names: /CONFLICTS python2.h/PBCryptBuffer - /bcrypt.h/PBCryptBuffer */

typedef struct _BCryptBufferDesc *PBCryptBufferDesc;

typedef BYTE *PCBYTE;

typedef CERT_CHAIN_ELEMENT *PCCERT_CHAIN_ELEMENT;

typedef CERT_CRL_CONTEXT_PAIR *PCCERT_CRL_CONTEXT_PAIR;

typedef CERT_SELECT_CHAIN_PARA *PCCERT_SELECT_CHAIN_PARA;

typedef CERT_SELECT_CRITERIA *PCCERT_SELECT_CRITERIA;

typedef CERT_SIMPLE_CHAIN *PCCERT_SIMPLE_CHAIN;

typedef CERT_STRONG_SIGN_PARA *PCCERT_STRONG_SIGN_PARA;

typedef struct _CERT_AUTHORITY_INFO_ACCESS *PCERT_AUTHORITY_INFO_ACCESS;

typedef struct _CERT_AUTHORITY_KEY_ID2_INFO *PCERT_AUTHORITY_KEY_ID2_INFO;

typedef struct _CERT_AUTHORITY_KEY_ID_INFO *PCERT_AUTHORITY_KEY_ID_INFO;

typedef struct _CERT_BASIC_CONSTRAINTS2_INFO *PCERT_BASIC_CONSTRAINTS2_INFO;

typedef struct _CERT_BASIC_CONSTRAINTS_INFO *PCERT_BASIC_CONSTRAINTS_INFO;

typedef struct _CERT_BIOMETRIC_EXT_INFO *PCERT_BIOMETRIC_EXT_INFO;

typedef struct _CERT_CHAIN *PCERT_CHAIN;

typedef struct _CERT_CHAIN_CONTEXT *PCERT_CHAIN_CONTEXT;

typedef struct _CERT_CHAIN_ENGINE_CONFIG *PCERT_CHAIN_ENGINE_CONFIG;

typedef struct _CERT_CHAIN_FIND_BY_ISSUER_PARA *PCERT_CHAIN_FIND_BY_ISSUER_PARA;

typedef struct _CERT_CHAIN_FIND_BY_ISSUER_PARA *PCERT_CHAIN_FIND_ISSUER_PARA;

typedef struct _CERT_CHAIN_POLICY_PARA *PCERT_CHAIN_POLICY_PARA;

typedef struct _CERT_CHAIN_POLICY_STATUS *PCERT_CHAIN_POLICY_STATUS;

typedef struct _CERT_CONTEXT *PCERT_CONTEXT;

typedef struct _CERT_CREATE_CONTEXT_PARA *PCERT_CREATE_CONTEXT_PARA;

typedef struct _CERT_CRL_CONTEXT_PAIR *PCERT_CRL_CONTEXT_PAIR;

typedef struct _CERT_DH_PARAMETERS *PCERT_DH_PARAMETERS;

typedef struct _CERT_DSS_PARAMETERS *PCERT_DSS_PARAMETERS;

typedef struct _CERT_ECC_SIGNATURE *PCERT_ECC_SIGNATURE;

typedef struct _CERT_EXTENSIONS *PCERT_EXTENSIONS;

typedef struct _CERT_ISSUER_SERIAL_NUMBER *PCERT_ISSUER_SERIAL_NUMBER;

typedef struct _CERT_KEY_ATTRIBUTES_INFO *PCERT_KEY_ATTRIBUTES_INFO;

typedef struct _CERT_KEY_CONTEXT *PCERT_KEY_CONTEXT;

typedef struct _CERT_KEY_USAGE_RESTRICTION_INFO *PCERT_KEY_USAGE_RESTRICTION_INFO;

typedef struct _CERT_KEYGEN_REQUEST_INFO *PCERT_KEYGEN_REQUEST_INFO;

typedef struct _CERT_LDAP_STORE_OPENED_PARA *PCERT_LDAP_STORE_OPENED_PARA;

typedef struct _CERT_LOGOTYPE_DETAILS *PCERT_LOGOTYPE_DETAILS;

typedef struct _CERT_LOGOTYPE_EXT_INFO *PCERT_LOGOTYPE_EXT_INFO;

typedef struct _CERT_NAME_CONSTRAINTS_INFO *PCERT_NAME_CONSTRAINTS_INFO;

typedef struct _CERT_NAME_INFO *PCERT_NAME_INFO;

typedef struct _CERT_NAME_VALUE *PCERT_NAME_VALUE;

typedef struct _CERT_OR_CRL_BUNDLE *PCERT_OR_CRL_BUNDLE;

typedef struct _CERT_PAIR *PCERT_PAIR;

typedef struct _CERT_PHYSICAL_STORE_INFO *PCERT_PHYSICAL_STORE_INFO;

typedef struct _CERT_POLICIES_INFO *PCERT_POLICIES_INFO;

typedef struct _CERT_POLICY95_QUALIFIER1 *PCERT_POLICY95_QUALIFIER1;

typedef struct _CERT_POLICY_CONSTRAINTS_INFO *PCERT_POLICY_CONSTRAINTS_INFO;

typedef struct _CERT_POLICY_INFO *PCERT_POLICY_INFO;

typedef struct _CERT_POLICY_MAPPINGS_INFO *PCERT_POLICY_MAPPINGS_INFO;

typedef struct _CERT_POLICY_QUALIFIER_INFO *PCERT_POLICY_QUALIFIER_INFO;

typedef struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE *PCERT_POLICY_QUALIFIER_NOTICE_REFERENCE;

typedef struct _CERT_POLICY_QUALIFIER_USER_NOTICE *PCERT_POLICY_QUALIFIER_USER_NOTICE;

typedef struct _CERT_PUBLIC_KEY_INFO *PCERT_PUBLIC_KEY_INFO;

typedef struct _CERT_QC_STATEMENTS_EXT_INFO *PCERT_QC_STATEMENTS_EXT_INFO;

typedef struct _CRYPTOAPI_BLOB *PCERT_RDN_VALUE_BLOB;

typedef struct _CERT_REGISTRY_STORE_CLIENT_GPT_PARA *PCERT_REGISTRY_STORE_CLIENT_GPT_PARA;

typedef struct _CERT_REGISTRY_STORE_ROAMING_PARA *PCERT_REGISTRY_STORE_ROAMING_PARA;

typedef struct _CERT_REQUEST_INFO *PCERT_REQUEST_INFO;

typedef struct _CERT_REVOCATION_PARA *PCERT_REVOCATION_PARA;

typedef struct _CERT_REVOCATION_STATUS *PCERT_REVOCATION_STATUS;

typedef struct _CERT_SELECT_CHAIN_PARA *PCERT_SELECT_CHAIN_PARA;

typedef struct _CERT_SELECT_CRITERIA *PCERT_SELECT_CRITERIA;

typedef struct _CERT_SERVER_OCSP_RESPONSE_CONTEXT *PCERT_SERVER_OCSP_RESPONSE_CONTEXT;

typedef struct _CERT_SERVER_OCSP_RESPONSE_OPEN_PARA *PCERT_SERVER_OCSP_RESPONSE_OPEN_PARA;

typedef struct _CERT_SIGNED_CONTENT_INFO *PCERT_SIGNED_CONTENT_INFO;

typedef struct _CERT_STORE_PROV_FIND_INFO *PCERT_STORE_PROV_FIND_INFO;

typedef struct _CERT_STORE_PROV_INFO *PCERT_STORE_PROV_INFO;

typedef struct _CERT_STRONG_SIGN_PARA *PCERT_STRONG_SIGN_PARA;

typedef struct _CERT_AUTHORITY_INFO_ACCESS *PCERT_SUBJECT_INFO_ACCESS;

typedef struct _CERT_SUPPORTED_ALGORITHM_INFO *PCERT_SUPPORTED_ALGORITHM_INFO;

typedef struct _CERT_SYSTEM_STORE_INFO *PCERT_SYSTEM_STORE_INFO;

typedef struct _CERT_SYSTEM_STORE_RELOCATE_PARA *PCERT_SYSTEM_STORE_RELOCATE_PARA;

typedef struct _CERT_TEMPLATE_EXT *PCERT_TEMPLATE_EXT;

typedef struct _CERT_TPM_SPECIFICATION_INFO *PCERT_TPM_SPECIFICATION_INFO;

typedef struct _CERT_TRUST_STATUS *PCERT_TRUST_STATUS;

typedef struct _CERT_USAGE_MATCH *PCERT_USAGE_MATCH;

typedef struct _CERT_X942_DH_PARAMETERS *PCERT_X942_DH_PARAMETERS;

typedef FVE_AUTH_DPAPI_NG *PCFVE_AUTH_DPAPI_NG;

typedef FVE_AUTH_ELEMENT *PCFVE_AUTH_ELEMENT;

typedef FVE_AUTH_EXTERNAL_KEY *PCFVE_AUTH_EXTERNAL_KEY;

typedef FVE_AUTH_INFO_PUBLIC_KEY *PCFVE_AUTH_INFO_PUBLIC_KEY;

typedef FVE_AUTH_INFORMATION *PCFVE_AUTH_INFORMATION;

typedef FVE_AUTH_PASSPHRASE *PCFVE_AUTH_PASSPHRASE;

typedef FVE_AUTH_PIN *PCFVE_AUTH_PIN;

typedef FVE_AUTH_PREDICTED_TPM_INFO *PCFVE_AUTH_PREDICTED_TPM_INFO;

typedef FVE_AUTH_PRIVATE_KEY *PCFVE_AUTH_PRIVATE_KEY;

typedef FVE_AUTH_PUBLIC_KEY *PCFVE_AUTH_PUBLIC_KEY;

typedef FVE_AUTH_RECOVERY_PASSWORD *PCFVE_AUTH_RECOVERY_PASSWORD;

typedef FVE_AUTH_TPM *PCFVE_AUTH_TPM;

typedef FVE_DE_SUPPORT *PCFVE_DE_SUPPORT;

typedef FVE_STATUS_V1 *PCFVE_STATUS_V1;

typedef FVE_STATUS_V2 *PCFVE_STATUS_V2;

typedef FVE_STATUS_V3 *PCFVE_STATUS_V3;

typedef FVE_STATUS_V4 *PCFVE_STATUS_V4;

typedef FVE_STATUS_V5 *PCFVE_STATUS_V5;

typedef FVE_STATUS_V6 *PCFVE_STATUS_V6;

typedef FVE_STATUS_V7 *PCFVE_STATUS_V7;

typedef FVE_STATUS_V8 *PCFVE_STATUS_V8;

typedef FVE_TPM_CAPS *PCFVE_TPM_CAPS;

typedef FVE_TPM_CAPS_TPM_PRESENCE *PCFVE_TPM_CAPS_TPM_PRESENCE;

typedef struct _CMC_ADD_ATTRIBUTES_INFO *PCMC_ADD_ATTRIBUTES_INFO;

typedef struct _CMC_ADD_EXTENSIONS_INFO *PCMC_ADD_EXTENSIONS_INFO;

typedef struct _CMC_DATA_INFO *PCMC_DATA_INFO;

typedef struct _CMC_RESPONSE_INFO *PCMC_RESPONSE_INFO;

typedef struct _CMC_STATUS_INFO *PCMC_STATUS_INFO;

typedef struct _CMS_DH_KEY_INFO *PCMS_DH_KEY_INFO;

typedef struct _CMS_KEY_INFO *PCMS_KEY_INFO;

typedef CRYPT_ATTRIBUTES *PCMSG_ATTR;

typedef struct _CMSG_CMS_RECIPIENT_INFO *PCMSG_CMS_RECIPIENT_INFO;

typedef struct _CMSG_CMS_SIGNER_INFO *PCMSG_CMS_SIGNER_INFO;

typedef struct _CMSG_CNG_CONTENT_DECRYPT_INFO *PCMSG_CNG_CONTENT_DECRYPT_INFO;

typedef struct _CMSG_CONTENT_ENCRYPT_INFO *PCMSG_CONTENT_ENCRYPT_INFO;

typedef struct _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA *PCMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA;

typedef struct _CMSG_CTRL_DECRYPT_PARA *PCMSG_CTRL_DECRYPT_PARA;

typedef struct _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA *PCMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA;

typedef struct _CMSG_CTRL_KEY_AGREE_DECRYPT_PARA *PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA;

typedef struct _CMSG_CTRL_KEY_TRANS_DECRYPT_PARA *PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA;

typedef struct _CMSG_CTRL_MAIL_LIST_DECRYPT_PARA *PCMSG_CTRL_MAIL_LIST_DECRYPT_PARA;

typedef struct _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA *PCMSG_CTRL_VERIFY_SIGNATURE_EX_PARA;

typedef struct _CMSG_ENCRYPTED_ENCODE_INFO *PCMSG_ENCRYPTED_ENCODE_INFO;

typedef struct _CMSG_ENVELOPED_ENCODE_INFO *PCMSG_ENVELOPED_ENCODE_INFO;

typedef struct _CMSG_HASHED_ENCODE_INFO *PCMSG_HASHED_ENCODE_INFO;

typedef struct _CMSG_KEY_AGREE_ENCRYPT_INFO *PCMSG_KEY_AGREE_ENCRYPT_INFO;

typedef struct _CMSG_KEY_TRANS_ENCRYPT_INFO *PCMSG_KEY_TRANS_ENCRYPT_INFO;

typedef struct _CMSG_MAIL_LIST_ENCRYPT_INFO *PCMSG_MAIL_LIST_ENCRYPT_INFO;

typedef struct _CMSG_RC2_AUX_INFO *PCMSG_RC2_AUX_INFO;

typedef struct _CMSG_RC4_AUX_INFO *PCMSG_RC4_AUX_INFO;

typedef struct _CMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO *PCMSG_SIGNED_AND_ENVELOPED_ENCODE_INFO;

typedef struct _CMSG_SIGNED_ENCODE_INFO *PCMSG_SIGNED_ENCODE_INFO;

typedef struct _CMSG_SP3_COMPATIBLE_AUX_INFO *PCMSG_SP3_COMPATIBLE_AUX_INFO;

typedef struct _CMSG_STREAM_INFO *PCMSG_STREAM_INFO;

typedef struct _CPS_URLS *PCPS_URLS;

typedef struct _CRL_CONTEXT *PCRL_CONTEXT;

typedef struct _CRL_DIST_POINT_NAME *PCRL_DIST_POINT_NAME;

typedef struct _CRL_DIST_POINTS_INFO *PCRL_DIST_POINTS_INFO;

typedef struct _CRL_FIND_ISSUED_FOR_PARA *PCRL_FIND_ISSUED_FOR_PARA;

typedef struct _CRL_ISSUING_DIST_POINT *PCRL_ISSUING_DIST_POINT;

typedef struct _CRL_REVOCATION_INFO *PCRL_REVOCATION_INFO;

typedef struct _CROSS_CERT_DIST_POINTS_INFO *PCROSS_CERT_DIST_POINTS_INFO;

typedef struct _CRYPT_3DES_KEY_STATE *PCRYPT_3DES_KEY_STATE;

typedef struct _CRYPT_AES_128_KEY_STATE *PCRYPT_AES_128_KEY_STATE;

typedef struct _CRYPT_AES_256_KEY_STATE *PCRYPT_AES_256_KEY_STATE;

typedef struct _CRYPT_ASYNC_RETRIEVAL_COMPLETION *PCRYPT_ASYNC_RETRIEVAL_COMPLETION;

typedef struct _CRYPT_BIT_BLOB *PCRYPT_BIT_BLOB;

typedef struct _CRYPT_BLOB_ARRAY *PCRYPT_BLOB_ARRAY;

typedef struct _CRYPT_CONTENT_INFO *PCRYPT_CONTENT_INFO;

typedef struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY *PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;

typedef struct _CRYPT_CONTEXT_CONFIG *PCRYPT_CONTEXT_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_CONFIG *PCRYPT_CONTEXT_FUNCTION_CONFIG;

typedef struct _CRYPT_CONTEXT_FUNCTION_PROVIDERS *PCRYPT_CONTEXT_FUNCTION_PROVIDERS;

typedef struct _CRYPT_CONTEXT_FUNCTIONS *PCRYPT_CONTEXT_FUNCTIONS;

typedef struct _CRYPT_CONTEXTS *PCRYPT_CONTEXTS;

typedef struct _CRYPT_CREDENTIALS *PCRYPT_CREDENTIALS;

typedef struct _CRYPT_CSP_PROVIDER *PCRYPT_CSP_PROVIDER;

typedef struct _CRYPT_DECODE_PARA *PCRYPT_DECODE_PARA;

typedef struct _CRYPT_DECRYPT_MESSAGE_PARA *PCRYPT_DECRYPT_MESSAGE_PARA;

typedef struct _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA *PCRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA;

typedef struct _CRYPT_DES_KEY_STATE *PCRYPT_DES_KEY_STATE;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_DIGEST_BLOB;

typedef struct _CRYPT_ECC_CMS_SHARED_INFO *PCRYPT_ECC_CMS_SHARED_INFO;

typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO *PCRYPT_ECC_PRIVATE_KEY_INFO;

typedef struct _CRYPT_ENCODE_PARA *PCRYPT_ENCODE_PARA;

typedef struct _CRYPT_ENCRYPT_MESSAGE_PARA *PCRYPT_ENCRYPT_MESSAGE_PARA;

typedef struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO *PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO;

typedef struct _CRYPT_ENROLLMENT_NAME_VALUE_PAIR *PCRYPT_ENROLLMENT_NAME_VALUE_PAIR;

typedef struct _CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO *PCRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_HASH_BLOB;

typedef struct _CRYPT_HASH_INFO *PCRYPT_HASH_INFO;

typedef struct _CRYPT_HASH_MESSAGE_PARA *PCRYPT_HASH_MESSAGE_PARA;

typedef struct _CRYPT_KEY_PROV_INFO *PCRYPT_KEY_PROV_INFO;

typedef struct _CRYPT_KEY_SIGN_MESSAGE_PARA *PCRYPT_KEY_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_KEY_VERIFY_MESSAGE_PARA *PCRYPT_KEY_VERIFY_MESSAGE_PARA;

typedef struct _CRYPT_MASK_GEN_ALGORITHM *PCRYPT_MASK_GEN_ALGORITHM;

typedef struct _CRYPT_OBJECT_LOCATOR_PROVIDER_TABLE *PCRYPT_OBJECT_LOCATOR_PROVIDER_TABLE;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_OBJID_BLOB;

typedef struct _CRYPT_OBJID_TABLE *PCRYPT_OBJID_TABLE;

typedef struct _CRYPT_OID_FUNC_ENTRY *PCRYPT_OID_FUNC_ENTRY;

typedef struct _CRYPT_OID_INFO *PCRYPT_OID_INFO;

typedef struct _CRYPT_PASSWORD_CREDENTIALSA *PCRYPT_PASSWORD_CREDENTIALSA;

typedef PCRYPT_PASSWORD_CREDENTIALSA PCRYPT_PASSWORD_CREDENTIALS;

typedef struct _CRYPT_PASSWORD_CREDENTIALSW *PCRYPT_PASSWORD_CREDENTIALSW;

typedef struct _CRYPT_PKCS8_EXPORT_PARAMS *PCRYPT_PKCS8_EXPORT_PARAMS;

typedef struct _CRYPT_PKCS8_IMPORT_PARAMS *PCRYPT_PKCS8_IMPORT_PARAMS;

typedef struct _CRYPT_PKCS8_IMPORT_PARAMS *PCRYPT_PRIVATE_KEY_BLOB_AND_PARAMS;

typedef struct _CRYPT_PRIVATE_KEY_INFO *PCRYPT_PRIVATE_KEY_INFO;

typedef struct _CRYPT_PROVIDER_REFS *PCRYPT_PROVIDER_REFS;

typedef struct _CRYPT_PROVIDER_REG *PCRYPT_PROVIDER_REG;

typedef struct _CRYPT_PROVIDERS *PCRYPT_PROVIDERS;

typedef struct _CRYPT_PSOURCE_ALGORITHM *PCRYPT_PSOURCE_ALGORITHM;

typedef struct _CRYPT_RC2_CBC_PARAMETERS *PCRYPT_RC2_CBC_PARAMETERS;

typedef struct _CRYPT_RC4_KEY_STATE *PCRYPT_RC4_KEY_STATE;

typedef struct _CRYPT_RETRIEVE_AUX_INFO *PCRYPT_RETRIEVE_AUX_INFO;

typedef struct _CRYPT_RSA_SSA_PSS_PARAMETERS *PCRYPT_RSA_SSA_PSS_PARAMETERS;

typedef struct _CRYPT_RSAES_OAEP_PARAMETERS *PCRYPT_RSAES_OAEP_PARAMETERS;

typedef struct _CRYPT_SEQUENCE_OF_ANY *PCRYPT_SEQUENCE_OF_ANY;

typedef struct _CRYPT_SIGN_MESSAGE_PARA *PCRYPT_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_SMART_CARD_ROOT_INFO *PCRYPT_SMART_CARD_ROOT_INFO;

typedef struct _CRYPT_SMIME_CAPABILITIES *PCRYPT_SMIME_CAPABILITIES;

typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO *PCRYPT_TIME_STAMP_REQUEST_INFO;

typedef struct _CRYPT_TIMESTAMP_CONTEXT *PCRYPT_TIMESTAMP_CONTEXT;

typedef struct _CRYPT_TIMESTAMP_PARA *PCRYPT_TIMESTAMP_PARA;

typedef struct _CRYPT_TIMESTAMP_REQUEST *PCRYPT_TIMESTAMP_REQUEST;

typedef struct _CRYPT_TIMESTAMP_RESPONSE *PCRYPT_TIMESTAMP_RESPONSE;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_UINT_BLOB;

typedef struct _CRYPT_URL_ARRAY *PCRYPT_URL_ARRAY;

typedef struct _CRYPT_URL_INFO *PCRYPT_URL_INFO;

typedef struct _CRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO *PCRYPT_VERIFY_CERT_SIGN_STRONG_PROPERTIES_INFO;

typedef struct _CRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO *PCRYPT_VERIFY_CERT_SIGN_WEAK_HASH_INFO;

typedef struct _CRYPT_VERIFY_MESSAGE_PARA *PCRYPT_VERIFY_MESSAGE_PARA;

typedef struct _CRYPT_X942_OTHER_INFO *PCRYPT_X942_OTHER_INFO;

typedef struct _CRYPTPROTECT_PROMPTSTRUCT *PCRYPTPROTECT_PROMPTSTRUCT;

typedef struct _CTL_ANY_SUBJECT_INFO *PCTL_ANY_SUBJECT_INFO;

typedef struct _CTL_CONTEXT *PCTL_CONTEXT;

typedef struct _CTL_FIND_SUBJECT_PARA *PCTL_FIND_SUBJECT_PARA;

typedef struct _CTL_USAGE *PCTL_USAGE;

typedef struct _CTL_USAGE_MATCH *PCTL_USAGE_MATCH;

typedef struct _CTL_VERIFY_USAGE_PARA *PCTL_VERIFY_USAGE_PARA;

typedef struct _CTL_VERIFY_USAGE_STATUS *PCTL_VERIFY_USAGE_STATUS;

typedef struct _CRYPTOAPI_BLOB *PDATA_BLOB;

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_PARA *PEV_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_STATUS *PEV_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef BOOL (*PFN_CERT_DLL_OPEN_STORE_PROV_FUNC)(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, void *, HCERTSTORE, PCERT_STORE_PROV_INFO);

typedef BOOL (*PFN_CERT_ENUM_PHYSICAL_STORE)(void *, DWORD, LPCWSTR, PCERT_PHYSICAL_STORE_INFO, void *, void *);

typedef BOOL (*PFN_CERT_ENUM_SYSTEM_STORE)(void *, DWORD, PCERT_SYSTEM_STORE_INFO, void *, void *);

typedef BOOL (*PFN_CERT_IS_WEAK_HASH)(DWORD, LPCWSTR, DWORD, PCCERT_CHAIN_CONTEXT, LPFILETIME, LPCWSTR);

typedef BOOL (*PFN_CERT_STORE_PROV_DELETE_CERT)(HCERTSTOREPROV, PCCERT_CONTEXT, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_DELETE_CRL)(HCERTSTOREPROV, PCCRL_CONTEXT, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_DELETE_CTL)(HCERTSTOREPROV, PCCTL_CONTEXT, DWORD);

typedef struct _CERT_STORE_PROV_FIND_INFO CERT_STORE_PROV_FIND_INFO;

typedef CERT_STORE_PROV_FIND_INFO *PCCERT_STORE_PROV_FIND_INFO;

typedef BOOL (*PFN_CERT_STORE_PROV_FIND_CERT)(HCERTSTOREPROV, PCCERT_STORE_PROV_FIND_INFO, PCCERT_CONTEXT, DWORD, void **, PCCERT_CONTEXT *);

typedef BOOL (*PFN_CERT_STORE_PROV_FIND_CRL)(HCERTSTOREPROV, PCCERT_STORE_PROV_FIND_INFO, PCCRL_CONTEXT, DWORD, void **, PCCRL_CONTEXT *);

typedef BOOL (*PFN_CERT_STORE_PROV_FIND_CTL)(HCERTSTOREPROV, PCCERT_STORE_PROV_FIND_INFO, PCCTL_CONTEXT, DWORD, void **, PCCTL_CONTEXT *);

typedef BOOL (*PFN_CERT_STORE_PROV_FREE_FIND_CERT)(HCERTSTOREPROV, PCCERT_CONTEXT, void *, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_FREE_FIND_CRL)(HCERTSTOREPROV, PCCRL_CONTEXT, void *, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_FREE_FIND_CTL)(HCERTSTOREPROV, PCCTL_CONTEXT, void *, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_GET_CERT_PROPERTY)(HCERTSTOREPROV, PCCERT_CONTEXT, DWORD, DWORD, void *, DWORD *);

typedef BOOL (*PFN_CERT_STORE_PROV_GET_CRL_PROPERTY)(HCERTSTOREPROV, PCCRL_CONTEXT, DWORD, DWORD, void *, DWORD *);

typedef BOOL (*PFN_CERT_STORE_PROV_GET_CTL_PROPERTY)(HCERTSTOREPROV, PCCTL_CONTEXT, DWORD, DWORD, void *, DWORD *);

typedef BOOL (*PFN_CERT_STORE_PROV_READ_CERT)(HCERTSTOREPROV, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT *);

typedef BOOL (*PFN_CERT_STORE_PROV_READ_CRL)(HCERTSTOREPROV, PCCRL_CONTEXT, DWORD, PCCRL_CONTEXT *);

typedef BOOL (*PFN_CERT_STORE_PROV_READ_CTL)(HCERTSTOREPROV, PCCTL_CONTEXT, DWORD, PCCTL_CONTEXT *);

typedef BOOL (*PFN_CERT_STORE_PROV_SET_CERT_PROPERTY)(HCERTSTOREPROV, PCCERT_CONTEXT, DWORD, DWORD, void *);

typedef BOOL (*PFN_CERT_STORE_PROV_SET_CRL_PROPERTY)(HCERTSTOREPROV, PCCRL_CONTEXT, DWORD, DWORD, void *);

typedef BOOL (*PFN_CERT_STORE_PROV_SET_CTL_PROPERTY)(HCERTSTOREPROV, PCCTL_CONTEXT, DWORD, DWORD, void *);

typedef BOOL (*PFN_CERT_STORE_PROV_WRITE_CERT)(HCERTSTOREPROV, PCCERT_CONTEXT, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_WRITE_CRL)(HCERTSTOREPROV, PCCRL_CONTEXT, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_WRITE_CTL)(HCERTSTOREPROV, PCCTL_CONTEXT, DWORD);

typedef BOOL (*PFN_CMSG_CNG_IMPORT_CONTENT_ENCRYPT_KEY)(PCMSG_CNG_CONTENT_DECRYPT_INFO, DWORD, void *);

typedef BOOL (*PFN_CMSG_CNG_IMPORT_KEY_AGREE)(PCMSG_CNG_CONTENT_DECRYPT_INFO, PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA, DWORD, void *);

typedef BOOL (*PFN_CMSG_CNG_IMPORT_KEY_TRANS)(PCMSG_CNG_CONTENT_DECRYPT_INFO, PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA, DWORD, void *);

typedef DWORD *PDWORD;

typedef BOOL (*PFN_CMSG_EXPORT_ENCRYPT_KEY)(HCRYPTPROV, HCRYPTKEY, PCERT_PUBLIC_KEY_INFO, PBYTE, PDWORD);

typedef BOOL (*PFN_CMSG_EXPORT_KEY_AGREE)(PCMSG_CONTENT_ENCRYPT_INFO, PCMSG_KEY_AGREE_RECIPIENT_ENCODE_INFO, PCMSG_KEY_AGREE_ENCRYPT_INFO, DWORD, void *);

typedef BOOL (*PFN_CMSG_EXPORT_KEY_TRANS)(PCMSG_CONTENT_ENCRYPT_INFO, PCMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO, PCMSG_KEY_TRANS_ENCRYPT_INFO, DWORD, void *);

typedef BOOL (*PFN_CMSG_EXPORT_MAIL_LIST)(PCMSG_CONTENT_ENCRYPT_INFO, PCMSG_MAIL_LIST_RECIPIENT_ENCODE_INFO, PCMSG_MAIL_LIST_ENCRYPT_INFO, DWORD, void *);

typedef BOOL (*PFN_CMSG_GEN_CONTENT_ENCRYPT_KEY)(PCMSG_CONTENT_ENCRYPT_INFO, DWORD, void *);

typedef BOOL (*PFN_CMSG_GEN_ENCRYPT_KEY)(HCRYPTPROV *, PCRYPT_ALGORITHM_IDENTIFIER, PVOID, PCERT_PUBLIC_KEY_INFO, PFN_CMSG_ALLOC, HCRYPTKEY *, PBYTE *, PDWORD);

typedef BOOL (*PFN_CMSG_IMPORT_ENCRYPT_KEY)(HCRYPTPROV, DWORD, PCRYPT_ALGORITHM_IDENTIFIER, PCRYPT_ALGORITHM_IDENTIFIER, PBYTE, DWORD, HCRYPTKEY *);

typedef BOOL (*PFN_CMSG_IMPORT_KEY_AGREE)(PCRYPT_ALGORITHM_IDENTIFIER, PCMSG_CTRL_KEY_AGREE_DECRYPT_PARA, DWORD, void *, HCRYPTKEY *);

typedef BOOL (*PFN_CMSG_IMPORT_KEY_TRANS)(PCRYPT_ALGORITHM_IDENTIFIER, PCMSG_CTRL_KEY_TRANS_DECRYPT_PARA, DWORD, void *, HCRYPTKEY *);

typedef BOOL (*PFN_CMSG_IMPORT_MAIL_LIST)(PCRYPT_ALGORITHM_IDENTIFIER, PCMSG_CTRL_MAIL_LIST_DECRYPT_PARA, DWORD, void *, HCRYPTKEY *);

typedef BOOL (*PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC)(NCRYPT_KEY_HANDLE, DWORD, LPSTR, DWORD, void *, PCERT_PUBLIC_KEY_INFO, DWORD *);

typedef BOOL (*PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC)(BCRYPT_KEY_HANDLE, DWORD, LPSTR, DWORD, void *, PCERT_PUBLIC_KEY_INFO, DWORD *);

typedef BOOL (*PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)(DWORD, PCRYPT_ALGORITHM_IDENTIFIER, void **, LPWSTR *);

typedef BOOL (*PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FLUSH)(LPVOID, PCERT_NAME_BLOB *, DWORD);

typedef BOOL (*PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_INITIALIZE)(PFN_CRYPT_OBJECT_LOCATOR_PROVIDER_FLUSH, LPVOID, DWORD *, PCRYPT_OBJECT_LOCATOR_PROVIDER_TABLE *, void **);

typedef BOOL (*PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC)(NCRYPT_KEY_HANDLE, DWORD, PCRYPT_ALGORITHM_IDENTIFIER, void *, LPCWSTR, LPCWSTR, BYTE *, DWORD, BYTE *, DWORD *);

typedef BOOL (*PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC)(DWORD, PCERT_PUBLIC_KEY_INFO, PCRYPT_ALGORITHM_IDENTIFIER, void *, LPCWSTR, LPCWSTR, BYTE *, DWORD, BYTE *, DWORD);

typedef BOOL (*PFN_EXPORT_PRIV_KEY_FUNC)(HCRYPTPROV, DWORD, LPSTR, DWORD, void *, CRYPT_PRIVATE_KEY_INFO *, DWORD *);

typedef void (*PFN_FREE_ENCODED_OBJECT_FUNC)(LPCSTR, PCRYPT_BLOB_ARRAY, LPVOID);

typedef BOOL (*PFN_IMPORT_PRIV_KEY_FUNC)(HCRYPTPROV, CRYPT_PRIVATE_KEY_INFO *, DWORD, void *);

typedef BOOL (*PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC)(DWORD, PCERT_PUBLIC_KEY_INFO, DWORD, void *, BCRYPT_KEY_HANDLE *);

typedef struct _FVE_AUTH_DPAPI_NG *PFVE_AUTH_DPAPI_NG;

typedef struct _FVE_AUTH_EXTERNAL_KEY *PFVE_AUTH_EXTERNAL_KEY;

typedef struct _FVE_AUTH_INFO_CLEAR_KEY *PFVE_AUTH_INFO_CLEAR_KEY;

typedef struct _FVE_AUTH_INFO_PUBLIC_KEY *PFVE_AUTH_INFO_PUBLIC_KEY;

typedef struct _FVE_AUTH_INFORMATION *PFVE_AUTH_INFORMATION;

typedef struct _FVE_AUTH_PASSPHRASE *PFVE_AUTH_PASSPHRASE;

typedef struct _FVE_AUTH_PIN *PFVE_AUTH_PIN;

typedef struct _FVE_AUTH_PREDICTED_TPM_INFO *PFVE_AUTH_PREDICTED_TPM_INFO;

typedef struct _FVE_AUTH_PRIVATE_KEY *PFVE_AUTH_PRIVATE_KEY;

typedef struct _FVE_AUTH_PUBLIC_KEY *PFVE_AUTH_PUBLIC_KEY;

typedef struct _FVE_AUTH_RECOVERY_PASSWORD *PFVE_AUTH_RECOVERY_PASSWORD;

typedef struct _FVE_AUTH_TPM *PFVE_AUTH_TPM;

typedef struct _FVE_DE_SUPPORT *PFVE_DE_SUPPORT;

typedef enum _FVE_DEVICE_TYPE *PFVE_DEVICE_TYPE;

typedef struct _FVE_FIND_DATA_V1 *PFVE_FIND_DATA_V1;

typedef enum _FVE_HANDLE_TYPE *PFVE_HANDLE_TYPE;

typedef enum _FVE_INTERFACE_TYPE *PFVE_INTERFACE_TYPE;

typedef enum _FVE_PROTECTOR_TYPE *PFVE_PROTECTOR_TYPE;

typedef enum _FVE_QUERY_TYPE *PFVE_QUERY_TYPE;

typedef enum _FVE_SCENARIO_TYPE *PFVE_SCENARIO_TYPE;

typedef enum _FVE_SECUREBOOT_BINDING_STATE *PFVE_SECUREBOOT_BINDING_STATE;

typedef struct _FVE_STATUS_V1 *PFVE_STATUS_V1;

typedef struct _FVE_STATUS_V2 *PFVE_STATUS_V2;

typedef struct _FVE_STATUS_V3 *PFVE_STATUS_V3;

typedef struct _FVE_STATUS_V4 *PFVE_STATUS_V4;

typedef struct _FVE_STATUS_V5 *PFVE_STATUS_V5;

typedef struct _FVE_STATUS_V6 *PFVE_STATUS_V6;

typedef struct _FVE_STATUS_V7 *PFVE_STATUS_V7;

typedef struct _FVE_STATUS_V8 *PFVE_STATUS_V8;

typedef HRESULT (*PFVE_TPM_API_CALLBACK)(PVOID, UINT32, PCBYTE, PUINT32, PBYTE);

typedef struct _FVE_TPM_CAPS *PFVE_TPM_CAPS;

typedef struct _FVE_TPM_CAPS_TPM_PRESENCE *PFVE_TPM_CAPS_TPM_PRESENCE;

typedef struct _FVE_TPM_INFO_ *PFVE_TPM_INFO;

typedef struct _FVE_WCOS_SEQURITY_INFO_REQUEST *PFVE_WCOS_SEQURITY_INFO_REQUEST;

typedef struct _FVE_WCOS_SEQURITY_INFO_RESPONSE *PFVE_WCOS_SEQURITY_INFO_RESPONSE;

typedef enum _FVE_WIPING_STATE *PFVE_WIPING_STATE;

typedef struct _HMAC_Info *PHMAC_INFO;

typedef struct _HTTPSPolicyCallbackData *PHTTPSPolicyCallbackData;

typedef struct _PKCS12_PBES2_EXPORT_PARAMS PKCS12_PBES2_EXPORT_PARAMS;

typedef struct _KEY_TYPE_SUBTYPE *PKEY_TYPE_SUBTYPE;

typedef struct _NCRYPT_CIPHER_PADDING_INFO *PNCRYPT_CIPHER_PADDING_INFO;

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE *PNCRYPT_EXPORTED_ISOLATED_KEY_ENVELOPE;

typedef struct _NCRYPT_EXPORTED_ISOLATED_KEY_HEADER *PNCRYPT_EXPORTED_ISOLATED_KEY_HEADER;

typedef struct _NCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES *PNCRYPT_ISOLATED_KEY_ATTESTED_ATTRIBUTES;

typedef struct _NCRYPT_KEY_BLOB_HEADER *PNCRYPT_KEY_BLOB_HEADER;

typedef struct __NCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT *PNCRYPT_PCP_TPM_WEB_AUTHN_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT *PNCRYPT_TPM_PLATFORM_ATTESTATION_STATEMENT;

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS *PNCRYPT_VSM_KEY_ATTESTATION_CLAIM_RESTRICTIONS;

typedef struct _NCRYPT_VSM_KEY_ATTESTATION_STATEMENT *PNCRYPT_VSM_KEY_ATTESTATION_STATEMENT;

typedef BCryptBufferDesc *PNCryptBufferDesc;

typedef struct _OCSP_BASIC_RESPONSE_INFO *POCSP_BASIC_RESPONSE_INFO;

typedef struct _OCSP_BASIC_SIGNED_RESPONSE_INFO *POCSP_BASIC_SIGNED_RESPONSE_INFO;

typedef struct _OCSP_CERT_ID *POCSP_CERT_ID;

typedef struct _OCSP_REQUEST_INFO *POCSP_REQUEST_INFO;

typedef struct _OCSP_RESPONSE_INFO *POCSP_RESPONSE_INFO;

typedef struct _OCSP_SIGNED_REQUEST_INFO *POCSP_SIGNED_REQUEST_INFO;

typedef struct _PKCS12_PBES2_EXPORT_PARAMS *PPKCS12_PBES2_EXPORT_PARAMS;

typedef struct _ROOT_INFO_LUID *PROOT_INFO_LUID;

typedef struct _SCHANNEL_ALG *PSCHANNEL_ALG;

typedef struct _SSL_ECCKEY_BLOB *PSSL_ECCKEY_BLOB;

typedef struct _HTTPSPolicyCallbackData *PSSL_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS *PSSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA *PSSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA *PSSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS *PSSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _SSL_ECCKEY_BLOB SSL_ECCKEY_BLOB;

typedef struct _SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA SSL_HPKP_HEADER_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS SSL_KEY_PIN_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct struct struct, *Pstruct;

struct struct {
    void *CFveApi::`scalar_deleting_destructor';
    void *CFveApiBase::GetVolumeName;
    void *CFveApiHandle::Release;
    void *CFveApiBase::DeviceOpen;
    void *CFveApiBase::DeviceClose;
    void *CFveApiBase::FlushFileBuffers;
    void *CFveApiBase::DeviceIoctl;
    void *CFveApiBase::IsVolumeAmk;
    void *CFveApiBase::IsVolumeSystem;
    void *CFveApiBase::IsSystemFlagSetForVolume;
    void *CFveApiBase::IsVolumeHidden;
    void *CFveApiBase::IsVolumeRecovery;
    void *CFveApiBase::IsVolumeDynamic;
    void *CFveApiBase::IsDeviceOpen;
    void *CFveApiBase::WriteBlocks;
    void *CFveApiBase::GetVolumeLabel;
    void *CFveApiBase::ReadRegString;
    void *CFveApiBase::ReadFipsSetting;
    void *CFveApiBase::WorksetHasClearKey;
    void *CFveApiBase::UnlockFileSystem;
    void *CFveApiBase::LockDismountFileSystem;
    void *CFveApiBase::MountFileSystem;
    void *CFveApiBase::DpapiNgProtectKey;
    void *CFveApiBase::DpapiNgUnprotectKey;
    void *CFveApiBase::GetProtectionDescriptorFromDpapiNgInfo;
    void *CFveApiBase::CheckDpapiNgInfoForSid;
    void *CFveApiBase::FsVolumeOpenNoCache;
    void *CFveApiBase::FsVolumeOpen;
    void *CFveApiBase::FsVolumeCloseNoCache;
    void *CFveApiBase::FsVolumeClose;
    void *CFveApiBase::IsVolumeClustered;
    void *CFveApiBase::ConversionDecryptEx;
    void *CFveApiBase::SetPagefileFlagIfOsVolume;
    void *CFveApiBase::ConversionStop;
    void *CFveApiBase::ConversionPause;
    void *CFveApiBase::ConversionResume;
    void *CFveApiBase::GetVolumeInformationW;
    void *CFveApi::LoadStringW;
    void *CFveApi::AttemptADBackup;
    void *CFveApi::ReadFromVolume;
    void *CFveApi::WriteDiscoveryVolumeData;
    void *CFveApi::ReadDiscoveryVolumeData;
};

typedef void VOID;

typedef longlong __time64_t;

typedef int errno_t;

typedef size_t rsize_t;

typedef __time64_t time_t;

typedef ushort wint_t;

#define __GLIBC_HAVE_LONG_LONG 1

#define __WORDSIZE 64

#define _INTEGRAL_MAX_BITS 64

#define _MSC_VER 1200

#define _WIN32_WINNT 2560

#define WINAPI_PARTITION_APP 1

#define WINAPI_PARTITION_GAMES 1

#define WINAPI_PARTITION_SYSTEM 1

#define WINVER 2304

typedef struct CComBSTR CComBSTR, *PCComBSTR;

struct CComBSTR { /* PlaceHolder Structure */
};

typedef struct _FVE_ALLOWED_DEBUG_EVENT _FVE_ALLOWED_DEBUG_EVENT, *P_FVE_ALLOWED_DEBUG_EVENT;

struct _FVE_ALLOWED_DEBUG_EVENT { /* PlaceHolder Structure */
};

typedef enum BitLockerSecureBootEvalState {
} BitLockerSecureBootEvalState;

typedef enum ePcrBitmapSource {
} ePcrBitmapSource;

typedef enum eSignatureDBCheckEventLogScenario {
} eSignatureDBCheckEventLogScenario;

typedef enum eSignatureDBType {
} eSignatureDBType;

typedef struct id id, *Pid;

struct id { /* PlaceHolder Structure */
};

typedef struct _Generic_error_category _Generic_error_category, *P_Generic_error_category;

struct _Generic_error_category { /* PlaceHolder Structure */
};

typedef struct _Iostream_error_category _Iostream_error_category, *P_Iostream_error_category;

struct _Iostream_error_category { /* PlaceHolder Structure */
};

typedef struct _System_error_category _System_error_category, *P_System_error_category;

struct _System_error_category { /* PlaceHolder Structure */
};

typedef struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>, *Pbasic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>;

struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> { /* PlaceHolder Structure */
};

typedef struct error_category error_category, *Perror_category;

struct error_category { /* PlaceHolder Structure */
};

typedef struct error_code error_code, *Perror_code;

struct error_code { /* PlaceHolder Structure */
};

typedef struct error_condition error_condition, *Perror_condition;

struct error_condition { /* PlaceHolder Structure */
};

typedef struct nothrow_t nothrow_t, *Pnothrow_t;

struct nothrow_t { /* PlaceHolder Structure */
};

typedef struct TpmDataObject TpmDataObject, *PTpmDataObject;

struct TpmDataObject { /* PlaceHolder Structure */
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    void *field8_0x8;
    uint field9_0x10;
    undefined4 field10_0x14;
    undefined4 field11_0x18;
    undefined field12_0x1c;
    undefined field13_0x1d;
    undefined field14_0x1e;
    undefined field15_0x1f;
    void *field16_0x20;
    uint field17_0x28;
    undefined4 field18_0x2c;
    undefined field19_0x30;
};

typedef struct TPMW82B_BUFFER TPMW82B_BUFFER, *PTPMW82B_BUFFER;

struct TPMW82B_BUFFER { /* PlaceHolder Structure */
    longlong field0_0x0;
    undefined field1_0x8;
    undefined field2_0x9;
    undefined field3_0xa;
    undefined field4_0xb;
    undefined field5_0xc;
    undefined field6_0xd;
    undefined field7_0xe;
    undefined field8_0xf;
    undefined field9_0x10;
    undefined field10_0x11;
    undefined field11_0x12;
    undefined field12_0x13;
    undefined field13_0x14;
    undefined field14_0x15;
    undefined field15_0x16;
    undefined field16_0x17;
    undefined field17_0x18;
    undefined field18_0x19;
    undefined field19_0x1a;
    undefined field20_0x1b;
    undefined field21_0x1c;
    undefined field22_0x1d;
    undefined field23_0x1e;
    undefined field24_0x1f;
    undefined field25_0x20;
    undefined field26_0x21;
    undefined field27_0x22;
    undefined field28_0x23;
    undefined field29_0x24;
    undefined field30_0x25;
    undefined field31_0x26;
    undefined field32_0x27;
    undefined field33_0x28;
    undefined field34_0x29;
    undefined field35_0x2a;
    undefined field36_0x2b;
    undefined field37_0x2c;
    undefined field38_0x2d;
    undefined field39_0x2e;
    undefined field40_0x2f;
    undefined field41_0x30;
    undefined field42_0x31;
    undefined field43_0x32;
    undefined field44_0x33;
    undefined field45_0x34;
    undefined field46_0x35;
    undefined field47_0x36;
    undefined field48_0x37;
    ushort BufferSize;
    undefined field50_0x3a;
    undefined field51_0x3b;
    undefined field52_0x3c;
    undefined field53_0x3d;
    undefined field54_0x3e;
    undefined field55_0x3f;
    void *Buffer;
};

typedef struct TPMW8_AUTH_PROVIDER TPMW8_AUTH_PROVIDER, *PTPMW8_AUTH_PROVIDER;

struct TPMW8_AUTH_PROVIDER { /* PlaceHolder Structure */
};

typedef struct TPMW8_COMMAND TPMW8_COMMAND, *PTPMW8_COMMAND;

struct TPMW8_COMMAND { /* PlaceHolder Structure */
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    void *field8_0x8;
    uint field9_0x10;
    undefined4 field10_0x14;
    undefined4 field11_0x18;
    undefined field12_0x1c;
    undefined field13_0x1d;
    undefined field14_0x1e;
    undefined field15_0x1f;
    void *field16_0x20;
    uint field17_0x28;
    undefined4 field18_0x2c;
    struct TpmDataObject field19_0x30;
    undefined4 field20_0x38;
    undefined8 field21_0x3c;
    undefined8 field22_0x44;
    undefined8 field23_0x4c;
    undefined4 field24_0x54;
    undefined field25_0x58;
    undefined field26_0x59;
    undefined field27_0x5a;
    undefined field28_0x5b;
    undefined field29_0x5c;
    undefined field30_0x5d;
    undefined field31_0x5e;
    undefined field32_0x5f;
    undefined field33_0x60;
    undefined field34_0x61;
    undefined field35_0x62;
    undefined field36_0x63;
    undefined field37_0x64;
    undefined field38_0x65;
    undefined field39_0x66;
    undefined field40_0x67;
    undefined field41_0x68;
    undefined field42_0x69;
    undefined field43_0x6a;
    undefined field44_0x6b;
    undefined field45_0x6c;
    undefined field46_0x6d;
    undefined field47_0x6e;
    undefined field48_0x6f;
    undefined field49_0x70;
    undefined field50_0x71;
    undefined field51_0x72;
    undefined field52_0x73;
    undefined field53_0x74;
    undefined field54_0x75;
    undefined field55_0x76;
    undefined field56_0x77;
    undefined field57_0x78;
    undefined field58_0x79;
    undefined field59_0x7a;
    undefined field60_0x7b;
    undefined field61_0x7c;
    undefined field62_0x7d;
    undefined field63_0x7e;
    undefined field64_0x7f;
    undefined field65_0x80;
    undefined field66_0x81;
    undefined field67_0x82;
    undefined field68_0x83;
    undefined field69_0x84;
    undefined field70_0x85;
    undefined field71_0x86;
    undefined field72_0x87;
    undefined field73_0x88;
    undefined field74_0x89;
    undefined field75_0x8a;
    undefined field76_0x8b;
    undefined field77_0x8c;
    undefined field78_0x8d;
    undefined field79_0x8e;
    undefined field80_0x8f;
    undefined field81_0x90;
    undefined field82_0x91;
    undefined field83_0x92;
    undefined field84_0x93;
    undefined field85_0x94;
    undefined field86_0x95;
    undefined field87_0x96;
    undefined field88_0x97;
    undefined field89_0x98;
    undefined field90_0x99;
    undefined field91_0x9a;
    undefined field92_0x9b;
    undefined field93_0x9c;
    undefined field94_0x9d;
    undefined field95_0x9e;
    undefined field96_0x9f;
    undefined8 field97_0xa0;
    undefined8 *field98_0xa8;
    undefined8 *field99_0xb0;
    undefined8 *field100_0xb8;
};

typedef struct TPMW8_Create TPMW8_Create, *PTPMW8_Create;

typedef UINT16 TPM_ST;

typedef TPM_ST TPMI_ST_COMMAND_TAG;

typedef struct TPMW8S_SENSITIVE_CREATE TPMW8S_SENSITIVE_CREATE, *PTPMW8S_SENSITIVE_CREATE;

typedef struct TPMW8T_PUBLIC TPMW8T_PUBLIC, *PTPMW8T_PUBLIC;

typedef struct TPMW8L_PCR_SELECTION TPMW8L_PCR_SELECTION, *PTPMW8L_PCR_SELECTION;

struct TPMW8S_SENSITIVE_CREATE { /* PlaceHolder Structure */
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    undefined field8_0x8;
    undefined field9_0x9;
    undefined field10_0xa;
    undefined field11_0xb;
    undefined field12_0xc;
    undefined field13_0xd;
    undefined field14_0xe;
    undefined field15_0xf;
    undefined field16_0x10;
    undefined field17_0x11;
    undefined field18_0x12;
    undefined field19_0x13;
    undefined field20_0x14;
    undefined field21_0x15;
    undefined field22_0x16;
    undefined field23_0x17;
    undefined field24_0x18;
    undefined field25_0x19;
    undefined field26_0x1a;
    undefined field27_0x1b;
    undefined field28_0x1c;
    undefined field29_0x1d;
    undefined field30_0x1e;
    undefined field31_0x1f;
    undefined field32_0x20;
    undefined field33_0x21;
    undefined field34_0x22;
    undefined field35_0x23;
    undefined field36_0x24;
    undefined field37_0x25;
    undefined field38_0x26;
    undefined field39_0x27;
    undefined field40_0x28;
    undefined field41_0x29;
    undefined field42_0x2a;
    undefined field43_0x2b;
    undefined field44_0x2c;
    undefined field45_0x2d;
    undefined field46_0x2e;
    undefined field47_0x2f;
    undefined field48_0x30;
    undefined field49_0x31;
    undefined field50_0x32;
    undefined field51_0x33;
    undefined field52_0x34;
    undefined field53_0x35;
    undefined field54_0x36;
    undefined field55_0x37;
    undefined field56_0x38;
    undefined field57_0x39;
    undefined field58_0x3a;
    undefined field59_0x3b;
    undefined field60_0x3c;
    undefined field61_0x3d;
    undefined field62_0x3e;
    undefined field63_0x3f;
    undefined field64_0x40;
    undefined field65_0x41;
    undefined field66_0x42;
    undefined field67_0x43;
    undefined field68_0x44;
    undefined field69_0x45;
    undefined field70_0x46;
    undefined field71_0x47;
    undefined field72_0x48;
    undefined field73_0x49;
    undefined field74_0x4a;
    undefined field75_0x4b;
    undefined field76_0x4c;
    undefined field77_0x4d;
    undefined field78_0x4e;
    undefined field79_0x4f;
    undefined field80_0x50;
    undefined field81_0x51;
    undefined field82_0x52;
    undefined field83_0x53;
    undefined field84_0x54;
    undefined field85_0x55;
    undefined field86_0x56;
    undefined field87_0x57;
    undefined field88_0x58;
    undefined field89_0x59;
    undefined field90_0x5a;
    undefined field91_0x5b;
    undefined field92_0x5c;
    undefined field93_0x5d;
    undefined field94_0x5e;
    undefined field95_0x5f;
    undefined field96_0x60;
    undefined field97_0x61;
    undefined field98_0x62;
    undefined field99_0x63;
    undefined field100_0x64;
    undefined field101_0x65;
    undefined field102_0x66;
    undefined field103_0x67;
    undefined field104_0x68;
    undefined field105_0x69;
    undefined field106_0x6a;
    undefined field107_0x6b;
    undefined field108_0x6c;
    undefined field109_0x6d;
    undefined field110_0x6e;
    undefined field111_0x6f;
    undefined field112_0x70;
    undefined field113_0x71;
    undefined field114_0x72;
    undefined field115_0x73;
    undefined field116_0x74;
    undefined field117_0x75;
    undefined field118_0x76;
    undefined field119_0x77;
    undefined1 AuthDataSize; /* Created by retype action */
    undefined field121_0x79;
    undefined field122_0x7a;
    undefined field123_0x7b;
    undefined field124_0x7c;
    undefined field125_0x7d;
    undefined field126_0x7e;
    undefined field127_0x7f;
    undefined1 AuthDataVar; /* Created by retype action */
    undefined field129_0x81;
    undefined field130_0x82;
    undefined field131_0x83;
    undefined field132_0x84;
    undefined field133_0x85;
    undefined field134_0x86;
    undefined field135_0x87;
    undefined field136_0x88;
    undefined field137_0x89;
    undefined field138_0x8a;
    undefined field139_0x8b;
    undefined field140_0x8c;
    undefined field141_0x8d;
    undefined field142_0x8e;
    undefined field143_0x8f;
    undefined field144_0x90;
    undefined field145_0x91;
    undefined field146_0x92;
    undefined field147_0x93;
    undefined field148_0x94;
    undefined field149_0x95;
    undefined field150_0x96;
    undefined field151_0x97;
    undefined field152_0x98;
    undefined field153_0x99;
    undefined field154_0x9a;
    undefined field155_0x9b;
    undefined field156_0x9c;
    undefined field157_0x9d;
    undefined field158_0x9e;
    undefined field159_0x9f;
    undefined field160_0xa0;
    undefined field161_0xa1;
    undefined field162_0xa2;
    undefined field163_0xa3;
    undefined field164_0xa4;
    undefined field165_0xa5;
    undefined field166_0xa6;
    undefined field167_0xa7;
    undefined field168_0xa8;
    undefined field169_0xa9;
    undefined field170_0xaa;
    undefined field171_0xab;
    undefined field172_0xac;
    undefined field173_0xad;
    undefined field174_0xae;
    undefined field175_0xaf;
    undefined field176_0xb0;
    undefined field177_0xb1;
    undefined field178_0xb2;
    undefined field179_0xb3;
    undefined field180_0xb4;
    undefined field181_0xb5;
    undefined field182_0xb6;
    undefined field183_0xb7;
    undefined field184_0xb8;
    undefined field185_0xb9;
    undefined field186_0xba;
    undefined field187_0xbb;
    undefined field188_0xbc;
    undefined field189_0xbd;
    undefined field190_0xbe;
    undefined field191_0xbf;
    undefined1 KeyDataSize; /* Created by retype action */
    undefined field193_0xc1;
    undefined field194_0xc2;
    undefined field195_0xc3;
    undefined field196_0xc4;
    undefined field197_0xc5;
    undefined field198_0xc6;
    undefined field199_0xc7;
    void *KeyDataVar;
};

struct TPMW8L_PCR_SELECTION { /* PlaceHolder Structure */
    undefined **PcrSelctionVtable;
    undefined8 field1_0x8;
    undefined8 field2_0x10;
    undefined4 field3_0x18;
    undefined field4_0x1c;
    undefined field5_0x1d;
    undefined field6_0x1e;
    undefined field7_0x1f;
    undefined8 field8_0x20;
    undefined8 field9_0x28;
    undefined field10_0x30;
    undefined field11_0x31;
    undefined field12_0x32;
    undefined field13_0x33;
    undefined field14_0x34;
    undefined field15_0x35;
    undefined field16_0x36;
    undefined field17_0x37;
    undefined4 field18_0x38;
    undefined field19_0x3c;
    undefined field20_0x3d;
    undefined field21_0x3e;
    undefined field22_0x3f;
    undefined8 field23_0x40;
};

struct TPMW8T_PUBLIC { /* PlaceHolder Structure */
    undefined **field0_0x0;
    undefined8 field1_0x8;
    undefined8 field2_0x10;
    undefined4 field3_0x18;
    undefined field4_0x1c;
    undefined field5_0x1d;
    undefined field6_0x1e;
    undefined field7_0x1f;
    undefined8 field8_0x20;
    undefined8 field9_0x28;
    undefined field10_0x30;
    undefined field11_0x31;
    undefined field12_0x32;
    undefined field13_0x33;
    undefined field14_0x34;
    undefined field15_0x35;
    undefined field16_0x36;
    undefined field17_0x37;
    undefined8 field18_0x38;
    undefined **field19_0x40;
    undefined8 field20_0x48;
    undefined8 field21_0x50;
    undefined4 field22_0x58;
    undefined field23_0x5c;
    undefined field24_0x5d;
    undefined field25_0x5e;
    undefined field26_0x5f;
    undefined8 field27_0x60;
    undefined8 field28_0x68;
    undefined field29_0x70;
    undefined field30_0x71;
    undefined field31_0x72;
    undefined field32_0x73;
    undefined field33_0x74;
    undefined field34_0x75;
    undefined field35_0x76;
    undefined field36_0x77;
    undefined2 field37_0x78;
    undefined field38_0x7a;
    undefined field39_0x7b;
    undefined field40_0x7c;
    undefined field41_0x7d;
    undefined field42_0x7e;
    undefined field43_0x7f;
    undefined8 field44_0x80;
    undefined field45_0x88;
    undefined field46_0x89;
    undefined field47_0x8a;
    undefined field48_0x8b;
    undefined field49_0x8c;
    undefined field50_0x8d;
    undefined field51_0x8e;
    undefined field52_0x8f;
    undefined field53_0x90;
    undefined field54_0x91;
    undefined field55_0x92;
    undefined field56_0x93;
    undefined field57_0x94;
    undefined field58_0x95;
    undefined field59_0x96;
    undefined field60_0x97;
    undefined field61_0x98;
    undefined field62_0x99;
    undefined field63_0x9a;
    undefined field64_0x9b;
    undefined field65_0x9c;
    undefined field66_0x9d;
    undefined field67_0x9e;
    undefined field68_0x9f;
    undefined field69_0xa0;
    undefined field70_0xa1;
    undefined field71_0xa2;
    undefined field72_0xa3;
    undefined field73_0xa4;
    undefined field74_0xa5;
    undefined field75_0xa6;
    undefined field76_0xa7;
    undefined field77_0xa8;
    undefined field78_0xa9;
    undefined field79_0xaa;
    undefined field80_0xab;
    undefined field81_0xac;
    undefined field82_0xad;
    undefined field83_0xae;
    undefined field84_0xaf;
    undefined field85_0xb0;
    undefined field86_0xb1;
    undefined field87_0xb2;
    undefined field88_0xb3;
    undefined field89_0xb4;
    undefined field90_0xb5;
    undefined field91_0xb6;
    undefined field92_0xb7;
    undefined field93_0xb8;
    undefined field94_0xb9;
    undefined field95_0xba;
    undefined field96_0xbb;
    undefined field97_0xbc;
    undefined field98_0xbd;
    undefined field99_0xbe;
    undefined field100_0xbf;
    undefined field101_0xc0;
    undefined field102_0xc1;
    undefined field103_0xc2;
    undefined field104_0xc3;
    undefined field105_0xc4;
    undefined field106_0xc5;
    undefined field107_0xc6;
    undefined field108_0xc7;
    undefined field109_0xc8;
    undefined field110_0xc9;
    undefined field111_0xca;
    undefined field112_0xcb;
    undefined field113_0xcc;
    undefined field114_0xcd;
    undefined field115_0xce;
    undefined field116_0xcf;
    undefined **field117_0xd0;
    undefined8 field118_0xd8;
    undefined8 field119_0xe0;
    undefined4 field120_0xe8;
    undefined field121_0xec;
    undefined field122_0xed;
    undefined field123_0xee;
    undefined field124_0xef;
    undefined8 field125_0xf0;
    undefined8 field126_0xf8;
    undefined field127_0x100;
    undefined field128_0x101;
    undefined field129_0x102;
    undefined field130_0x103;
    undefined field131_0x104;
    undefined field132_0x105;
    undefined field133_0x106;
    undefined field134_0x107;
    undefined field135_0x108;
    undefined field136_0x109;
    undefined field137_0x10a;
    undefined field138_0x10b;
    undefined field139_0x10c;
    undefined field140_0x10d;
    undefined field141_0x10e;
    undefined field142_0x10f;
    undefined2 field143_0x110;
    undefined field144_0x112;
    undefined field145_0x113;
    undefined4 field146_0x114;
    undefined field147_0x118;
    undefined field148_0x119;
    undefined field149_0x11a;
    undefined field150_0x11b;
    undefined field151_0x11c;
    undefined field152_0x11d;
    undefined field153_0x11e;
    undefined field154_0x11f;
    undefined field155_0x120;
    undefined field156_0x121;
    undefined field157_0x122;
    undefined field158_0x123;
    undefined field159_0x124;
    undefined field160_0x125;
    undefined field161_0x126;
    undefined field162_0x127;
    undefined field163_0x128;
    undefined field164_0x129;
    undefined field165_0x12a;
    undefined field166_0x12b;
    undefined field167_0x12c;
    undefined field168_0x12d;
    undefined field169_0x12e;
    undefined field170_0x12f;
    undefined field171_0x130;
    undefined field172_0x131;
    undefined field173_0x132;
    undefined field174_0x133;
    undefined field175_0x134;
    undefined field176_0x135;
    undefined field177_0x136;
    undefined field178_0x137;
    undefined field179_0x138;
    undefined field180_0x139;
    undefined field181_0x13a;
    undefined field182_0x13b;
    undefined field183_0x13c;
    undefined field184_0x13d;
    undefined field185_0x13e;
    undefined field186_0x13f;
    undefined field187_0x140;
    undefined field188_0x141;
    undefined field189_0x142;
    undefined field190_0x143;
    undefined field191_0x144;
    undefined field192_0x145;
    undefined field193_0x146;
    undefined field194_0x147;
    undefined field195_0x148;
    undefined field196_0x149;
    undefined field197_0x14a;
    undefined field198_0x14b;
    undefined field199_0x14c;
    undefined field200_0x14d;
    undefined field201_0x14e;
    undefined field202_0x14f;
    undefined field203_0x150;
    undefined field204_0x151;
    undefined field205_0x152;
    undefined field206_0x153;
    undefined field207_0x154;
    undefined field208_0x155;
    undefined field209_0x156;
    undefined field210_0x157;
    undefined field211_0x158;
    undefined field212_0x159;
    undefined field213_0x15a;
    undefined field214_0x15b;
    undefined field215_0x15c;
    undefined field216_0x15d;
    undefined field217_0x15e;
    undefined field218_0x15f;
    undefined **field219_0x160;
    undefined8 field220_0x168;
    undefined8 field221_0x170;
    undefined4 field222_0x178;
    undefined field223_0x17c;
    undefined field224_0x17d;
    undefined field225_0x17e;
    undefined field226_0x17f;
    undefined8 field227_0x180;
    undefined8 field228_0x188;
    undefined field229_0x190;
    undefined field230_0x191;
    undefined field231_0x192;
    undefined field232_0x193;
    undefined field233_0x194;
    undefined field234_0x195;
    undefined field235_0x196;
    undefined field236_0x197;
    undefined field237_0x198;
    undefined field238_0x199;
    undefined field239_0x19a;
    undefined field240_0x19b;
    undefined field241_0x19c;
    undefined field242_0x19d;
    undefined field243_0x19e;
    undefined field244_0x19f;
    undefined2 field245_0x1a0;
    undefined field246_0x1a2;
    undefined field247_0x1a3;
    undefined field248_0x1a4;
    undefined field249_0x1a5;
    undefined field250_0x1a6;
    undefined field251_0x1a7;
    undefined **field252_0x1a8;
    undefined8 field253_0x1b0;
    undefined8 field254_0x1b8;
    undefined4 field255_0x1c0;
    undefined field256_0x1c4;
    undefined field257_0x1c5;
    undefined field258_0x1c6;
    undefined field259_0x1c7;
    undefined8 field260_0x1c8;
    undefined8 field261_0x1d0;
    undefined field262_0x1d8;
    undefined field263_0x1d9;
    undefined field264_0x1da;
    undefined field265_0x1db;
    undefined field266_0x1dc;
    undefined field267_0x1dd;
    undefined field268_0x1de;
    undefined field269_0x1df;
    undefined field270_0x1e0;
    undefined field271_0x1e1;
    undefined field272_0x1e2;
    undefined field273_0x1e3;
    undefined field274_0x1e4;
    undefined field275_0x1e5;
    undefined field276_0x1e6;
    undefined field277_0x1e7;
    undefined **field278_0x1e8;
    undefined8 field279_0x1f0;
    undefined8 field280_0x1f8;
    undefined4 field281_0x200;
    undefined field282_0x204;
    undefined field283_0x205;
    undefined field284_0x206;
    undefined field285_0x207;
    undefined8 field286_0x208;
    undefined8 field287_0x210;
    undefined field288_0x218;
    undefined field289_0x219;
    undefined field290_0x21a;
    undefined field291_0x21b;
    undefined field292_0x21c;
    undefined field293_0x21d;
    undefined field294_0x21e;
    undefined field295_0x21f;
    undefined2 field296_0x220;
    undefined field297_0x222;
    undefined field298_0x223;
    undefined field299_0x224;
    undefined field300_0x225;
    undefined field301_0x226;
    undefined field302_0x227;
    undefined8 field303_0x228;
    undefined **field304_0x230;
    undefined8 field305_0x238;
    undefined8 field306_0x240;
    undefined4 field307_0x248;
    undefined field308_0x24c;
    undefined field309_0x24d;
    undefined field310_0x24e;
    undefined field311_0x24f;
    undefined8 field312_0x250;
    undefined8 field313_0x258;
    undefined field314_0x260;
    undefined field315_0x261;
    undefined field316_0x262;
    undefined field317_0x263;
    undefined field318_0x264;
    undefined field319_0x265;
    undefined field320_0x266;
    undefined field321_0x267;
    undefined2 field322_0x268;
    undefined field323_0x26a;
    undefined field324_0x26b;
    undefined field325_0x26c;
    undefined field326_0x26d;
    undefined field327_0x26e;
    undefined field328_0x26f;
    undefined8 field329_0x270;
    undefined **field330_0x278;
    undefined8 field331_0x280;
    undefined8 field332_0x288;
    undefined4 field333_0x290;
    undefined field334_0x294;
    undefined field335_0x295;
    undefined field336_0x296;
    undefined field337_0x297;
    undefined8 field338_0x298;
    undefined8 field339_0x2a0;
    undefined field340_0x2a8;
    undefined field341_0x2a9;
    undefined field342_0x2aa;
    undefined field343_0x2ab;
    undefined field344_0x2ac;
    undefined field345_0x2ad;
    undefined field346_0x2ae;
    undefined field347_0x2af;
    undefined field348_0x2b0;
    undefined field349_0x2b1;
    undefined field350_0x2b2;
    undefined field351_0x2b3;
    undefined field352_0x2b4;
    undefined field353_0x2b5;
    undefined field354_0x2b6;
    undefined field355_0x2b7;
    undefined **field356_0x2b8;
    undefined8 field357_0x2c0;
    undefined8 field358_0x2c8;
    undefined4 field359_0x2d0;
    undefined field360_0x2d4;
    undefined field361_0x2d5;
    undefined field362_0x2d6;
    undefined field363_0x2d7;
    undefined8 field364_0x2d8;
    undefined8 field365_0x2e0;
    undefined field366_0x2e8;
    undefined field367_0x2e9;
    undefined field368_0x2ea;
    undefined field369_0x2eb;
    undefined field370_0x2ec;
    undefined field371_0x2ed;
    undefined field372_0x2ee;
    undefined field373_0x2ef;
    undefined field374_0x2f0;
    undefined field375_0x2f1;
    undefined field376_0x2f2;
    undefined field377_0x2f3;
    undefined field378_0x2f4;
    undefined field379_0x2f5;
    undefined field380_0x2f6;
    undefined field381_0x2f7;
    undefined **field382_0x2f8;
    undefined8 field383_0x300;
    undefined8 field384_0x308;
    undefined4 field385_0x310;
    undefined field386_0x314;
    undefined field387_0x315;
    undefined field388_0x316;
    undefined field389_0x317;
    undefined8 field390_0x318;
    undefined8 field391_0x320;
    undefined field392_0x328;
    undefined field393_0x329;
    undefined field394_0x32a;
    undefined field395_0x32b;
    undefined field396_0x32c;
    undefined field397_0x32d;
    undefined field398_0x32e;
    undefined field399_0x32f;
    undefined2 field400_0x330;
    undefined field401_0x332;
    undefined field402_0x333;
    undefined field403_0x334;
    undefined field404_0x335;
    undefined field405_0x336;
    undefined field406_0x337;
    undefined8 field407_0x338;
};

struct TPMW8_Create { /* PlaceHolder Structure */
    undefined **field0_0x0;
    void *field1_0x8;
    uint field2_0x10;
    undefined4 field3_0x14;
    undefined4 field4_0x18;
    undefined field5_0x1c;
    undefined field6_0x1d;
    undefined field7_0x1e;
    undefined field8_0x1f;
    void *field9_0x20;
    uint field10_0x28;
    undefined4 field11_0x2c;
    undefined field12_0x30;
    undefined field13_0x31;
    undefined field14_0x32;
    undefined field15_0x33;
    undefined field16_0x34;
    undefined field17_0x35;
    undefined field18_0x36;
    undefined field19_0x37;
    undefined2 tag;
    undefined field21_0x3a;
    undefined field22_0x3b;
    undefined field23_0x3c;
    undefined field24_0x3d;
    undefined field25_0x3e;
    undefined field26_0x3f;
    undefined field27_0x40;
    undefined field28_0x41;
    undefined field29_0x42;
    undefined field30_0x43;
    undefined field31_0x44;
    undefined field32_0x45;
    undefined field33_0x46;
    undefined field34_0x47;
    undefined field35_0x48;
    undefined field36_0x49;
    undefined field37_0x4a;
    undefined field38_0x4b;
    undefined field39_0x4c;
    undefined field40_0x4d;
    undefined field41_0x4e;
    undefined field42_0x4f;
    undefined field43_0x50;
    undefined field44_0x51;
    undefined field45_0x52;
    undefined field46_0x53;
    undefined field47_0x54;
    undefined field48_0x55;
    undefined field49_0x56;
    undefined field50_0x57;
    undefined **field51_0x58;
    undefined8 field52_0x60;
    undefined8 field53_0x68;
    undefined4 field54_0x70;
    undefined field55_0x74;
    undefined field56_0x75;
    undefined field57_0x76;
    undefined field58_0x77;
    undefined8 field59_0x78;
    undefined8 field60_0x80;
    undefined field61_0x88;
    undefined field62_0x89;
    undefined field63_0x8a;
    undefined field64_0x8b;
    undefined field65_0x8c;
    undefined field66_0x8d;
    undefined field67_0x8e;
    undefined field68_0x8f;
    undefined2 field69_0x90;
    undefined field70_0x92;
    undefined field71_0x93;
    undefined field72_0x94;
    undefined field73_0x95;
    undefined field74_0x96;
    undefined field75_0x97;
    undefined field76_0x98;
    undefined field77_0x99;
    undefined field78_0x9a;
    undefined field79_0x9b;
    undefined field80_0x9c;
    undefined field81_0x9d;
    undefined field82_0x9e;
    undefined field83_0x9f;
    TPMI_ST_COMMAND_TAG commandCode;
    undefined field85_0xa2;
    undefined field86_0xa3;
    undefined field87_0xa4;
    undefined field88_0xa5;
    undefined field89_0xa6;
    undefined field90_0xa7;
    undefined8 *Session;
    undefined field92_0xb0;
    undefined field93_0xb1;
    undefined field94_0xb2;
    undefined field95_0xb3;
    undefined field96_0xb4;
    undefined field97_0xb5;
    undefined field98_0xb6;
    undefined field99_0xb7;
    undefined field100_0xb8;
    undefined field101_0xb9;
    undefined field102_0xba;
    undefined field103_0xbb;
    undefined field104_0xbc;
    undefined field105_0xbd;
    undefined field106_0xbe;
    undefined field107_0xbf;
    undefined8 field108_0xc0;
    UINT32 parentHandle;
    undefined field110_0xcc;
    undefined field111_0xcd;
    undefined field112_0xce;
    undefined field113_0xcf;
    undefined **BufferVtable;
    undefined8 field115_0xd8;
    undefined8 field116_0xe0;
    undefined4 field117_0xe8;
    undefined field118_0xec;
    undefined field119_0xed;
    undefined field120_0xee;
    undefined field121_0xef;
    undefined8 field122_0xf0;
    undefined8 field123_0xf8;
    undefined field124_0x100;
    undefined field125_0x101;
    undefined field126_0x102;
    undefined field127_0x103;
    undefined field128_0x104;
    undefined field129_0x105;
    undefined field130_0x106;
    undefined field131_0x107;
    undefined2 field132_0x108;
    undefined field133_0x10a;
    undefined field134_0x10b;
    undefined field135_0x10c;
    undefined field136_0x10d;
    undefined field137_0x10e;
    undefined field138_0x10f;
    undefined8 field139_0x110;
    struct TPMW8S_SENSITIVE_CREATE *SensitiveCreate;
    struct TPMW8T_PUBLIC *field141_0x120;
    undefined **BufferVtable2;
    undefined8 field143_0x130;
    undefined8 field144_0x138;
    undefined4 field145_0x140;
    undefined field146_0x144;
    undefined field147_0x145;
    undefined field148_0x146;
    undefined field149_0x147;
    undefined8 field150_0x148;
    undefined8 field151_0x150;
    undefined field152_0x158;
    undefined field153_0x159;
    undefined field154_0x15a;
    undefined field155_0x15b;
    undefined field156_0x15c;
    undefined field157_0x15d;
    undefined field158_0x15e;
    undefined field159_0x15f;
    undefined2 field160_0x160;
    undefined field161_0x162;
    undefined field162_0x163;
    undefined field163_0x164;
    undefined field164_0x165;
    undefined field165_0x166;
    undefined field166_0x167;
    undefined8 field167_0x168;
    struct TPMW8L_PCR_SELECTION PCRSelection;
    undefined **BufferVtable3;
    undefined8 field170_0x1c0;
    undefined8 field171_0x1c8;
    undefined4 field172_0x1d0;
    undefined field173_0x1d4;
    undefined field174_0x1d5;
    undefined field175_0x1d6;
    undefined field176_0x1d7;
    undefined8 field177_0x1d8;
    undefined8 field178_0x1e0;
    undefined field179_0x1e8;
    undefined field180_0x1e9;
    undefined field181_0x1ea;
    undefined field182_0x1eb;
    undefined field183_0x1ec;
    undefined field184_0x1ed;
    undefined field185_0x1ee;
    undefined field186_0x1ef;
    undefined2 field187_0x1f0;
    undefined field188_0x1f2;
    undefined field189_0x1f3;
    undefined field190_0x1f4;
    undefined field191_0x1f5;
    undefined field192_0x1f6;
    undefined field193_0x1f7;
    undefined8 field194_0x1f8;
    undefined8 field195_0x200;
    undefined8 field196_0x208;
    undefined **BufferVtable4;
    undefined8 field198_0x218;
    undefined8 field199_0x220;
    undefined4 field200_0x228;
    undefined field201_0x22c;
    undefined field202_0x22d;
    undefined field203_0x22e;
    undefined field204_0x22f;
    undefined8 field205_0x230;
    undefined8 field206_0x238;
    undefined field207_0x240;
    undefined field208_0x241;
    undefined field209_0x242;
    undefined field210_0x243;
    undefined field211_0x244;
    undefined field212_0x245;
    undefined field213_0x246;
    undefined field214_0x247;
    undefined2 field215_0x248;
    undefined field216_0x24a;
    undefined field217_0x24b;
    undefined field218_0x24c;
    undefined field219_0x24d;
    undefined field220_0x24e;
    undefined field221_0x24f;
    undefined8 field222_0x250;
    longlong *field223_0x258;
};

typedef struct TPMW8_FlushContext TPMW8_FlushContext, *PTPMW8_FlushContext;

struct TPMW8_FlushContext { /* PlaceHolder Structure */
    undefined **field0_0x0;
    void *field1_0x8;
    uint field2_0x10;
    undefined4 field3_0x14;
    undefined4 field4_0x18;
    undefined field5_0x1c;
    undefined field6_0x1d;
    undefined field7_0x1e;
    undefined field8_0x1f;
    void *field9_0x20;
    uint field10_0x28;
    undefined4 field11_0x2c;
    undefined field12_0x30;
    undefined field13_0x31;
    undefined field14_0x32;
    undefined field15_0x33;
    undefined field16_0x34;
    undefined field17_0x35;
    undefined field18_0x36;
    undefined field19_0x37;
    undefined2 field20_0x38;
    undefined field21_0x3a;
    undefined field22_0x3b;
    undefined field23_0x3c;
    undefined field24_0x3d;
    undefined field25_0x3e;
    undefined field26_0x3f;
    undefined field27_0x40;
    undefined field28_0x41;
    undefined field29_0x42;
    undefined field30_0x43;
    undefined field31_0x44;
    undefined field32_0x45;
    undefined field33_0x46;
    undefined field34_0x47;
    undefined field35_0x48;
    undefined field36_0x49;
    undefined field37_0x4a;
    undefined field38_0x4b;
    undefined field39_0x4c;
    undefined field40_0x4d;
    undefined field41_0x4e;
    undefined field42_0x4f;
    undefined field43_0x50;
    undefined field44_0x51;
    undefined field45_0x52;
    undefined field46_0x53;
    undefined field47_0x54;
    undefined field48_0x55;
    undefined field49_0x56;
    undefined field50_0x57;
    undefined **field51_0x58;
    undefined8 field52_0x60;
    undefined8 field53_0x68;
    undefined4 field54_0x70;
    undefined field55_0x74;
    undefined field56_0x75;
    undefined field57_0x76;
    undefined field58_0x77;
    undefined8 field59_0x78;
    undefined8 field60_0x80;
    undefined field61_0x88;
    undefined field62_0x89;
    undefined field63_0x8a;
    undefined field64_0x8b;
    undefined field65_0x8c;
    undefined field66_0x8d;
    undefined field67_0x8e;
    undefined field68_0x8f;
    undefined2 field69_0x90;
    undefined field70_0x92;
    undefined field71_0x93;
    undefined field72_0x94;
    undefined field73_0x95;
    undefined field74_0x96;
    undefined field75_0x97;
    undefined8 field76_0x98;
    undefined4 field77_0xa0;
    undefined field78_0xa4;
    undefined field79_0xa5;
    undefined field80_0xa6;
    undefined field81_0xa7;
    undefined field82_0xa8;
    undefined field83_0xa9;
    undefined field84_0xaa;
    undefined field85_0xab;
    undefined field86_0xac;
    undefined field87_0xad;
    undefined field88_0xae;
    undefined field89_0xaf;
    undefined field90_0xb0;
    undefined field91_0xb1;
    undefined field92_0xb2;
    undefined field93_0xb3;
    undefined field94_0xb4;
    undefined field95_0xb5;
    undefined field96_0xb6;
    undefined field97_0xb7;
    undefined field98_0xb8;
    undefined field99_0xb9;
    undefined field100_0xba;
    undefined field101_0xbb;
    undefined field102_0xbc;
    undefined field103_0xbd;
    undefined field104_0xbe;
    undefined field105_0xbf;
    undefined4 field106_0xc0;
};

typedef struct TPMW8_GetCapability TPMW8_GetCapability, *PTPMW8_GetCapability;

struct TPMW8_GetCapability { /* PlaceHolder Structure */
};

typedef struct TPMW8_NV_DefineSpace TPMW8_NV_DefineSpace, *PTPMW8_NV_DefineSpace;

struct TPMW8_NV_DefineSpace { /* PlaceHolder Structure */
};

typedef struct TPMW8_NV_Increment TPMW8_NV_Increment, *PTPMW8_NV_Increment;

struct TPMW8_NV_Increment { /* PlaceHolder Structure */
};

typedef struct TPMW8_NV_Read TPMW8_NV_Read, *PTPMW8_NV_Read;

struct TPMW8_NV_Read { /* PlaceHolder Structure */
};

typedef struct TPMW8_NV_ReadPublic TPMW8_NV_ReadPublic, *PTPMW8_NV_ReadPublic;

struct TPMW8_NV_ReadPublic { /* PlaceHolder Structure */
};

typedef struct TPMW8_PCR_Read TPMW8_PCR_Read, *PTPMW8_PCR_Read;

struct TPMW8_PCR_Read { /* PlaceHolder Structure */
};

typedef struct TPMW8_PolicyAuthValue TPMW8_PolicyAuthValue, *PTPMW8_PolicyAuthValue;

struct TPMW8_PolicyAuthValue { /* PlaceHolder Structure */
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    undefined field8_0x8;
    undefined field9_0x9;
    undefined field10_0xa;
    undefined field11_0xb;
    undefined field12_0xc;
    undefined field13_0xd;
    undefined field14_0xe;
    undefined field15_0xf;
    undefined field16_0x10;
    undefined field17_0x11;
    undefined field18_0x12;
    undefined field19_0x13;
    undefined field20_0x14;
    undefined field21_0x15;
    undefined field22_0x16;
    undefined field23_0x17;
    undefined field24_0x18;
    undefined field25_0x19;
    undefined field26_0x1a;
    undefined field27_0x1b;
    undefined field28_0x1c;
    undefined field29_0x1d;
    undefined field30_0x1e;
    undefined field31_0x1f;
    undefined field32_0x20;
    undefined field33_0x21;
    undefined field34_0x22;
    undefined field35_0x23;
    undefined field36_0x24;
    undefined field37_0x25;
    undefined field38_0x26;
    undefined field39_0x27;
    undefined field40_0x28;
    undefined field41_0x29;
    undefined field42_0x2a;
    undefined field43_0x2b;
    undefined field44_0x2c;
    undefined field45_0x2d;
    undefined field46_0x2e;
    undefined field47_0x2f;
    undefined field48_0x30;
    undefined field49_0x31;
    undefined field50_0x32;
    undefined field51_0x33;
    undefined field52_0x34;
    undefined field53_0x35;
    undefined field54_0x36;
    undefined field55_0x37;
    undefined2 tag;
    undefined field57_0x3a;
    undefined field58_0x3b;
    undefined8 field59_0x3c;
    undefined8 field60_0x44;
    undefined8 field61_0x4c;
    undefined4 field62_0x54;
    undefined field63_0x58;
    undefined field64_0x59;
    undefined field65_0x5a;
    undefined field66_0x5b;
    undefined field67_0x5c;
    undefined field68_0x5d;
    undefined field69_0x5e;
    undefined field70_0x5f;
    undefined field71_0x60;
    undefined field72_0x61;
    undefined field73_0x62;
    undefined field74_0x63;
    undefined field75_0x64;
    undefined field76_0x65;
    undefined field77_0x66;
    undefined field78_0x67;
    undefined field79_0x68;
    undefined field80_0x69;
    undefined field81_0x6a;
    undefined field82_0x6b;
    undefined field83_0x6c;
    undefined field84_0x6d;
    undefined field85_0x6e;
    undefined field86_0x6f;
    undefined field87_0x70;
    undefined field88_0x71;
    undefined field89_0x72;
    undefined field90_0x73;
    undefined field91_0x74;
    undefined field92_0x75;
    undefined field93_0x76;
    undefined field94_0x77;
    undefined field95_0x78;
    undefined field96_0x79;
    undefined field97_0x7a;
    undefined field98_0x7b;
    undefined field99_0x7c;
    undefined field100_0x7d;
    undefined field101_0x7e;
    undefined field102_0x7f;
    undefined field103_0x80;
    undefined field104_0x81;
    undefined field105_0x82;
    undefined field106_0x83;
    undefined field107_0x84;
    undefined field108_0x85;
    undefined field109_0x86;
    undefined field110_0x87;
    undefined field111_0x88;
    undefined field112_0x89;
    undefined field113_0x8a;
    undefined field114_0x8b;
    undefined field115_0x8c;
    undefined field116_0x8d;
    undefined field117_0x8e;
    undefined field118_0x8f;
    undefined field119_0x90;
    undefined field120_0x91;
    undefined field121_0x92;
    undefined field122_0x93;
    undefined field123_0x94;
    undefined field124_0x95;
    undefined field125_0x96;
    undefined field126_0x97;
    undefined field127_0x98;
    undefined field128_0x99;
    undefined field129_0x9a;
    undefined field130_0x9b;
    undefined field131_0x9c;
    undefined field132_0x9d;
    undefined field133_0x9e;
    undefined field134_0x9f;
    undefined4 commandCode;
    undefined field136_0xa4;
    undefined field137_0xa5;
    undefined field138_0xa6;
    undefined field139_0xa7;
    undefined8 *field140_0xa8;
    undefined8 *field141_0xb0;
    undefined8 *field142_0xb8;
    undefined4 policySession;
};

typedef struct TPMW8_PolicyGetDigest TPMW8_PolicyGetDigest, *PTPMW8_PolicyGetDigest;

struct TPMW8_PolicyGetDigest { /* PlaceHolder Structure */
    undefined field0_0x0;
    undefined field1_0x1;
    undefined field2_0x2;
    undefined field3_0x3;
    undefined field4_0x4;
    undefined field5_0x5;
    undefined field6_0x6;
    undefined field7_0x7;
    undefined field8_0x8;
    undefined field9_0x9;
    undefined field10_0xa;
    undefined field11_0xb;
    undefined field12_0xc;
    undefined field13_0xd;
    undefined field14_0xe;
    undefined field15_0xf;
    undefined field16_0x10;
    undefined field17_0x11;
    undefined field18_0x12;
    undefined field19_0x13;
    undefined field20_0x14;
    undefined field21_0x15;
    undefined field22_0x16;
    undefined field23_0x17;
    undefined field24_0x18;
    undefined field25_0x19;
    undefined field26_0x1a;
    undefined field27_0x1b;
    undefined field28_0x1c;
    undefined field29_0x1d;
    undefined field30_0x1e;
    undefined field31_0x1f;
    undefined field32_0x20;
    undefined field33_0x21;
    undefined field34_0x22;
    undefined field35_0x23;
    undefined field36_0x24;
    undefined field37_0x25;
    undefined field38_0x26;
    undefined field39_0x27;
    undefined field40_0x28;
    undefined field41_0x29;
    undefined field42_0x2a;
    undefined field43_0x2b;
    undefined field44_0x2c;
    undefined field45_0x2d;
    undefined field46_0x2e;
    undefined field47_0x2f;
    undefined field48_0x30;
    undefined field49_0x31;
    undefined field50_0x32;
    undefined field51_0x33;
    undefined field52_0x34;
    undefined field53_0x35;
    undefined field54_0x36;
    undefined field55_0x37;
    undefined2 tag;
    undefined field57_0x3a;
    undefined field58_0x3b;
    undefined8 field59_0x3c;
    undefined8 field60_0x44;
    undefined8 field61_0x4c;
    undefined4 field62_0x54;
    undefined field63_0x58;
    undefined field64_0x59;
    undefined field65_0x5a;
    undefined field66_0x5b;
    undefined field67_0x5c;
    undefined field68_0x5d;
    undefined field69_0x5e;
    undefined field70_0x5f;
    undefined field71_0x60;
    undefined field72_0x61;
    undefined field73_0x62;
    undefined field74_0x63;
    undefined field75_0x64;
    undefined field76_0x65;
    undefined field77_0x66;
    undefined field78_0x67;
    undefined field79_0x68;
    undefined field80_0x69;
    undefined field81_0x6a;
    undefined field82_0x6b;
    undefined field83_0x6c;
    undefined field84_0x6d;
    undefined field85_0x6e;
    undefined field86_0x6f;
    undefined field87_0x70;
    undefined field88_0x71;
    undefined field89_0x72;
    undefined field90_0x73;
    undefined field91_0x74;
    undefined field92_0x75;
    undefined field93_0x76;
    undefined field94_0x77;
    undefined field95_0x78;
    undefined field96_0x79;
    undefined field97_0x7a;
    undefined field98_0x7b;
    undefined field99_0x7c;
    undefined field100_0x7d;
    undefined field101_0x7e;
    undefined field102_0x7f;
    undefined field103_0x80;
    undefined field104_0x81;
    undefined field105_0x82;
    undefined field106_0x83;
    undefined field107_0x84;
    undefined field108_0x85;
    undefined field109_0x86;
    undefined field110_0x87;
    undefined field111_0x88;
    undefined field112_0x89;
    undefined field113_0x8a;
    undefined field114_0x8b;
    undefined field115_0x8c;
    undefined field116_0x8d;
    undefined field117_0x8e;
    undefined field118_0x8f;
    undefined field119_0x90;
    undefined field120_0x91;
    undefined field121_0x92;
    undefined field122_0x93;
    undefined field123_0x94;
    undefined field124_0x95;
    undefined field125_0x96;
    undefined field126_0x97;
    undefined field127_0x98;
    undefined field128_0x99;
    undefined field129_0x9a;
    undefined field130_0x9b;
    undefined field131_0x9c;
    undefined field132_0x9d;
    undefined field133_0x9e;
    undefined field134_0x9f;
    undefined4 commandCode;
    undefined field136_0xa4;
    undefined field137_0xa5;
    undefined field138_0xa6;
    undefined field139_0xa7;
    undefined8 *field140_0xa8;
    undefined8 *field141_0xb0;
    undefined8 *field142_0xb8;
    undefined4 PolicySession;
};

typedef struct TPMW8_PolicyPCR TPMW8_PolicyPCR, *PTPMW8_PolicyPCR;

struct TPMW8_PolicyPCR { /* PlaceHolder Structure */
    undefined **field0_0x0;
    void *field1_0x8;
    uint field2_0x10;
    undefined4 field3_0x14;
    undefined4 field4_0x18;
    undefined field5_0x1c;
    undefined field6_0x1d;
    undefined field7_0x1e;
    undefined field8_0x1f;
    void *field9_0x20;
    uint field10_0x28;
    undefined4 field11_0x2c;
    undefined field12_0x30;
    undefined field13_0x31;
    undefined field14_0x32;
    undefined field15_0x33;
    undefined field16_0x34;
    undefined field17_0x35;
    undefined field18_0x36;
    undefined field19_0x37;
    undefined2 field20_0x38;
    undefined field21_0x3a;
    undefined field22_0x3b;
    undefined field23_0x3c;
    undefined field24_0x3d;
    undefined field25_0x3e;
    undefined field26_0x3f;
    undefined field27_0x40;
    undefined field28_0x41;
    undefined field29_0x42;
    undefined field30_0x43;
    undefined field31_0x44;
    undefined field32_0x45;
    undefined field33_0x46;
    undefined field34_0x47;
    undefined field35_0x48;
    undefined field36_0x49;
    undefined field37_0x4a;
    undefined field38_0x4b;
    undefined field39_0x4c;
    undefined field40_0x4d;
    undefined field41_0x4e;
    undefined field42_0x4f;
    undefined field43_0x50;
    undefined field44_0x51;
    undefined field45_0x52;
    undefined field46_0x53;
    undefined field47_0x54;
    undefined field48_0x55;
    undefined field49_0x56;
    undefined field50_0x57;
    undefined **field51_0x58;
    undefined8 field52_0x60;
    undefined8 field53_0x68;
    undefined4 field54_0x70;
    undefined field55_0x74;
    undefined field56_0x75;
    undefined field57_0x76;
    undefined field58_0x77;
    undefined8 field59_0x78;
    undefined8 field60_0x80;
    undefined field61_0x88;
    undefined field62_0x89;
    undefined field63_0x8a;
    undefined field64_0x8b;
    undefined field65_0x8c;
    undefined field66_0x8d;
    undefined field67_0x8e;
    undefined field68_0x8f;
    undefined2 field69_0x90;
    undefined field70_0x92;
    undefined field71_0x93;
    undefined field72_0x94;
    undefined field73_0x95;
    undefined field74_0x96;
    undefined field75_0x97;
    undefined8 field76_0x98;
    undefined4 field77_0xa0;
    undefined field78_0xa4;
    undefined field79_0xa5;
    undefined field80_0xa6;
    undefined field81_0xa7;
    undefined field82_0xa8;
    undefined field83_0xa9;
    undefined field84_0xaa;
    undefined field85_0xab;
    undefined field86_0xac;
    undefined field87_0xad;
    undefined field88_0xae;
    undefined field89_0xaf;
    undefined field90_0xb0;
    undefined field91_0xb1;
    undefined field92_0xb2;
    undefined field93_0xb3;
    undefined field94_0xb4;
    undefined field95_0xb5;
    undefined field96_0xb6;
    undefined field97_0xb7;
    undefined field98_0xb8;
    undefined field99_0xb9;
    undefined field100_0xba;
    undefined field101_0xbb;
    undefined field102_0xbc;
    undefined field103_0xbd;
    undefined field104_0xbe;
    undefined field105_0xbf;
    undefined4 field106_0xc0;
    undefined field107_0xc4;
    undefined field108_0xc5;
    undefined field109_0xc6;
    undefined field110_0xc7;
    undefined **field111_0xc8;
    undefined8 field112_0xd0;
    undefined8 field113_0xd8;
    undefined4 field114_0xe0;
    undefined field115_0xe4;
    undefined field116_0xe5;
    undefined field117_0xe6;
    undefined field118_0xe7;
    undefined8 field119_0xe8;
    undefined8 field120_0xf0;
    undefined field121_0xf8;
    undefined field122_0xf9;
    undefined field123_0xfa;
    undefined field124_0xfb;
    undefined field125_0xfc;
    undefined field126_0xfd;
    undefined field127_0xfe;
    undefined field128_0xff;
    undefined2 field129_0x100;
    undefined field130_0x102;
    undefined field131_0x103;
    undefined field132_0x104;
    undefined field133_0x105;
    undefined field134_0x106;
    undefined field135_0x107;
    undefined8 field136_0x108;
    struct TPMW8L_PCR_SELECTION field137_0x110;
};

typedef struct TPMW8_ReadPublic TPMW8_ReadPublic, *PTPMW8_ReadPublic;

struct TPMW8_ReadPublic { /* PlaceHolder Structure */
    undefined **field0_0x0;
    void *field1_0x8;
    uint field2_0x10;
    undefined4 field3_0x14;
    undefined4 field4_0x18;
    undefined field5_0x1c;
    undefined field6_0x1d;
    undefined field7_0x1e;
    undefined field8_0x1f;
    void *field9_0x20;
    uint field10_0x28;
    undefined4 field11_0x2c;
    undefined field12_0x30;
    undefined field13_0x31;
    undefined field14_0x32;
    undefined field15_0x33;
    undefined field16_0x34;
    undefined field17_0x35;
    undefined field18_0x36;
    undefined field19_0x37;
    undefined2 field20_0x38;
    undefined field21_0x3a;
    undefined field22_0x3b;
    undefined field23_0x3c;
    undefined field24_0x3d;
    undefined field25_0x3e;
    undefined field26_0x3f;
    undefined field27_0x40;
    undefined field28_0x41;
    undefined field29_0x42;
    undefined field30_0x43;
    undefined field31_0x44;
    undefined field32_0x45;
    undefined field33_0x46;
    undefined field34_0x47;
    undefined field35_0x48;
    undefined field36_0x49;
    undefined field37_0x4a;
    undefined field38_0x4b;
    undefined field39_0x4c;
    undefined field40_0x4d;
    undefined field41_0x4e;
    undefined field42_0x4f;
    undefined field43_0x50;
    undefined field44_0x51;
    undefined field45_0x52;
    undefined field46_0x53;
    undefined field47_0x54;
    undefined field48_0x55;
    undefined field49_0x56;
    undefined field50_0x57;
    undefined **field51_0x58;
    undefined8 field52_0x60;
    undefined8 field53_0x68;
    undefined4 field54_0x70;
    undefined field55_0x74;
    undefined field56_0x75;
    undefined field57_0x76;
    undefined field58_0x77;
    undefined8 field59_0x78;
    undefined8 field60_0x80;
    undefined field61_0x88;
    undefined field62_0x89;
    undefined field63_0x8a;
    undefined field64_0x8b;
    undefined field65_0x8c;
    undefined field66_0x8d;
    undefined field67_0x8e;
    undefined field68_0x8f;
    undefined2 field69_0x90;
    undefined field70_0x92;
    undefined field71_0x93;
    undefined field72_0x94;
    undefined field73_0x95;
    undefined field74_0x96;
    undefined field75_0x97;
    undefined8 field76_0x98;
    undefined4 field77_0xa0;
    undefined field78_0xa4;
    undefined field79_0xa5;
    undefined field80_0xa6;
    undefined field81_0xa7;
    undefined field82_0xa8;
    undefined field83_0xa9;
    undefined field84_0xaa;
    undefined field85_0xab;
    undefined field86_0xac;
    undefined field87_0xad;
    undefined field88_0xae;
    undefined field89_0xaf;
    undefined field90_0xb0;
    undefined field91_0xb1;
    undefined field92_0xb2;
    undefined field93_0xb3;
    undefined field94_0xb4;
    undefined field95_0xb5;
    undefined field96_0xb6;
    undefined field97_0xb7;
    undefined field98_0xb8;
    undefined field99_0xb9;
    undefined field100_0xba;
    undefined field101_0xbb;
    undefined field102_0xbc;
    undefined field103_0xbd;
    undefined field104_0xbe;
    undefined field105_0xbf;
    undefined field106_0xc0;
    undefined field107_0xc1;
    undefined field108_0xc2;
    undefined field109_0xc3;
    undefined4 ParentHandle;
    undefined8 field111_0xc8;
    undefined **field112_0xd0;
    undefined8 field113_0xd8;
    undefined8 field114_0xe0;
    undefined4 field115_0xe8;
    undefined field116_0xec;
    undefined field117_0xed;
    undefined field118_0xee;
    undefined field119_0xef;
    undefined8 field120_0xf0;
    undefined8 field121_0xf8;
    undefined field122_0x100;
    undefined field123_0x101;
    undefined field124_0x102;
    undefined field125_0x103;
    undefined field126_0x104;
    undefined field127_0x105;
    undefined field128_0x106;
    undefined field129_0x107;
    undefined2 size;
    undefined field131_0x10a;
    undefined field132_0x10b;
    undefined field133_0x10c;
    undefined field134_0x10d;
    undefined field135_0x10e;
    undefined field136_0x10f;
    undefined8 PublicData;
    undefined **field138_0x118;
    undefined8 field139_0x120;
    undefined8 field140_0x128;
    undefined4 field141_0x130;
    undefined field142_0x134;
    undefined field143_0x135;
    undefined field144_0x136;
    undefined field145_0x137;
    undefined8 field146_0x138;
    undefined8 field147_0x140;
    undefined field148_0x148;
    undefined field149_0x149;
    undefined field150_0x14a;
    undefined field151_0x14b;
    undefined field152_0x14c;
    undefined field153_0x14d;
    undefined field154_0x14e;
    undefined field155_0x14f;
    undefined2 field156_0x150;
    undefined field157_0x152;
    undefined field158_0x153;
    undefined field159_0x154;
    undefined field160_0x155;
    undefined field161_0x156;
    undefined field162_0x157;
    undefined8 field163_0x158;
};

typedef struct TPMW8_SESSION TPMW8_SESSION, *PTPMW8_SESSION;

struct TPMW8_SESSION { /* PlaceHolder Structure */
    undefined **field0_0x0;
    undefined8 field1_0x8;
    undefined4 field2_0x10;
    undefined field3_0x14;
    undefined field4_0x15;
    undefined field5_0x16;
    undefined field6_0x17;
    undefined **field7_0x18;
    undefined8 field8_0x20;
    undefined8 field9_0x28;
    undefined4 field10_0x30;
    undefined field11_0x34;
    undefined field12_0x35;
    undefined field13_0x36;
    undefined field14_0x37;
    undefined8 field15_0x38;
    undefined8 field16_0x40;
    undefined field17_0x48;
    undefined field18_0x49;
    undefined field19_0x4a;
    undefined field20_0x4b;
    undefined field21_0x4c;
    undefined field22_0x4d;
    undefined field23_0x4e;
    undefined field24_0x4f;
    undefined2 field25_0x50;
    undefined field26_0x52;
    undefined field27_0x53;
    undefined field28_0x54;
    undefined field29_0x55;
    undefined field30_0x56;
    undefined field31_0x57;
    undefined8 field32_0x58;
    undefined **field33_0x60;
    undefined8 field34_0x68;
    undefined8 field35_0x70;
    undefined4 field36_0x78;
    undefined field37_0x7c;
    undefined field38_0x7d;
    undefined field39_0x7e;
    undefined field40_0x7f;
    undefined8 field41_0x80;
    undefined8 field42_0x88;
    undefined field43_0x90;
    undefined field44_0x91;
    undefined field45_0x92;
    undefined field46_0x93;
    undefined field47_0x94;
    undefined field48_0x95;
    undefined field49_0x96;
    undefined field50_0x97;
    undefined2 field51_0x98;
    undefined field52_0x9a;
    undefined field53_0x9b;
    undefined field54_0x9c;
    undefined field55_0x9d;
    undefined field56_0x9e;
    undefined field57_0x9f;
    undefined8 field58_0xa0;
    undefined **field59_0xa8;
    undefined8 field60_0xb0;
    undefined8 field61_0xb8;
    undefined4 field62_0xc0;
    undefined field63_0xc4;
    undefined field64_0xc5;
    undefined field65_0xc6;
    undefined field66_0xc7;
    undefined8 field67_0xc8;
    undefined8 field68_0xd0;
    undefined field69_0xd8;
    undefined field70_0xd9;
    undefined field71_0xda;
    undefined field72_0xdb;
    undefined field73_0xdc;
    undefined field74_0xdd;
    undefined field75_0xde;
    undefined field76_0xdf;
    undefined2 field77_0xe0;
    undefined field78_0xe2;
    undefined field79_0xe3;
    undefined field80_0xe4;
    undefined field81_0xe5;
    undefined field82_0xe6;
    undefined field83_0xe7;
    undefined8 field84_0xe8;
    undefined **field85_0xf0;
    undefined8 field86_0xf8;
    undefined8 field87_0x100;
    undefined4 field88_0x108;
    undefined field89_0x10c;
    undefined field90_0x10d;
    undefined field91_0x10e;
    undefined field92_0x10f;
    undefined8 field93_0x110;
    undefined8 field94_0x118;
    undefined field95_0x120;
    undefined field96_0x121;
    undefined field97_0x122;
    undefined field98_0x123;
    undefined field99_0x124;
    undefined field100_0x125;
    undefined field101_0x126;
    undefined field102_0x127;
    undefined2 field103_0x128;
    undefined field104_0x12a;
    undefined field105_0x12b;
    undefined field106_0x12c;
    undefined field107_0x12d;
    undefined field108_0x12e;
    undefined field109_0x12f;
    undefined8 field110_0x130;
    undefined **field111_0x138;
    undefined8 field112_0x140;
    undefined8 field113_0x148;
    undefined4 field114_0x150;
    undefined field115_0x154;
    undefined field116_0x155;
    undefined field117_0x156;
    undefined field118_0x157;
    undefined8 field119_0x158;
    undefined8 field120_0x160;
    undefined field121_0x168;
    undefined field122_0x169;
    undefined field123_0x16a;
    undefined field124_0x16b;
    undefined field125_0x16c;
    undefined field126_0x16d;
    undefined field127_0x16e;
    undefined field128_0x16f;
    undefined2 field129_0x170;
    undefined field130_0x172;
    undefined field131_0x173;
    undefined field132_0x174;
    undefined field133_0x175;
    undefined field134_0x176;
    undefined field135_0x177;
    undefined8 field136_0x178;
    undefined **field137_0x180;
    undefined8 field138_0x188;
    undefined8 field139_0x190;
    undefined4 field140_0x198;
    undefined field141_0x19c;
    undefined field142_0x19d;
    undefined field143_0x19e;
    undefined field144_0x19f;
    undefined8 field145_0x1a0;
    undefined8 field146_0x1a8;
    undefined field147_0x1b0;
    undefined field148_0x1b1;
    undefined field149_0x1b2;
    undefined field150_0x1b3;
    undefined field151_0x1b4;
    undefined field152_0x1b5;
    undefined field153_0x1b6;
    undefined field154_0x1b7;
    undefined2 field155_0x1b8;
    undefined field156_0x1ba;
    undefined field157_0x1bb;
    undefined field158_0x1bc;
    undefined field159_0x1bd;
    undefined field160_0x1be;
    undefined field161_0x1bf;
    undefined8 field162_0x1c0;
    undefined **field163_0x1c8;
    undefined8 field164_0x1d0;
    undefined8 field165_0x1d8;
    undefined4 field166_0x1e0;
    undefined field167_0x1e4;
    undefined field168_0x1e5;
    undefined field169_0x1e6;
    undefined field170_0x1e7;
    undefined8 field171_0x1e8;
    undefined8 field172_0x1f0;
    undefined field173_0x1f8;
    undefined field174_0x1f9;
    undefined field175_0x1fa;
    undefined field176_0x1fb;
    undefined field177_0x1fc;
    undefined field178_0x1fd;
    undefined field179_0x1fe;
    undefined field180_0x1ff;
    undefined2 field181_0x200;
    undefined field182_0x202;
    undefined field183_0x203;
    undefined field184_0x204;
    undefined field185_0x205;
    undefined field186_0x206;
    undefined field187_0x207;
    undefined8 field188_0x208;
    undefined **field189_0x210;
    undefined8 field190_0x218;
    undefined8 field191_0x220;
    undefined4 field192_0x228;
    undefined field193_0x22c;
    undefined field194_0x22d;
    undefined field195_0x22e;
    undefined field196_0x22f;
    undefined8 field197_0x230;
    undefined8 field198_0x238;
    undefined field199_0x240;
    undefined field200_0x241;
    undefined field201_0x242;
    undefined field202_0x243;
    undefined field203_0x244;
    undefined field204_0x245;
    undefined field205_0x246;
    undefined field206_0x247;
    undefined2 field207_0x248;
    undefined field208_0x24a;
    undefined field209_0x24b;
    undefined field210_0x24c;
    undefined field211_0x24d;
    undefined field212_0x24e;
    undefined field213_0x24f;
    undefined8 field214_0x250;
    undefined field215_0x258;
    undefined field216_0x259;
    undefined field217_0x25a;
    undefined field218_0x25b;
    undefined4 field219_0x25c;
    undefined **field220_0x260;
    undefined8 field221_0x268;
    undefined8 field222_0x270;
    undefined4 field223_0x278;
    undefined field224_0x27c;
    undefined field225_0x27d;
    undefined field226_0x27e;
    undefined field227_0x27f;
    undefined8 field228_0x280;
    undefined8 field229_0x288;
    undefined field230_0x290;
    undefined field231_0x291;
    undefined field232_0x292;
    undefined field233_0x293;
    undefined field234_0x294;
    undefined field235_0x295;
    undefined field236_0x296;
    undefined field237_0x297;
    undefined2 field238_0x298;
    undefined field239_0x29a;
    undefined field240_0x29b;
    undefined field241_0x29c;
    undefined field242_0x29d;
    undefined field243_0x29e;
    undefined field244_0x29f;
    undefined8 field245_0x2a0;
    undefined field246_0x2a8;
    undefined field247_0x2a9;
    undefined field248_0x2aa;
    undefined field249_0x2ab;
    undefined field250_0x2ac;
    undefined field251_0x2ad;
    undefined field252_0x2ae;
    undefined field253_0x2af;
    undefined field254_0x2b0;
    undefined field255_0x2b1;
    undefined field256_0x2b2;
    undefined field257_0x2b3;
    undefined field258_0x2b4;
    undefined field259_0x2b5;
    undefined field260_0x2b6;
    undefined field261_0x2b7;
    undefined field262_0x2b8;
    undefined field263_0x2b9;
    undefined field264_0x2ba;
    undefined field265_0x2bb;
    undefined field266_0x2bc;
    undefined field267_0x2bd;
    undefined field268_0x2be;
    undefined field269_0x2bf;
    undefined field270_0x2c0;
    undefined field271_0x2c1;
    undefined field272_0x2c2;
    undefined field273_0x2c3;
    undefined field274_0x2c4;
    undefined field275_0x2c5;
    undefined field276_0x2c6;
    undefined field277_0x2c7;
    undefined field278_0x2c8;
    undefined field279_0x2c9;
    undefined field280_0x2ca;
    undefined field281_0x2cb;
    undefined field282_0x2cc;
    undefined field283_0x2cd;
    undefined field284_0x2ce;
    undefined field285_0x2cf;
    undefined field286_0x2d0;
    undefined field287_0x2d1;
    undefined field288_0x2d2;
    undefined field289_0x2d3;
    undefined field290_0x2d4;
    undefined field291_0x2d5;
    undefined field292_0x2d6;
    undefined field293_0x2d7;
    undefined field294_0x2d8;
    undefined field295_0x2d9;
    undefined field296_0x2da;
    undefined field297_0x2db;
    undefined field298_0x2dc;
    undefined field299_0x2dd;
    undefined field300_0x2de;
    undefined field301_0x2df;
    undefined field302_0x2e0;
    undefined field303_0x2e1;
    undefined field304_0x2e2;
    undefined field305_0x2e3;
    undefined field306_0x2e4;
    undefined field307_0x2e5;
    undefined field308_0x2e6;
    undefined field309_0x2e7;
    undefined field310_0x2e8;
    undefined field311_0x2e9;
    undefined field312_0x2ea;
    undefined field313_0x2eb;
    undefined field314_0x2ec;
    undefined field315_0x2ed;
    undefined field316_0x2ee;
    undefined field317_0x2ef;
    undefined8 field318_0x2f0;
    undefined field319_0x2f8;
    undefined field320_0x2f9;
    undefined2 field321_0x2fa;
    undefined field322_0x2fc;
    undefined field323_0x2fd;
    undefined field324_0x2fe;
    undefined field325_0x2ff;
    undefined4 field326_0x300;
    undefined field327_0x304;
    undefined field328_0x305;
    undefined field329_0x306;
    undefined field330_0x307;
    undefined8 *field331_0x308;
    undefined field332_0x310;
};

typedef struct TPMW8_StartAuthSession TPMW8_StartAuthSession, *PTPMW8_StartAuthSession;

struct TPMW8_StartAuthSession { /* PlaceHolder Structure */
    undefined **field0_0x0;
    undefined8 field1_0x8;
    undefined8 field2_0x10;
    undefined4 field3_0x18;
    undefined field4_0x1c;
    undefined field5_0x1d;
    undefined field6_0x1e;
    undefined field7_0x1f;
    undefined8 field8_0x20;
    undefined8 field9_0x28;
    struct TPMW8_COMMAND field10_0x30;
    undefined2 field11_0x38;
    undefined field12_0x3a;
    undefined field13_0x3b;
    undefined field14_0x3c;
    undefined field15_0x3d;
    undefined field16_0x3e;
    undefined field17_0x3f;
    undefined field18_0x40;
    undefined field19_0x41;
    undefined field20_0x42;
    undefined field21_0x43;
    undefined field22_0x44;
    undefined field23_0x45;
    undefined field24_0x46;
    undefined field25_0x47;
    undefined field26_0x48;
    undefined field27_0x49;
    undefined field28_0x4a;
    undefined field29_0x4b;
    undefined field30_0x4c;
    undefined field31_0x4d;
    undefined field32_0x4e;
    undefined field33_0x4f;
    undefined field34_0x50;
    undefined field35_0x51;
    undefined field36_0x52;
    undefined field37_0x53;
    undefined field38_0x54;
    undefined field39_0x55;
    undefined field40_0x56;
    undefined field41_0x57;
    undefined **field42_0x58;
    undefined8 field43_0x60;
    undefined8 field44_0x68;
    undefined4 field45_0x70;
    undefined field46_0x74;
    undefined field47_0x75;
    undefined field48_0x76;
    undefined field49_0x77;
    undefined8 field50_0x78;
    undefined8 field51_0x80;
    struct TPMW8_COMMAND field52_0x88;
    undefined2 field53_0x90;
    undefined field54_0x92;
    undefined field55_0x93;
    undefined field56_0x94;
    undefined field57_0x95;
    undefined field58_0x96;
    undefined field59_0x97;
    undefined8 field60_0x98;
    undefined4 field61_0xa0;
    undefined field62_0xa4;
    undefined field63_0xa5;
    undefined field64_0xa6;
    undefined field65_0xa7;
    undefined field66_0xa8;
    undefined field67_0xa9;
    undefined field68_0xaa;
    undefined field69_0xab;
    undefined field70_0xac;
    undefined field71_0xad;
    undefined field72_0xae;
    undefined field73_0xaf;
    undefined field74_0xb0;
    undefined field75_0xb1;
    undefined field76_0xb2;
    undefined field77_0xb3;
    undefined field78_0xb4;
    undefined field79_0xb5;
    undefined field80_0xb6;
    undefined field81_0xb7;
    undefined field82_0xb8;
    undefined field83_0xb9;
    undefined field84_0xba;
    undefined field85_0xbb;
    undefined field86_0xbc;
    undefined field87_0xbd;
    undefined field88_0xbe;
    undefined field89_0xbf;
    undefined4 field90_0xc0;
    undefined4 field91_0xc4;
    undefined **field92_0xc8;
    undefined8 field93_0xd0;
    undefined8 field94_0xd8;
    undefined4 field95_0xe0;
    undefined field96_0xe4;
    undefined field97_0xe5;
    undefined field98_0xe6;
    undefined field99_0xe7;
    undefined8 field100_0xe8;
    undefined8 field101_0xf0;
    undefined field102_0xf8;
    undefined field103_0xf9;
    undefined field104_0xfa;
    undefined field105_0xfb;
    undefined field106_0xfc;
    undefined field107_0xfd;
    undefined field108_0xfe;
    undefined field109_0xff;
    undefined2 field110_0x100;
    undefined field111_0x102;
    undefined field112_0x103;
    undefined field113_0x104;
    undefined field114_0x105;
    undefined field115_0x106;
    undefined field116_0x107;
    undefined8 field117_0x108;
    undefined field118_0x110;
    undefined field119_0x111;
    undefined field120_0x112;
    undefined field121_0x113;
    undefined field122_0x114;
    undefined field123_0x115;
    undefined field124_0x116;
    undefined field125_0x117;
    undefined **field126_0x118;
    undefined8 field127_0x120;
    undefined8 field128_0x128;
    undefined4 field129_0x130;
    undefined field130_0x134;
    undefined field131_0x135;
    undefined field132_0x136;
    undefined field133_0x137;
    undefined8 field134_0x138;
    undefined8 field135_0x140;
    undefined field136_0x148;
    undefined field137_0x149;
    undefined field138_0x14a;
    undefined field139_0x14b;
    undefined field140_0x14c;
    undefined field141_0x14d;
    undefined field142_0x14e;
    undefined field143_0x14f;
    undefined2 field144_0x150;
    undefined field145_0x152;
    undefined field146_0x153;
    undefined field147_0x154;
    undefined field148_0x155;
    undefined field149_0x156;
    undefined field150_0x157;
    undefined8 field151_0x158;
    undefined field152_0x160;
    undefined field153_0x161;
    undefined field154_0x162;
    undefined field155_0x163;
    undefined field156_0x164;
    undefined field157_0x165;
    undefined field158_0x166;
    undefined field159_0x167;
    undefined field160_0x168;
    undefined field161_0x169;
    undefined field162_0x16a;
    undefined field163_0x16b;
    undefined field164_0x16c;
    undefined field165_0x16d;
    undefined field166_0x16e;
    undefined field167_0x16f;
    undefined field168_0x170;
    undefined field169_0x171;
    undefined field170_0x172;
    undefined field171_0x173;
    undefined field172_0x174;
    undefined field173_0x175;
    undefined field174_0x176;
    undefined field175_0x177;
    undefined field176_0x178;
    undefined field177_0x179;
    undefined field178_0x17a;
    undefined field179_0x17b;
    undefined field180_0x17c;
    undefined field181_0x17d;
    undefined field182_0x17e;
    undefined field183_0x17f;
    undefined field184_0x180;
    undefined field185_0x181;
    undefined field186_0x182;
    undefined field187_0x183;
    undefined field188_0x184;
    undefined field189_0x185;
    undefined field190_0x186;
    undefined field191_0x187;
    undefined field192_0x188;
    undefined field193_0x189;
    undefined field194_0x18a;
    undefined field195_0x18b;
    undefined field196_0x18c;
    undefined field197_0x18d;
    undefined field198_0x18e;
    undefined field199_0x18f;
    undefined field200_0x190;
    undefined field201_0x191;
    undefined field202_0x192;
    undefined field203_0x193;
    undefined field204_0x194;
    undefined field205_0x195;
    undefined field206_0x196;
    undefined field207_0x197;
    undefined field208_0x198;
    undefined field209_0x199;
    undefined field210_0x19a;
    undefined field211_0x19b;
    undefined field212_0x19c;
    undefined field213_0x19d;
    undefined field214_0x19e;
    undefined field215_0x19f;
    undefined field216_0x1a0;
    undefined field217_0x1a1;
    undefined field218_0x1a2;
    undefined field219_0x1a3;
    undefined field220_0x1a4;
    undefined field221_0x1a5;
    undefined field222_0x1a6;
    undefined field223_0x1a7;
    undefined2 field224_0x1a8;
    undefined field225_0x1aa;
    undefined field226_0x1ab;
    undefined4 field227_0x1ac;
    undefined **field228_0x1b0;
    undefined8 field229_0x1b8;
    undefined8 field230_0x1c0;
    undefined4 field231_0x1c8;
    undefined field232_0x1cc;
    undefined field233_0x1cd;
    undefined field234_0x1ce;
    undefined field235_0x1cf;
    undefined8 field236_0x1d0;
    undefined8 field237_0x1d8;
    undefined field238_0x1e0;
    undefined field239_0x1e1;
    undefined field240_0x1e2;
    undefined field241_0x1e3;
    undefined field242_0x1e4;
    undefined field243_0x1e5;
    undefined field244_0x1e6;
    undefined field245_0x1e7;
    undefined2 field246_0x1e8;
    undefined field247_0x1ea;
    undefined field248_0x1eb;
    undefined field249_0x1ec;
    undefined field250_0x1ed;
    undefined field251_0x1ee;
    undefined field252_0x1ef;
    undefined8 field253_0x1f0;
};

typedef struct TPMW8S_CREATION_DATA TPMW8S_CREATION_DATA, *PTPMW8S_CREATION_DATA;

struct TPMW8S_CREATION_DATA { /* PlaceHolder Structure */
};

typedef struct TPMW8S_NV_PUBLIC TPMW8S_NV_PUBLIC, *PTPMW8S_NV_PUBLIC;

struct TPMW8S_NV_PUBLIC { /* PlaceHolder Structure */
};

typedef struct TPMW8S_PCR_SELECTION TPMW8S_PCR_SELECTION, *PTPMW8S_PCR_SELECTION;

struct TPMW8S_PCR_SELECTION { /* PlaceHolder Structure */
};

typedef struct TPMW8T_ECC_SCHEME TPMW8T_ECC_SCHEME, *PTPMW8T_ECC_SCHEME;

struct TPMW8T_ECC_SCHEME { /* PlaceHolder Structure */
};

typedef struct TPMW8T_KDF_SCHEME TPMW8T_KDF_SCHEME, *PTPMW8T_KDF_SCHEME;

struct TPMW8T_KDF_SCHEME { /* PlaceHolder Structure */
};

typedef struct TPMW8T_KEYEDHASH_SCHEME TPMW8T_KEYEDHASH_SCHEME, *PTPMW8T_KEYEDHASH_SCHEME;

struct TPMW8T_KEYEDHASH_SCHEME { /* PlaceHolder Structure */
};

typedef struct TPMW8T_RSA_SCHEME TPMW8T_RSA_SCHEME, *PTPMW8T_RSA_SCHEME;

struct TPMW8T_RSA_SCHEME { /* PlaceHolder Structure */
};

typedef struct TPMW8T_SYM_DEF TPMW8T_SYM_DEF, *PTPMW8T_SYM_DEF;

struct TPMW8T_SYM_DEF { /* PlaceHolder Structure */
};

typedef struct TPMW8T_SYM_DEF_OBJECT TPMW8T_SYM_DEF_OBJECT, *PTPMW8T_SYM_DEF_OBJECT;

struct TPMW8T_SYM_DEF_OBJECT { /* PlaceHolder Structure */
};

typedef struct TPMW8T_TK TPMW8T_TK, *PTPMW8T_TK;

struct TPMW8T_TK { /* PlaceHolder Structure */
};

typedef struct _MODULE_INFO _MODULE_INFO, *P_MODULE_INFO;

struct _MODULE_INFO { /* PlaceHolder Structure */
};

typedef struct EnabledStateManager EnabledStateManager, *PEnabledStateManager;

struct EnabledStateManager { /* PlaceHolder Structure */
};

typedef struct FeatureImpl<struct___WilFeatureTraits_Feature_ClientRecoveryPasswordRotation> FeatureImpl<struct___WilFeatureTraits_Feature_ClientRecoveryPasswordRotation>, *PFeatureImpl<struct___WilFeatureTraits_Feature_ClientRecoveryPasswordRotation>;

struct FeatureImpl<struct___WilFeatureTraits_Feature_ClientRecoveryPasswordRotation> { /* PlaceHolder Structure */
};

typedef struct FeatureImpl<struct___WilFeatureTraits_Feature_Servicing_BitLockerSupportForBootmgrAuthority> FeatureImpl<struct___WilFeatureTraits_Feature_Servicing_BitLockerSupportForBootmgrAuthority>, *PFeatureImpl<struct___WilFeatureTraits_Feature_Servicing_BitLockerSupportForBootmgrAuthority>;

struct FeatureImpl<struct___WilFeatureTraits_Feature_Servicing_BitLockerSupportForBootmgrAuthority> { /* PlaceHolder Structure */
};

typedef struct FeatureImpl<struct___WilFeatureTraits_Feature_SID_Protection_To_L1> FeatureImpl<struct___WilFeatureTraits_Feature_SID_Protection_To_L1>, *PFeatureImpl<struct___WilFeatureTraits_Feature_SID_Protection_To_L1>;

struct FeatureImpl<struct___WilFeatureTraits_Feature_SID_Protection_To_L1> { /* PlaceHolder Structure */
};

typedef struct FeatureStateManager FeatureStateManager, *PFeatureStateManager;

struct FeatureStateManager { /* PlaceHolder Structure */
};

typedef enum ReportFailureOptions {
} ReportFailureOptions;

typedef struct unique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_> unique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_>, *Punique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_>;

struct unique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_> { /* PlaceHolder Structure */
};

typedef struct unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_> unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>, *Punique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>;

struct unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_> { /* PlaceHolder Structure */
};

typedef struct unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::ReleaseMutex(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,2>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_> unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::ReleaseMutex(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,2>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>, *Punique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::ReleaseMutex(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,2>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>;

struct unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::ReleaseMutex(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,2>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_> { /* PlaceHolder Structure */
};

typedef enum CountSize {
} CountSize;

typedef struct FeatureStateData FeatureStateData, *PFeatureStateData;

struct FeatureStateData { /* PlaceHolder Structure */
};

typedef struct heap_buffer heap_buffer, *Pheap_buffer;

struct heap_buffer { /* PlaceHolder Structure */
};

typedef struct heap_vector<struct_wil_details_FeatureUsageSRUM> heap_vector<struct_wil_details_FeatureUsageSRUM>, *Pheap_vector<struct_wil_details_FeatureUsageSRUM>;

struct heap_vector<struct_wil_details_FeatureUsageSRUM> { /* PlaceHolder Structure */
};

typedef struct ProcessLocalStorage<struct_wil::details_abi::ProcessLocalData> ProcessLocalStorage<struct_wil::details_abi::ProcessLocalData>, *PProcessLocalStorage<struct_wil::details_abi::ProcessLocalData>;

struct ProcessLocalStorage<struct_wil::details_abi::ProcessLocalData> { /* PlaceHolder Structure */
};

typedef struct ProcessLocalStorageData<class_wil::details_abi::FeatureStateData> ProcessLocalStorageData<class_wil::details_abi::FeatureStateData>, *PProcessLocalStorageData<class_wil::details_abi::FeatureStateData>;

struct ProcessLocalStorageData<class_wil::details_abi::FeatureStateData> { /* PlaceHolder Structure */
};

typedef struct ProcessLocalStorageData<struct_wil::details_abi::ProcessLocalData> ProcessLocalStorageData<struct_wil::details_abi::ProcessLocalData>, *PProcessLocalStorageData<struct_wil::details_abi::ProcessLocalData>;

struct ProcessLocalStorageData<struct_wil::details_abi::ProcessLocalData> { /* PlaceHolder Structure */
};

typedef struct RawUsageIndex RawUsageIndex, *PRawUsageIndex;

struct RawUsageIndex { /* PlaceHolder Structure */
};

typedef struct SemaphoreValue SemaphoreValue, *PSemaphoreValue;

struct SemaphoreValue { /* PlaceHolder Structure */
};

typedef struct SubscriptionList SubscriptionList, *PSubscriptionList;

struct SubscriptionList { /* PlaceHolder Structure */
};

typedef struct ThreadLocalData ThreadLocalData, *PThreadLocalData;

struct ThreadLocalData { /* PlaceHolder Structure */
};

typedef struct ThreadLocalFailureInfo ThreadLocalFailureInfo, *PThreadLocalFailureInfo;

struct ThreadLocalFailureInfo { /* PlaceHolder Structure */
};

typedef struct ThreadLocalStorage<class_wil::details::ThreadFailureCallbackHolder*___ptr64> ThreadLocalStorage<class_wil::details::ThreadFailureCallbackHolder*___ptr64>, *PThreadLocalStorage<class_wil::details::ThreadFailureCallbackHolder*___ptr64>;

struct ThreadLocalStorage<class_wil::details::ThreadFailureCallbackHolder*___ptr64> { /* PlaceHolder Structure */
};

typedef struct ThreadLocalStorage<struct_wil::details_abi::ThreadLocalData> ThreadLocalStorage<struct_wil::details_abi::ThreadLocalData>, *PThreadLocalStorage<struct_wil::details_abi::ThreadLocalData>;

struct ThreadLocalStorage<struct_wil::details_abi::ThreadLocalData> { /* PlaceHolder Structure */
};

typedef struct UsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,0> UsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,0>, *PUsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,0>;

struct UsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,0> { /* PlaceHolder Structure */
};

typedef struct UsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,2> UsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,2>, *PUsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,2>;

struct UsageIndex<enum_wil_details_ServiceReportingKind,unsigned_int,2> { /* PlaceHolder Structure */
};

typedef struct UsageIndexes UsageIndexes, *PUsageIndexes;

struct UsageIndexes { /* PlaceHolder Structure */
};

typedef struct UsageIndexProperty UsageIndexProperty, *PUsageIndexProperty;

struct UsageIndexProperty { /* PlaceHolder Structure */
};

typedef struct FailureInfo FailureInfo, *PFailureInfo;

struct FailureInfo { /* PlaceHolder Structure */
};

typedef enum FailureType {
} FailureType;

typedef struct manually_managed_shutdown_aware_object<class_wil::details::EnabledStateManager> manually_managed_shutdown_aware_object<class_wil::details::EnabledStateManager>, *Pmanually_managed_shutdown_aware_object<class_wil::details::EnabledStateManager>;

struct manually_managed_shutdown_aware_object<class_wil::details::EnabledStateManager> { /* PlaceHolder Structure */
};

typedef struct manually_managed_shutdown_aware_object<class_wil::details::FeatureStateManager> manually_managed_shutdown_aware_object<class_wil::details::FeatureStateManager>, *Pmanually_managed_shutdown_aware_object<class_wil::details::FeatureStateManager>;

struct manually_managed_shutdown_aware_object<class_wil::details::FeatureStateManager> { /* PlaceHolder Structure */
};

typedef struct mutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy> mutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy>, *Pmutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy>;

struct mutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy> { /* PlaceHolder Structure */
};

typedef enum ReportingKind {
} ReportingKind;

typedef struct shutdown_aware_object<class_wil::details::EnabledStateManager> shutdown_aware_object<class_wil::details::EnabledStateManager>, *Pshutdown_aware_object<class_wil::details::EnabledStateManager>;

struct shutdown_aware_object<class_wil::details::EnabledStateManager> { /* PlaceHolder Structure */
};

typedef struct shutdown_aware_object<class_wil::details::FeatureStateManager> shutdown_aware_object<class_wil::details::FeatureStateManager>, *Pshutdown_aware_object<class_wil::details::FeatureStateManager>;

struct shutdown_aware_object<class_wil::details::FeatureStateManager> { /* PlaceHolder Structure */
};

typedef struct srwlock srwlock, *Psrwlock;

struct srwlock { /* PlaceHolder Structure */
};

typedef struct unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,void_(__cdecl*)(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),&void___cdecl_wil::details::UnsubscribeWilWnf(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,0,std::nullptr_t>_>_> unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,void_(__cdecl*)(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),&void___cdecl_wil::details::UnsubscribeWilWnf(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,0,std::nullptr_t>_>_>, *Punique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,void_(__cdecl*)(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),&void___cdecl_wil::details::UnsubscribeWilWnf(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,0,std::nullptr_t>_>_>;

struct unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,void_(__cdecl*)(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),&void___cdecl_wil::details::UnsubscribeWilWnf(struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,struct___WIL__WNF_USER_SUBSCRIPTION*___ptr64,0,std::nullptr_t>_>_> { /* PlaceHolder Structure */
};

typedef struct unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__RTL_SRWLOCK*___ptr64,void_(__cdecl*)(struct__RTL_SRWLOCK*___ptr64),&void___cdecl_ReleaseSRWLockExclusive(struct__RTL_SRWLOCK*___ptr64),struct_wistd::integral_constant<unsigned___int64,1>,struct__RTL_SRWLOCK*___ptr64,struct__RTL_SRWLOCK*___ptr64,0,std::nullptr_t>_>_> unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__RTL_SRWLOCK*___ptr64,void_(__cdecl*)(struct__RTL_SRWLOCK*___ptr64),&void___cdecl_ReleaseSRWLockExclusive(struct__RTL_SRWLOCK*___ptr64),struct_wistd::integral_constant<unsigned___int64,1>,struct__RTL_SRWLOCK*___ptr64,struct__RTL_SRWLOCK*___ptr64,0,std::nullptr_t>_>_>, *Punique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__RTL_SRWLOCK*___ptr64,void_(__cdecl*)(struct__RTL_SRWLOCK*___ptr64),&void___cdecl_ReleaseSRWLockExclusive(struct__RTL_SRWLOCK*___ptr64),struct_wistd::integral_constant<unsigned___int64,1>,struct__RTL_SRWLOCK*___ptr64,struct__RTL_SRWLOCK*___ptr64,0,std::nullptr_t>_>_>;

struct unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__RTL_SRWLOCK*___ptr64,void_(__cdecl*)(struct__RTL_SRWLOCK*___ptr64),&void___cdecl_ReleaseSRWLockExclusive(struct__RTL_SRWLOCK*___ptr64),struct_wistd::integral_constant<unsigned___int64,1>,struct__RTL_SRWLOCK*___ptr64,struct__RTL_SRWLOCK*___ptr64,0,std::nullptr_t>_>_> { /* PlaceHolder Structure */
};

typedef struct unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_>_> unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_>_>, *Punique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_>_>;

struct unique_any_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<struct__TP_TIMER*___ptr64,void_(__cdecl*)(struct__TP_TIMER*___ptr64),&public:_static_void___cdecl_wil::details::DestroyThreadPoolTimer<struct_wil::details::SystemThreadPoolMethods,0>::Destroy(struct__TP_TIMER*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,struct__TP_TIMER*___ptr64,struct__TP_TIMER*___ptr64,0,std::nullptr_t>_>_> { /* PlaceHolder Structure */
};

typedef struct unique_any_t<class_wil::mutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy>_> unique_any_t<class_wil::mutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy>_>, *Punique_any_t<class_wil::mutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy>_>;

struct unique_any_t<class_wil::mutex_t<class_wil::details::unique_storage<struct_wil::details::resource_policy<void*___ptr64,void_(__cdecl*)(void*___ptr64),&void___cdecl_wil::details::CloseHandle(void*___ptr64),struct_wistd::integral_constant<unsigned___int64,0>,void*___ptr64,void*___ptr64,0,std::nullptr_t>_>,struct_wil::err_returncode_policy>_> { /* PlaceHolder Structure */
};

typedef struct __base<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)> __base<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)>, *P__base<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)>;

struct __base<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)> { /* PlaceHolder Structure */
};

typedef struct __func<class_<lambda_8db0ce862824541f40dfb767113f1e28>,bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)> __func<class_<lambda_8db0ce862824541f40dfb767113f1e28>,bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)>, *P__func<class_<lambda_8db0ce862824541f40dfb767113f1e28>,bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)>;

struct __func<class_<lambda_8db0ce862824541f40dfb767113f1e28>,bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)> { /* PlaceHolder Structure */
};

typedef struct function<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)> function<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)>, *Pfunction<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)>;

struct function<bool___cdecl(void*___ptr64,unsigned___int64,void*___ptr64,unsigned___int64,unsigned_int)> { /* PlaceHolder Structure */
};

typedef struct __FAT32_VOLUME_DATA __FAT32_VOLUME_DATA, *P__FAT32_VOLUME_DATA;

struct __FAT32_VOLUME_DATA { /* PlaceHolder Structure */
};

typedef struct __FILE_INFO_NODE __FILE_INFO_NODE, *P__FILE_INFO_NODE;

struct __FILE_INFO_NODE { /* PlaceHolder Structure */
};

typedef struct __WIL__WNF_STATE_NAME __WIL__WNF_STATE_NAME, *P__WIL__WNF_STATE_NAME;

struct __WIL__WNF_STATE_NAME { /* PlaceHolder Structure */
};

typedef struct __WIL__WNF_TYPE_ID __WIL__WNF_TYPE_ID, *P__WIL__WNF_TYPE_ID;

struct __WIL__WNF_TYPE_ID { /* PlaceHolder Structure */
};

typedef struct __WIL__WNF_USER_SUBSCRIPTION __WIL__WNF_USER_SUBSCRIPTION, *P__WIL__WNF_USER_SUBSCRIPTION;

struct __WIL__WNF_USER_SUBSCRIPTION { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/_ADA_GP_OPTIONS - /CONFLICTS python2.h/_ADA_GP_OPTIONS */

typedef struct _BCD_ELEMENT _BCD_ELEMENT, *P_BCD_ELEMENT;

struct _BCD_ELEMENT { /* PlaceHolder Structure */
};

typedef struct _BCDE_DEVICE _BCDE_DEVICE, *P_BCDE_DEVICE;

struct _BCDE_DEVICE { /* PlaceHolder Structure */
};

typedef enum _BDE_SQM_EHDD_CONFIG_FO_CAUSE {
} _BDE_SQM_EHDD_CONFIG_FO_CAUSE;

typedef enum _CM_NOTIFY_ACTION {
} _CM_NOTIFY_ACTION;

typedef struct _CM_NOTIFY_EVENT_DATA _CM_NOTIFY_EVENT_DATA, *P_CM_NOTIFY_EVENT_DATA;

struct _CM_NOTIFY_EVENT_DATA { /* PlaceHolder Structure */
};

typedef struct _DISCOVERY_VOLUME_FILE_INFORMATION _DISCOVERY_VOLUME_FILE_INFORMATION, *P_DISCOVERY_VOLUME_FILE_INFORMATION;

struct _DISCOVERY_VOLUME_FILE_INFORMATION { /* PlaceHolder Structure */
};

typedef enum _eDeviceJoinStatus {
} _eDeviceJoinStatus;

typedef struct _EXCLUDE_RANGE _EXCLUDE_RANGE, *P_EXCLUDE_RANGE;

struct _EXCLUDE_RANGE { /* PlaceHolder Structure */
};

typedef struct _FAT_TIME_STAMP _FAT_TIME_STAMP, *P_FAT_TIME_STAMP;

struct _FAT_TIME_STAMP { /* PlaceHolder Structure */
};

typedef enum _FIRMWARE_TYPE {
} _FIRMWARE_TYPE;

typedef struct _FVE_AAD_DELETE_INFO _FVE_AAD_DELETE_INFO, *P_FVE_AAD_DELETE_INFO;

struct _FVE_AAD_DELETE_INFO { /* PlaceHolder Structure */
};

typedef struct _FVE_AAD_DELETE_REQUEST _FVE_AAD_DELETE_REQUEST, *P_FVE_AAD_DELETE_REQUEST;

struct _FVE_AAD_DELETE_REQUEST { /* PlaceHolder Structure */
};

typedef struct _FVE_ACTION _FVE_ACTION, *P_FVE_ACTION;

struct _FVE_ACTION { /* PlaceHolder Structure */
};

typedef struct _FVE_ACTION2 _FVE_ACTION2, *P_FVE_ACTION2;

struct _FVE_ACTION2 { /* PlaceHolder Structure */
};

typedef struct _FVE_ASYNC_REQUEST_ENTRY _FVE_ASYNC_REQUEST_ENTRY, *P_FVE_ASYNC_REQUEST_ENTRY;

struct _FVE_ASYNC_REQUEST_ENTRY { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/_FVE_AUTH_DPAPI_NG - /CONFLICTS python2.h/_FVE_AUTH_DPAPI_NG */


/* WARNING! conflicting data type names: /Demangler/_FVE_AUTH_ELEMENT - /CONFLICTS python2.h/_FVE_AUTH_ELEMENT */


/* WARNING! conflicting data type names: /Demangler/_FVE_AUTH_INFORMATION - /CONFLICTS python2.h/_FVE_AUTH_INFORMATION */

typedef struct _FVE_BOOT_LOG_HEADER _FVE_BOOT_LOG_HEADER, *P_FVE_BOOT_LOG_HEADER;

struct _FVE_BOOT_LOG_HEADER { /* PlaceHolder Structure */
};

typedef enum _FVE_BOOT_LOG_TYPE {
} _FVE_BOOT_LOG_TYPE;

typedef struct _FVE_CERT_INFO _FVE_CERT_INFO, *P_FVE_CERT_INFO;

struct _FVE_CERT_INFO { /* PlaceHolder Structure */
};

typedef struct _FVE_DATASET _FVE_DATASET, *P_FVE_DATASET;

struct _FVE_DATASET { /* PlaceHolder Structure */
};

typedef struct _FVE_DATUM_EXPORTED_PUBLIC_KEY _FVE_DATUM_EXPORTED_PUBLIC_KEY, *P_FVE_DATUM_EXPORTED_PUBLIC_KEY;

struct _FVE_DATUM_EXPORTED_PUBLIC_KEY { /* PlaceHolder Structure */
};

typedef struct _FVE_DATUM_EXTERNAL_INFO _FVE_DATUM_EXTERNAL_INFO, *P_FVE_DATUM_EXTERNAL_INFO;

struct _FVE_DATUM_EXTERNAL_INFO { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/_FVE_DATUM_KEY - /fve.h/_FVE_DATUM_KEY */

typedef struct _FVE_DATUM_PUBLIC_KEY_INFO _FVE_DATUM_PUBLIC_KEY_INFO, *P_FVE_DATUM_PUBLIC_KEY_INFO;

struct _FVE_DATUM_PUBLIC_KEY_INFO { /* PlaceHolder Structure */
};

typedef struct _FVE_DATUM_UNICODE _FVE_DATUM_UNICODE, *P_FVE_DATUM_UNICODE;

struct _FVE_DATUM_UNICODE { /* PlaceHolder Structure */
};

typedef struct _FVE_DATUM_VALIDATION_ENTRY _FVE_DATUM_VALIDATION_ENTRY, *P_FVE_DATUM_VALIDATION_ENTRY;

struct _FVE_DATUM_VALIDATION_ENTRY { /* PlaceHolder Structure */
};

typedef struct _FVE_DATUM_VALIDATION_INFO _FVE_DATUM_VALIDATION_INFO, *P_FVE_DATUM_VALIDATION_INFO;

struct _FVE_DATUM_VALIDATION_INFO { /* PlaceHolder Structure */
};

typedef struct _FVE_DATUM_VMK_INFO _FVE_DATUM_VMK_INFO, *P_FVE_DATUM_VMK_INFO;

struct _FVE_DATUM_VMK_INFO { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/_FVE_DE_SUPPORT - /CONFLICTS python2.h/_FVE_DE_SUPPORT */

typedef struct _FVE_DEVICE_LOCKOUT_COUNTER_HDR _FVE_DEVICE_LOCKOUT_COUNTER_HDR, *P_FVE_DEVICE_LOCKOUT_COUNTER_HDR;

struct _FVE_DEVICE_LOCKOUT_COUNTER_HDR { /* PlaceHolder Structure */
};

typedef struct _FVE_DEVICE_LOCKOUT_COUNTER_TPM _FVE_DEVICE_LOCKOUT_COUNTER_TPM, *P_FVE_DEVICE_LOCKOUT_COUNTER_TPM;

struct _FVE_DEVICE_LOCKOUT_COUNTER_TPM { /* PlaceHolder Structure */
};

typedef struct _FVE_DEVICE_LOCKOUT_STATE _FVE_DEVICE_LOCKOUT_STATE, *P_FVE_DEVICE_LOCKOUT_STATE;

struct _FVE_DEVICE_LOCKOUT_STATE { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/_FVE_DEVICE_TYPE - /CONFLICTS python2.h/_FVE_DEVICE_TYPE */

typedef struct _FVE_DPAPI_NG_INFO _FVE_DPAPI_NG_INFO, *P_FVE_DPAPI_NG_INFO;

struct _FVE_DPAPI_NG_INFO { /* PlaceHolder Structure */
};

typedef struct _FVE_EVENT_LOG _FVE_EVENT_LOG, *P_FVE_EVENT_LOG;

struct _FVE_EVENT_LOG { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/_FVE_FIND_DATA_V1 - /CONFLICTS python2.h/_FVE_FIND_DATA_V1 */

typedef struct _FVE_NONCE _FVE_NONCE, *P_FVE_NONCE;

struct _FVE_NONCE { /* PlaceHolder Structure */
};

typedef struct _FVE_PERSISTENT_REQUEST_CONFIG _FVE_PERSISTENT_REQUEST_CONFIG, *P_FVE_PERSISTENT_REQUEST_CONFIG;

struct _FVE_PERSISTENT_REQUEST_CONFIG { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/_FVE_PROTECTOR_TYPE - /CONFLICTS python2.h/_FVE_PROTECTOR_TYPE */


/* WARNING! conflicting data type names: /Demangler/_FVE_QUERY_TYPE - /CONFLICTS python2.h/_FVE_QUERY_TYPE */

typedef enum _FVE_REQUEST_TYPE {
} _FVE_REQUEST_TYPE;


/* WARNING! conflicting data type names: /Demangler/_FVE_SECUREBOOT_BINDING_STATE - /CONFLICTS python2.h/_FVE_SECUREBOOT_BINDING_STATE */


/* WARNING! conflicting data type names: /Demangler/_FVE_WCOS_SEQURITY_INFO_REQUEST - /CONFLICTS python2.h/_FVE_WCOS_SEQURITY_INFO_REQUEST */


/* WARNING! conflicting data type names: /Demangler/_FVE_WCOS_SEQURITY_INFO_RESPONSE - /CONFLICTS python2.h/_FVE_WCOS_SEQURITY_INFO_RESPONSE */

typedef enum _FVEAPI_BACKUP_FILTER {
} _FVEAPI_BACKUP_FILTER;

typedef enum _FVEAPI_OBJECT_TYPE {
} _FVEAPI_OBJECT_TYPE;

typedef struct _HASHLIB_LOADED_IMAGE _HASHLIB_LOADED_IMAGE, *P_HASHLIB_LOADED_IMAGE;

struct _HASHLIB_LOADED_IMAGE { /* PlaceHolder Structure */
};

typedef struct _NGSCB_HSTI_PARSING_STATUS _NGSCB_HSTI_PARSING_STATUS, *P_NGSCB_HSTI_PARSING_STATUS;

struct _NGSCB_HSTI_PARSING_STATUS { /* PlaceHolder Structure */
};

typedef struct _NGSCB_HSTI_RESULTS _NGSCB_HSTI_RESULTS, *P_NGSCB_HSTI_RESULTS;

struct _NGSCB_HSTI_RESULTS { /* PlaceHolder Structure */
};

typedef struct _NGSCB_NAME_VALUE_COLLECTION _NGSCB_NAME_VALUE_COLLECTION, *P_NGSCB_NAME_VALUE_COLLECTION;

struct _NGSCB_NAME_VALUE_COLLECTION { /* PlaceHolder Structure */
};

typedef struct _PACKED_DIRENT _PACKED_DIRENT, *P_PACKED_DIRENT;

struct _PACKED_DIRENT { /* PlaceHolder Structure */
};

typedef struct _STRING _STRING, *P_STRING;

struct _STRING { /* PlaceHolder Structure */
};

typedef struct _tlgProvider_t _tlgProvider_t, *P_tlgProvider_t;

struct _tlgProvider_t { /* PlaceHolder Structure */
};

typedef struct _tlgWrapperBinary _tlgWrapperBinary, *P_tlgWrapperBinary;

struct _tlgWrapperBinary { /* PlaceHolder Structure */
};

typedef struct _tlgWrapperByRef<16> _tlgWrapperByRef<16>, *P_tlgWrapperByRef<16>;

struct _tlgWrapperByRef<16> { /* PlaceHolder Structure */
};

typedef struct _tlgWrapperByVal<1> _tlgWrapperByVal<1>, *P_tlgWrapperByVal<1>;

struct _tlgWrapperByVal<1> { /* PlaceHolder Structure */
};

typedef struct _tlgWrapperByVal<2> _tlgWrapperByVal<2>, *P_tlgWrapperByVal<2>;

struct _tlgWrapperByVal<2> { /* PlaceHolder Structure */
};

typedef struct _tlgWrapperByVal<4> _tlgWrapperByVal<4>, *P_tlgWrapperByVal<4>;

struct _tlgWrapperByVal<4> { /* PlaceHolder Structure */
};

typedef struct _tlgWrapperByVal<8> _tlgWrapperByVal<8>, *P_tlgWrapperByVal<8>;

struct _tlgWrapperByVal<8> { /* PlaceHolder Structure */
};

typedef struct _tlgWrapSz<char> _tlgWrapSz<char>, *P_tlgWrapSz<char>;

struct _tlgWrapSz<char> { /* PlaceHolder Structure */
};

typedef struct _tlgWrapSz<unsigned_short> _tlgWrapSz<unsigned_short>, *P_tlgWrapSz<unsigned_short>;

struct _tlgWrapSz<unsigned_short> { /* PlaceHolder Structure */
};

typedef struct _TPM_API_HASH_DATA _TPM_API_HASH_DATA, *P_TPM_API_HASH_DATA;

struct _TPM_API_HASH_DATA { /* PlaceHolder Structure */
};

typedef struct _TPM_API_HASH_DATA20 _TPM_API_HASH_DATA20, *P_TPM_API_HASH_DATA20;

struct _TPM_API_HASH_DATA20 { /* PlaceHolder Structure */
};

typedef struct _TPM_API_PCR_INFO _TPM_API_PCR_INFO, *P_TPM_API_PCR_INFO;

struct _TPM_API_PCR_INFO { /* PlaceHolder Structure */
};

typedef struct _TPM_API_PCR_INFO20 _TPM_API_PCR_INFO20, *P_TPM_API_PCR_INFO20;

struct _TPM_API_PCR_INFO20 { /* PlaceHolder Structure */
};

typedef struct _UNICODE_STRING _UNICODE_STRING, *P_UNICODE_STRING;

struct _UNICODE_STRING { /* PlaceHolder Structure */
};

typedef struct _WBCL_Iterator _WBCL_Iterator, *P_WBCL_Iterator;

struct _WBCL_Iterator { /* PlaceHolder Structure */
};

typedef struct _WNF_STATE_NAME _WNF_STATE_NAME, *P_WNF_STATE_NAME;

struct _WNF_STATE_NAME { /* PlaceHolder Structure */
};

typedef struct _WNF_TYPE_ID _WNF_TYPE_ID, *P_WNF_TYPE_ID;

struct _WNF_TYPE_ID { /* PlaceHolder Structure */
};

typedef struct AuthFlags AuthFlags, *PAuthFlags;

struct AuthFlags {
    int field0_0x0:16;
    int ClearKey:1;
    int TPM:1;
    int USB:1;
    int Password:1;
    int PIN:1;
    int Certificate:1;
    int N/A:1;
    int PassPhrase:1;
    int field9_0x3:8;
};

typedef struct BCRYPT_HASH_CTXT BCRYPT_HASH_CTXT, *PBCRYPT_HASH_CTXT;

struct BCRYPT_HASH_CTXT { /* PlaceHolder Structure */
};

typedef struct CDropImpersonation CDropImpersonation, *PCDropImpersonation;

struct CDropImpersonation { /* PlaceHolder Structure */
};

typedef struct CFveApi CFveApi, *PCFveApi;

typedef struct CFveApiBase CFveApiBase, *PCFveApiBase;


/* WARNING! conflicting data type names: /fve.h/_FVE_DATASET - /Demangler/_FVE_DATASET */

typedef struct _FVE_DATASET FVE_DATASET;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION RTL_CRITICAL_SECTION;

typedef RTL_CRITICAL_SECTION CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct CFveApiBase { /* PlaceHolder Structure */
    struct struct *CFveApiBase;
    enum AuthFlagsEnum AuthFlags;
    undefined field2_0xc;
    undefined field3_0xd;
    undefined field4_0xe;
    undefined field5_0xf;
    undefined field6_0x10;
    undefined field7_0x11;
    undefined field8_0x12;
    undefined field9_0x13;
    undefined field10_0x14;
    undefined field11_0x15;
    undefined field12_0x16;
    undefined field13_0x17;
    undefined field14_0x18;
    undefined field15_0x19;
    undefined field16_0x1a;
    undefined field17_0x1b;
    undefined field18_0x1c;
    undefined field19_0x1d;
    undefined field20_0x1e;
    undefined field21_0x1f;
    undefined field22_0x20;
    undefined field23_0x21;
    undefined field24_0x22;
    undefined field25_0x23;
    undefined field26_0x24;
    undefined field27_0x25;
    undefined field28_0x26;
    undefined field29_0x27;
    undefined field30_0x28;
    undefined field31_0x29;
    undefined field32_0x2a;
    undefined field33_0x2b;
    undefined field34_0x2c;
    undefined field35_0x2d;
    undefined field36_0x2e;
    undefined field37_0x2f;
    undefined field38_0x30;
    undefined field39_0x31;
    undefined field40_0x32;
    undefined field41_0x33;
    undefined field42_0x34;
    undefined field43_0x35;
    undefined field44_0x36;
    undefined field45_0x37;
    undefined field46_0x38;
    undefined field47_0x39;
    undefined field48_0x3a;
    undefined field49_0x3b;
    undefined field50_0x3c;
    undefined field51_0x3d;
    undefined field52_0x3e;
    undefined field53_0x3f;
    undefined field54_0x40;
    undefined field55_0x41;
    undefined field56_0x42;
    undefined field57_0x43;
    undefined field58_0x44;
    undefined field59_0x45;
    undefined field60_0x46;
    undefined field61_0x47;
    void *CFveApiBase::LogEvent; /* Created by retype action */
    undefined field63_0x50;
    undefined field64_0x51;
    undefined field65_0x52;
    undefined field66_0x53;
    undefined field67_0x54;
    undefined field68_0x55;
    undefined field69_0x56;
    undefined field70_0x57;
    undefined field71_0x58;
    undefined field72_0x59;
    undefined field73_0x5a;
    undefined field74_0x5b;
    undefined field75_0x5c;
    undefined field76_0x5d;
    undefined field77_0x5e;
    undefined field78_0x5f;
    undefined field79_0x60;
    undefined field80_0x61;
    undefined field81_0x62;
    undefined field82_0x63;
    undefined field83_0x64;
    undefined field84_0x65;
    undefined field85_0x66;
    undefined field86_0x67;
    undefined field87_0x68;
    undefined field88_0x69;
    short field89_0x6a;
    undefined1 FveVersion; /* Created by retype action */
    undefined field91_0x6d;
    undefined field92_0x6e;
    undefined field93_0x6f;
    undefined field94_0x70;
    undefined field95_0x71;
    undefined field96_0x72;
    undefined field97_0x73;
    undefined field98_0x74;
    undefined field99_0x75;
    undefined field100_0x76;
    undefined field101_0x77;
    NTSTATUS LastConvertStatus;
    undefined field103_0x7c;
    undefined field104_0x7d;
    undefined field105_0x7e;
    undefined field106_0x7f;
    undefined field107_0x80;
    undefined field108_0x81;
    undefined field109_0x82;
    undefined field110_0x83;
    undefined field111_0x84;
    undefined field112_0x85;
    undefined field113_0x86;
    undefined field114_0x87;
    undefined field115_0x88;
    undefined field116_0x89;
    undefined field117_0x8a;
    undefined field118_0x8b;
    undefined field119_0x8c;
    undefined field120_0x8d;
    undefined field121_0x8e;
    undefined field122_0x8f;
    undefined field123_0x90;
    undefined field124_0x91;
    undefined field125_0x92;
    undefined field126_0x93;
    undefined field127_0x94;
    undefined field128_0x95;
    undefined field129_0x96;
    undefined field130_0x97;
    undefined field131_0x98;
    undefined field132_0x99;
    undefined field133_0x9a;
    undefined field134_0x9b;
    undefined field135_0x9c;
    undefined field136_0x9d;
    undefined field137_0x9e;
    undefined field138_0x9f;
    LONGLONG VolArriveTime;
    undefined field140_0xa8;
    undefined field141_0xa9;
    undefined field142_0xaa;
    undefined field143_0xab;
    undefined field144_0xac;
    undefined field145_0xad;
    undefined field146_0xae;
    undefined field147_0xaf;
    undefined field148_0xb0;
    undefined field149_0xb1;
    undefined field150_0xb2;
    undefined field151_0xb3;
    undefined field152_0xb4;
    undefined field153_0xb5;
    undefined field154_0xb6;
    undefined field155_0xb7;
    undefined field156_0xb8;
    undefined field157_0xb9;
    undefined field158_0xba;
    undefined field159_0xbb;
    undefined field160_0xbc;
    undefined field161_0xbd;
    undefined field162_0xbe;
    undefined field163_0xbf;
    undefined field164_0xc0;
    undefined field165_0xc1;
    undefined field166_0xc2;
    undefined field167_0xc3;
    undefined field168_0xc4;
    undefined field169_0xc5;
    undefined field170_0xc6;
    undefined field171_0xc7;
    undefined field172_0xc8;
    undefined field173_0xc9;
    undefined field174_0xca;
    undefined field175_0xcb;
    undefined field176_0xcc;
    undefined field177_0xcd;
    undefined field178_0xce;
    undefined field179_0xcf;
    undefined field180_0xd0;
    undefined field181_0xd1;
    undefined field182_0xd2;
    undefined field183_0xd3;
    undefined field184_0xd4;
    undefined field185_0xd5;
    undefined field186_0xd6;
    undefined field187_0xd7;
    undefined field188_0xd8;
    undefined field189_0xd9;
    undefined field190_0xda;
    undefined field191_0xdb;
    undefined field192_0xdc;
    undefined field193_0xdd;
    undefined field194_0xde;
    undefined field195_0xdf;
    undefined field196_0xe0;
    undefined field197_0xe1;
    undefined field198_0xe2;
    undefined field199_0xe3;
    undefined field200_0xe4;
    undefined field201_0xe5;
    undefined field202_0xe6;
    undefined field203_0xe7;
    undefined field204_0xe8;
    undefined field205_0xe9;
    undefined field206_0xea;
    undefined field207_0xeb;
    undefined field208_0xec;
    undefined field209_0xed;
    undefined field210_0xee;
    undefined field211_0xef;
    undefined field212_0xf0;
    undefined field213_0xf1;
    undefined field214_0xf2;
    undefined field215_0xf3;
    undefined field216_0xf4;
    undefined field217_0xf5;
    undefined field218_0xf6;
    undefined field219_0xf7;
    undefined1 WipeCount; /* Created by retype action */
    undefined field221_0xf9;
    undefined field222_0xfa;
    undefined field223_0xfb;
    undefined1 WipeState; /* Created by retype action */
    undefined field225_0xfd;
    undefined field226_0xfe;
    undefined field227_0xff;
    undefined field228_0x100;
    undefined field229_0x101;
    undefined field230_0x102;
    undefined field231_0x103;
    undefined field232_0x104;
    undefined field233_0x105;
    undefined field234_0x106;
    undefined field235_0x107;
    undefined field236_0x108;
    undefined field237_0x109;
    undefined field238_0x10a;
    undefined field239_0x10b;
    undefined field240_0x10c;
    undefined field241_0x10d;
    undefined field242_0x10e;
    undefined field243_0x10f;
    undefined field244_0x110;
    undefined field245_0x111;
    undefined field246_0x112;
    undefined field247_0x113;
    undefined field248_0x114;
    undefined field249_0x115;
    undefined field250_0x116;
    undefined field251_0x117;
    ULONGLONG WimBootHashedSizeRequired;
    ULONGLONG WimBootHashedSizeActual;
    ULONG WcosOsMainProtectLevel; /* Created by retype action */
    ulong WcosOsDataProtectLevel;
    ulong WcosPreInstalledProtectLevel;
    ulong WcosUserDataProtectLevel;
    ulong WcosBspProtectLevel; /* Created by retype action */
    ulong WcosDppProtectLevel; /* Created by retype action */
    ulong WcosWspProtectLevel; /* Created by retype action */
    undefined field261_0x144;
    undefined field262_0x145;
    undefined field263_0x146;
    undefined field264_0x147;
    ULONGLONG ExtendedFlags2;
    undefined field266_0x150;
    undefined field267_0x151;
    undefined field268_0x152;
    undefined field269_0x153;
    undefined field270_0x154;
    undefined field271_0x155;
    undefined field272_0x156;
    undefined field273_0x157;
    undefined field274_0x158;
    undefined field275_0x159;
    undefined field276_0x15a;
    undefined field277_0x15b;
    undefined field278_0x15c;
    undefined field279_0x15d;
    undefined field280_0x15e;
    undefined field281_0x15f;
    undefined field282_0x160;
    undefined field283_0x161;
    undefined field284_0x162;
    undefined field285_0x163;
    undefined field286_0x164;
    undefined field287_0x165;
    undefined field288_0x166;
    undefined field289_0x167;
    undefined field290_0x168;
    undefined field291_0x169;
    undefined field292_0x16a;
    undefined field293_0x16b;
    undefined field294_0x16c;
    undefined field295_0x16d;
    undefined field296_0x16e;
    undefined field297_0x16f;
    undefined field298_0x170;
    undefined field299_0x171;
    undefined field300_0x172;
    undefined field301_0x173;
    undefined field302_0x174;
    undefined field303_0x175;
    undefined field304_0x176;
    undefined field305_0x177;
    undefined field306_0x178;
    undefined field307_0x179;
    undefined field308_0x17a;
    undefined field309_0x17b;
    undefined field310_0x17c;
    undefined field311_0x17d;
    undefined field312_0x17e;
    undefined field313_0x17f;
    undefined field314_0x180;
    undefined field315_0x181;
    undefined field316_0x182;
    undefined field317_0x183;
    undefined field318_0x184;
    undefined field319_0x185;
    undefined field320_0x186;
    undefined field321_0x187;
    undefined field322_0x188;
    undefined field323_0x189;
    undefined field324_0x18a;
    undefined field325_0x18b;
    undefined field326_0x18c;
    undefined field327_0x18d;
    undefined field328_0x18e;
    undefined field329_0x18f;
    undefined field330_0x190;
    undefined field331_0x191;
    undefined field332_0x192;
    undefined field333_0x193;
    undefined field334_0x194;
    undefined field335_0x195;
    undefined field336_0x196;
    undefined field337_0x197;
    undefined field338_0x198;
    undefined field339_0x199;
    undefined field340_0x19a;
    undefined field341_0x19b;
    undefined field342_0x19c;
    undefined field343_0x19d;
    undefined field344_0x19e;
    undefined field345_0x19f;
    CRITICAL_SECTION criticalSection;
    undefined field347_0x1c8;
    undefined field348_0x1c9;
    undefined field349_0x1ca;
    undefined field350_0x1cb;
    undefined field351_0x1cc;
    undefined field352_0x1cd;
    undefined field353_0x1ce;
    undefined field354_0x1cf;
    undefined field355_0x1d0;
    undefined field356_0x1d1;
    undefined field357_0x1d2;
    undefined field358_0x1d3;
    undefined field359_0x1d4;
    undefined field360_0x1d5;
    undefined field361_0x1d6;
    undefined field362_0x1d7;
    undefined field363_0x1d8;
    undefined field364_0x1d9;
    undefined field365_0x1da;
    undefined field366_0x1db;
    undefined field367_0x1dc;
    undefined field368_0x1dd;
    undefined field369_0x1de;
    undefined field370_0x1df;
    undefined field371_0x1e0;
    undefined field372_0x1e1;
    undefined field373_0x1e2;
    undefined field374_0x1e3;
    undefined field375_0x1e4;
    undefined field376_0x1e5;
    undefined field377_0x1e6;
    undefined field378_0x1e7;
    undefined field379_0x1e8;
    undefined field380_0x1e9;
    undefined field381_0x1ea;
    undefined field382_0x1eb;
    undefined field383_0x1ec;
    undefined field384_0x1ed;
    undefined field385_0x1ee;
    undefined field386_0x1ef;
    undefined field387_0x1f0;
    undefined field388_0x1f1;
    undefined field389_0x1f2;
    undefined field390_0x1f3;
    undefined field391_0x1f4;
    undefined field392_0x1f5;
    undefined field393_0x1f6;
    undefined field394_0x1f7;
    undefined field395_0x1f8;
    undefined field396_0x1f9;
    undefined field397_0x1fa;
    undefined field398_0x1fb;
    undefined field399_0x1fc;
    undefined field400_0x1fd;
    undefined field401_0x1fe;
    undefined field402_0x1ff;
    undefined field403_0x200;
    undefined field404_0x201;
    undefined field405_0x202;
    undefined field406_0x203;
    undefined field407_0x204;
    undefined field408_0x205;
    undefined field409_0x206;
    undefined field410_0x207;
    undefined field411_0x208;
    undefined field412_0x209;
    undefined field413_0x20a;
    undefined field414_0x20b;
    undefined field415_0x20c;
    undefined field416_0x20d;
    undefined field417_0x20e;
    undefined field418_0x20f;
    undefined field419_0x210;
    undefined field420_0x211;
    undefined field421_0x212;
    undefined field422_0x213;
    undefined field423_0x214;
    undefined field424_0x215;
    undefined field425_0x216;
    undefined field426_0x217;
    undefined field427_0x218;
    undefined field428_0x219;
    undefined field429_0x21a;
    undefined field430_0x21b;
    undefined field431_0x21c;
    undefined field432_0x21d;
    undefined field433_0x21e;
    undefined field434_0x21f;
    undefined field435_0x220;
    undefined field436_0x221;
    undefined field437_0x222;
    undefined field438_0x223;
    undefined field439_0x224;
    undefined field440_0x225;
    undefined field441_0x226;
    undefined field442_0x227;
    undefined field443_0x228;
    undefined field444_0x229;
    undefined field445_0x22a;
    undefined field446_0x22b;
    undefined field447_0x22c;
    undefined field448_0x22d;
    undefined field449_0x22e;
    undefined field450_0x22f;
    undefined field451_0x230;
    undefined field452_0x231;
    undefined field453_0x232;
    undefined field454_0x233;
    undefined field455_0x234;
    undefined field456_0x235;
    undefined field457_0x236;
    undefined field458_0x237;
    undefined field459_0x238;
    undefined field460_0x239;
    undefined field461_0x23a;
    undefined field462_0x23b;
    undefined field463_0x23c;
    undefined field464_0x23d;
    undefined field465_0x23e;
    undefined field466_0x23f;
    undefined field467_0x240;
    undefined field468_0x241;
    undefined field469_0x242;
    undefined field470_0x243;
    undefined field471_0x244;
    undefined field472_0x245;
    undefined field473_0x246;
    undefined field474_0x247;
    undefined field475_0x248;
    undefined field476_0x249;
    undefined field477_0x24a;
    undefined field478_0x24b;
    undefined field479_0x24c;
    undefined field480_0x24d;
    undefined field481_0x24e;
    undefined field482_0x24f;
    undefined field483_0x250;
    undefined field484_0x251;
    undefined field485_0x252;
    undefined field486_0x253;
    undefined field487_0x254;
    undefined field488_0x255;
    undefined field489_0x256;
    undefined field490_0x257;
    undefined field491_0x258;
    undefined field492_0x259;
    undefined field493_0x25a;
    undefined field494_0x25b;
    undefined field495_0x25c;
    undefined field496_0x25d;
    undefined field497_0x25e;
    undefined field498_0x25f;
    undefined field499_0x260;
    undefined field500_0x261;
    undefined field501_0x262;
    undefined field502_0x263;
    undefined field503_0x264;
    undefined field504_0x265;
    undefined field505_0x266;
    undefined field506_0x267;
    undefined field507_0x268;
    undefined field508_0x269;
    bool ReturnNonce; /* Created by retype action */
    undefined field510_0x26b;
    undefined field511_0x26c;
    undefined field512_0x26d;
    undefined field513_0x26e;
    undefined field514_0x26f;
    undefined1 Dataset; /* Created by retype action */
    undefined field516_0x271;
    undefined field517_0x272;
    undefined field518_0x273;
    undefined field519_0x274;
    undefined field520_0x275;
    undefined field521_0x276;
    undefined field522_0x277;
    undefined field523_0x278;
    undefined field524_0x279;
    undefined field525_0x27a;
    undefined field526_0x27b;
    undefined field527_0x27c;
    undefined field528_0x27d;
    undefined field529_0x27e;
    undefined field530_0x27f;
    undefined1 VMKDatum; /* Created by retype action */
    undefined field532_0x281;
    undefined field533_0x282;
    undefined field534_0x283;
    undefined field535_0x284;
    undefined field536_0x285;
    undefined field537_0x286;
    undefined field538_0x287;
    struct Nonce Nonce;
    undefined field540_0x294;
    undefined field541_0x295;
    undefined field542_0x296;
    undefined field543_0x297;
    undefined field544_0x298;
    undefined field545_0x299;
    undefined field546_0x29a;
    undefined field547_0x29b;
    undefined field548_0x29c;
    undefined field549_0x29d;
    undefined field550_0x29e;
    undefined field551_0x29f;
    undefined field552_0x2a0;
    undefined field553_0x2a1;
    undefined field554_0x2a2;
    undefined field555_0x2a3;
    undefined field556_0x2a4;
    undefined field557_0x2a5;
    undefined field558_0x2a6;
    undefined field559_0x2a7;
    LPVOID field560_0x2a8;
};

struct CFveApi { /* PlaceHolder Structure */
    struct struct *Vtable;
    undefined field1_0x8;
    undefined field2_0x9;
    undefined field3_0xa;
    undefined field4_0xb;
    undefined field5_0xc;
    undefined field6_0xd;
    undefined field7_0xe;
    undefined field8_0xf;
    undefined field9_0x10;
    undefined field10_0x11;
    undefined field11_0x12;
    undefined field12_0x13;
    undefined field13_0x14;
    undefined field14_0x15;
    undefined field15_0x16;
    undefined field16_0x17;
    undefined field17_0x18;
    undefined field18_0x19;
    undefined field19_0x1a;
    undefined field20_0x1b;
    undefined field21_0x1c;
    undefined field22_0x1d;
    undefined field23_0x1e;
    undefined field24_0x1f;
    undefined field25_0x20;
    undefined field26_0x21;
    undefined field27_0x22;
    undefined field28_0x23;
    undefined field29_0x24;
    undefined field30_0x25;
    undefined field31_0x26;
    undefined field32_0x27;
    undefined field33_0x28;
    undefined field34_0x29;
    undefined field35_0x2a;
    undefined field36_0x2b;
    undefined field37_0x2c;
    undefined field38_0x2d;
    undefined field39_0x2e;
    undefined field40_0x2f;
    undefined field41_0x30;
    undefined field42_0x31;
    undefined field43_0x32;
    undefined field44_0x33;
    undefined field45_0x34;
    undefined field46_0x35;
    undefined field47_0x36;
    undefined field48_0x37;
    void *field49_0x38;
    undefined field50_0x40;
    undefined field51_0x41;
    undefined field52_0x42;
    undefined field53_0x43;
    undefined field54_0x44;
    undefined field55_0x45;
    undefined field56_0x46;
    undefined field57_0x47;
    undefined **field58_0x48;
    undefined field59_0x50;
    undefined field60_0x51;
    undefined field61_0x52;
    undefined field62_0x53;
    undefined field63_0x54;
    undefined field64_0x55;
    undefined field65_0x56;
    undefined field66_0x57;
    undefined field67_0x58;
    undefined field68_0x59;
    undefined field69_0x5a;
    undefined field70_0x5b;
    undefined field71_0x5c;
    undefined field72_0x5d;
    undefined field73_0x5e;
    undefined field74_0x5f;
    undefined field75_0x60;
    undefined field76_0x61;
    undefined field77_0x62;
    undefined field78_0x63;
    undefined field79_0x64;
    undefined field80_0x65;
    undefined field81_0x66;
    undefined field82_0x67;
    undefined field83_0x68;
    undefined field84_0x69;
    undefined field85_0x6a;
    undefined field86_0x6b;
    short FveVersion;
    undefined field88_0x6e;
    undefined field89_0x6f;
    uint field90_0x70;
    uint field91_0x74;
    undefined field92_0x78;
    undefined field93_0x79;
    undefined field94_0x7a;
    undefined field95_0x7b;
    int field96_0x7c;
    undefined field97_0x80;
    undefined field98_0x81;
    undefined field99_0x82;
    undefined field100_0x83;
    undefined field101_0x84;
    undefined field102_0x85;
    undefined field103_0x86;
    undefined field104_0x87;
    undefined field105_0x88;
    undefined field106_0x89;
    undefined field107_0x8a;
    undefined field108_0x8b;
    undefined field109_0x8c;
    undefined field110_0x8d;
    undefined field111_0x8e;
    undefined field112_0x8f;
    undefined field113_0x90;
    undefined field114_0x91;
    undefined field115_0x92;
    undefined field116_0x93;
    undefined field117_0x94;
    undefined field118_0x95;
    undefined field119_0x96;
    undefined field120_0x97;
    undefined field121_0x98;
    undefined field122_0x99;
    undefined field123_0x9a;
    undefined field124_0x9b;
    undefined field125_0x9c;
    undefined field126_0x9d;
    undefined field127_0x9e;
    undefined field128_0x9f;
    undefined field129_0xa0;
    undefined field130_0xa1;
    undefined field131_0xa2;
    undefined field132_0xa3;
    undefined field133_0xa4;
    undefined field134_0xa5;
    undefined field135_0xa6;
    undefined field136_0xa7;
    undefined field137_0xa8;
    undefined field138_0xa9;
    undefined field139_0xaa;
    undefined field140_0xab;
    undefined field141_0xac;
    undefined field142_0xad;
    undefined field143_0xae;
    undefined field144_0xaf;
    undefined field145_0xb0;
    undefined field146_0xb1;
    undefined field147_0xb2;
    undefined field148_0xb3;
    undefined field149_0xb4;
    undefined field150_0xb5;
    undefined field151_0xb6;
    undefined field152_0xb7;
    undefined field153_0xb8;
    undefined field154_0xb9;
    undefined field155_0xba;
    undefined field156_0xbb;
    undefined field157_0xbc;
    undefined field158_0xbd;
    undefined field159_0xbe;
    undefined field160_0xbf;
    undefined field161_0xc0;
    undefined field162_0xc1;
    undefined field163_0xc2;
    undefined field164_0xc3;
    undefined field165_0xc4;
    undefined field166_0xc5;
    undefined field167_0xc6;
    undefined field168_0xc7;
    undefined field169_0xc8;
    undefined field170_0xc9;
    undefined field171_0xca;
    undefined field172_0xcb;
    undefined field173_0xcc;
    undefined field174_0xcd;
    undefined field175_0xce;
    undefined field176_0xcf;
    undefined field177_0xd0;
    undefined field178_0xd1;
    undefined field179_0xd2;
    undefined field180_0xd3;
    undefined field181_0xd4;
    undefined field182_0xd5;
    undefined field183_0xd6;
    undefined field184_0xd7;
    undefined field185_0xd8;
    undefined field186_0xd9;
    undefined field187_0xda;
    undefined field188_0xdb;
    undefined field189_0xdc;
    undefined field190_0xdd;
    undefined field191_0xde;
    undefined field192_0xdf;
    undefined field193_0xe0;
    undefined field194_0xe1;
    undefined field195_0xe2;
    undefined field196_0xe3;
    undefined field197_0xe4;
    undefined field198_0xe5;
    undefined field199_0xe6;
    undefined field200_0xe7;
    ulonglong field201_0xe8;
    undefined field202_0xf0;
    undefined field203_0xf1;
    undefined field204_0xf2;
    undefined field205_0xf3;
    undefined field206_0xf4;
    undefined field207_0xf5;
    undefined field208_0xf6;
    undefined field209_0xf7;
    undefined field210_0xf8;
    undefined field211_0xf9;
    undefined field212_0xfa;
    undefined field213_0xfb;
    undefined field214_0xfc;
    undefined field215_0xfd;
    undefined field216_0xfe;
    undefined field217_0xff;
    undefined field218_0x100;
    undefined field219_0x101;
    undefined field220_0x102;
    undefined field221_0x103;
    undefined field222_0x104;
    undefined field223_0x105;
    undefined field224_0x106;
    undefined field225_0x107;
    undefined field226_0x108;
    undefined field227_0x109;
    undefined field228_0x10a;
    undefined field229_0x10b;
    undefined field230_0x10c;
    undefined field231_0x10d;
    undefined field232_0x10e;
    undefined field233_0x10f;
    undefined field234_0x110;
    undefined field235_0x111;
    undefined field236_0x112;
    undefined field237_0x113;
    undefined field238_0x114;
    undefined field239_0x115;
    undefined field240_0x116;
    undefined field241_0x117;
    undefined field242_0x118;
    undefined field243_0x119;
    undefined field244_0x11a;
    undefined field245_0x11b;
    undefined field246_0x11c;
    undefined field247_0x11d;
    undefined field248_0x11e;
    undefined field249_0x11f;
    undefined field250_0x120;
    undefined field251_0x121;
    undefined field252_0x122;
    undefined field253_0x123;
    undefined field254_0x124;
    undefined field255_0x125;
    undefined field256_0x126;
    undefined field257_0x127;
    undefined field258_0x128;
    undefined field259_0x129;
    undefined field260_0x12a;
    undefined field261_0x12b;
    undefined field262_0x12c;
    undefined field263_0x12d;
    undefined field264_0x12e;
    undefined field265_0x12f;
    undefined field266_0x130;
    undefined field267_0x131;
    undefined field268_0x132;
    undefined field269_0x133;
    undefined field270_0x134;
    undefined field271_0x135;
    undefined field272_0x136;
    undefined field273_0x137;
    undefined field274_0x138;
    undefined field275_0x139;
    undefined field276_0x13a;
    undefined field277_0x13b;
    undefined field278_0x13c;
    undefined field279_0x13d;
    undefined field280_0x13e;
    undefined field281_0x13f;
    undefined field282_0x140;
    undefined field283_0x141;
    undefined field284_0x142;
    undefined field285_0x143;
    undefined field286_0x144;
    undefined field287_0x145;
    undefined field288_0x146;
    undefined field289_0x147;
    undefined field290_0x148;
    undefined field291_0x149;
    undefined field292_0x14a;
    undefined field293_0x14b;
    undefined field294_0x14c;
    undefined field295_0x14d;
    undefined field296_0x14e;
    undefined field297_0x14f;
    int field298_0x150;
    struct CFveApiBase field299_0x154;
    ushort *field300_0x160;
    undefined field301_0x168;
    undefined field302_0x169;
    undefined field303_0x16a;
    undefined field304_0x16b;
    undefined field305_0x16c;
    undefined field306_0x16d;
    undefined field307_0x16e;
    undefined field308_0x16f;
    ushort *field309_0x170;
    ushort *field310_0x178;
    undefined field311_0x180;
    undefined field312_0x181;
    undefined field313_0x182;
    undefined field314_0x183;
    undefined field315_0x184;
    undefined field316_0x185;
    undefined field317_0x186;
    undefined field318_0x187;
    undefined field319_0x188;
    undefined field320_0x189;
    undefined field321_0x18a;
    undefined field322_0x18b;
    undefined field323_0x18c;
    undefined field324_0x18d;
    undefined field325_0x18e;
    undefined field326_0x18f;
    undefined field327_0x190;
    undefined field328_0x191;
    undefined field329_0x192;
    undefined field330_0x193;
    undefined field331_0x194;
    undefined field332_0x195;
    undefined field333_0x196;
    undefined field334_0x197;
    undefined field335_0x198;
    undefined field336_0x199;
    undefined field337_0x19a;
    undefined field338_0x19b;
    undefined field339_0x19c;
    undefined field340_0x19d;
    undefined field341_0x19e;
    undefined field342_0x19f;
    undefined field343_0x1a0;
    undefined field344_0x1a1;
    undefined field345_0x1a2;
    undefined field346_0x1a3;
    undefined field347_0x1a4;
    undefined field348_0x1a5;
    undefined field349_0x1a6;
    undefined field350_0x1a7;
    undefined field351_0x1a8;
    undefined field352_0x1a9;
    undefined field353_0x1aa;
    undefined field354_0x1ab;
    undefined field355_0x1ac;
    undefined field356_0x1ad;
    undefined field357_0x1ae;
    undefined field358_0x1af;
    undefined field359_0x1b0;
    undefined field360_0x1b1;
    undefined field361_0x1b2;
    undefined field362_0x1b3;
    undefined field363_0x1b4;
    undefined field364_0x1b5;
    undefined field365_0x1b6;
    undefined field366_0x1b7;
    undefined field367_0x1b8;
    undefined field368_0x1b9;
    undefined field369_0x1ba;
    undefined field370_0x1bb;
    undefined field371_0x1bc;
    undefined field372_0x1bd;
    undefined field373_0x1be;
    undefined field374_0x1bf;
    undefined field375_0x1c0;
    undefined field376_0x1c1;
    undefined field377_0x1c2;
    undefined field378_0x1c3;
    undefined field379_0x1c4;
    undefined field380_0x1c5;
    undefined field381_0x1c6;
    undefined field382_0x1c7;
    undefined field383_0x1c8;
    undefined field384_0x1c9;
    undefined field385_0x1ca;
    undefined field386_0x1cb;
    undefined field387_0x1cc;
    undefined field388_0x1cd;
    undefined field389_0x1ce;
    undefined field390_0x1cf;
    undefined field391_0x1d0;
    undefined field392_0x1d1;
    undefined field393_0x1d2;
    undefined field394_0x1d3;
    undefined field395_0x1d4;
    undefined field396_0x1d5;
    undefined field397_0x1d6;
    undefined field398_0x1d7;
    undefined field399_0x1d8;
    undefined field400_0x1d9;
    undefined field401_0x1da;
    undefined field402_0x1db;
    undefined field403_0x1dc;
    undefined field404_0x1dd;
    undefined field405_0x1de;
    undefined field406_0x1df;
    undefined field407_0x1e0;
    undefined field408_0x1e1;
    undefined field409_0x1e2;
    undefined field410_0x1e3;
    undefined field411_0x1e4;
    undefined field412_0x1e5;
    undefined field413_0x1e6;
    undefined field414_0x1e7;
    undefined field415_0x1e8;
    undefined field416_0x1e9;
    undefined field417_0x1ea;
    undefined field418_0x1eb;
    undefined field419_0x1ec;
    undefined field420_0x1ed;
    undefined field421_0x1ee;
    undefined field422_0x1ef;
    undefined field423_0x1f0;
    undefined field424_0x1f1;
    undefined field425_0x1f2;
    undefined field426_0x1f3;
    undefined field427_0x1f4;
    undefined field428_0x1f5;
    undefined field429_0x1f6;
    undefined field430_0x1f7;
    undefined field431_0x1f8;
    undefined field432_0x1f9;
    undefined field433_0x1fa;
    undefined field434_0x1fb;
    undefined field435_0x1fc;
    undefined field436_0x1fd;
    undefined field437_0x1fe;
    undefined field438_0x1ff;
    undefined field439_0x200;
    undefined field440_0x201;
    undefined field441_0x202;
    undefined field442_0x203;
    undefined field443_0x204;
    undefined field444_0x205;
    undefined field445_0x206;
    undefined field446_0x207;
    undefined field447_0x208;
    undefined field448_0x209;
    undefined field449_0x20a;
    undefined field450_0x20b;
    undefined field451_0x20c;
    undefined field452_0x20d;
    undefined field453_0x20e;
    undefined field454_0x20f;
    undefined field455_0x210;
    undefined field456_0x211;
    undefined field457_0x212;
    undefined field458_0x213;
    undefined field459_0x214;
    undefined field460_0x215;
    undefined field461_0x216;
    undefined field462_0x217;
    undefined field463_0x218;
    undefined field464_0x219;
    undefined field465_0x21a;
    undefined field466_0x21b;
    undefined field467_0x21c;
    undefined field468_0x21d;
    undefined field469_0x21e;
    undefined field470_0x21f;
    undefined field471_0x220;
    undefined field472_0x221;
    undefined field473_0x222;
    undefined field474_0x223;
    undefined field475_0x224;
    undefined field476_0x225;
    undefined field477_0x226;
    undefined field478_0x227;
    undefined field479_0x228;
    undefined field480_0x229;
    undefined field481_0x22a;
    undefined field482_0x22b;
    undefined field483_0x22c;
    undefined field484_0x22d;
    undefined field485_0x22e;
    undefined field486_0x22f;
    undefined field487_0x230;
    undefined field488_0x231;
    undefined field489_0x232;
    undefined field490_0x233;
    undefined field491_0x234;
    undefined field492_0x235;
    undefined field493_0x236;
    undefined field494_0x237;
    undefined field495_0x238;
    undefined field496_0x239;
    undefined field497_0x23a;
    undefined field498_0x23b;
    undefined field499_0x23c;
    undefined field500_0x23d;
    undefined field501_0x23e;
    undefined field502_0x23f;
    undefined field503_0x240;
    undefined field504_0x241;
    undefined field505_0x242;
    undefined field506_0x243;
    undefined field507_0x244;
    undefined field508_0x245;
    undefined field509_0x246;
    undefined field510_0x247;
    undefined field511_0x248;
    undefined field512_0x249;
    undefined field513_0x24a;
    undefined field514_0x24b;
    undefined field515_0x24c;
    undefined field516_0x24d;
    undefined field517_0x24e;
    undefined field518_0x24f;
    undefined field519_0x250;
    undefined field520_0x251;
    undefined field521_0x252;
    undefined field522_0x253;
    undefined field523_0x254;
    undefined field524_0x255;
    undefined field525_0x256;
    undefined field526_0x257;
    undefined field527_0x258;
    undefined field528_0x259;
    undefined field529_0x25a;
    undefined field530_0x25b;
    undefined field531_0x25c;
    undefined field532_0x25d;
    undefined field533_0x25e;
    undefined field534_0x25f;
    undefined field535_0x260;
    undefined field536_0x261;
    undefined field537_0x262;
    undefined field538_0x263;
    struct CFveApiBase field539_0x264;
    struct CFveApiBase field540_0x26a;
    FVE_DATASET *Dataset;
    undefined field542_0x278;
    undefined field543_0x279;
    undefined field544_0x27a;
    undefined field545_0x27b;
    undefined field546_0x27c;
    undefined field547_0x27d;
    undefined field548_0x27e;
    undefined field549_0x27f;
    FVE_DATUM_KEY *VMKDatum;
    struct _FILETIME field551_0x288;
    undefined4 field552_0x290;
    undefined field553_0x294;
    undefined field554_0x295;
    undefined field555_0x296;
    undefined field556_0x297;
    undefined field557_0x298;
    undefined field558_0x299;
    undefined field559_0x29a;
    undefined field560_0x29b;
    undefined field561_0x29c;
    undefined field562_0x29d;
    undefined field563_0x29e;
    undefined field564_0x29f;
    struct CFveApiBase field565_0x2a0;
    struct CFveApiBase field566_0x2a1;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct CFveApiEnum CFveApiEnum, *PCFveApiEnum;

struct CFveApiEnum { /* PlaceHolder Structure */
};

typedef struct CFveApiHandle CFveApiHandle, *PCFveApiHandle;

struct CFveApiHandle { /* PlaceHolder Structure */
    undefined **field0_0x0;
    undefined8 field1_0x8;
    CRITICAL_SECTION CriticalSection;
    undefined4 field3_0x38;
    enum _FVEAPI_OBJECT_TYPE field4_0x3c;
    undefined4 field5_0x40;
};

typedef struct CFveBcdSettingParser CFveBcdSettingParser, *PCFveBcdSettingParser;

struct CFveBcdSettingParser { /* PlaceHolder Structure */
};

typedef struct CFveBcdSettings CFveBcdSettings, *PCFveBcdSettings;

struct CFveBcdSettings { /* PlaceHolder Structure */
};

typedef struct CFveEncryptionSettings CFveEncryptionSettings, *PCFveEncryptionSettings;

struct CFveEncryptionSettings { /* PlaceHolder Structure */
};

typedef struct CFvePassphraseSettings CFvePassphraseSettings, *PCFvePassphraseSettings;

struct CFvePassphraseSettings { /* PlaceHolder Structure */
};

typedef struct CFveSys CFveSys, *PCFveSys;

struct CFveSys { /* PlaceHolder Structure */
};

typedef struct CFveTpm CFveTpm, *PCFveTpm;

struct CFveTpm { /* PlaceHolder Structure */
    longlong field0_0x0;
    undefined8 *field1_0x8;
    longlong field2_0x10;
    undefined8 field3_0x18;
    void *field4_0x20;
    uint field5_0x28;
    uint field6_0x2c;
    uint field7_0x30;
    undefined field8_0x34;
    undefined field9_0x35;
    undefined field10_0x36;
    undefined field11_0x37;
    uchar *field12_0x38;
    ulong field13_0x40;
    undefined field14_0x44;
    undefined field15_0x45;
    undefined field16_0x46;
    undefined field17_0x47;
    undefined field18_0x48;
    undefined field19_0x49;
    undefined field20_0x4a;
    undefined field21_0x4b;
    undefined field22_0x4c;
    undefined field23_0x4d;
    undefined field24_0x4e;
    undefined field25_0x4f;
    longlong field26_0x50;
};

typedef struct CFveTpmSoftwarePCR CFveTpmSoftwarePCR, *PCFveTpmSoftwarePCR;

struct CFveTpmSoftwarePCR { /* PlaceHolder Structure */
};

typedef struct CNgscbScopedPrivilege CNgscbScopedPrivilege, *PCNgscbScopedPrivilege;

struct CNgscbScopedPrivilege { /* PlaceHolder Structure */
};

typedef struct CScopedPolicyRedirector CScopedPolicyRedirector, *PCScopedPolicyRedirector;

struct CScopedPolicyRedirector { /* PlaceHolder Structure */
};

typedef enum eFveBootApplicationPolicy {
} eFveBootApplicationPolicy;

typedef enum eFveGpBinSetting {
} eFveGpBinSetting;

typedef enum eFveGpConfigurationState {
} eFveGpConfigurationState;

typedef enum eFveGpDwSetting {
} eFveGpDwSetting;

typedef enum eFveGpPassphraseComplexity {
} eFveGpPassphraseComplexity;

typedef enum eFveGpPermission {
} eFveGpPermission;

typedef enum eFveGpSettingsLocation {
} eFveGpSettingsLocation;

typedef enum eFveGpStrSetting {
} eFveGpStrSetting;

typedef enum eFveGpUsePassphrase {
} eFveGpUsePassphrase;

typedef enum eFveVolumeType {
} eFveVolumeType;

typedef struct exception exception, *Pexception;

struct exception { /* PlaceHolder Structure */
};

typedef enum FEATURE_CHANGE_TIME {
} FEATURE_CHANGE_TIME;

typedef enum FEATURE_ENABLED_STATE {
} FEATURE_ENABLED_STATE;

typedef struct FEATURE_ERROR FEATURE_ERROR, *PFEATURE_ERROR;

struct FEATURE_ERROR { /* PlaceHolder Structure */
};

typedef struct FEATURE_LOGGED_TRAITS FEATURE_LOGGED_TRAITS, *PFEATURE_LOGGED_TRAITS;

struct FEATURE_LOGGED_TRAITS { /* PlaceHolder Structure */
};

typedef struct FEATURE_STATE_CHANGE_SUBSCRIPTION__ FEATURE_STATE_CHANGE_SUBSCRIPTION__, *PFEATURE_STATE_CHANGE_SUBSCRIPTION__;

struct FEATURE_STATE_CHANGE_SUBSCRIPTION__ { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/FVE_AUTH_INFORMATION - /CONFLICTS python2.h/FVE_AUTH_INFORMATION */

typedef struct FveAADKeyDeleteRequest FveAADKeyDeleteRequest, *PFveAADKeyDeleteRequest;

struct FveAADKeyDeleteRequest { /* PlaceHolder Structure */
};

typedef struct FveClientKeyRotationRequest FveClientKeyRotationRequest, *PFveClientKeyRotationRequest;

struct FveClientKeyRotationRequest { /* PlaceHolder Structure */
};

typedef struct FvePersistentRequest FvePersistentRequest, *PFvePersistentRequest;

struct FvePersistentRequest { /* PlaceHolder Structure */
};

typedef struct FveRequest FveRequest, *PFveRequest;

struct FveRequest { /* PlaceHolder Structure */
};

typedef struct FveServerKeyRotationRequest FveServerKeyRotationRequest, *PFveServerKeyRotationRequest;

struct FveServerKeyRotationRequest { /* PlaceHolder Structure */
};

typedef struct HASHLIB_CERT_INFO HASHLIB_CERT_INFO, *PHASHLIB_CERT_INFO;

struct HASHLIB_CERT_INFO { /* PlaceHolder Structure */
};

typedef struct HCMNOTIFICATION__ HCMNOTIFICATION__, *PHCMNOTIFICATION__;

struct HCMNOTIFICATION__ { /* PlaceHolder Structure */
};

typedef struct HTPMCONTEXT__ HTPMCONTEXT__, *PHTPMCONTEXT__;

struct HTPMCONTEXT__ { /* PlaceHolder Structure */
};

typedef struct IFveEventLogger IFveEventLogger, *PIFveEventLogger;

struct IFveEventLogger { /* PlaceHolder Structure */
};

typedef struct MicrosoftTelemetryAssertTriggeredNode MicrosoftTelemetryAssertTriggeredNode, *PMicrosoftTelemetryAssertTriggeredNode;

struct MicrosoftTelemetryAssertTriggeredNode { /* PlaceHolder Structure */
};

typedef struct MULTI_STRING_ARRAY MULTI_STRING_ARRAY, *PMULTI_STRING_ARRAY;

struct MULTI_STRING_ARRAY { /* PlaceHolder Structure */
};

typedef enum NgscbManageDEVolumeOptOutOption {
} NgscbManageDEVolumeOptOutOption;

typedef struct POLICY_REGISTRY_INFO<unsigned_long> POLICY_REGISTRY_INFO<unsigned_long>, *PPOLICY_REGISTRY_INFO<unsigned_long>;

struct POLICY_REGISTRY_INFO<unsigned_long> { /* PlaceHolder Structure */
    longlong field0_0x0;
    void *field1_0x8;
    longlong field2_0x10;
};

typedef struct POLICY_REGISTRY_INFO<unsigned_short_const*___ptr64*___ptr64> POLICY_REGISTRY_INFO<unsigned_short_const*___ptr64*___ptr64>, *PPOLICY_REGISTRY_INFO<unsigned_short_const*___ptr64*___ptr64>;

struct POLICY_REGISTRY_INFO<unsigned_short_const*___ptr64*___ptr64> { /* PlaceHolder Structure */
};

typedef struct POLICY_REGISTRY_INFO<unsigned_short_const*___ptr64> POLICY_REGISTRY_INFO<unsigned_short_const*___ptr64>, *PPOLICY_REGISTRY_INFO<unsigned_short_const*___ptr64>;

struct POLICY_REGISTRY_INFO<unsigned_short_const*___ptr64> { /* PlaceHolder Structure */
};

typedef struct SP<unsigned_char,class_SP_HLOCAL<unsigned_char>_> SP<unsigned_char,class_SP_HLOCAL<unsigned_char>_>, *PSP<unsigned_char,class_SP_HLOCAL<unsigned_char>_>;

struct SP<unsigned_char,class_SP_HLOCAL<unsigned_char>_> { /* PlaceHolder Structure */
};


/* WARNING! conflicting data type names: /Demangler/struct - /CONFLICTS python2.h/struct */

typedef struct TPM_SYMBOLTABLE_ENTRY TPM_SYMBOLTABLE_ENTRY, *PTPM_SYMBOLTABLE_ENTRY;

struct TPM_SYMBOLTABLE_ENTRY { /* PlaceHolder Structure */
};

typedef struct TpmContext TpmContext, *PTpmContext;

struct TpmContext { /* PlaceHolder Structure */
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { /* PlaceHolder Structure */
};

typedef struct wil_details_FeatureReportingCache wil_details_FeatureReportingCache, *Pwil_details_FeatureReportingCache;

struct wil_details_FeatureReportingCache { /* PlaceHolder Structure */
};

typedef union wil_details_FeatureStateCache wil_details_FeatureStateCache, *Pwil_details_FeatureStateCache;

union wil_details_FeatureStateCache {
};

typedef struct wil_details_RecordUsageResult wil_details_RecordUsageResult, *Pwil_details_RecordUsageResult;

struct wil_details_RecordUsageResult { /* PlaceHolder Structure */
};

typedef enum wil_details_ServiceReportingKind {
} wil_details_ServiceReportingKind;

typedef struct wil_details_StagingConfig wil_details_StagingConfig, *Pwil_details_StagingConfig;

struct wil_details_StagingConfig { /* PlaceHolder Structure */
};

typedef struct wil_details_StagingConfigFeature wil_details_StagingConfigFeature, *Pwil_details_StagingConfigFeature;

struct wil_details_StagingConfigFeature { /* PlaceHolder Structure */
};

typedef enum wil_FeatureChangeTime {
} wil_FeatureChangeTime;

typedef struct wil_FeatureState wil_FeatureState, *Pwil_FeatureState;

struct wil_FeatureState { /* PlaceHolder Structure */
};

typedef enum wil_FeatureStore {
} wil_FeatureStore;

typedef enum wil_ReportingKind {
} wil_ReportingKind;

typedef enum wil_VariantReportingKind {
} wil_VariantReportingKind;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; /* Magic number */
    word e_cblp; /* Bytes of last page */
    word e_cp; /* Pages in file */
    word e_crlc; /* Relocations */
    word e_cparhdr; /* Size of header in paragraphs */
    word e_minalloc; /* Minimum extra paragraphs needed */
    word e_maxalloc; /* Maximum extra paragraphs needed */
    word e_ss; /* Initial (relative) SS value */
    word e_sp; /* Initial SP value */
    word e_csum; /* Checksum */
    word e_ip; /* Initial IP value */
    word e_cs; /* Initial (relative) CS value */
    word e_lfarlc; /* File address of relocation table */
    word e_ovno; /* Overlay number */
    word e_res[4][4]; /* Reserved words */
    word e_oemid; /* OEM identifier (for e_oeminfo) */
    word e_oeminfo; /* OEM information; e_oemid specific */
    word e_res2[10][10]; /* Reserved words */
    dword e_lfanew; /* File address of new exe header */
    byte e_program[64]; /* Actual DOS program */
};

#define __drv_typeBitset 2

#define __drv_typeCond 1

#define __drv_typeConst 0

#define __drv_typeExpr 3

typedef int __ehstate_t;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

typedef int PMFN;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct PMD PMD, *PPMD;

struct PMD {
    int mdisp;
    int pdisp;
    int vdisp;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

typedef struct _EVENT_DATA_DESCRIPTOR _EVENT_DATA_DESCRIPTOR, *P_EVENT_DATA_DESCRIPTOR;


/* WARNING! conflicting data type names: /wtypes.h/ULONG - /WinDef.h/ULONG */

struct _EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Reserved;
};

typedef struct _EVENT_DESCRIPTOR _EVENT_DESCRIPTOR, *P_EVENT_DESCRIPTOR;


/* WARNING! conflicting data type names: /winsmcrd.h/UCHAR - /WinDef.h/UCHAR */

struct _EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
};

typedef struct _EVENT_FILTER_DESCRIPTOR _EVENT_FILTER_DESCRIPTOR, *P_EVENT_FILTER_DESCRIPTOR;

struct _EVENT_FILTER_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Type;
};

typedef struct _EVENT_DESCRIPTOR EVENT_DESCRIPTOR;

typedef EVENT_DESCRIPTOR *PCEVENT_DESCRIPTOR;

typedef GUID *LPCGUID;

typedef struct _EVENT_FILTER_DESCRIPTOR *PEVENT_FILTER_DESCRIPTOR;

typedef void (*PENABLECALLBACK)(LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, PEVENT_FILTER_DESCRIPTOR, PVOID);

typedef struct _EVENT_DATA_DESCRIPTOR *PEVENT_DATA_DESCRIPTOR;

typedef ULONGLONG *PREGHANDLE;

typedef ULONGLONG REGHANDLE;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

struct _M128A {
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55 {
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54 {
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

typedef struct _DISPATCHER_CONTEXT _DISPATCHER_CONTEXT, *P_DISPATCHER_CONTEXT;

struct _DISPATCHER_CONTEXT {
};

typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution=0,
    ExceptionContinueSearch=1,
    ExceptionNestedException=2,
    ExceptionCollidedUnwind=3
} _EXCEPTION_DISPOSITION;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT *PCONTEXT;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef struct _FVE_DATUM_AES_ENC _FVE_DATUM_AES_ENC, *P_FVE_DATUM_AES_ENC;

struct _FVE_DATUM_AES_ENC {
    FVE_DATUM h;
    struct Nonce nonce;
    byte HMAC[16];
    byte EncryptedData[1];
};

typedef struct _FVE_DATUM_ASYM_ENC_BLOB _FVE_DATUM_ASYM_ENC_BLOB, *P_FVE_DATUM_ASYM_ENC_BLOB;

struct _FVE_DATUM_ASYM_ENC_BLOB {
    FVE_DATUM_KEY h;
};


/* WARNING! conflicting data type names: /fve.h/_FVE_DATUM_VMK_INFO - /Demangler/_FVE_DATUM_VMK_INFO */

typedef struct Callback Callback, *PCallback;

struct Callback {
    void *FveAllocCallback;
    void *FveFreeCallback;
    void *field2_0x10;
    void *FveSealCallback;
    void *FveRandomCallback;
    void *FveGenGuidCallback;
    void *FveGetTimeCallback;
    void *FveGlobalLockAcquireCallback;
    void *FveGlobalLockReleaseCallback;
};

typedef enum Datum_Types {
    FveDatumErasedTypeProp=0,
    FveDatumKeyTypeProp=1,
    FveDatumUnicodeTypeProp=2,
    FveDatumStretchKeyTypeProp=3,
    FveDatumUseKeyTypeProp=4,
    FveDatumAesCcmEncTypeProp=5,
    FveDatumTpmEncBlobTypeProp=6,
    FveDatumValidationInfoTypeProp=7,
    FveDatumVmkInfoTypeProp=8,
    FveDatumExternalInfoTypeProp=9,
    FveDatumUpdateTypeProp=10,
    FveDatumErrorTypeProp=11,
    FveDatumAsymEncTypeProp=12,
    FveDatumExportedKeyTypeProp=13,
    FveDatumPublicKeyInfoTypeProp=14,
    FveDatumVirtualizationInfoTypeProp=15,
    FveDatumSimpleType1Prop=16,
    FveDatumSimpleType2Prop=17,
    FveDatumConcatHashKeyTypeProp=18,
    FveDatumSimpleType3Prop=19,
    FveDatumSimpleLargeTypeProp=20
} Datum_Types;

typedef struct DatumTypeStruct DatumTypeStruct, *PDatumTypeStruct;

struct DatumTypeStruct {
    short DatumHeaderSize;
    bool isNested;
};

typedef HRESULT (*fpFveCloseVolume)(HANDLE);

typedef HRESULT (*fpFveCommitChanges)(HANDLE);

typedef NTSTATUS (*fpFveDatasetAppendDatum)(FVE_DATASET *, FVE_DATUM *, WORD);

typedef NTSTATUS (*fpFveDatasetGetDatumPointer)(FVE_DATASET *, uint, FVE_DATUM **);

typedef NTSTATUS (*fpFveDatasetGetNext)(FVE_DATASET *, WORD, WORD, uint, uint *);

typedef NTSTATUS (*fpFveDatumNestedGetNext)(FVE_DATUM *, WORD, WORD, WORD, WORD *);

typedef HRESULT (*fpFveOpenVolumeW)(LPWSTR, bool, HANDLE *);

typedef struct _FVE_DATUM_VMK_INFO FVE_DATUM_VMK_INFO;

typedef struct _FVE_DATASET *PFVE_DATASET;

typedef struct _FVE_DATUM *PFVE_DATUM;

typedef struct _FVE_DATUM_KEY *PFVE_DATUM_KEY;

typedef struct _FVE_DATUM_VMK_INFO *PFVE_DATUM_VMK_INFO;

typedef struct _FVE_DATUM **PPFVE_DATUM;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef GUID CLSID;

typedef GUID FMTID;

typedef GUID IID;

typedef CLSID *LPCLSID;

typedef FMTID *LPFMTID;

typedef GUID *LPGUID;

typedef IID *LPIID;

#define APC_LEVEL 1

#define DISPATCH_LEVEL 2

#define HIGH_LEVEL 15

#define PASSIVE_LEVEL 0

typedef struct _LSA_OBJECT_ATTRIBUTES _LSA_OBJECT_ATTRIBUTES, *P_LSA_OBJECT_ATTRIBUTES;

typedef struct _LSA_UNICODE_STRING _LSA_UNICODE_STRING, *P_LSA_UNICODE_STRING;

typedef struct _LSA_UNICODE_STRING *PLSA_UNICODE_STRING;

struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct _LSA_OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PLSA_UNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

typedef struct _LSA_OBJECT_ATTRIBUTES *PLSA_OBJECT_ATTRIBUTES;

typedef union _union_5374 _union_5374, *P_union_5374;

typedef struct MS_ADDINFO_FLAT_ MS_ADDINFO_FLAT_, *PMS_ADDINFO_FLAT_;

typedef struct MS_ADDINFO_CATALOGMEMBER_ MS_ADDINFO_CATALOGMEMBER_, *PMS_ADDINFO_CATALOGMEMBER_;

typedef struct MS_ADDINFO_BLOB_ MS_ADDINFO_BLOB_, *PMS_ADDINFO_BLOB_;

typedef struct SIP_INDIRECT_DATA_ SIP_INDIRECT_DATA_, *PSIP_INDIRECT_DATA_;

typedef struct CRYPTCATSTORE_ CRYPTCATSTORE_, *PCRYPTCATSTORE_;

typedef struct CRYPTCATMEMBER_ CRYPTCATMEMBER_, *PCRYPTCATMEMBER_;

typedef struct _CRYPT_ATTRIBUTE_TYPE_VALUE CRYPT_ATTRIBUTE_TYPE_VALUE;

typedef struct _CRYPTOAPI_BLOB CRYPT_ATTR_BLOB;

union _union_5374 {
    struct MS_ADDINFO_FLAT_ *psFlat;
    struct MS_ADDINFO_CATALOGMEMBER_ *psCatMember;
    struct MS_ADDINFO_BLOB_ *psBlob;
};

struct MS_ADDINFO_CATALOGMEMBER_ {
    DWORD cbStruct;
    struct CRYPTCATSTORE_ *pStore;
    struct CRYPTCATMEMBER_ *pMember;
};

struct MS_ADDINFO_BLOB_ {
    DWORD cbStruct;
    DWORD cbMemObject;
    BYTE *pbMemObject;
    DWORD cbMemSignedMsg;
    BYTE *pbMemSignedMsg;
};

struct SIP_INDIRECT_DATA_ {
    CRYPT_ATTRIBUTE_TYPE_VALUE Data;
    CRYPT_ALGORITHM_IDENTIFIER DigestAlgorithm;
    CRYPT_HASH_BLOB Digest;
};

struct MS_ADDINFO_FLAT_ {
    DWORD cbStruct;
    struct SIP_INDIRECT_DATA_ *pIndirectData;
};

struct CRYPTCATMEMBER_ {
    DWORD cbStruct;
    LPWSTR pwszReferenceTag;
    LPWSTR pwszFileName;
    GUID gSubjectType;
    DWORD fdwMemberFlags;
    struct SIP_INDIRECT_DATA_ *pIndirectData;
    DWORD dwCertVersion;
    DWORD dwReserved;
    HANDLE hReserved;
    CRYPT_ATTR_BLOB sEncodedIndirectData;
    CRYPT_ATTR_BLOB sEncodedMemberInfo;
};

struct CRYPTCATSTORE_ {
    DWORD cbStruct;
    DWORD dwPublicVersion;
    LPWSTR pwszP7File;
    HCRYPTPROV hProv;
    DWORD dwEncodingType;
    DWORD fdwStoreFlags;
    HANDLE hReserved;
    HANDLE hAttrs;
    HCRYPTMSG hCryptMsg;
    HANDLE hSorted;
};

typedef struct SIP_SUBJECTINFO_ SIP_SUBJECTINFO_, *PSIP_SUBJECTINFO_;

typedef struct SIP_SUBJECTINFO_ SIP_SUBJECTINFO;

typedef struct SIP_INDIRECT_DATA_ SIP_INDIRECT_DATA;

typedef BOOL (*pCryptSIPCreateIndirectData)(SIP_SUBJECTINFO *, DWORD *, SIP_INDIRECT_DATA *);

struct SIP_SUBJECTINFO_ {
    DWORD cbSize;
    GUID *pgSubjectType;
    HANDLE hFile;
    LPCWSTR pwsFileName;
    LPCWSTR pwsDisplayName;
    DWORD dwReserved1;
    DWORD dwIntVersion;
    HCRYPTPROV hProv;
    CRYPT_ALGORITHM_IDENTIFIER DigestAlgorithm;
    DWORD dwFlags;
    DWORD dwEncodingType;
    DWORD dwReserved2;
    DWORD fdwCAPISettings;
    DWORD fdwSecuritySettings;
    DWORD dwIndex;
    DWORD dwUnionChoice;
    union _union_5374 field16_0x70;
    LPVOID pClientData;
};

typedef BOOL (*pCryptSIPGetSignedDataMsg)(SIP_SUBJECTINFO *, DWORD *, DWORD, DWORD *, BYTE *);

typedef BOOL (*pCryptSIPPutSignedDataMsg)(SIP_SUBJECTINFO *, DWORD, DWORD *, DWORD, BYTE *);

typedef BOOL (*pCryptSIPRemoveSignedDataMsg)(SIP_SUBJECTINFO *, DWORD);

typedef BOOL (*pCryptSIPVerifyIndirectData)(SIP_SUBJECTINFO *, SIP_INDIRECT_DATA *);

typedef struct SIP_DISPATCH_INFO_ SIP_DISPATCH_INFO_, *PSIP_DISPATCH_INFO_;

struct SIP_DISPATCH_INFO_ {
    DWORD cbSize;
    HANDLE hSIP;
    pCryptSIPGetSignedDataMsg pfGet;
    pCryptSIPPutSignedDataMsg pfPut;
    pCryptSIPCreateIndirectData pfCreate;
    pCryptSIPVerifyIndirectData pfVerify;
    pCryptSIPRemoveSignedDataMsg pfRemove;
};

typedef ULONG_PTR NCRYPT_HANDLE;

typedef ULONG_PTR NCRYPT_HASH_HANDLE;

typedef ULONG_PTR NCRYPT_PROV_HANDLE;

typedef ULONG_PTR NCRYPT_SECRET_HANDLE;

typedef struct __NCRYPT_SUPPORTED_LENGTHS NCRYPT_SUPPORTED_LENGTHS;

typedef struct __NCRYPT_UI_POLICY NCRYPT_UI_POLICY;

typedef struct _NCryptAlgorithmName NCryptAlgorithmName;

typedef BCryptBuffer NCryptBuffer;


/* WARNING! conflicting data type names: /ncrypt.h/NCryptBufferDesc - /CONFLICTS python2.h/NCryptBufferDesc */

typedef BCryptBuffer *PNCryptBuffer;

typedef LONG SECURITY_STATUS;

#define ALL_PROCESSOR_GROUPS 65535

#define ANSI_NULL 0

#define ANYSIZE_ARRAY 1

#define APPLICATION_ERROR_MASK 536870912

#define DUMMYUNIONNAME 0

#define ERROR_SEVERITY_ERROR 3221225472

#define ERROR_SEVERITY_INFORMATIONAL 1073741824

#define ERROR_SEVERITY_SUCCESS 0

#define ERROR_SEVERITY_WARNING 2147483648

#define FALSE 0

#define LANG_AFRIKAANS 54

#define LANG_ALBANIAN 28

#define LANG_ALSATIAN 132

#define LANG_AMHARIC 94

#define LANG_ARABIC 1

#define LANG_ARMENIAN 43

#define LANG_ASSAMESE 77

#define LANG_AZERBAIJANI 44

#define LANG_AZERI 44

#define LANG_BANGLA 69

#define LANG_BASHKIR 109

#define LANG_BASQUE 45

#define LANG_BELARUSIAN 35

#define LANG_BENGALI 69

#define LANG_BOSNIAN 26

#define LANG_BOSNIAN_NEUTRAL 30746

#define LANG_BRETON 126

#define LANG_BULGARIAN 2

#define LANG_CATALAN 3

#define LANG_CENTRAL_KURDISH 146

#define LANG_CHEROKEE 92

#define LANG_CHINESE 4

#define LANG_CHINESE_SIMPLIFIED 4

#define LANG_CHINESE_TRADITIONAL 31748

#define LANG_CORSICAN 131

#define LANG_CROATIAN 26

#define LANG_CZECH 5

#define LANG_DANISH 6

#define LANG_DARI 140

#define LANG_DIVEHI 101

#define LANG_DUTCH 19

#define LANG_ENGLISH 9

#define LANG_ESTONIAN 37

#define LANG_FAEROESE 56

#define LANG_FARSI 41

#define LANG_FILIPINO 100

#define LANG_FINNISH 11

#define LANG_FRENCH 12

#define LANG_FRISIAN 98

#define LANG_FULAH 103

#define LANG_GALICIAN 86

#define LANG_GEORGIAN 55

#define LANG_GERMAN 7

#define LANG_GREEK 8

#define LANG_GREENLANDIC 111

#define LANG_GUJARATI 71

#define LANG_HAUSA 104

#define LANG_HAWAIIAN 117

#define LANG_HEBREW 13

#define LANG_HINDI 57

#define LANG_HUNGARIAN 14

#define LANG_ICELANDIC 15

#define LANG_IGBO 112

#define LANG_INDONESIAN 33

#define LANG_INUKTITUT 93

#define LANG_INVARIANT 127

#define LANG_IRISH 60

#define LANG_ITALIAN 16

#define LANG_JAPANESE 17

#define LANG_KANNADA 75

#define LANG_KASHMIRI 96

#define LANG_KAZAK 63

#define LANG_KHMER 83

#define LANG_KICHE 134

#define LANG_KINYARWANDA 135

#define LANG_KONKANI 87

#define LANG_KOREAN 18

#define LANG_KYRGYZ 64

#define LANG_LAO 84

#define LANG_LATVIAN 38

#define LANG_LITHUANIAN 39

#define LANG_LOWER_SORBIAN 46

#define LANG_LUXEMBOURGISH 110

#define LANG_MACEDONIAN 47

#define LANG_MALAY 62

#define LANG_MALAYALAM 76

#define LANG_MALTESE 58

#define LANG_MANIPURI 88

#define LANG_MAORI 129

#define LANG_MAPUDUNGUN 122

#define LANG_MARATHI 78

#define LANG_MOHAWK 124

#define LANG_MONGOLIAN 80

#define LANG_NEPALI 97

#define LANG_NEUTRAL 0

#define LANG_NORWEGIAN 20

#define LANG_OCCITAN 130

#define LANG_ODIA 72

#define LANG_ORIYA 72

#define LANG_PASHTO 99

#define LANG_PERSIAN 41

#define LANG_POLISH 21

#define LANG_PORTUGUESE 22

#define LANG_PULAR 103

#define LANG_PUNJABI 70

#define LANG_QUECHUA 107

#define LANG_ROMANIAN 24

#define LANG_ROMANSH 23

#define LANG_RUSSIAN 25

#define LANG_SAKHA 133

#define LANG_SAMI 59

#define LANG_SANSKRIT 79

#define LANG_SCOTTISH_GAELIC 145

#define LANG_SERBIAN 26

#define LANG_SERBIAN_NEUTRAL 31770

#define LANG_SINDHI 89

#define LANG_SINHALESE 91

#define LANG_SLOVAK 27

#define LANG_SLOVENIAN 36

#define LANG_SOTHO 108

#define LANG_SPANISH 10

#define LANG_SWAHILI 65

#define LANG_SWEDISH 29

#define LANG_SYRIAC 90

#define LANG_SYSTEM_DEFAULT 2048

#define LANG_TAJIK 40

#define LANG_TAMAZIGHT 95

#define LANG_TAMIL 73

#define LANG_TATAR 68

#define LANG_TELUGU 74

#define LANG_THAI 30

#define LANG_TIBETAN 81

#define LANG_TIGRIGNA 115

#define LANG_TIGRINYA 115

#define LANG_TSWANA 50

#define LANG_TURKISH 31

#define LANG_TURKMEN 66

#define LANG_UIGHUR 128

#define LANG_UKRAINIAN 34

#define LANG_UPPER_SORBIAN 46

#define LANG_URDU 32

#define LANG_USER_DEFAULT 1024

#define LANG_UZBEK 67

#define LANG_VALENCIAN 3

#define LANG_VIETNAMESE 42

#define LANG_WELSH 82

#define LANG_WOLOF 136

#define LANG_XHOSA 52

#define LANG_YAKUT 133

#define LANG_YI 120

#define LANG_YORUBA 106

#define LANG_ZULU 53

#define LOCALE_CUSTOM_DEFAULT 3072

#define LOCALE_CUSTOM_UI_DEFAULT 5120

#define LOCALE_CUSTOM_UNSPECIFIED 4096

#define LOCALE_INVARIANT 127

#define LOCALE_NAME_MAX_LENGTH 85

#define LOCALE_NEUTRAL 0

#define LOCALE_SYSTEM_DEFAULT 2048

#define LOCALE_TRANSIENT_KEYBOARD1 8192

#define LOCALE_TRANSIENT_KEYBOARD2 9216

#define LOCALE_TRANSIENT_KEYBOARD3 10240

#define LOCALE_TRANSIENT_KEYBOARD4 11264

#define LOCALE_UNASSIGNED_LCID 4096

#define LOCALE_USER_DEFAULT 1024

#define MAX_UCSCHAR 1114111

#define MAXCHAR 127

#define MAXIMUM_PROC_PER_GROUP 64

#define MAXIMUM_PROCESSORS 64

#define MAXLONG 2147483647

#define MAXLONGLONG 9223372036854775807

#define MAXSHORT 32767

#define MAXUCHAR 255

#define MAXULONG 4294967295

#define MAXUSHORT 65535

#define MEMORY_ALLOCATION_ALIGNMENT 16

#define MIN_UCSCHAR 0

#define MINCHAR 128

#define MINLONG 2147483648

#define MINSHORT 32768

#define NLS_VALID_LOCALE_MASK 1048575

#define NULL 0

#define NULL64 0

#define OBJ_CASE_INSENSITIVE 64

#define OBJ_EXCLUSIVE 32

#define OBJ_FORCE_ACCESS_CHECK 1024

#define OBJ_HANDLE_TAGBITS 3

#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 2048

#define OBJ_INHERIT 2

#define OBJ_KERNEL_HANDLE 512

#define OBJ_OPENIF 128

#define OBJ_OPENLINK 256

#define OBJ_PERMANENT 16

#define OBJ_VALID_ATTRIBUTES 4082

#define PRAGMA_DEPRECATED_DDK 0

#define PRODUCT_ARM64_SERVER 120

#define PRODUCT_BUSINESS 6

#define PRODUCT_BUSINESS_N 16

#define PRODUCT_CLOUD_HOST_INFRASTRUCTURE_SERVER 124

#define PRODUCT_CLOUD_STORAGE_SERVER 110

#define PRODUCT_CLUSTER_SERVER 18

#define PRODUCT_CLUSTER_SERVER_V 64

#define PRODUCT_CONNECTED_CAR 117

#define PRODUCT_CORE 101

#define PRODUCT_CORE_ARM 97

#define PRODUCT_CORE_CONNECTED 111

#define PRODUCT_CORE_CONNECTED_COUNTRYSPECIFIC 116

#define PRODUCT_CORE_CONNECTED_N 113

#define PRODUCT_CORE_CONNECTED_SINGLELANGUAGE 115

#define PRODUCT_CORE_COUNTRYSPECIFIC 99

#define PRODUCT_CORE_N 98

#define PRODUCT_CORE_SINGLELANGUAGE 100

#define PRODUCT_DATACENTER_EVALUATION_SERVER 80

#define PRODUCT_DATACENTER_SERVER 8

#define PRODUCT_DATACENTER_SERVER_CORE 12

#define PRODUCT_DATACENTER_SERVER_CORE_V 39

#define PRODUCT_DATACENTER_SERVER_V 37

#define PRODUCT_EDUCATION 121

#define PRODUCT_EDUCATION_N 122

#define PRODUCT_EMBEDDED 65

#define PRODUCT_EMBEDDED_A 88

#define PRODUCT_EMBEDDED_AUTOMOTIVE 85

#define PRODUCT_EMBEDDED_E 90

#define PRODUCT_EMBEDDED_E_EVAL 108

#define PRODUCT_EMBEDDED_EVAL 107

#define PRODUCT_EMBEDDED_INDUSTRY 89

#define PRODUCT_EMBEDDED_INDUSTRY_A 86

#define PRODUCT_EMBEDDED_INDUSTRY_A_E 92

#define PRODUCT_EMBEDDED_INDUSTRY_E 91

#define PRODUCT_EMBEDDED_INDUSTRY_E_EVAL 106

#define PRODUCT_EMBEDDED_INDUSTRY_EVAL 105

#define PRODUCT_ENTERPRISE 4

#define PRODUCT_ENTERPRISE_E 70

#define PRODUCT_ENTERPRISE_EVALUATION 72

#define PRODUCT_ENTERPRISE_N 27

#define PRODUCT_ENTERPRISE_N_EVALUATION 84

#define PRODUCT_ENTERPRISE_S 125

#define PRODUCT_ENTERPRISE_S_EVALUATION 129

#define PRODUCT_ENTERPRISE_S_N 126

#define PRODUCT_ENTERPRISE_S_N_EVALUATION 130

#define PRODUCT_ENTERPRISE_SERVER 10

#define PRODUCT_ENTERPRISE_SERVER_CORE 14

#define PRODUCT_ENTERPRISE_SERVER_CORE_V 41

#define PRODUCT_ENTERPRISE_SERVER_IA64 15

#define PRODUCT_ENTERPRISE_SERVER_V 38

#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDL 60

#define PRODUCT_ESSENTIALBUSINESS_SERVER_ADDLSVC 62

#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMT 59

#define PRODUCT_ESSENTIALBUSINESS_SERVER_MGMTSVC 61

#define PRODUCT_HOME_BASIC 2

#define PRODUCT_HOME_BASIC_E 67

#define PRODUCT_HOME_BASIC_N 5

#define PRODUCT_HOME_PREMIUM 3

#define PRODUCT_HOME_PREMIUM_E 68

#define PRODUCT_HOME_PREMIUM_N 26

#define PRODUCT_HOME_PREMIUM_SERVER 34

#define PRODUCT_HOME_SERVER 19

#define PRODUCT_HYPERV 42

#define PRODUCT_INDUSTRY_HANDHELD 118

#define PRODUCT_IOTUAP 123

#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT 30

#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING 32

#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY 31

#define PRODUCT_MOBILE_CORE 104

#define PRODUCT_MULTIPOINT_PREMIUM_SERVER 77

#define PRODUCT_MULTIPOINT_STANDARD_SERVER 76

#define PRODUCT_NANO_SERVER 109

#define PRODUCT_PPI_PRO 119

#define PRODUCT_PROFESSIONAL 48

#define PRODUCT_PROFESSIONAL_E 69

#define PRODUCT_PROFESSIONAL_EMBEDDED 58

#define PRODUCT_PROFESSIONAL_N 49

#define PRODUCT_PROFESSIONAL_S 127

#define PRODUCT_PROFESSIONAL_S_N 128

#define PRODUCT_PROFESSIONAL_STUDENT 112

#define PRODUCT_PROFESSIONAL_STUDENT_N 114

#define PRODUCT_PROFESSIONAL_WMC 103

#define PRODUCT_SB_SOLUTION_SERVER 50

#define PRODUCT_SB_SOLUTION_SERVER_EM 54

#define PRODUCT_SERVER_FOR_SB_SOLUTIONS 51

#define PRODUCT_SERVER_FOR_SB_SOLUTIONS_EM 55

#define PRODUCT_SERVER_FOR_SMALLBUSINESS 24

#define PRODUCT_SERVER_FOR_SMALLBUSINESS_V 35

#define PRODUCT_SERVER_FOUNDATION 33

#define PRODUCT_SMALLBUSINESS_SERVER 9

#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM 25

#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE 63

#define PRODUCT_SOLUTION_EMBEDDEDSERVER 56

#define PRODUCT_SOLUTION_EMBEDDEDSERVER_CORE 57

#define PRODUCT_STANDARD_EVALUATION_SERVER 79

#define PRODUCT_STANDARD_SERVER 7

#define PRODUCT_STANDARD_SERVER_CORE 13

#define PRODUCT_STANDARD_SERVER_CORE_V 40

#define PRODUCT_STANDARD_SERVER_SOLUTIONS 52

#define PRODUCT_STANDARD_SERVER_SOLUTIONS_CORE 53

#define PRODUCT_STANDARD_SERVER_V 36

#define PRODUCT_STARTER 11

#define PRODUCT_STARTER_E 66

#define PRODUCT_STARTER_N 47

#define PRODUCT_STORAGE_ENTERPRISE_SERVER 23

#define PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE 46

#define PRODUCT_STORAGE_EXPRESS_SERVER 20

#define PRODUCT_STORAGE_EXPRESS_SERVER_CORE 43

#define PRODUCT_STORAGE_STANDARD_EVALUATION_SERVER 96

#define PRODUCT_STORAGE_STANDARD_SERVER 21

#define PRODUCT_STORAGE_STANDARD_SERVER_CORE 44

#define PRODUCT_STORAGE_WORKGROUP_EVALUATION_SERVER 95

#define PRODUCT_STORAGE_WORKGROUP_SERVER 22

#define PRODUCT_STORAGE_WORKGROUP_SERVER_CORE 45

#define PRODUCT_THINPC 87

#define PRODUCT_ULTIMATE 1

#define PRODUCT_ULTIMATE_E 71

#define PRODUCT_ULTIMATE_N 28

#define PRODUCT_UNDEFINED 0

#define PRODUCT_UNLICENSED 2882382797

#define PRODUCT_WEB_SERVER 17

#define PRODUCT_WEB_SERVER_CORE 29

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

#define SORT_CHINESE_BIG5 0

#define SORT_CHINESE_BOPOMOFO 3

#define SORT_CHINESE_PRC 2

#define SORT_CHINESE_PRCP 0

#define SORT_CHINESE_RADICALSTROKE 4

#define SORT_CHINESE_UNICODE 1

#define SORT_DEFAULT 0

#define SORT_GEORGIAN_MODERN 1

#define SORT_GEORGIAN_TRADITIONAL 0

#define SORT_GERMAN_PHONE_BOOK 1

#define SORT_HUNGARIAN_DEFAULT 0

#define SORT_HUNGARIAN_TECHNICAL 1

#define SORT_INVARIANT_MATH 1

#define SORT_JAPANESE_RADICALSTROKE 4

#define SORT_JAPANESE_UNICODE 1

#define SORT_JAPANESE_XJIS 0

#define SORT_KOREAN_KSC 0

#define SORT_KOREAN_UNICODE 1

#define STRICT 1

#define SUBLANG_AFRIKAANS_SOUTH_AFRICA 1

#define SUBLANG_ALBANIAN_ALBANIA 1

#define SUBLANG_ALSATIAN_FRANCE 1

#define SUBLANG_AMHARIC_ETHIOPIA 1

#define SUBLANG_ARABIC_ALGERIA 5

#define SUBLANG_ARABIC_BAHRAIN 15

#define SUBLANG_ARABIC_EGYPT 3

#define SUBLANG_ARABIC_IRAQ 2

#define SUBLANG_ARABIC_JORDAN 11

#define SUBLANG_ARABIC_KUWAIT 13

#define SUBLANG_ARABIC_LEBANON 12

#define SUBLANG_ARABIC_LIBYA 4

#define SUBLANG_ARABIC_MOROCCO 6

#define SUBLANG_ARABIC_OMAN 8

#define SUBLANG_ARABIC_QATAR 16

#define SUBLANG_ARABIC_SAUDI_ARABIA 1

#define SUBLANG_ARABIC_SYRIA 10

#define SUBLANG_ARABIC_TUNISIA 7

#define SUBLANG_ARABIC_UAE 14

#define SUBLANG_ARABIC_YEMEN 9

#define SUBLANG_ARMENIAN_ARMENIA 1

#define SUBLANG_ASSAMESE_INDIA 1

#define SUBLANG_AZERBAIJANI_AZERBAIJAN_CYRILLIC 2

#define SUBLANG_AZERBAIJANI_AZERBAIJAN_LATIN 1

#define SUBLANG_AZERI_CYRILLIC 2

#define SUBLANG_AZERI_LATIN 1

#define SUBLANG_BANGLA_BANGLADESH 2

#define SUBLANG_BANGLA_INDIA 1

#define SUBLANG_BASHKIR_RUSSIA 1

#define SUBLANG_BASQUE_BASQUE 1

#define SUBLANG_BELARUSIAN_BELARUS 1

#define SUBLANG_BENGALI_BANGLADESH 2

#define SUBLANG_BENGALI_INDIA 1

#define SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC 8

#define SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN 5

#define SUBLANG_BRETON_FRANCE 1

#define SUBLANG_BULGARIAN_BULGARIA 1

#define SUBLANG_CATALAN_CATALAN 1

#define SUBLANG_CENTRAL_KURDISH_IRAQ 1

#define SUBLANG_CHEROKEE_CHEROKEE 1

#define SUBLANG_CHINESE_HONGKONG 3

#define SUBLANG_CHINESE_MACAU 5

#define SUBLANG_CHINESE_SIMPLIFIED 2

#define SUBLANG_CHINESE_SINGAPORE 4

#define SUBLANG_CHINESE_TRADITIONAL 1

#define SUBLANG_CORSICAN_FRANCE 1

#define SUBLANG_CROATIAN_BOSNIA_HERZEGOVINA_LATIN 4

#define SUBLANG_CROATIAN_CROATIA 1

#define SUBLANG_CUSTOM_DEFAULT 3

#define SUBLANG_CUSTOM_UNSPECIFIED 4

#define SUBLANG_CZECH_CZECH_REPUBLIC 1

#define SUBLANG_DANISH_DENMARK 1

#define SUBLANG_DARI_AFGHANISTAN 1

#define SUBLANG_DEFAULT 1

#define SUBLANG_DIVEHI_MALDIVES 1

#define SUBLANG_DUTCH 1

#define SUBLANG_DUTCH_BELGIAN 2

#define SUBLANG_ENGLISH_AUS 3

#define SUBLANG_ENGLISH_BELIZE 10

#define SUBLANG_ENGLISH_CAN 4

#define SUBLANG_ENGLISH_CARIBBEAN 9

#define SUBLANG_ENGLISH_EIRE 6

#define SUBLANG_ENGLISH_INDIA 16

#define SUBLANG_ENGLISH_JAMAICA 8

#define SUBLANG_ENGLISH_MALAYSIA 17

#define SUBLANG_ENGLISH_NZ 5

#define SUBLANG_ENGLISH_PHILIPPINES 13

#define SUBLANG_ENGLISH_SINGAPORE 18

#define SUBLANG_ENGLISH_SOUTH_AFRICA 7

#define SUBLANG_ENGLISH_TRINIDAD 11

#define SUBLANG_ENGLISH_UK 2

#define SUBLANG_ENGLISH_US 1

#define SUBLANG_ENGLISH_ZIMBABWE 12

#define SUBLANG_ESTONIAN_ESTONIA 1

#define SUBLANG_FAEROESE_FAROE_ISLANDS 1

#define SUBLANG_FILIPINO_PHILIPPINES 1

#define SUBLANG_FINNISH_FINLAND 1

#define SUBLANG_FRENCH 1

#define SUBLANG_FRENCH_BELGIAN 2

#define SUBLANG_FRENCH_CANADIAN 3

#define SUBLANG_FRENCH_LUXEMBOURG 5

#define SUBLANG_FRENCH_MONACO 6

#define SUBLANG_FRENCH_SWISS 4

#define SUBLANG_FRISIAN_NETHERLANDS 1

#define SUBLANG_FULAH_SENEGAL 2

#define SUBLANG_GALICIAN_GALICIAN 1

#define SUBLANG_GEORGIAN_GEORGIA 1

#define SUBLANG_GERMAN 1

#define SUBLANG_GERMAN_AUSTRIAN 3

#define SUBLANG_GERMAN_LIECHTENSTEIN 5

#define SUBLANG_GERMAN_LUXEMBOURG 4

#define SUBLANG_GERMAN_SWISS 2

#define SUBLANG_GREEK_GREECE 1

#define SUBLANG_GREENLANDIC_GREENLAND 1

#define SUBLANG_GUJARATI_INDIA 1

#define SUBLANG_HAUSA_NIGERIA_LATIN 1

#define SUBLANG_HAWAIIAN_US 1

#define SUBLANG_HEBREW_ISRAEL 1

#define SUBLANG_HINDI_INDIA 1

#define SUBLANG_HUNGARIAN_HUNGARY 1

#define SUBLANG_ICELANDIC_ICELAND 1

#define SUBLANG_IGBO_NIGERIA 1

#define SUBLANG_INDONESIAN_INDONESIA 1

#define SUBLANG_INUKTITUT_CANADA 1

#define SUBLANG_INUKTITUT_CANADA_LATIN 2

#define SUBLANG_IRISH_IRELAND 2

#define SUBLANG_ITALIAN 1

#define SUBLANG_ITALIAN_SWISS 2

#define SUBLANG_JAPANESE_JAPAN 1

#define SUBLANG_KANNADA_INDIA 1

#define SUBLANG_KASHMIRI_INDIA 2

#define SUBLANG_KASHMIRI_SASIA 2

#define SUBLANG_KAZAK_KAZAKHSTAN 1

#define SUBLANG_KHMER_CAMBODIA 1

#define SUBLANG_KICHE_GUATEMALA 1

#define SUBLANG_KINYARWANDA_RWANDA 1

#define SUBLANG_KONKANI_INDIA 1

#define SUBLANG_KOREAN 1

#define SUBLANG_KYRGYZ_KYRGYZSTAN 1

#define SUBLANG_LAO_LAO 1

#define SUBLANG_LATVIAN_LATVIA 1

#define SUBLANG_LITHUANIAN 1

#define SUBLANG_LOWER_SORBIAN_GERMANY 2

#define SUBLANG_LUXEMBOURGISH_LUXEMBOURG 1

#define SUBLANG_MACEDONIAN_MACEDONIA 1

#define SUBLANG_MALAY_BRUNEI_DARUSSALAM 2

#define SUBLANG_MALAY_MALAYSIA 1

#define SUBLANG_MALAYALAM_INDIA 1

#define SUBLANG_MALTESE_MALTA 1

#define SUBLANG_MAORI_NEW_ZEALAND 1

#define SUBLANG_MAPUDUNGUN_CHILE 1

#define SUBLANG_MARATHI_INDIA 1

#define SUBLANG_MOHAWK_MOHAWK 1

#define SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA 1

#define SUBLANG_MONGOLIAN_PRC 2

#define SUBLANG_NEPALI_INDIA 2

#define SUBLANG_NEPALI_NEPAL 1

#define SUBLANG_NEUTRAL 0

#define SUBLANG_NORWEGIAN_BOKMAL 1

#define SUBLANG_NORWEGIAN_NYNORSK 2

#define SUBLANG_OCCITAN_FRANCE 1

#define SUBLANG_ODIA_INDIA 1

#define SUBLANG_ORIYA_INDIA 1

#define SUBLANG_PASHTO_AFGHANISTAN 1

#define SUBLANG_PERSIAN_IRAN 1

#define SUBLANG_POLISH_POLAND 1

#define SUBLANG_PORTUGUESE 2

#define SUBLANG_PORTUGUESE_BRAZILIAN 1

#define SUBLANG_PULAR_SENEGAL 2

#define SUBLANG_PUNJABI_INDIA 1

#define SUBLANG_PUNJABI_PAKISTAN 2

#define SUBLANG_QUECHUA_BOLIVIA 1

#define SUBLANG_QUECHUA_ECUADOR 2

#define SUBLANG_QUECHUA_PERU 3

#define SUBLANG_ROMANIAN_ROMANIA 1

#define SUBLANG_ROMANSH_SWITZERLAND 1

#define SUBLANG_RUSSIAN_RUSSIA 1

#define SUBLANG_SAKHA_RUSSIA 1

#define SUBLANG_SAMI_INARI_FINLAND 9

#define SUBLANG_SAMI_LULE_NORWAY 4

#define SUBLANG_SAMI_LULE_SWEDEN 5

#define SUBLANG_SAMI_NORTHERN_FINLAND 3

#define SUBLANG_SAMI_NORTHERN_NORWAY 1

#define SUBLANG_SAMI_NORTHERN_SWEDEN 2

#define SUBLANG_SAMI_SKOLT_FINLAND 8

#define SUBLANG_SAMI_SOUTHERN_NORWAY 6

#define SUBLANG_SAMI_SOUTHERN_SWEDEN 7

#define SUBLANG_SANSKRIT_INDIA 1

#define SUBLANG_SCOTTISH_GAELIC 1

#define SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC 7

#define SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN 6

#define SUBLANG_SERBIAN_CROATIA 1

#define SUBLANG_SERBIAN_CYRILLIC 3

#define SUBLANG_SERBIAN_LATIN 2

#define SUBLANG_SERBIAN_MONTENEGRO_CYRILLIC 12

#define SUBLANG_SERBIAN_MONTENEGRO_LATIN 11

#define SUBLANG_SERBIAN_SERBIA_CYRILLIC 10

#define SUBLANG_SERBIAN_SERBIA_LATIN 9

#define SUBLANG_SINDHI_AFGHANISTAN 2

#define SUBLANG_SINDHI_INDIA 1

#define SUBLANG_SINDHI_PAKISTAN 2

#define SUBLANG_SINHALESE_SRI_LANKA 1

#define SUBLANG_SLOVAK_SLOVAKIA 1

#define SUBLANG_SLOVENIAN_SLOVENIA 1

#define SUBLANG_SOTHO_NORTHERN_SOUTH_AFRICA 1

#define SUBLANG_SPANISH 1

#define SUBLANG_SPANISH_ARGENTINA 11

#define SUBLANG_SPANISH_BOLIVIA 16

#define SUBLANG_SPANISH_CHILE 13

#define SUBLANG_SPANISH_COLOMBIA 9

#define SUBLANG_SPANISH_COSTA_RICA 5

#define SUBLANG_SPANISH_DOMINICAN_REPUBLIC 7

#define SUBLANG_SPANISH_ECUADOR 12

#define SUBLANG_SPANISH_EL_SALVADOR 17

#define SUBLANG_SPANISH_GUATEMALA 4

#define SUBLANG_SPANISH_HONDURAS 18

#define SUBLANG_SPANISH_MEXICAN 2

#define SUBLANG_SPANISH_MODERN 3

#define SUBLANG_SPANISH_NICARAGUA 19

#define SUBLANG_SPANISH_PANAMA 6

#define SUBLANG_SPANISH_PARAGUAY 15

#define SUBLANG_SPANISH_PERU 10

#define SUBLANG_SPANISH_PUERTO_RICO 20

#define SUBLANG_SPANISH_URUGUAY 14

#define SUBLANG_SPANISH_US 21

#define SUBLANG_SPANISH_VENEZUELA 8

#define SUBLANG_SWAHILI_KENYA 1

#define SUBLANG_SWEDISH 1

#define SUBLANG_SWEDISH_FINLAND 2

#define SUBLANG_SYRIAC_SYRIA 1

#define SUBLANG_SYS_DEFAULT 2

#define SUBLANG_TAJIK_TAJIKISTAN 1

#define SUBLANG_TAMAZIGHT_ALGERIA_LATIN 2

#define SUBLANG_TAMAZIGHT_MOROCCO_TIFINAGH 4

#define SUBLANG_TAMIL_INDIA 1

#define SUBLANG_TAMIL_SRI_LANKA 2

#define SUBLANG_TATAR_RUSSIA 1

#define SUBLANG_TELUGU_INDIA 1

#define SUBLANG_THAI_THAILAND 1

#define SUBLANG_TIBETAN_PRC 1

#define SUBLANG_TIGRIGNA_ERITREA 2

#define SUBLANG_TIGRINYA_ERITREA 2

#define SUBLANG_TIGRINYA_ETHIOPIA 1

#define SUBLANG_TSWANA_BOTSWANA 2

#define SUBLANG_TSWANA_SOUTH_AFRICA 1

#define SUBLANG_TURKISH_TURKEY 1

#define SUBLANG_TURKMEN_TURKMENISTAN 1

#define SUBLANG_UI_CUSTOM_DEFAULT 5

#define SUBLANG_UIGHUR_PRC 1

#define SUBLANG_UKRAINIAN_UKRAINE 1

#define SUBLANG_UPPER_SORBIAN_GERMANY 1

#define SUBLANG_URDU_INDIA 2

#define SUBLANG_URDU_PAKISTAN 1

#define SUBLANG_UZBEK_CYRILLIC 2

#define SUBLANG_UZBEK_LATIN 1

#define SUBLANG_VALENCIAN_VALENCIA 2

#define SUBLANG_VIETNAMESE_VIETNAM 1

#define SUBLANG_WELSH_UNITED_KINGDOM 1

#define SUBLANG_WOLOF_SENEGAL 1

#define SUBLANG_XHOSA_SOUTH_AFRICA 1

#define SUBLANG_YAKUT_RUSSIA 1

#define SUBLANG_YI_PRC 1

#define SUBLANG_YORUBA_NIGERIA 1

#define SUBLANG_ZULU_SOUTH_AFRICA 1

#define SYSTEM_CACHE_ALIGNMENT_SIZE 64

#define TRUE 1

#define UCSCHAR_INVALID_CHARACTER 4294967295

#define UNICODE_NULL 0

#define UNICODE_STRING_MAX_BYTES 65534

#define UNICODE_STRING_MAX_CHARS 32767

#define VER_SERVER_NT 2147483648

#define VER_SUITE_BACKOFFICE 4

#define VER_SUITE_BLADE 1024

#define VER_SUITE_COMMUNICATIONS 8

#define VER_SUITE_COMPUTE_SERVER 16384

#define VER_SUITE_DATACENTER 128

#define VER_SUITE_EMBEDDED_RESTRICTED 2048

#define VER_SUITE_EMBEDDEDNT 64

#define VER_SUITE_ENTERPRISE 2

#define VER_SUITE_PERSONAL 512

#define VER_SUITE_SECURITY_APPLIANCE 4096

#define VER_SUITE_SINGLEUSERTS 256

#define VER_SUITE_SMALLBUSINESS 1

#define VER_SUITE_SMALLBUSINESS_RESTRICTED 32

#define VER_SUITE_STORAGE_SERVER 8192

#define VER_SUITE_TERMINAL 16

#define VER_SUITE_WH_SERVER 32768

#define VER_WORKSTATION_NT 1073741824


/* WARNING! conflicting data type names: /ntdef.h/_CONTEXT - /excpt.h/_CONTEXT */

typedef struct _CSTRING _CSTRING, *P_CSTRING;

struct _CSTRING {
    USHORT Length;
    USHORT MaximumLength;
    char *Buffer;
};

typedef enum _EVENT_TYPE {
    NotificationEvent=0,
    SynchronizationEvent=1
} _EVENT_TYPE;


/* WARNING! conflicting data type names: /ntdef.h/_EXCEPTION_RECORD - /excpt.h/_EXCEPTION_RECORD */

typedef struct _FLOAT128 _FLOAT128, *P_FLOAT128;

struct _FLOAT128 {
    longlong LowPart;
    longlong HighPart;
};

typedef struct _GROUP_AFFINITY _GROUP_AFFINITY, *P_GROUP_AFFINITY;

struct _GROUP_AFFINITY {
    KAFFINITY Mask;
    USHORT Group;
    USHORT Reserved[3];
};

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_8 _struct_8, *P_struct_8;

typedef struct _struct_9 _struct_9, *P_struct_9;

struct _struct_9 {
    ULONG LowPart;
    LONG HighPart;
};

struct _struct_8 {
    ULONG LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_8 s;
    struct _struct_9 u;
    LONGLONG QuadPart;
};


/* WARNING! conflicting data type names: /ntdef.h/_LIST_ENTRY - /winnt.h/_LIST_ENTRY */

typedef struct _LUID _LUID, *P_LUID;

struct _LUID {
    ULONG LowPart;
    LONG HighPart;
};

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt=1,
    NtProductLanManNt=2,
    NtProductServer=3
} _NT_PRODUCT_TYPE;

typedef struct _OBJECT_ATTRIBUTES _OBJECT_ATTRIBUTES, *P_OBJECT_ATTRIBUTES;


/* WARNING! conflicting data type names: /ntdef.h/_UNICODE_STRING - /Demangler/_UNICODE_STRING */

typedef struct _UNICODE_STRING UNICODE_STRING;

typedef UNICODE_STRING *PUNICODE_STRING;

struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

typedef struct _OBJECT_ATTRIBUTES32 _OBJECT_ATTRIBUTES32, *P_OBJECT_ATTRIBUTES32;

struct _OBJECT_ATTRIBUTES32 {
    ULONG Length;
    ULONG RootDirectory;
    ULONG ObjectName;
    ULONG Attributes;
    ULONG SecurityDescriptor;
    ULONG SecurityQualityOfService;
};

typedef struct _OBJECT_ATTRIBUTES64 _OBJECT_ATTRIBUTES64, *P_OBJECT_ATTRIBUTES64;

struct _OBJECT_ATTRIBUTES64 {
    ULONG Length;
    ULONG64 RootDirectory;
    ULONG64 ObjectName;
    ULONG Attributes;
    ULONG64 SecurityDescriptor;
    ULONG64 SecurityQualityOfService;
};

typedef struct _OBJECTID _OBJECTID, *P_OBJECTID;

struct _OBJECTID {
    GUID Lineage;
    ULONG Uniquifier;
};

typedef struct _PROCESSOR_NUMBER _PROCESSOR_NUMBER, *P_PROCESSOR_NUMBER;

struct _PROCESSOR_NUMBER {
    USHORT Group;
    UCHAR Number;
    UCHAR Reserved;
};

typedef struct _QUAD _QUAD, *P_QUAD;

typedef union _union_2 _union_2, *P_union_2;

union _union_2 {
    longlong UseThisFieldToCopy;
    double DoNotUseThisField;
};

struct _QUAD {
    union _union_2 u;
};

typedef struct _RTL_BALANCED_NODE _RTL_BALANCED_NODE, *P_RTL_BALANCED_NODE;

typedef union _union_23 _union_23, *P_union_23;

typedef union _union_28 _union_28, *P_union_28;

typedef struct _struct_25 _struct_25, *P_struct_25;

struct _struct_25 {
    struct _RTL_BALANCED_NODE *Left;
    struct _RTL_BALANCED_NODE *Right;
};

union _union_23 {
    struct _RTL_BALANCED_NODE *Children[2];
    struct _struct_25 s;
};

union _union_28 {
    UCHAR Red:1;
    UCHAR Balance:2;
    ULONG_PTR ParentValue;
};

struct _RTL_BALANCED_NODE {
    union _union_23 u;
    union _union_28 u2;
};

typedef struct _SINGLE_LIST_ENTRY _SINGLE_LIST_ENTRY, *P_SINGLE_LIST_ENTRY;

struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
};

typedef struct _SINGLE_LIST_ENTRY32 _SINGLE_LIST_ENTRY32, *P_SINGLE_LIST_ENTRY32;

struct _SINGLE_LIST_ENTRY32 {
    ULONG Next;
};


/* WARNING! conflicting data type names: /ntdef.h/_STRING - /Demangler/_STRING */

typedef struct _STRING32 _STRING32, *P_STRING32;

struct _STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
};

typedef struct _STRING64 _STRING64, *P_STRING64;

struct _STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONGLONG Buffer;
};

typedef struct _struct_11 _struct_11, *P_struct_11;

struct _struct_11 {
    ULONG LowPart;
    ULONG HighPart;
};

typedef struct _struct_12 _struct_12, *P_struct_12;

struct _struct_12 {
    ULONG LowPart;
    ULONG HighPart;
};

typedef enum _SUITE_TYPE {
    SmallBusiness=0,
    Enterprise=1,
    BackOffice=2,
    CommunicationServer=3,
    TerminalServer=4,
    SmallBusinessRestricted=5,
    EmbeddedNT=6,
    DataCenter=7,
    SingleUserTS=8,
    Personal=9,
    Blade=10,
    EmbeddedRestricted=11,
    SecurityAppliance=12,
    StorageServer=13,
    ComputeServer=14,
    WHServer=15,
    PhoneNT=16,
    MaxSuiteType=17
} _SUITE_TYPE;

typedef enum _TIMER_TYPE {
    NotificationTimer=0,
    SynchronizationTimer=1
} _TIMER_TYPE;

typedef union _ULARGE_INTEGER _ULARGE_INTEGER, *P_ULARGE_INTEGER;

union _ULARGE_INTEGER {
    struct _struct_11 s;
    struct _struct_12 u;
    ULONGLONG QuadPart;
};

typedef enum _WAIT_TYPE {
    WaitAll=0,
    WaitAny=1,
    WaitNotification=2
} _WAIT_TYPE;

typedef struct _STRING STRING;

typedef STRING ANSI_STRING;

typedef struct _STRING32 STRING32;

typedef STRING32 ANSI_STRING32;

typedef struct _STRING64 STRING64;

typedef STRING64 ANSI_STRING64;

typedef STRING CANSI_STRING;

typedef ULONG CLONG;

typedef enum enum_5 {
    UNSPECIFIED_COMPARTMENT_ID=0,
    DEFAULT_COMPARTMENT_ID=1
} enum_5;

typedef enum enum_5 COMPARTMENT_ID;

typedef short CSHORT;

typedef struct _CSTRING CSTRING;

typedef enum _EVENT_TYPE EVENT_TYPE;

typedef EXCEPTION_DISPOSITION (EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef UCHAR FCHAR;

typedef ULONG FLONG;

typedef USHORT FSHORT;

typedef struct _GROUP_AFFINITY GROUP_AFFINITY;

typedef UCHAR KIRQL;

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef ULONG LCID;


/* WARNING! conflicting data type names: /ntdef.h/LIST_ENTRY - /winnt.h/LIST_ENTRY */

typedef struct LIST_ENTRY32 LIST_ENTRY32, *PLIST_ENTRY32;

struct LIST_ENTRY32 {
    ULONG Flink;
    ULONG Blink;
};

typedef struct LIST_ENTRY64 LIST_ENTRY64, *PLIST_ENTRY64;

struct LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
};

typedef ULONG LOGICAL;

typedef struct _LUID LUID;

typedef enum _NT_PRODUCT_TYPE NT_PRODUCT_TYPE;

typedef struct _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES;

typedef struct _OBJECT_ATTRIBUTES32 OBJECT_ATTRIBUTES32;

typedef struct _OBJECT_ATTRIBUTES64 OBJECT_ATTRIBUTES64;

typedef struct _OBJECTID OBJECTID;

typedef STRING OEM_STRING;

typedef STRING *PSTRING;

typedef PSTRING PANSI_STRING;

typedef ANSI_STRING32 *PANSI_STRING32;

typedef ANSI_STRING64 *PANSI_STRING64;

typedef BOOLEAN *PBOOLEAN;

typedef PSTRING PCANSI_STRING;

typedef char CCHAR;

typedef CCHAR *PCCHAR;

typedef CLONG *PCLONG;

typedef NTSTATUS *PCNTSTATUS;

typedef OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES32 *PCOBJECT_ATTRIBUTES32;

typedef OBJECT_ATTRIBUTES64 *PCOBJECT_ATTRIBUTES64;

typedef STRING *PCOEM_STRING;

typedef enum enum_5 *PCOMPARTMENT_ID;

typedef char SCHAR;

typedef SCHAR *PCSCHAR;

typedef CSHORT *PCSHORT;

typedef CSTRING *PCSTRING;

typedef char *PCSZ;

typedef UCHAR *PCUCHAR;

typedef ULONG *PCULONG;

typedef UNICODE_STRING *PCUNICODE_STRING;

typedef struct _QUAD QUAD;

typedef QUAD UQUAD;

typedef UQUAD *PCUQUAD;

typedef USHORT *PCUSHORT;

typedef CHAR *PCSTR;

typedef PCSTR *PCZPCSTR;

typedef PCWSTR *PCZPCWSTR;

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;

typedef struct _GROUP_AFFINITY *PGROUP_AFFINITY;

typedef LARGE_INTEGER PHYSICAL_ADDRESS;

typedef KIRQL *PKIRQL;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef ULONG *PULONG;

typedef PULONG PLCID;

typedef struct _LIST_ENTRY *PLIST_ENTRY;

typedef ULONG *PLOGICAL;

typedef struct _LUID *PLUID;

typedef enum _NT_PRODUCT_TYPE *PNT_PRODUCT_TYPE;

typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef OBJECT_ATTRIBUTES32 *POBJECT_ATTRIBUTES32;

typedef OBJECT_ATTRIBUTES64 *POBJECT_ATTRIBUTES64;

typedef PSTRING POEM_STRING;

typedef void *POINTER_64;

typedef LARGE_INTEGER *PPHYSICAL_ADDRESS;

typedef struct _PROCESSOR_NUMBER *PPROCESSOR_NUMBER;

typedef QUAD *PQUAD;

typedef struct _LIST_ENTRY *PRLIST_ENTRY;

typedef struct _PROCESSOR_NUMBER PROCESSOR_NUMBER;

typedef struct _RTL_BALANCED_NODE *PRTL_BALANCED_NODE;

typedef LONG_PTR *PRTL_REFERENCE_COUNT;

typedef SCHAR *PSCHAR;

typedef struct _SINGLE_LIST_ENTRY *PSINGLE_LIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY32 *PSINGLE_LIST_ENTRY32;

typedef STRING32 *PSTRING32;

typedef STRING64 *PSTRING64;

typedef CHAR *PSZ;

typedef uchar *PTUCHAR;

typedef union _ULARGE_INTEGER ULARGE_INTEGER;

typedef ULARGE_INTEGER *PULARGE_INTEGER;

typedef STRING32 UNICODE_STRING32;

typedef UNICODE_STRING32 *PUNICODE_STRING32;

typedef STRING64 UNICODE_STRING64;

typedef UNICODE_STRING64 *PUNICODE_STRING64;

typedef UQUAD *PUQUAD;

typedef CHAR *PSTR;

typedef PSTR *PZPSTR;

typedef PZPSTR PZPTSTR;

typedef struct _RTL_BALANCED_NODE RTL_BALANCED_NODE;

typedef LONG_PTR RTL_REFERENCE_COUNT;

typedef USHORT RTL_STRING_LENGTH_TYPE;


/* WARNING! conflicting data type names: /ntdef.h/SECURITY_STATUS - /ncrypt.h/SECURITY_STATUS */

typedef struct _SINGLE_LIST_ENTRY SINGLE_LIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY32 SINGLE_LIST_ENTRY32;

typedef enum _SUITE_TYPE SUITE_TYPE;

typedef enum _TIMER_TYPE TIMER_TYPE;

typedef uchar TUCHAR;

typedef enum _WAIT_TYPE WAIT_TYPE;

typedef enum _POLICY_INFORMATION_CLASS {
    PolicyAuditLogInformation=1,
    PolicyAuditEventsInformation=2,
    PolicyPrimaryDomainInformation=3,
    PolicyPdAccountInformation=4,
    PolicyAccountDomainInformation=5,
    PolicyLsaServerRoleInformation=6,
    PolicyReplicaSourceInformation=7,
    PolicyDefaultQuotaInformation=8,
    PolicyModificationInformation=9,
    PolicyAuditFullSetInformation=10,
    PolicyAuditFullQueryInformation=11,
    PolicyDnsDomainInformation=12,
    PolicyDnsDomainInformationInt=13,
    PolicyLocalAccountDomainInformation=14,
    PolicyLastEntry=15
} _POLICY_INFORMATION_CLASS;

typedef PVOID LSA_HANDLE;

typedef PVOID *PLSA_HANDLE;

typedef enum _POLICY_INFORMATION_CLASS POLICY_INFORMATION_CLASS;

typedef struct __tagBRECORD __tagBRECORD, *P__tagBRECORD;

typedef struct IRecordInfo IRecordInfo, *PIRecordInfo;

typedef struct IRecordInfoVtbl IRecordInfoVtbl, *PIRecordInfoVtbl;

typedef WCHAR OLECHAR;

typedef OLECHAR *BSTR;

typedef struct ITypeInfo ITypeInfo, *PITypeInfo;

typedef OLECHAR *LPCOLESTR;

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

typedef struct tagVARIANT VARIANT;

typedef struct ITypeInfoVtbl ITypeInfoVtbl, *PITypeInfoVtbl;

typedef struct tagTYPEATTR tagTYPEATTR, *PtagTYPEATTR;

typedef struct tagTYPEATTR TYPEATTR;

typedef struct ITypeComp ITypeComp, *PITypeComp;

typedef uint UINT;

typedef struct tagFUNCDESC tagFUNCDESC, *PtagFUNCDESC;

typedef struct tagFUNCDESC FUNCDESC;

typedef struct tagVARDESC tagVARDESC, *PtagVARDESC;

typedef struct tagVARDESC VARDESC;

typedef LONG DISPID;

typedef DISPID MEMBERID;

typedef DWORD HREFTYPE;

typedef int INT;

typedef OLECHAR *LPOLESTR;

typedef struct tagDISPPARAMS tagDISPPARAMS, *PtagDISPPARAMS;

typedef struct tagDISPPARAMS DISPPARAMS;

typedef struct tagEXCEPINFO tagEXCEPINFO, *PtagEXCEPINFO;

typedef struct tagEXCEPINFO EXCEPINFO;

typedef enum tagINVOKEKIND {
    INVOKE_FUNC=1,
    INVOKE_PROPERTYGET=2,
    INVOKE_PROPERTYPUT=4,
    INVOKE_PROPERTYPUTREF=8
} tagINVOKEKIND;

typedef enum tagINVOKEKIND INVOKEKIND;

typedef struct IUnknown IUnknown, *PIUnknown;

typedef struct ITypeLib ITypeLib, *PITypeLib;

typedef union _union_2707 _union_2707, *P_union_2707;


/* WARNING! conflicting data type names: /winnt.h/LCID - /ntdef.h/LCID */

typedef enum tagTYPEKIND {
    TKIND_ENUM=0,
    TKIND_RECORD=1,
    TKIND_MODULE=2,
    TKIND_INTERFACE=3,
    TKIND_DISPATCH=4,
    TKIND_COCLASS=5,
    TKIND_ALIAS=6,
    TKIND_UNION=7,
    TKIND_MAX=8
} tagTYPEKIND;

typedef enum tagTYPEKIND TYPEKIND;

typedef struct tagTYPEDESC tagTYPEDESC, *PtagTYPEDESC;

typedef struct tagTYPEDESC TYPEDESC;

typedef struct tagIDLDESC tagIDLDESC, *PtagIDLDESC;

typedef struct tagIDLDESC IDLDESC;

typedef struct ITypeCompVtbl ITypeCompVtbl, *PITypeCompVtbl;

typedef enum tagDESCKIND {
    DESCKIND_NONE=0,
    DESCKIND_FUNCDESC=1,
    DESCKIND_VARDESC=2,
    DESCKIND_TYPECOMP=3,
    DESCKIND_IMPLICITAPPOBJ=4,
    DESCKIND_MAX=5
} tagDESCKIND;

typedef enum tagDESCKIND DESCKIND;

typedef union tagBINDPTR tagBINDPTR, *PtagBINDPTR;

typedef union tagBINDPTR BINDPTR;

typedef LONG SCODE;

typedef struct tagELEMDESC tagELEMDESC, *PtagELEMDESC;

typedef struct tagELEMDESC ELEMDESC;

typedef enum tagFUNCKIND {
    FUNC_VIRTUAL=0,
    FUNC_PUREVIRTUAL=1,
    FUNC_NONVIRTUAL=2,
    FUNC_STATIC=3,
    FUNC_DISPATCH=4
} tagFUNCKIND;

typedef enum tagFUNCKIND FUNCKIND;

typedef enum tagCALLCONV {
    CC_FASTCALL=0,
    CC_CDECL=1,
    CC_MSCPASCAL=2,
    CC_PASCAL=3,
    CC_MACPASCAL=4,
    CC_STDCALL=5,
    CC_FPFASTCALL=6,
    CC_SYSCALL=7,
    CC_MPWCDECL=8,
    CC_MPWPASCAL=9,
    CC_MAX=10
} tagCALLCONV;

typedef enum tagCALLCONV CALLCONV;

typedef short SHORT;

typedef union _union_2735 _union_2735, *P_union_2735;

typedef enum tagVARKIND {
    VAR_PERINSTANCE=0,
    VAR_STATIC=1,
    VAR_CONST=2,
    VAR_DISPATCH=3
} tagVARKIND;

typedef enum tagVARKIND VARKIND;

typedef VARIANT VARIANTARG;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct ITypeLibVtbl ITypeLibVtbl, *PITypeLibVtbl;

typedef struct tagTLIBATTR tagTLIBATTR, *PtagTLIBATTR;

typedef struct tagTLIBATTR TLIBATTR;

typedef struct __tagVARIANT __tagVARIANT, *P__tagVARIANT;

typedef struct tagDEC tagDEC, *PtagDEC;

typedef struct tagDEC DECIMAL;

typedef union _union_2715 _union_2715, *P_union_2715;

typedef ushort VARTYPE;

typedef union _union_2726 _union_2726, *P_union_2726;

typedef enum tagSYSKIND {
    SYS_WIN16=0,
    SYS_WIN32=1,
    SYS_MAC=2,
    SYS_WIN64=3
} tagSYSKIND;

typedef enum tagSYSKIND SYSKIND;

typedef union _union_2709 _union_2709, *P_union_2709;

typedef union _union_1717 _union_1717, *P_union_1717;

typedef union _union_1719 _union_1719, *P_union_1719;

typedef struct tagARRAYDESC tagARRAYDESC, *PtagARRAYDESC;

typedef struct tagPARAMDESC tagPARAMDESC, *PtagPARAMDESC;

typedef struct tagPARAMDESC PARAMDESC;

typedef float FLOAT;

typedef double DOUBLE;

typedef short VARIANT_BOOL;

typedef union tagCY tagCY, *PtagCY;

typedef union tagCY CY;

typedef double DATE;

typedef struct IDispatch IDispatch, *PIDispatch;

typedef struct tagSAFEARRAY tagSAFEARRAY, *PtagSAFEARRAY;

typedef struct tagSAFEARRAY SAFEARRAY;

typedef struct _struct_1718 _struct_1718, *P_struct_1718;

typedef struct _struct_1720 _struct_1720, *P_struct_1720;

typedef struct tagSAFEARRAYBOUND tagSAFEARRAYBOUND, *PtagSAFEARRAYBOUND;

typedef struct tagSAFEARRAYBOUND SAFEARRAYBOUND;

typedef struct tagPARAMDESCEX tagPARAMDESCEX, *PtagPARAMDESCEX;

typedef struct tagPARAMDESCEX *LPPARAMDESCEX;

typedef struct _struct_1715 _struct_1715, *P_struct_1715;

typedef struct IDispatchVtbl IDispatchVtbl, *PIDispatchVtbl;

struct _struct_1715 {
    ulong Lo;
    long Hi;
};

union tagCY {
    struct _struct_1715 s;
    LONGLONG int64;
};

struct tagIDLDESC {
    ULONG_PTR dwReserved;
    USHORT wIDLFlags;
};

struct tagPARAMDESC {
    LPPARAMDESCEX pparamdescex;
    USHORT wParamFlags;
};

union _union_2726 {
    IDLDESC idldesc;
    PARAMDESC paramdesc;
};

union _union_2715 {
    struct tagTYPEDESC *lptdesc;
    struct tagARRAYDESC *lpadesc;
    HREFTYPE hreftype;
};

struct tagTYPEDESC {
    union _union_2715 u;
    VARTYPE vt;
};

struct tagELEMDESC {
    TYPEDESC tdesc;
    union _union_2726 u;
};

struct tagFUNCDESC {
    MEMBERID memid;
    SCODE *lprgscode;
    ELEMDESC *lprgelemdescParam;
    FUNCKIND funckind;
    INVOKEKIND invkind;
    CALLCONV callconv;
    SHORT cParams;
    SHORT cParamsOpt;
    SHORT oVft;
    SHORT cScodes;
    ELEMDESC elemdescFunc;
    WORD wFuncFlags;
};

struct _struct_1720 {
    ULONG Lo32;
    ULONG Mid32;
};

union _union_1719 {
    struct _struct_1720 s2;
    ULONGLONG Lo64;
};

struct _struct_1718 {
    BYTE scale;
    BYTE sign;
};

union _union_1717 {
    struct _struct_1718 s;
    USHORT signscale;
};

struct tagDEC {
    USHORT wReserved;
    union _union_1717 u;
    ULONG Hi32;
    union _union_1719 u2;
};

struct __tagBRECORD {
    PVOID pvRecord;
    struct IRecordInfo *pRecInfo;
};

union _union_2709 {
    LONGLONG llVal;
    LONG lVal;
    BYTE bVal;
    SHORT iVal;
    FLOAT fltVal;
    DOUBLE dblVal;
    VARIANT_BOOL boolVal;
    SCODE scode;
    CY cyVal;
    DATE date;
    BSTR bstrVal;
    struct IUnknown *punkVal;
    struct IDispatch *pdispVal;
    SAFEARRAY *parray;
    BYTE *pbVal;
    SHORT *piVal;
    LONG *plVal;
    LONGLONG *pllVal;
    FLOAT *pfltVal;
    DOUBLE *pdblVal;
    VARIANT_BOOL *pboolVal;
    SCODE *pscode;
    CY *pcyVal;
    DATE *pdate;
    BSTR *pbstrVal;
    struct IUnknown **ppunkVal;
    struct IDispatch **ppdispVal;
    SAFEARRAY **pparray;
    VARIANT *pvarVal;
    PVOID byref;
    CHAR cVal;
    USHORT uiVal;
    ULONG ulVal;
    ULONGLONG ullVal;
    INT intVal;
    UINT uintVal;
    DECIMAL *pdecVal;
    CHAR *pcVal;
    USHORT *puiVal;
    ULONG *pulVal;
    ULONGLONG *pullVal;
    INT *pintVal;
    UINT *puintVal;
    struct __tagBRECORD brecVal;
};

struct __tagVARIANT {
    VARTYPE vt;
    WORD wReserved1;
    WORD wReserved2;
    WORD wReserved3;
    union _union_2709 n3;
};

union _union_2707 {
    struct __tagVARIANT n2;
    DECIMAL decVal;
};

struct tagVARIANT {
    union _union_2707 n1;
};

struct tagPARAMDESCEX {
    ULONG cBytes;
    VARIANTARG varDefaultValue;
};

union _union_2735 {
    ULONG oInst;
    VARIANT *lpvarValue;
};

struct tagVARDESC {
    MEMBERID memid;
    LPOLESTR lpstrSchema;
    union _union_2735 u;
    ELEMDESC elemdescVar;
    WORD wVarFlags;
    VARKIND varkind;
};

struct ITypeCompVtbl {
    HRESULT (*QueryInterface)(struct ITypeComp *, IID *, void **);
    ULONG (*AddRef)(struct ITypeComp *);
    ULONG (*Release)(struct ITypeComp *);
    HRESULT (*Bind)(struct ITypeComp *, LPOLESTR, ULONG, WORD, struct ITypeInfo **, DESCKIND *, BINDPTR *);
    HRESULT (*BindType)(struct ITypeComp *, LPOLESTR, ULONG, struct ITypeInfo **, struct ITypeComp **);
};

struct ITypeInfoVtbl {
    HRESULT (*QueryInterface)(struct ITypeInfo *, IID *, void **);
    ULONG (*AddRef)(struct ITypeInfo *);
    ULONG (*Release)(struct ITypeInfo *);
    HRESULT (*GetTypeAttr)(struct ITypeInfo *, TYPEATTR **);
    HRESULT (*GetTypeComp)(struct ITypeInfo *, struct ITypeComp **);
    HRESULT (*GetFuncDesc)(struct ITypeInfo *, UINT, FUNCDESC **);
    HRESULT (*GetVarDesc)(struct ITypeInfo *, UINT, VARDESC **);
    HRESULT (*GetNames)(struct ITypeInfo *, MEMBERID, BSTR *, UINT, UINT *);
    HRESULT (*GetRefTypeOfImplType)(struct ITypeInfo *, UINT, HREFTYPE *);
    HRESULT (*GetImplTypeFlags)(struct ITypeInfo *, UINT, INT *);
    HRESULT (*GetIDsOfNames)(struct ITypeInfo *, LPOLESTR *, UINT, MEMBERID *);
    HRESULT (*Invoke)(struct ITypeInfo *, PVOID, MEMBERID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *);
    HRESULT (*GetDocumentation)(struct ITypeInfo *, MEMBERID, BSTR *, BSTR *, DWORD *, BSTR *);
    HRESULT (*GetDllEntry)(struct ITypeInfo *, MEMBERID, INVOKEKIND, BSTR *, BSTR *, WORD *);
    HRESULT (*GetRefTypeInfo)(struct ITypeInfo *, HREFTYPE, struct ITypeInfo **);
    HRESULT (*AddressOfMember)(struct ITypeInfo *, MEMBERID, INVOKEKIND, PVOID *);
    HRESULT (*CreateInstance)(struct ITypeInfo *, struct IUnknown *, IID *, PVOID *);
    HRESULT (*GetMops)(struct ITypeInfo *, MEMBERID, BSTR *);
    HRESULT (*GetContainingTypeLib)(struct ITypeInfo *, struct ITypeLib **, UINT *);
    void (*ReleaseTypeAttr)(struct ITypeInfo *, TYPEATTR *);
    void (*ReleaseFuncDesc)(struct ITypeInfo *, FUNCDESC *);
    void (*ReleaseVarDesc)(struct ITypeInfo *, VARDESC *);
};

struct ITypeLibVtbl {
    HRESULT (*QueryInterface)(struct ITypeLib *, IID *, void **);
    ULONG (*AddRef)(struct ITypeLib *);
    ULONG (*Release)(struct ITypeLib *);
    UINT (*GetTypeInfoCount)(struct ITypeLib *);
    HRESULT (*GetTypeInfo)(struct ITypeLib *, UINT, struct ITypeInfo **);
    HRESULT (*GetTypeInfoType)(struct ITypeLib *, UINT, TYPEKIND *);
    HRESULT (*GetTypeInfoOfGuid)(struct ITypeLib *, GUID *, struct ITypeInfo **);
    HRESULT (*GetLibAttr)(struct ITypeLib *, TLIBATTR **);
    HRESULT (*GetTypeComp)(struct ITypeLib *, struct ITypeComp **);
    HRESULT (*GetDocumentation)(struct ITypeLib *, INT, BSTR *, BSTR *, DWORD *, BSTR *);
    HRESULT (*IsName)(struct ITypeLib *, LPOLESTR, ULONG, BOOL *);
    HRESULT (*FindName)(struct ITypeLib *, LPOLESTR, ULONG, struct ITypeInfo **, MEMBERID *, USHORT *);
    void (*ReleaseTLibAttr)(struct ITypeLib *, TLIBATTR *);
};

struct tagSAFEARRAYBOUND {
    ULONG cElements;
    LONG lLbound;
};

struct tagSAFEARRAY {
    USHORT cDims;
    USHORT fFeatures;
    ULONG cbElements;
    ULONG cLocks;
    PVOID pvData;
    SAFEARRAYBOUND rgsabound[1];
};

struct tagTLIBATTR {
    GUID guid;
    LCID lcid;
    SYSKIND syskind;
    WORD wMajorVerNum;
    WORD wMinorVerNum;
    WORD wLibFlags;
};

struct tagARRAYDESC {
    TYPEDESC tdescElem;
    USHORT cDims;
    SAFEARRAYBOUND rgbounds[1];
};

struct ITypeComp {
    struct ITypeCompVtbl *lpVtbl;
};

struct IRecordInfo {
    struct IRecordInfoVtbl *lpVtbl;
};

struct tagTYPEATTR {
    GUID guid;
    LCID lcid;
    DWORD dwReserved;
    MEMBERID memidConstructor;
    MEMBERID memidDestructor;
    LPOLESTR lpstrSchema;
    ULONG cbSizeInstance;
    TYPEKIND typekind;
    WORD cFuncs;
    WORD cVars;
    WORD cImplTypes;
    WORD cbSizeVft;
    WORD cbAlignment;
    WORD wTypeFlags;
    WORD wMajorVerNum;
    WORD wMinorVerNum;
    TYPEDESC tdescAlias;
    IDLDESC idldescType;
};

struct IRecordInfoVtbl {
    HRESULT (*QueryInterface)(struct IRecordInfo *, IID *, void **);
    ULONG (*AddRef)(struct IRecordInfo *);
    ULONG (*Release)(struct IRecordInfo *);
    HRESULT (*RecordInit)(struct IRecordInfo *, PVOID);
    HRESULT (*RecordClear)(struct IRecordInfo *, PVOID);
    HRESULT (*RecordCopy)(struct IRecordInfo *, PVOID, PVOID);
    HRESULT (*GetGuid)(struct IRecordInfo *, GUID *);
    HRESULT (*GetName)(struct IRecordInfo *, BSTR *);
    HRESULT (*GetSize)(struct IRecordInfo *, ULONG *);
    HRESULT (*GetTypeInfo)(struct IRecordInfo *, struct ITypeInfo **);
    HRESULT (*GetField)(struct IRecordInfo *, PVOID, LPCOLESTR, VARIANT *);
    HRESULT (*GetFieldNoCopy)(struct IRecordInfo *, PVOID, LPCOLESTR, VARIANT *, PVOID *);
    HRESULT (*PutField)(struct IRecordInfo *, ULONG, PVOID, LPCOLESTR, VARIANT *);
    HRESULT (*PutFieldNoCopy)(struct IRecordInfo *, ULONG, PVOID, LPCOLESTR, VARIANT *);
    HRESULT (*GetFieldNames)(struct IRecordInfo *, ULONG *, BSTR *);
    BOOL (*IsMatchingType)(struct IRecordInfo *, struct IRecordInfo *);
    PVOID (*RecordCreate)(struct IRecordInfo *);
    HRESULT (*RecordCreateCopy)(struct IRecordInfo *, PVOID, PVOID *);
    HRESULT (*RecordDestroy)(struct IRecordInfo *, PVOID);
};

struct tagDISPPARAMS {
    VARIANTARG *rgvarg;
    DISPID *rgdispidNamedArgs;
    UINT cArgs;
    UINT cNamedArgs;
};

union tagBINDPTR {
    FUNCDESC *lpfuncdesc;
    VARDESC *lpvardesc;
    struct ITypeComp *lptcomp;
};

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IDispatch {
    struct IDispatchVtbl *lpVtbl;
};

struct IDispatchVtbl {
    HRESULT (*QueryInterface)(struct IDispatch *, IID *, void **);
    ULONG (*AddRef)(struct IDispatch *);
    ULONG (*Release)(struct IDispatch *);
    HRESULT (*GetTypeInfoCount)(struct IDispatch *, UINT *);
    HRESULT (*GetTypeInfo)(struct IDispatch *, UINT, LCID, struct ITypeInfo **);
    HRESULT (*GetIDsOfNames)(struct IDispatch *, IID *, LPOLESTR *, UINT, LCID, DISPID *);
    HRESULT (*Invoke)(struct IDispatch *, DISPID, IID *, LCID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
};

struct ITypeLib {
    struct ITypeLibVtbl *lpVtbl;
};

struct ITypeInfo {
    struct ITypeInfoVtbl *lpVtbl;
};

struct tagEXCEPINFO {
    WORD wCode;
    WORD wReserved;
    BSTR bstrSource;
    BSTR bstrDescription;
    BSTR bstrHelpFile;
    DWORD dwHelpContext;
    PVOID pvReserved;
    HRESULT (*pfnDeferredFillIn)(struct tagEXCEPINFO *);
    SCODE scode;
};

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[10];
};

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; /* 34404 */
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

typedef struct IMAGE_IMPORT_BY_NAME_11 IMAGE_IMPORT_BY_NAME_11, *PIMAGE_IMPORT_BY_NAME_11;

struct IMAGE_IMPORT_BY_NAME_11 {
    word Hint;
    char Name[11];
};

typedef struct IMAGE_IMPORT_BY_NAME_13 IMAGE_IMPORT_BY_NAME_13, *PIMAGE_IMPORT_BY_NAME_13;

struct IMAGE_IMPORT_BY_NAME_13 {
    word Hint;
    char Name[13];
};

typedef struct IMAGE_IMPORT_BY_NAME_14 IMAGE_IMPORT_BY_NAME_14, *PIMAGE_IMPORT_BY_NAME_14;

struct IMAGE_IMPORT_BY_NAME_14 {
    word Hint;
    char Name[14];
};

typedef struct IMAGE_IMPORT_BY_NAME_15 IMAGE_IMPORT_BY_NAME_15, *PIMAGE_IMPORT_BY_NAME_15;

struct IMAGE_IMPORT_BY_NAME_15 {
    word Hint;
    char Name[15];
};

typedef struct IMAGE_IMPORT_BY_NAME_16 IMAGE_IMPORT_BY_NAME_16, *PIMAGE_IMPORT_BY_NAME_16;

struct IMAGE_IMPORT_BY_NAME_16 {
    word Hint;
    char Name[16];
};

typedef struct IMAGE_IMPORT_BY_NAME_17 IMAGE_IMPORT_BY_NAME_17, *PIMAGE_IMPORT_BY_NAME_17;

struct IMAGE_IMPORT_BY_NAME_17 {
    word Hint;
    char Name[17];
};

typedef struct IMAGE_IMPORT_BY_NAME_18 IMAGE_IMPORT_BY_NAME_18, *PIMAGE_IMPORT_BY_NAME_18;

struct IMAGE_IMPORT_BY_NAME_18 {
    word Hint;
    char Name[18];
};

typedef struct IMAGE_IMPORT_BY_NAME_19 IMAGE_IMPORT_BY_NAME_19, *PIMAGE_IMPORT_BY_NAME_19;

struct IMAGE_IMPORT_BY_NAME_19 {
    word Hint;
    char Name[19];
};

typedef struct IMAGE_IMPORT_BY_NAME_20 IMAGE_IMPORT_BY_NAME_20, *PIMAGE_IMPORT_BY_NAME_20;

struct IMAGE_IMPORT_BY_NAME_20 {
    word Hint;
    char Name[20];
};

typedef struct IMAGE_IMPORT_BY_NAME_21 IMAGE_IMPORT_BY_NAME_21, *PIMAGE_IMPORT_BY_NAME_21;

struct IMAGE_IMPORT_BY_NAME_21 {
    word Hint;
    char Name[21];
};

typedef struct IMAGE_IMPORT_BY_NAME_22 IMAGE_IMPORT_BY_NAME_22, *PIMAGE_IMPORT_BY_NAME_22;

struct IMAGE_IMPORT_BY_NAME_22 {
    word Hint;
    char Name[22];
};

typedef struct IMAGE_IMPORT_BY_NAME_23 IMAGE_IMPORT_BY_NAME_23, *PIMAGE_IMPORT_BY_NAME_23;

struct IMAGE_IMPORT_BY_NAME_23 {
    word Hint;
    char Name[23];
};

typedef struct IMAGE_IMPORT_BY_NAME_24 IMAGE_IMPORT_BY_NAME_24, *PIMAGE_IMPORT_BY_NAME_24;

struct IMAGE_IMPORT_BY_NAME_24 {
    word Hint;
    char Name[24];
};

typedef struct IMAGE_IMPORT_BY_NAME_26 IMAGE_IMPORT_BY_NAME_26, *PIMAGE_IMPORT_BY_NAME_26;

struct IMAGE_IMPORT_BY_NAME_26 {
    word Hint;
    char Name[26];
};

typedef struct IMAGE_IMPORT_BY_NAME_27 IMAGE_IMPORT_BY_NAME_27, *PIMAGE_IMPORT_BY_NAME_27;

struct IMAGE_IMPORT_BY_NAME_27 {
    word Hint;
    char Name[27];
};

typedef struct IMAGE_IMPORT_BY_NAME_28 IMAGE_IMPORT_BY_NAME_28, *PIMAGE_IMPORT_BY_NAME_28;

struct IMAGE_IMPORT_BY_NAME_28 {
    word Hint;
    char Name[28];
};

typedef struct IMAGE_IMPORT_BY_NAME_29 IMAGE_IMPORT_BY_NAME_29, *PIMAGE_IMPORT_BY_NAME_29;

struct IMAGE_IMPORT_BY_NAME_29 {
    word Hint;
    char Name[29];
};

typedef struct IMAGE_IMPORT_BY_NAME_30 IMAGE_IMPORT_BY_NAME_30, *PIMAGE_IMPORT_BY_NAME_30;

struct IMAGE_IMPORT_BY_NAME_30 {
    word Hint;
    char Name[30];
};

typedef struct IMAGE_IMPORT_BY_NAME_31 IMAGE_IMPORT_BY_NAME_31, *PIMAGE_IMPORT_BY_NAME_31;

struct IMAGE_IMPORT_BY_NAME_31 {
    word Hint;
    char Name[31];
};

typedef struct IMAGE_IMPORT_BY_NAME_32 IMAGE_IMPORT_BY_NAME_32, *PIMAGE_IMPORT_BY_NAME_32;

struct IMAGE_IMPORT_BY_NAME_32 {
    word Hint;
    char Name[32];
};

typedef struct IMAGE_IMPORT_BY_NAME_33 IMAGE_IMPORT_BY_NAME_33, *PIMAGE_IMPORT_BY_NAME_33;

struct IMAGE_IMPORT_BY_NAME_33 {
    word Hint;
    char Name[33];
};

typedef struct IMAGE_IMPORT_BY_NAME_34 IMAGE_IMPORT_BY_NAME_34, *PIMAGE_IMPORT_BY_NAME_34;

struct IMAGE_IMPORT_BY_NAME_34 {
    word Hint;
    char Name[34];
};

typedef struct IMAGE_IMPORT_BY_NAME_35 IMAGE_IMPORT_BY_NAME_35, *PIMAGE_IMPORT_BY_NAME_35;

struct IMAGE_IMPORT_BY_NAME_35 {
    word Hint;
    char Name[35];
};

typedef struct IMAGE_IMPORT_BY_NAME_39 IMAGE_IMPORT_BY_NAME_39, *PIMAGE_IMPORT_BY_NAME_39;

struct IMAGE_IMPORT_BY_NAME_39 {
    word Hint;
    char Name[39];
};

typedef struct IMAGE_IMPORT_BY_NAME_41 IMAGE_IMPORT_BY_NAME_41, *PIMAGE_IMPORT_BY_NAME_41;

struct IMAGE_IMPORT_BY_NAME_41 {
    word Hint;
    char Name[41];
};

typedef struct IMAGE_IMPORT_BY_NAME_42 IMAGE_IMPORT_BY_NAME_42, *PIMAGE_IMPORT_BY_NAME_42;

struct IMAGE_IMPORT_BY_NAME_42 {
    word Hint;
    char Name[42];
};

typedef struct IMAGE_IMPORT_BY_NAME_47 IMAGE_IMPORT_BY_NAME_47, *PIMAGE_IMPORT_BY_NAME_47;

struct IMAGE_IMPORT_BY_NAME_47 {
    word Hint;
    char Name[47];
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

struct IMAGE_OPTIONAL_HEADER64 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS64 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_26 IMAGE_RESOURCE_DIR_STRING_U_26, *PIMAGE_RESOURCE_DIR_STRING_U_26;

struct IMAGE_RESOURCE_DIR_STRING_U_26 {
    word Length;
    wchar16 NameString[13];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_6 IMAGE_RESOURCE_DIR_STRING_U_6, *PIMAGE_RESOURCE_DIR_STRING_U_6;

struct IMAGE_RESOURCE_DIR_STRING_U_6 {
    word Length;
    wchar16 NameString[3];
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct ImgDelayDescr ImgDelayDescr, *PImgDelayDescr;

struct ImgDelayDescr {
    dword grAttrs;
    ImageBaseOffset32 szName;
    ImageBaseOffset32 phmod;
    ImageBaseOffset32 pIAT;
    ImageBaseOffset32 pINT;
    ImageBaseOffset32 pBoundIAT;
    ImageBaseOffset32 pUnloadIAT;
    dword dwTimeStamp;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef void *I_RPC_HANDLE;

typedef long RPC_STATUS;

typedef I_RPC_HANDLE RPC_BINDING_HANDLE;

typedef ushort *RPC_WSTR;

typedef GUID UUID;

typedef uchar boolean;

#define __SAL_H_VERSION 180000000

#define _SAL_VERSION 20

#define _USE_ATTRIBUTES_FOR_SAL 0

#define _USE_DECLSPECS_FOR_SAL 0

#define _WIN32_IE 2048

#define _WIN32_IE_IE100 2560

#define _WIN32_IE_IE110 2560

#define _WIN32_IE_IE20 512

#define _WIN32_IE_IE30 768

#define _WIN32_IE_IE302 770

#define _WIN32_IE_IE40 1024

#define _WIN32_IE_IE401 1025

#define _WIN32_IE_IE50 1280

#define _WIN32_IE_IE501 1281

#define _WIN32_IE_IE55 1360

#define _WIN32_IE_IE60 1536

#define _WIN32_IE_IE60SP1 1537

#define _WIN32_IE_IE60SP2 1539

#define _WIN32_IE_IE70 1792

#define _WIN32_IE_IE80 2048

#define _WIN32_IE_IE90 2304

#define _WIN32_IE_LONGHORN 1792

#define _WIN32_IE_NT4 512

#define _WIN32_IE_NT4SP1 512

#define _WIN32_IE_NT4SP2 512

#define _WIN32_IE_NT4SP3 770

#define _WIN32_IE_NT4SP4 1025

#define _WIN32_IE_NT4SP5 1025

#define _WIN32_IE_NT4SP6 1280

#define _WIN32_IE_WIN10 2560

#define _WIN32_IE_WIN2K 1281

#define _WIN32_IE_WIN2KSP1 1281

#define _WIN32_IE_WIN2KSP2 1281

#define _WIN32_IE_WIN2KSP3 1281

#define _WIN32_IE_WIN2KSP4 1281

#define _WIN32_IE_WIN6 1792

#define _WIN32_IE_WIN7 2048

#define _WIN32_IE_WIN8 2560

#define _WIN32_IE_WIN98 1025

#define _WIN32_IE_WIN98SE 1280

#define _WIN32_IE_WINBLUE 2560

#define _WIN32_IE_WINME 1360

#define _WIN32_IE_WINTHRESHOLD 2560

#define _WIN32_IE_WS03 1538

#define _WIN32_IE_WS03SP1 1539

#define _WIN32_IE_XP 1536

#define _WIN32_IE_XPSP1 1537

#define _WIN32_IE_XPSP2 1539

#define _WIN32_WINNT_LONGHORN 1536

#define _WIN32_WINNT_NT4 1024

#define _WIN32_WINNT_VISTA 1536

#define _WIN32_WINNT_WIN10 2560

#define _WIN32_WINNT_WIN2K 1280

#define _WIN32_WINNT_WIN6 1536

#define _WIN32_WINNT_WIN7 1537

#define _WIN32_WINNT_WIN8 1538

#define _WIN32_WINNT_WINBLUE 1539

#define _WIN32_WINNT_WINTHRESHOLD 2560

#define _WIN32_WINNT_WINXP 1281

#define _WIN32_WINNT_WS03 1282

#define _WIN32_WINNT_WS08 1536

#define NTDDI_LONGHORN 100663296

#define NTDDI_VISTA 100663296

#define NTDDI_VISTASP1 100663552

#define NTDDI_VISTASP2 100663808

#define NTDDI_VISTASP3 100664064

#define NTDDI_VISTASP4 100664320

#define NTDDI_WIN10 167772160

#define NTDDI_WIN2K 83886080

#define NTDDI_WIN2KSP1 83886336

#define NTDDI_WIN2KSP2 83886592

#define NTDDI_WIN2KSP3 83886848

#define NTDDI_WIN2KSP4 83887104

#define NTDDI_WIN6 100663296

#define NTDDI_WIN6SP1 100663552

#define NTDDI_WIN6SP2 100663808

#define NTDDI_WIN6SP3 100664064

#define NTDDI_WIN6SP4 100664320

#define NTDDI_WIN7 100728832

#define NTDDI_WIN8 100794368

#define NTDDI_WINBLUE 100859904

#define NTDDI_WINTHRESHOLD 167772160

#define NTDDI_WINXP 83951616

#define NTDDI_WINXPSP1 83951872

#define NTDDI_WINXPSP2 83952128

#define NTDDI_WINXPSP3 83952384

#define NTDDI_WINXPSP4 83952640

#define NTDDI_WS03 84017152

#define NTDDI_WS03SP1 84017408

#define NTDDI_WS03SP2 84017664

#define NTDDI_WS03SP3 84017920

#define NTDDI_WS03SP4 84018176

#define NTDDI_WS08 100663552

#define NTDDI_WS08SP2 100663808

#define NTDDI_WS08SP3 100664064

#define NTDDI_WS08SP4 100664320

#define OSVERSION_MASK 4294901760

#define SPVERSION_MASK 65280

#define SUBVERSION_MASK 255

#define __SAL_H_FULL_VER 140050727

#define __SPECSTRINGS_STRICT_LEVEL 1

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { /* PlaceHolder Class Structure */
};

typedef struct length_error length_error, *Plength_error;

struct length_error { /* PlaceHolder Class Structure */
};

typedef struct out_of_range out_of_range, *Pout_of_range;

struct out_of_range { /* PlaceHolder Class Structure */
};

typedef int (*_onexit_t)(void);

typedef char *STRSAFE_LPCSTR;

typedef wchar_t *STRSAFE_LPCWSTR;

typedef char *STRSAFE_LPSTR;

typedef wchar_t *STRSAFE_LPWSTR;

#define CAP_PROP_SESSION_DAA 282

#define TPM_AD_AUDITDIGEST 2

#define TPM_AD_CONTEXTCOUNT 4

#define TPM_AD_CONTEXTLIST 5

#define TPM_AD_CONTEXTNONCESESSION 1

#define TPM_AD_CURRENTTICKS 3

#define TPM_AD_SESSIONS 6

#define TPM_AF_LOCALITYMODIFIER 2

#define TPM_AF_POSTINITIALISE 1

#define TPM_AF_TOSPRESENT 4

#define TPM_AF_TRANSPORTEXCLUSIVE 3

#define TPM_ALG_3DES 3

#define TPM_ALG_AES128 6

#define TPM_ALG_AES192 8

#define TPM_ALG_AES256 9

#define TPM_ALG_DES 2

#define TPM_ALG_HMAC 5

#define TPM_ALG_MGF1 7

#define TPM_ALG_RSA 1

#define TPM_ALG_SHA 4

#define TPM_ALG_XOR 10

#define TPM_AREA_LOCKED 60

#define TPM_AUDITFAIL_SUCCESSFUL 49

#define TPM_AUDITFAIL_UNSUCCESSFUL 48

#define TPM_AUDITFAILURE 4

#define TPM_AUTH2FAIL 29

#define TPM_AUTH_ALWAYS 1

#define TPM_AUTH_CONFLICT 59

#define TPM_AUTH_NEVER 0

#define TPM_AUTH_PRIV_USE_ONLY 3

#define TPM_AUTHFAIL 1

#define TPM_BAD_ATTRIBUTES 66

#define TPM_BAD_COUNTER 69

#define TPM_BAD_DATASIZE 43

#define TPM_BAD_DELEGATE 89

#define TPM_BAD_HANDLE 88

#define TPM_BAD_KEY_PROPERTY 40

#define TPM_BAD_LOCALITY 61

#define TPM_BAD_MIGRATION 41

#define TPM_BAD_MODE 44

#define TPM_BAD_ORDINAL 10

#define TPM_BAD_PARAM_SIZE 25

#define TPM_BAD_PARAMETER 3

#define TPM_BAD_PRESENCE 45

#define TPM_BAD_SCHEME 42

#define TPM_BAD_SIGNATURE 98

#define TPM_BAD_TYPE 52

#define TPM_BAD_VERSION 46

#define TPM_BADCONTEXT 90

#define TPM_BADINDEX 2

#define TPM_BADTAG 30

#define TPM_BASE 0

#define TPM_CAP_ALG 2

#define TPM_CAP_AUTH_ENCRYPT 23

#define TPM_CAP_CHECK_LOADED 8

#define TPM_CAP_FLAG 4

#define TPM_CAP_FLAG_PERMANENT 264

#define TPM_CAP_FLAG_VOLATILE 265

#define TPM_CAP_HANDLE 20

#define TPM_CAP_KEY_HANDLE 7

#define TPM_CAP_KEY_STATUS 12

#define TPM_CAP_MFR 16

#define TPM_CAP_NV_INDEX 17

#define TPM_CAP_NV_LIST 13

#define TPM_CAP_ORD 1

#define TPM_CAP_PID 3

#define TPM_CAP_PROP_ACTIVE_COUNTER 290

#define TPM_CAP_PROP_AUTHSESS 266

#define TPM_CAP_PROP_CMK_RESTRICTION 287

#define TPM_CAP_PROP_CONTEXT 274

#define TPM_CAP_PROP_CONTEXT_DIST 283

#define TPM_CAP_PROP_COUNTERS 268

#define TPM_CAP_PROP_DAA_INTERRUPT 284

#define TPM_CAP_PROP_DAA_MAX 281

#define TPM_CAP_PROP_DELEGATE_ROW 279

#define TPM_CAP_PROP_DIR 258

#define TPM_CAP_PROP_DURATION 288

#define TPM_CAP_PROP_FAMILYROWS 276

#define TPM_CAP_PROP_INPUT_BUFFER 292

#define TPM_CAP_PROP_KEYS 260

#define TPM_CAP_PROP_MANUFACTURER 259

#define TPM_CAP_PROP_MAX_AUTHSESS 269

#define TPM_CAP_PROP_MAX_CONTEXT 275

#define TPM_CAP_PROP_MAX_COUNTERS 271

#define TPM_CAP_PROP_MAX_KEYS 272

#define TPM_CAP_PROP_MAX_NV_AVAILABLE 291

#define TPM_CAP_PROP_MAX_SESSIONS 286

#define TPM_CAP_PROP_MAX_TRANSESS 270

#define TPM_CAP_PROP_MIN_COUNTER 263

#define TPM_CAP_PROP_OWNER 273

#define TPM_CAP_PROP_PCR 257

#define TPM_CAP_PROP_SESSIONS 285

#define TPM_CAP_PROP_STARTUP_EFFECT 278

#define TPM_CAP_PROP_TIS_TIMEOUT 277

#define TPM_CAP_PROP_TRANSESS 267

#define TPM_CAP_PROPERTY 5

#define TPM_CAP_SELECT_SIZE 24

#define TPM_CAP_SYM_MODE 9

#define TPM_CAP_TRANS_ALG 18

#define TPM_CAP_TRANS_ES 21

#define TPM_CAP_VERSION 6

#define TPM_CAP_VERSION_VAL 26

#define TPM_CLEAR_DISABLED 5

#define TPM_CONTEXT_GAP 71

#define TPM_DA_ACTION_DEACTIVATE 4

#define TPM_DA_ACTION_DISABLE 2

#define TPM_DA_ACTION_FAILURE_MODE 8

#define TPM_DA_ACTION_TIMEOUT 1

#define TPM_DA_STATE_ACTIVE 1

#define TPM_DA_STATE_INACTIVE 0

#define TPM_DAA_INPUT_DATA0 81

#define TPM_DAA_INPUT_DATA1 82

#define TPM_DAA_ISSUER_SETTINGS 83

#define TPM_DAA_ISSUER_VALIDITY 86

#define TPM_DAA_power0 104

#define TPM_DAA_power1 1024

#define TPM_DAA_RESOURCES 80

#define TPM_DAA_SIZE_issuerModulus 256

#define TPM_DAA_SIZE_NE 256

#define TPM_DAA_SIZE_NT 20

#define TPM_DAA_SIZE_r0 43

#define TPM_DAA_SIZE_r1 43

#define TPM_DAA_SIZE_r2 128

#define TPM_DAA_SIZE_r3 168

#define TPM_DAA_SIZE_r4 219

#define TPM_DAA_SIZE_v0 128

#define TPM_DAA_SIZE_v1 192

#define TPM_DAA_SIZE_w 256

#define TPM_DAA_STAGE 85

#define TPM_DAA_TPM_SETTINGS 84

#define TPM_DAA_WRONG_W 87

#define TPM_DEACTIVATED 6

#define TPM_DECRYPT_ERROR 33

#define TPM_DEFEND_LOCK_RUNNING 2051

#define TPM_DEL_KEY_BITS 2

#define TPM_DEL_OWNER_BITS 1

#define TPM_DELEGATE_ADMIN 77

#define TPM_DELEGATE_FAMILY 76

#define TPM_DELEGATE_LOCK 75

#define TPM_DELEGATETABLE 18

#define TPM_DISABLED 7

#define TPM_DISABLED_CMD 8

#define TPM_DOING_SELFTEST 2050

#define TPM_EK_TYPE_ACTIVATE 1

#define TPM_EK_TYPE_AUTH 2

#define TPM_ENCRYPT_ERROR 32

#define TPM_ES_NONE 1

#define TPM_ES_RSAESOAEP_SHA1_MGF1 3

#define TPM_ES_RSAESPKCSv15 2

#define TPM_ES_SYM_CNT 4

#define TPM_ES_SYM_CTR 4

#define TPM_ES_SYM_OFB 5

#define TPM_ET_AES128 6

#define TPM_ET_COUNTER 10

#define TPM_ET_DATA 3

#define TPM_ET_DEL_KEY_BLOB 9

#define TPM_ET_DEL_OWNER_BLOB 7

#define TPM_ET_DEL_ROW 8

#define TPM_ET_KEY 5

#define TPM_ET_KEYHANDLE 1

#define TPM_ET_NV 11

#define TPM_ET_OPERATOR 12

#define TPM_ET_OWNER 2

#define TPM_ET_RESERVED_HANDLE 64

#define TPM_ET_REVOKE 6

#define TPM_ET_SRK 4

#define TPM_ET_XOR 0

#define TPM_FAIL 9

#define TPM_FAILEDSELFTEST 28

#define TPM_FAMILY_ADMIN 3

#define TPM_FAMILY_CREATE 1

#define TPM_FAMILY_ENABLE 2

#define TPM_FAMILY_INVALIDATE 4

#define TPM_FAMILYCOUNT 64

#define TPM_INAPPROPRIATE_ENC 14

#define TPM_INAPPROPRIATE_SIG 39

#define TPM_INSTALL_DISABLED 11

#define TPM_INVALID_AUTHHANDLE 34

#define TPM_INVALID_FAMILY 55

#define TPM_INVALID_KEYHANDLE 12

#define TPM_INVALID_KEYUSAGE 36

#define TPM_INVALID_PCR_INFO 16

#define TPM_INVALID_POSTINIT 38

#define TPM_INVALID_RESOURCE 53

#define TPM_INVALID_STRUCTURE 67

#define TPM_IOERROR 31

#define TPM_KEY_AUTHCHANGE 19

#define TPM_KEY_BIND 20

#define TPM_KEY_CONTROL_OWNER_EVICT 1

#define TPM_KEY_IDENTITY 18

#define TPM_KEY_LEGACY 21

#define TPM_KEY_MIGRATE 22

#define TPM_KEY_NOTSUPPORTED 58

#define TPM_KEY_OWNER_CONTROL 68

#define TPM_KEY_SIGNING 16

#define TPM_KEY_STORAGE 17

#define TPM_KEYNOTFOUND 13

#define TPM_KH_ADMIN 1073741829

#define TPM_KH_EK 1073741830

#define TPM_KH_OPERATOR 1073741828

#define TPM_KH_OWNER 1073741825

#define TPM_KH_REVOKE 1073741826

#define TPM_KH_SRK 1073741824

#define TPM_KH_TRANSPORT 1073741827

#define TPM_LOC_FOUR 16

#define TPM_LOC_ONE 2

#define TPM_LOC_THREE 8

#define TPM_LOC_TWO 4

#define TPM_LOC_ZERO 1

#define TPM_MA_AUTHORITY 95

#define TPM_MA_DESTINATION 93

#define TPM_MA_SOURCE 94

#define TPM_MA_TICKET_SIGNATURE 92

#define TPM_MAX_NV_WRITE_NOOWNER 64

#define TPM_MAXNVWRITES 72

#define TPM_MIGRATEFAIL 15

#define TPM_MIN_COUNTERS 4

#define TPM_MS_MAINT 3

#define TPM_MS_MIGRATE 1

#define TPM_MS_RESTRICT_APPROVE_DOUBLE 5

#define TPM_MS_RESTRICT_MIGRATE 4

#define TPM_MS_REWRAP 2

#define TPM_NEEDS_SELFTEST 2049

#define TPM_NO_ENDORSEMENT 35

#define TPM_NO_NV_PERMISSION 56

#define TPM_NO_WRAP_TRANSPORT 47

#define TPM_NOCONTEXTSPACE 99

#define TPM_NON_FATAL 2048

#define TPM_NOOPERATOR 73

#define TPM_NOSPACE 17

#define TPM_NOSRK 18

#define TPM_NOT_FULLWRITE 70

#define TPM_NOTFIPS 54

#define TPM_NOTLOCAL 51

#define TPM_NOTRESETABLE 50

#define TPM_NOTSEALED_BLOB 19

#define TPM_NUM_DELEGATE_TABLE_ENTRY_MIN 2

#define TPM_NUM_FAMILY_TABLE_ENTRY_MIN 8

#define TPM_NUM_PCR 16

#define TPM_NV_INDEX0 0

#define TPM_NV_INDEX_DIR 268435457

#define TPM_NV_INDEX_EKCert 61440

#define TPM_NV_INDEX_GROUP_RESV_BASE 65536

#define TPM_NV_INDEX_LOCK 4294967295

#define TPM_NV_INDEX_MOBILE_BASE 70656

#define TPM_NV_INDEX_PC_BASE 70144

#define TPM_NV_INDEX_PERIPHERAL_BASE 70912

#define TPM_NV_INDEX_Platform_CC 61443

#define TPM_NV_INDEX_PlatformCert 61442

#define TPM_NV_INDEX_SERVER_BASE 70400

#define TPM_NV_INDEX_TPM_CC 61441

#define TPM_NV_INDEX_TSS_BASE 69888

#define TPM_ORD_ActivateIdentity 122

#define TPM_ORD_AuthorizeMigrationKey 43

#define TPM_ORD_CertifyKey 50

#define TPM_ORD_CertifyKey2 51

#define TPM_ORD_CertifySelfTest 82

#define TPM_ORD_ChangeAuth 12

#define TPM_ORD_ChangeAuthAsymFinish 15

#define TPM_ORD_ChangeAuthAsymStart 14

#define TPM_ORD_ChangeAuthOwner 16

#define TPM_ORD_CMK_ApproveMA 29

#define TPM_ORD_CMK_ConvertMigration 36

#define TPM_ORD_CMK_CreateBlob 27

#define TPM_ORD_CMK_CreateKey 19

#define TPM_ORD_CMK_CreateTicket 18

#define TPM_ORD_CMK_SetRestrictions 28

#define TPM_ORD_ContinueSelfTest 83

#define TPM_ORD_ConvertMigrationBlob 42

#define TPM_ORD_CreateCounter 220

#define TPM_ORD_CreateEndorsementKeyPair 120

#define TPM_ORD_CreateMaintenanceArchive 44

#define TPM_ORD_CreateMigrationBlob 40

#define TPM_ORD_CreateRevocableEK 127

#define TPM_ORD_CreateWrapKey 31

#define TPM_ORD_DAA_JOIN 41

#define TPM_ORD_DAA_SIGN 49

#define TPM_ORD_Delegate_CreateKeyDelegation 212

#define TPM_ORD_Delegate_CreateOwnerDelegation 213

#define TPM_ORD_Delegate_LoadOwnerDelegation 216

#define TPM_ORD_Delegate_Manage 210

#define TPM_ORD_Delegate_ReadTable 219

#define TPM_ORD_Delegate_UpdateVerification 209

#define TPM_ORD_Delegate_VerifyDelegation 214

#define TPM_ORD_DirRead 26

#define TPM_ORD_DirWriteAuth 25

#define TPM_ORD_DisableForceClear 94

#define TPM_ORD_DisableOwnerClear 92

#define TPM_ORD_DisablePubekRead 126

#define TPM_ORD_DSAP 17

#define TPM_ORD_EstablishTransport 230

#define TPM_ORD_EvictKey 34

#define TPM_ORD_ExecuteTransport 231

#define TPM_ORD_Extend 20

#define TPM_ORD_FieldUpgrade 170

#define TPM_ORD_FlushSpecific 186

#define TPM_ORD_ForceClear 93

#define TPM_ORD_GetAuditDigest 133

#define TPM_ORD_GetAuditDigestSigned 134

#define TPM_ORD_GetAuditEvent 130

#define TPM_ORD_GetAuditEventSigned 131

#define TPM_ORD_GetCapability 101

#define TPM_ORD_GetCapabilityOwner 102

#define TPM_ORD_GetCapabilitySigned 100

#define TPM_ORD_GetOrdinalAuditStatus 140

#define TPM_ORD_GetPubKey 33

#define TPM_ORD_GetRandom 70

#define TPM_ORD_GetTestResult 84

#define TPM_ORD_GetTicks 241

#define TPM_ORD_IncrementCounter 221

#define TPM_ORD_Init 151

#define TPM_ORD_KeyControlOwner 35

#define TPM_ORD_KillMaintenanceFeature 46

#define TPM_ORD_LoadAuthContext 183

#define TPM_ORD_LoadContext 185

#define TPM_ORD_LoadKey 32

#define TPM_ORD_LoadKey2 65

#define TPM_ORD_LoadKeyContext 181

#define TPM_ORD_LoadMaintenanceArchive 45

#define TPM_ORD_LoadManuMaintPub 47

#define TPM_ORD_MakeIdentity 121

#define TPM_ORD_MigrateKey 37

#define TPM_ORD_NV_DefineSpace 204

#define TPM_ORD_NV_ReadValue 207

#define TPM_ORD_NV_ReadValueAuth 208

#define TPM_ORD_NV_WriteValue 205

#define TPM_ORD_NV_WriteValueAuth 206

#define TPM_ORD_OIAP 10

#define TPM_ORD_OSAP 11

#define TPM_ORD_OwnerClear 91

#define TPM_ORD_OwnerReadInternalPub 129

#define TPM_ORD_OwnerReadPubek 125

#define TPM_ORD_OwnerSetDisable 110

#define TPM_ORD_PCR_Reset 200

#define TPM_ORD_PcrRead 21

#define TPM_ORD_PhysicalDisable 112

#define TPM_ORD_PhysicalEnable 111

#define TPM_ORD_PhysicalSetDeactivated 114

#define TPM_ORD_Quote 22

#define TPM_ORD_Quote2 62

#define TPM_ORD_ReadCounter 222

#define TPM_ORD_ReadManuMaintPub 48

#define TPM_ORD_ReadPubek 124

#define TPM_ORD_ReleaseCounter 223

#define TPM_ORD_ReleaseCounterOwner 224

#define TPM_ORD_ReleaseTransportSigned 232

#define TPM_ORD_Reset 90

#define TPM_ORD_ResetLockValue 64

#define TPM_ORD_RevokeTrust 128

#define TPM_ORD_SaveAuthContext 182

#define TPM_ORD_SaveContext 184

#define TPM_ORD_SaveKeyContext 180

#define TPM_ORD_SaveState 152

#define TPM_ORD_Seal 23

#define TPM_ORD_Sealx 61

#define TPM_ORD_SelfTestFull 80

#define TPM_ORD_SetCapability 63

#define TPM_ORD_SetOperatorAuth 116

#define TPM_ORD_SetOrdinalAuditStatus 141

#define TPM_ORD_SetOwnerInstall 113

#define TPM_ORD_SetOwnerPointer 117

#define TPM_ORD_SetRedirection 154

#define TPM_ORD_SetTempDeactivated 115

#define TPM_ORD_SHA1Complete 162

#define TPM_ORD_SHA1CompleteExtend 163

#define TPM_ORD_SHA1Start 160

#define TPM_ORD_SHA1Update 161

#define TPM_ORD_Sign 60

#define TPM_ORD_Startup 153

#define TPM_ORD_StirRandom 71

#define TPM_ORD_TakeOwnership 13

#define TPM_ORD_Terminate_Handle 150

#define TPM_ORD_TickStampBlob 242

#define TPM_ORD_UnBind 30

#define TPM_ORD_Unseal 24

#define TPM_OWNER_CONTROL 79

#define TPM_OWNER_SET 20

#define TPM_PD_AUDITMONOTONICCOUNTER 11

#define TPM_PD_AUTHDIR 15

#define TPM_PD_CONTEXTKEY 10

#define TPM_PD_DAAPROOF 25

#define TPM_PD_DELEGATEKEY 9

#define TPM_PD_EKRESET 19

#define TPM_PD_ENDORSEMENTKEY 7

#define TPM_PD_FAMILYTABLE 17

#define TPM_PD_LASTFAMILYID 21

#define TPM_PD_MANUMAINTPUB 6

#define TPM_PD_MAXNVBUFSIZE 20

#define TPM_PD_MONOTONICCOUNTER 12

#define TPM_PD_NOOWNERNVWRITE 22

#define TPM_PD_OPERATORAUTH 5

#define TPM_PD_ORDINALAUDITSTATUS 14

#define TPM_PD_OWNERAUTH 4

#define TPM_PD_PCRATTRIB 13

#define TPM_PD_RESTRICTDELEGATE 23

#define TPM_PD_REVMAJOR 1

#define TPM_PD_REVMINOR 2

#define TPM_PD_RNGSTATE 16

#define TPM_PD_SRK 8

#define TPM_PD_TPMDAASEED 24

#define TPM_PD_TPMPROOF 3

#define TPM_PER_NOWRITE 63

#define TPM_PERMANENTEK 97

#define TPM_PF_ALLOWMAINTENANCE 6

#define TPM_PF_CEKPUSED 10

#define TPM_PF_DEACTIVATED 3

#define TPM_PF_DISABLE 1

#define TPM_PF_DISABLEFULLDALOGICINFO 20

#define TPM_PF_DISABLEOWNERCLEAR 5

#define TPM_PF_ENABLEREVOKEEK 15

#define TPM_PF_FIPS 13

#define TPM_PF_MAINTENANCEDONE 19

#define TPM_PF_NV_LOCKED 16

#define TPM_PF_OPERATOR 14

#define TPM_PF_OWNERSHIP 2

#define TPM_PF_PHYSICALPRESENCECMDENABLE 9

#define TPM_PF_PHYSICALPRESENCEHWENABLE 8

#define TPM_PF_PHYSICALPRESENCELIFETIMELOCK 7

#define TPM_PF_READPUBEK 4

#define TPM_PF_READSRKPUB 17

#define TPM_PF_TPMESTABLISHED 18

#define TPM_PF_TPMPOST 11

#define TPM_PF_TPMPOSTLOCK 12

#define TPM_PHYSICAL_PRESENCE_CMD_DISABLE 256

#define TPM_PHYSICAL_PRESENCE_CMD_ENABLE 32

#define TPM_PHYSICAL_PRESENCE_HW_DISABLE 512

#define TPM_PHYSICAL_PRESENCE_HW_ENABLE 64

#define TPM_PHYSICAL_PRESENCE_LIFETIME_LOCK 128

#define TPM_PHYSICAL_PRESENCE_LOCK 4

#define TPM_PHYSICAL_PRESENCE_NOTPRESENT 16

#define TPM_PHYSICAL_PRESENCE_PRESENT 8

#define TPM_PID_ADCP 4

#define TPM_PID_ADIP 3

#define TPM_PID_DSAP 6

#define TPM_PID_OIAP 1

#define TPM_PID_OSAP 2

#define TPM_PID_OWNER 5

#define TPM_PID_TRANSPORT 7

#define TPM_PS_Mobile_12 5

#define TPM_PS_PC_11 1

#define TPM_PS_PC_12 2

#define TPM_PS_PDA_12 3

#define TPM_PS_Server_12 4

#define TPM_PT_ASYM 1

#define TPM_PT_BIND 2

#define TPM_PT_CMK_MIGRATE 8

#define TPM_PT_MAINT 4

#define TPM_PT_MIGRATE 3

#define TPM_PT_MIGRATE_EXTERNAL 7

#define TPM_PT_MIGRATE_RESTRICTED 6

#define TPM_PT_SEAL 5

#define TPM_PT_VENDOR_SPECIFIC 128

#define TPM_READ_ONLY 62

#define TPM_REDIR_GPIO 1

#define TPM_REQUIRES_SIGN 57

#define TPM_RESOURCEMISSING 74

#define TPM_RESOURCES 21

#define TPM_RETRY 2048

#define TPM_RT_AUTH 2

#define TPM_RT_CONTEXT 5

#define TPM_RT_COUNTER 6

#define TPM_RT_DAA_TPM 8

#define TPM_RT_DAA_V0 9

#define TPM_RT_DAA_V1 10

#define TPM_RT_DELEGATE 7

#define TPM_RT_HASH 3

#define TPM_RT_KEY 1

#define TPM_RT_TRANS 4

#define TPM_SD_CONTEXTNONCEKEY 1

#define TPM_SD_COUNTID 2

#define TPM_SD_DEFERREDPHYSICALPRESENCE 6

#define TPM_SD_DISABLERESETLOCK 4

#define TPM_SD_OWNERREFERENCE 3

#define TPM_SD_PCR 5

#define TPM_SET_PERM_DATA 2

#define TPM_SET_PERM_FLAGS 1

#define TPM_SET_STANY_DATA 6

#define TPM_SET_STANY_FLAGS 5

#define TPM_SET_STCLEAR_DATA 4

#define TPM_SET_STCLEAR_FLAGS 3

#define TPM_SF_BGLOBALLOCK 5

#define TPM_SF_DEACTIVATED 1

#define TPM_SF_DISABLEFORCECLEAR 2

#define TPM_SF_PHYSICALPRESENCE 3

#define TPM_SF_PHYSICALPRESENCELOCK 4

#define TPM_SHA1_160_HASH_LEN 20

#define TPM_SHA1BASED_NONCE_LEN 20

#define TPM_SHA_ERROR 27

#define TPM_SHA_THREAD 26

#define TPM_SHORTRANDOM 22

#define TPM_SIZE 23

#define TPM_SS_NONE 1

#define TPM_SS_RSASSAPKCS1v15_DER 3

#define TPM_SS_RSASSAPKCS1v15_INFO 4

#define TPM_SS_RSASSAPKCS1v15_SHA1 2

#define TPM_ST_CLEAR 1

#define TPM_ST_DEACTIVATED 3

#define TPM_ST_STATE 2

#define TPM_SUCCESS 0

#define TPM_TAG_AUDIT_EVENT_IN 18

#define TPM_TAG_AUDIT_EVENT_OUT 19

#define TPM_TAG_CAP_VERSION_INFO 48

#define TPM_TAG_CERTIFY_INFO2 41

#define TPM_TAG_CMK_MA_APPROVAL 53

#define TPM_TAG_CMK_MIGAUTH 51

#define TPM_TAG_CMK_SIGTICKET 52

#define TPM_TAG_CONTEXT_SENSITIVE 2

#define TPM_TAG_CONTEXTBLOB 1

#define TPM_TAG_CONTEXTLIST 4

#define TPM_TAG_CONTEXTPOINTER 3

#define TPM_TAG_COUNTER_VALUE 14

#define TPM_TAG_CURRENT_TICKS 20

#define TPM_TAG_DA_ACTION_TYPE 57

#define TPM_TAG_DA_INFO 55

#define TPM_TAG_DA_LIMITED 56

#define TPM_TAG_DAA_BLOB 44

#define TPM_TAG_DAA_CONTEXT 45

#define TPM_TAG_DAA_ENFORCE 46

#define TPM_TAG_DAA_ISSUER 47

#define TPM_TAG_DAA_SENSITIVE 49

#define TPM_TAG_DAA_TPM 50

#define TPM_TAG_DELEGATE_OWNER_BLOB 42

#define TPM_TAG_DELEGATE_PUBLIC 27

#define TPM_TAG_DELEGATE_SENSITIVE 38

#define TPM_TAG_DELEGATE_TABLE_ROW 28

#define TPM_TAG_DELEGATIONS 26

#define TPM_TAG_DELG_KEY_BLOB 39

#define TPM_TAG_EK_BLOB 12

#define TPM_TAG_EK_BLOB_ACTIVATE 43

#define TPM_TAG_EK_BLOB_AUTH 13

#define TPM_TAG_FAMILY_TABLE_ENTRY 37

#define TPM_TAG_KEY 21

#define TPM_TAG_KEY12 40

#define TPM_TAG_NV_ATTRIBUTES 23

#define TPM_TAG_NV_DATA_PUBLIC 24

#define TPM_TAG_NV_DATA_SENSITIVE 25

#define TPM_TAG_PCR_INFO_LONG 6

#define TPM_TAG_PERMANENT_DATA 34

#define TPM_TAG_PERMANENT_FLAGS 31

#define TPM_TAG_PERSISTENT_DATA 9

#define TPM_TAG_PERSISTENT_FLAGS 7

#define TPM_TAG_QUOTE_INFO2 54

#define TPM_TAG_RQU_AUTH1_COMMAND 194

#define TPM_TAG_RQU_AUTH2_COMMAND 195

#define TPM_TAG_RQU_COMMAND 193

#define TPM_TAG_RSP_AUTH1_COMMAND 197

#define TPM_TAG_RSP_AUTH2_COMMAND 198

#define TPM_TAG_RSP_COMMAND 196

#define TPM_TAG_SIGNINFO 5

#define TPM_TAG_STANY_DATA 36

#define TPM_TAG_STANY_FLAGS 33

#define TPM_TAG_STCLEAR_DATA 35

#define TPM_TAG_STCLEAR_FLAGS 32

#define TPM_TAG_STORED_DATA12 22

#define TPM_TAG_SV_DATA 11

#define TPM_TAG_TRANSPORT_AUTH 29

#define TPM_TAG_TRANSPORT_INTERNAL 15

#define TPM_TAG_TRANSPORT_LOG_IN 16

#define TPM_TAG_TRANSPORT_LOG_OUT 17

#define TPM_TAG_TRANSPORT_PUBLIC 30

#define TPM_TAG_VOLATILE_DATA 10

#define TPM_TAG_VOLATILE_FLAGS 8

#define TPM_TOOMANYCONTEXTS 91

#define TPM_TRANSPORT_NOTEXCLUSIVE 78

#define TPM_VENDOR_ERROR 1024

#define TPM_Vendor_Specific32 1024

#define TPM_Vendor_Specific8 128

#define TPM_WRITE_LOCKED 65

#define TPM_WRONG_ENTITYTYPE 37

#define TPM_WRONGPCRVAL 24

#define TSC_ORD_PhysicalPresence 1073741834

#define TSC_ORD_ResetEstablishmentBit 1073741835

typedef struct tdTPM_ASYM_CA_CONTENTS tdTPM_ASYM_CA_CONTENTS, *PtdTPM_ASYM_CA_CONTENTS;

typedef struct tdTPM_SYMMETRIC_KEY tdTPM_SYMMETRIC_KEY, *PtdTPM_SYMMETRIC_KEY;

typedef struct tdTPM_SYMMETRIC_KEY TPM_SYMMETRIC_KEY;

typedef struct tdTPM_DIGEST tdTPM_DIGEST, *PtdTPM_DIGEST;

typedef struct tdTPM_DIGEST TPM_DIGEST;

typedef UINT32 TPM_ALGORITHM_ID;

typedef UINT16 TPM_ENC_SCHEME;

struct tdTPM_DIGEST {
    UINT8 digest[20];
};

struct tdTPM_SYMMETRIC_KEY {
    TPM_ALGORITHM_ID algId;
    TPM_ENC_SCHEME encScheme;
    UINT16 dataSize;
    UINT8 *data;
};

struct tdTPM_ASYM_CA_CONTENTS {
    TPM_SYMMETRIC_KEY sessionKey;
    TPM_DIGEST idDigest;
};

typedef struct tdTPM_AUDIT_EVENT_IN tdTPM_AUDIT_EVENT_IN, *PtdTPM_AUDIT_EVENT_IN;

typedef UINT16 TPM_STRUCTURE_TAG;

typedef struct tdTPM_COUNTER_VALUE tdTPM_COUNTER_VALUE, *PtdTPM_COUNTER_VALUE;

typedef struct tdTPM_COUNTER_VALUE TPM_COUNTER_VALUE;

typedef UINT32 TPM_ACTUAL_COUNT;

struct tdTPM_COUNTER_VALUE {
    TPM_STRUCTURE_TAG tag;
    UINT8 label[4];
    TPM_ACTUAL_COUNT counter;
};

struct tdTPM_AUDIT_EVENT_IN {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST inputParms;
    TPM_COUNTER_VALUE auditCount;
};

typedef struct tdTPM_AUDIT_EVENT_OUT tdTPM_AUDIT_EVENT_OUT, *PtdTPM_AUDIT_EVENT_OUT;

typedef UINT32 TPM_COMMAND_CODE;

typedef UINT32 TPM_RESULT;

struct tdTPM_AUDIT_EVENT_OUT {
    TPM_STRUCTURE_TAG tag;
    TPM_COMMAND_CODE ordinal;
    TPM_DIGEST outputParms;
    TPM_COUNTER_VALUE auditCount;
    TPM_RESULT returnCode;
};

typedef UINT8 tdTPM_AUTHDATA[20];

typedef struct tdTPM_BOUND_DATA tdTPM_BOUND_DATA, *PtdTPM_BOUND_DATA;

typedef struct tdTPM_STRUCT_VER tdTPM_STRUCT_VER, *PtdTPM_STRUCT_VER;

typedef struct tdTPM_STRUCT_VER TPM_STRUCT_VER;

typedef UINT8 TPM_PAYLOAD_TYPE;

struct tdTPM_STRUCT_VER {
    UINT8 major;
    UINT8 minor;
    UINT8 revMajor;
    UINT8 revMinor;
};

struct tdTPM_BOUND_DATA {
    TPM_STRUCT_VER ver;
    TPM_PAYLOAD_TYPE payload;
    UINT8 payloadData[1];
};

typedef struct tdTPM_CAP_VERSION_INFO tdTPM_CAP_VERSION_INFO, *PtdTPM_CAP_VERSION_INFO;

typedef struct tdTPM_VERSION tdTPM_VERSION, *PtdTPM_VERSION;

typedef struct tdTPM_VERSION TPM_VERSION;

typedef UINT8 TPM_VERSION_BYTE;

struct tdTPM_VERSION {
    TPM_VERSION_BYTE major;
    TPM_VERSION_BYTE minor;
    UINT8 revMajor;
    UINT8 revMinor;
};

struct tdTPM_CAP_VERSION_INFO {
    TPM_STRUCTURE_TAG tag;
    TPM_VERSION version;
    UINT16 specLevel;
    UINT8 errataRev;
    UINT8 tpmVendorID[4];
    UINT16 vendorSpecificSize;
    UINT8 *vendorSpecific;
};

typedef struct tdTPM_CERTIFY_INFO tdTPM_CERTIFY_INFO, *PtdTPM_CERTIFY_INFO;

typedef UINT16 TPM_KEY_USAGE;

typedef UINT32 TPM_KEY_FLAGS;

typedef UINT8 TPM_AUTH_DATA_USAGE;

typedef struct tdTPM_KEY_PARMS tdTPM_KEY_PARMS, *PtdTPM_KEY_PARMS;

typedef struct tdTPM_KEY_PARMS TPM_KEY_PARMS;

typedef struct tdTPM_NONCE tdTPM_NONCE, *PtdTPM_NONCE;

typedef struct tdTPM_NONCE TPM_NONCE;

typedef UINT16 TPM_SIG_SCHEME;

struct tdTPM_NONCE {
    UINT8 nonce[20];
};

struct tdTPM_KEY_PARMS {
    TPM_ALGORITHM_ID algorithmID;
    TPM_ENC_SCHEME encScheme;
    TPM_SIG_SCHEME sigScheme;
    UINT32 parmSize;
    UINT8 *parms;
};

struct tdTPM_CERTIFY_INFO {
    TPM_STRUCT_VER version;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    TPM_DIGEST pubkeyDigest;
    TPM_NONCE data;
    BOOLEAN parentPCRStatus;
    UINT32 PCRInfoSize;
    UINT8 *PCRInfo;
};

typedef struct tdTPM_CERTIFY_INFO2 tdTPM_CERTIFY_INFO2, *PtdTPM_CERTIFY_INFO2;

struct tdTPM_CERTIFY_INFO2 {
    TPM_STRUCTURE_TAG tag;
    UINT8 fill;
    TPM_PAYLOAD_TYPE payloadType;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    TPM_DIGEST pubkeyDigest;
    TPM_NONCE data;
    BOOLEAN parentPCRStatus;
    UINT32 PCRInfoSize;
    UINT8 *PCRInfo;
    UINT32 migrationAuthoritySize;
    UINT8 *migrationAuthority;
};

typedef struct tdTPM_CHANGEAUTH_VALIDATE tdTPM_CHANGEAUTH_VALIDATE, *PtdTPM_CHANGEAUTH_VALIDATE;

typedef tdTPM_AUTHDATA TPM_AUTHDATA;

typedef TPM_AUTHDATA TPM_SECRET;

struct tdTPM_CHANGEAUTH_VALIDATE {
    TPM_SECRET newAuthSecret;
    TPM_NONCE n1;
};

typedef struct tdTPM_CMK_AUTH tdTPM_CMK_AUTH, *PtdTPM_CMK_AUTH;

struct tdTPM_CMK_AUTH {
    TPM_DIGEST migrationAuthorityDigest;
    TPM_DIGEST destinationKeyDigest;
    TPM_DIGEST sourceKeyDigest;
};

typedef struct tdTPM_CMK_MA_APPROVAL tdTPM_CMK_MA_APPROVAL, *PtdTPM_CMK_MA_APPROVAL;

struct tdTPM_CMK_MA_APPROVAL {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST migrationAuthorityDigest;
};

typedef struct tdTPM_CMK_MIGAUTH tdTPM_CMK_MIGAUTH, *PtdTPM_CMK_MIGAUTH;

struct tdTPM_CMK_MIGAUTH {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST msaDigest;
    TPM_DIGEST pubKeyDigest;
};

typedef struct tdTPM_CMK_SIGTICKET tdTPM_CMK_SIGTICKET, *PtdTPM_CMK_SIGTICKET;

struct tdTPM_CMK_SIGTICKET {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST verKeyDigest;
    TPM_DIGEST signedData;
};

typedef struct tdTPM_CONTEXT_BLOB tdTPM_CONTEXT_BLOB, *PtdTPM_CONTEXT_BLOB;

typedef UINT32 TPM_RESOURCE_TYPE;

typedef UINT32 TPM_HANDLE;

struct tdTPM_CONTEXT_BLOB {
    TPM_STRUCTURE_TAG tag;
    TPM_RESOURCE_TYPE resourceType;
    TPM_HANDLE handle;
    UINT8 label[16];
    UINT32 contextCount;
    TPM_DIGEST integrityDigest;
    UINT32 additionalSize;
    UINT8 *additionalData;
    UINT32 sensitiveSize;
    UINT8 *sensitiveData;
};

typedef struct tdTPM_CONTEXT_SENSITIVE tdTPM_CONTEXT_SENSITIVE, *PtdTPM_CONTEXT_SENSITIVE;

struct tdTPM_CONTEXT_SENSITIVE {
    TPM_STRUCTURE_TAG tag;
    TPM_NONCE contextNonce;
    UINT32 internalSize;
    UINT8 *internalData;
};

typedef struct tdTPM_CURRENT_TICKS tdTPM_CURRENT_TICKS, *PtdTPM_CURRENT_TICKS;

struct tdTPM_CURRENT_TICKS {
    TPM_STRUCTURE_TAG tag;
    UINT64 currentTicks;
    UINT16 tickRate;
    TPM_NONCE tickNonce;
};

typedef struct tdTPM_DA_ACTION_TYPE tdTPM_DA_ACTION_TYPE, *PtdTPM_DA_ACTION_TYPE;

struct tdTPM_DA_ACTION_TYPE {
    TPM_STRUCTURE_TAG tag;
    UINT32 actions;
};

typedef struct tdTPM_DA_INFO tdTPM_DA_INFO, *PtdTPM_DA_INFO;

typedef UINT8 TPM_DA_STATE;

typedef struct tdTPM_DA_ACTION_TYPE TPM_DA_ACTION_TYPE;

struct tdTPM_DA_INFO {
    TPM_STRUCTURE_TAG tag;
    TPM_DA_STATE state;
    UINT16 currentCount;
    UINT16 thresholdCount;
    TPM_DA_ACTION_TYPE actionAtThreshold;
    UINT32 actionDependValue;
    UINT32 vendorDataSize;
    UINT8 *vendorData;
};

typedef struct tdTPM_DA_INFO_LIMITED tdTPM_DA_INFO_LIMITED, *PtdTPM_DA_INFO_LIMITED;

struct tdTPM_DA_INFO_LIMITED {
    TPM_STRUCTURE_TAG tag;
    TPM_DA_STATE state;
    TPM_DA_ACTION_TYPE actionAtThreshold;
    UINT32 vendorDataSize;
    UINT8 *vendorData;
};

typedef struct tdTPM_DAA_BLOB tdTPM_DAA_BLOB, *PtdTPM_DAA_BLOB;

struct tdTPM_DAA_BLOB {
    TPM_STRUCTURE_TAG tag;
    TPM_RESOURCE_TYPE resourceType;
    UINT8 label[16];
    TPM_DIGEST blobIntegrity;
    UINT32 additionalSize;
    UINT8 *additionalData;
    UINT32 sensitiveSize;
    UINT8 *sensitiveData;
};

typedef struct tdTPM_DAA_CONTEXT tdTPM_DAA_CONTEXT, *PtdTPM_DAA_CONTEXT;

typedef TPM_NONCE TPM_DAA_CONTEXT_SEED;

struct tdTPM_DAA_CONTEXT {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST DAA_digestContext;
    TPM_DIGEST DAA_digest;
    TPM_DAA_CONTEXT_SEED DAA_contextSeed;
    UINT8 DAA_scratch[256];
    UINT8 DAA_stage;
};

typedef struct tdTPM_DAA_ISSUER tdTPM_DAA_ISSUER, *PtdTPM_DAA_ISSUER;

struct tdTPM_DAA_ISSUER {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST DAA_digest_R0;
    TPM_DIGEST DAA_digest_R1;
    TPM_DIGEST DAA_digest_S0;
    TPM_DIGEST DAA_digest_S1;
    TPM_DIGEST DAA_digest_n;
    TPM_DIGEST DAA_digest_gamma;
    UINT8 DAA_generic_q[26];
};

typedef struct tdTPM_DAA_JOINDATA tdTPM_DAA_JOINDATA, *PtdTPM_DAA_JOINDATA;

struct tdTPM_DAA_JOINDATA {
    UINT8 DAA_join_u0[128];
    UINT8 DAA_join_u1[138];
    TPM_DIGEST DAA_digest_n0;
};

typedef struct tdTPM_DAA_SENSITIVE tdTPM_DAA_SENSITIVE, *PtdTPM_DAA_SENSITIVE;

struct tdTPM_DAA_SENSITIVE {
    TPM_STRUCTURE_TAG tag;
    UINT32 internalSize;
    UINT8 *internalData;
};

typedef struct tdTPM_DAA_TPM tdTPM_DAA_TPM, *PtdTPM_DAA_TPM;

struct tdTPM_DAA_TPM {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST DAA_digestIssuer;
    TPM_DIGEST DAA_digest_v0;
    TPM_DIGEST DAA_digest_v1;
    TPM_DIGEST DAA_rekey;
    UINT32 DAA_count;
};

typedef struct tdTPM_DELEGATE_KEY_BLOB tdTPM_DELEGATE_KEY_BLOB, *PtdTPM_DELEGATE_KEY_BLOB;

typedef struct tdTPM_DELEGATE_PUBLIC tdTPM_DELEGATE_PUBLIC, *PtdTPM_DELEGATE_PUBLIC;

typedef struct tdTPM_DELEGATE_PUBLIC TPM_DELEGATE_PUBLIC;

typedef struct tdTPM_DELEGATE_LABEL tdTPM_DELEGATE_LABEL, *PtdTPM_DELEGATE_LABEL;

typedef struct tdTPM_DELEGATE_LABEL TPM_DELEGATE_LABEL;

typedef struct tdTPM_PCR_INFO_SHORT tdTPM_PCR_INFO_SHORT, *PtdTPM_PCR_INFO_SHORT;

typedef struct tdTPM_PCR_INFO_SHORT TPM_PCR_INFO_SHORT;

typedef struct tdTPM_DELEGATIONS tdTPM_DELEGATIONS, *PtdTPM_DELEGATIONS;

typedef struct tdTPM_DELEGATIONS TPM_DELEGATIONS;

typedef UINT32 TPM_FAMILY_ID;

typedef UINT32 TPM_FAMILY_VERIFICATION;

typedef struct tdTPM_PCR_SELECTION tdTPM_PCR_SELECTION, *PtdTPM_PCR_SELECTION;

typedef struct tdTPM_PCR_SELECTION TPM_PCR_SELECTION;

typedef UINT8 TPM_LOCALITY_SELECTION;

typedef TPM_DIGEST TPM_COMPOSITE_HASH;

struct tdTPM_DELEGATE_LABEL {
    UINT8 label;
};

struct tdTPM_PCR_SELECTION {
    UINT16 sizeOfSelect;
    UINT8 pcrSelect[1];
};

struct tdTPM_PCR_INFO_SHORT {
    TPM_PCR_SELECTION pcrSelection;
    TPM_LOCALITY_SELECTION localityAtRelease;
    TPM_COMPOSITE_HASH digestAtRelease;
};

struct tdTPM_DELEGATIONS {
    TPM_STRUCTURE_TAG tag;
    UINT32 delegateType;
    UINT32 per1;
    UINT32 per2;
};

struct tdTPM_DELEGATE_PUBLIC {
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_LABEL label;
    TPM_PCR_INFO_SHORT pcrInfo;
    TPM_DELEGATIONS permissions;
    TPM_FAMILY_ID familyID;
    TPM_FAMILY_VERIFICATION verificationCount;
};

struct tdTPM_DELEGATE_KEY_BLOB {
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_PUBLIC pub;
    TPM_DIGEST integrityDigest;
    TPM_DIGEST pubKeyDigest;
    UINT32 additionalSize;
    UINT8 *additionalArea;
    UINT32 sensitiveSize;
    UINT8 *sensitiveArea;
};

typedef struct tdTPM_DELEGATE_OWNER_BLOB tdTPM_DELEGATE_OWNER_BLOB, *PtdTPM_DELEGATE_OWNER_BLOB;

struct tdTPM_DELEGATE_OWNER_BLOB {
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_PUBLIC pub;
    TPM_DIGEST integrityDigest;
    UINT32 additionalSize;
    UINT8 *additionalArea;
    UINT32 sensitiveSize;
    UINT8 *sensitiveArea;
};

typedef struct tdTPM_DELEGATE_SENSITIVE tdTPM_DELEGATE_SENSITIVE, *PtdTPM_DELEGATE_SENSITIVE;

struct tdTPM_DELEGATE_SENSITIVE {
    TPM_STRUCTURE_TAG tag;
    TPM_SECRET authValue;
};

typedef struct tdTPM_DELEGATE_TABLE tdTPM_DELEGATE_TABLE, *PtdTPM_DELEGATE_TABLE;

typedef struct tdTPM_DELEGATE_TABLE_ROW tdTPM_DELEGATE_TABLE_ROW, *PtdTPM_DELEGATE_TABLE_ROW;

typedef struct tdTPM_DELEGATE_TABLE_ROW TPM_DELEGATE_TABLE_ROW;

struct tdTPM_DELEGATE_TABLE_ROW {
    TPM_STRUCTURE_TAG tag;
    TPM_DELEGATE_PUBLIC pub;
    TPM_SECRET authValue;
};

struct tdTPM_DELEGATE_TABLE {
    TPM_DELEGATE_TABLE_ROW delRow[2];
};

typedef struct tdTPM_EK_BLOB tdTPM_EK_BLOB, *PtdTPM_EK_BLOB;

typedef UINT16 TPM_EK_TYPE;

struct tdTPM_EK_BLOB {
    TPM_STRUCTURE_TAG tag;
    TPM_EK_TYPE ekType;
    UINT32 blobSize;
    UINT8 *blob;
};

typedef struct tdTPM_EK_BLOB_ACTIVATE tdTPM_EK_BLOB_ACTIVATE, *PtdTPM_EK_BLOB_ACTIVATE;

struct tdTPM_EK_BLOB_ACTIVATE {
    TPM_STRUCTURE_TAG tag;
    TPM_SYMMETRIC_KEY sessionKey;
    TPM_DIGEST idDigest;
    TPM_PCR_INFO_SHORT pcrInfo;
};

typedef struct tdTPM_EK_BLOB_AUTH tdTPM_EK_BLOB_AUTH, *PtdTPM_EK_BLOB_AUTH;

struct tdTPM_EK_BLOB_AUTH {
    TPM_STRUCTURE_TAG tag;
    TPM_SECRET authValue;
};

typedef struct tdTPM_FAMILY_LABEL tdTPM_FAMILY_LABEL, *PtdTPM_FAMILY_LABEL;

struct tdTPM_FAMILY_LABEL {
    UINT8 label;
};

typedef struct tdTPM_FAMILY_TABLE tdTPM_FAMILY_TABLE, *PtdTPM_FAMILY_TABLE;

typedef struct tdTPM_FAMILY_TABLE_ENTRY tdTPM_FAMILY_TABLE_ENTRY, *PtdTPM_FAMILY_TABLE_ENTRY;

typedef struct tdTPM_FAMILY_TABLE_ENTRY TPM_FAMILY_TABLE_ENTRY;

typedef struct tdTPM_FAMILY_LABEL TPM_FAMILY_LABEL;

typedef UINT32 TPM_FAMILY_FLAGS;

struct tdTPM_FAMILY_TABLE_ENTRY {
    TPM_STRUCTURE_TAG tag;
    TPM_FAMILY_LABEL label;
    TPM_FAMILY_ID familyID;
    TPM_FAMILY_VERIFICATION verificationCount;
    TPM_FAMILY_FLAGS flags;
};

struct tdTPM_FAMILY_TABLE {
    TPM_FAMILY_TABLE_ENTRY famTableRow[8];
};

typedef struct tdTPM_IDENTITY_CONTENTS tdTPM_IDENTITY_CONTENTS, *PtdTPM_IDENTITY_CONTENTS;

typedef TPM_DIGEST TPM_CHOSENID_HASH;

typedef struct tdTPM_PUBKEY tdTPM_PUBKEY, *PtdTPM_PUBKEY;

typedef struct tdTPM_PUBKEY TPM_PUBKEY;

typedef struct tdTPM_STORE_PUBKEY tdTPM_STORE_PUBKEY, *PtdTPM_STORE_PUBKEY;

typedef struct tdTPM_STORE_PUBKEY TPM_STORE_PUBKEY;

struct tdTPM_STORE_PUBKEY {
    UINT32 keyLength;
    UINT8 key[1];
};

struct tdTPM_PUBKEY {
    TPM_KEY_PARMS algorithmParms;
    TPM_STORE_PUBKEY pubKey;
};

struct tdTPM_IDENTITY_CONTENTS {
    TPM_STRUCT_VER ver;
    UINT32 ordinal;
    TPM_CHOSENID_HASH labelPrivCADigest;
    TPM_PUBKEY identityPubKey;
};

typedef struct tdTPM_IDENTITY_PROOF tdTPM_IDENTITY_PROOF, *PtdTPM_IDENTITY_PROOF;

struct tdTPM_IDENTITY_PROOF {
    TPM_STRUCT_VER ver;
    UINT32 labelSize;
    UINT32 identityBindingSize;
    UINT32 endorsementSize;
    UINT32 platformSize;
    UINT32 conformanceSize;
    TPM_PUBKEY identityKey;
    UINT8 *labelArea;
    UINT8 *identityBinding;
    UINT8 *endorsementCredential;
    UINT8 *platformCredential;
    UINT8 *conformanceCredential;
};

typedef struct tdTPM_IDENTITY_REQ tdTPM_IDENTITY_REQ, *PtdTPM_IDENTITY_REQ;

struct tdTPM_IDENTITY_REQ {
    UINT32 asymSize;
    UINT32 symSize;
    TPM_KEY_PARMS asymAlgorithm;
    TPM_KEY_PARMS symAlgorithm;
    UINT8 *asymBlob;
    UINT8 *symBlob;
};

typedef struct tdTPM_KEY tdTPM_KEY, *PtdTPM_KEY;

struct tdTPM_KEY {
    TPM_STRUCT_VER ver;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    UINT32 PCRInfoSize;
    UINT8 *PCRInfo;
    TPM_STORE_PUBKEY pubKey;
    UINT32 encDataSize;
    UINT8 *encData;
};

typedef struct tdTPM_KEY12 tdTPM_KEY12, *PtdTPM_KEY12;

struct tdTPM_KEY12 {
    TPM_STRUCTURE_TAG tag;
    UINT16 fill;
    TPM_KEY_USAGE keyUsage;
    TPM_KEY_FLAGS keyFlags;
    TPM_AUTH_DATA_USAGE authDataUsage;
    TPM_KEY_PARMS algorithmParms;
    UINT32 PCRInfoSize;
    UINT8 *PCRInfo;
    TPM_STORE_PUBKEY pubKey;
    UINT32 encDataSize;
    UINT8 *encData;
};

typedef enum tdTPM_KEY_FLAGS {
    redirection=1,
    migratable=2,
    isVolatile=4,
    pcrIgnoredOnRead=8,
    migrateAuthority=16
} tdTPM_KEY_FLAGS;

typedef struct tdTPM_KEY_HANDLE_LIST tdTPM_KEY_HANDLE_LIST, *PtdTPM_KEY_HANDLE_LIST;

typedef UINT32 TPM_KEY_HANDLE;

struct tdTPM_KEY_HANDLE_LIST {
    UINT16 loaded;
    TPM_KEY_HANDLE handle[1];
};

typedef struct tdTPM_MIGRATE_ASYMKEY tdTPM_MIGRATE_ASYMKEY, *PtdTPM_MIGRATE_ASYMKEY;

struct tdTPM_MIGRATE_ASYMKEY {
    TPM_PAYLOAD_TYPE payload;
    TPM_SECRET usageAuth;
    TPM_DIGEST pubDataDigest;
    UINT32 partPrivKeyLen;
    UINT8 *partPrivKey;
};

typedef struct tdTPM_MIGRATIONKEYAUTH tdTPM_MIGRATIONKEYAUTH, *PtdTPM_MIGRATIONKEYAUTH;

typedef UINT16 TPM_MIGRATE_SCHEME;

struct tdTPM_MIGRATIONKEYAUTH {
    TPM_PUBKEY migrationKey;
    TPM_MIGRATE_SCHEME migrationScheme;
    TPM_DIGEST digest;
};

typedef struct tdTPM_MSA_COMPOSITE tdTPM_MSA_COMPOSITE, *PtdTPM_MSA_COMPOSITE;

struct tdTPM_MSA_COMPOSITE {
    UINT32 MSAlist;
    TPM_DIGEST migAuthDigest[1];
};

typedef struct tdTPM_NV_ATTRIBUTES tdTPM_NV_ATTRIBUTES, *PtdTPM_NV_ATTRIBUTES;

struct tdTPM_NV_ATTRIBUTES {
    TPM_STRUCTURE_TAG tag;
    UINT32 attributes;
};

typedef struct tdTPM_NV_DATA_PUBLIC tdTPM_NV_DATA_PUBLIC, *PtdTPM_NV_DATA_PUBLIC;

typedef UINT32 TPM_NV_INDEX;

typedef struct tdTPM_NV_ATTRIBUTES TPM_NV_ATTRIBUTES;

struct tdTPM_NV_DATA_PUBLIC {
    TPM_STRUCTURE_TAG tag;
    TPM_NV_INDEX nvIndex;
    TPM_PCR_INFO_SHORT pcrInfoRead;
    TPM_PCR_INFO_SHORT pcrInfoWrite;
    TPM_NV_ATTRIBUTES permission;
    BOOLEAN bReadSTClear;
    BOOLEAN bWriteSTClear;
    BOOLEAN bWriteDefine;
    UINT32 dataSize;
};

typedef struct tdTPM_PCR_ATTRIBUTES tdTPM_PCR_ATTRIBUTES, *PtdTPM_PCR_ATTRIBUTES;

struct tdTPM_PCR_ATTRIBUTES {
    BOOLEAN pcrReset;
    TPM_LOCALITY_SELECTION pcrExtendLocal;
    TPM_LOCALITY_SELECTION pcrResetLocal;
};

typedef struct tdTPM_PCR_COMPOSITE tdTPM_PCR_COMPOSITE, *PtdTPM_PCR_COMPOSITE;

typedef TPM_DIGEST TPM_PCRVALUE;

struct tdTPM_PCR_COMPOSITE {
    TPM_PCR_SELECTION select;
    UINT32 valueSize;
    TPM_PCRVALUE pcrValue[1];
};

typedef struct tdTPM_PCR_INFO tdTPM_PCR_INFO, *PtdTPM_PCR_INFO;

struct tdTPM_PCR_INFO {
    TPM_PCR_SELECTION pcrSelection;
    TPM_COMPOSITE_HASH digestAtRelease;
    TPM_COMPOSITE_HASH digestAtCreation;
};

typedef struct tdTPM_PCR_INFO_LONG tdTPM_PCR_INFO_LONG, *PtdTPM_PCR_INFO_LONG;

struct tdTPM_PCR_INFO_LONG {
    TPM_STRUCTURE_TAG tag;
    TPM_LOCALITY_SELECTION localityAtCreation;
    TPM_LOCALITY_SELECTION localityAtRelease;
    TPM_PCR_SELECTION creationPCRSelection;
    TPM_PCR_SELECTION releasePCRSelection;
    TPM_COMPOSITE_HASH digestAtCreation;
    TPM_COMPOSITE_HASH digestAtRelease;
};

typedef struct tdTPM_PERMANENT_FLAGS tdTPM_PERMANENT_FLAGS, *PtdTPM_PERMANENT_FLAGS;

struct tdTPM_PERMANENT_FLAGS {
    TPM_STRUCTURE_TAG tag;
    BOOLEAN disable;
    BOOLEAN ownership;
    BOOLEAN deactivated;
    BOOLEAN readPubek;
    BOOLEAN disableOwnerClear;
    BOOLEAN allowMaintenance;
    BOOLEAN physicalPresenceLifetimeLock;
    BOOLEAN physicalPresenceHWEnable;
    BOOLEAN physicalPresenceCMDEnable;
    BOOLEAN CEKPUsed;
    BOOLEAN TPMpost;
    BOOLEAN TPMpostLock;
    BOOLEAN FIPS;
    BOOLEAN operator;
    BOOLEAN enableRevokeEK;
    BOOLEAN nvLocked;
    BOOLEAN readSRKPub;
    BOOLEAN tpmEstablished;
    BOOLEAN maintenanceDone;
    BOOLEAN disableFullDALogicInfo;
};

typedef struct tdTPM_QUOTE_INFO tdTPM_QUOTE_INFO, *PtdTPM_QUOTE_INFO;

struct tdTPM_QUOTE_INFO {
    TPM_STRUCT_VER version;
    UINT8 fixed[4];
    TPM_COMPOSITE_HASH digestValue;
    TPM_NONCE externalData;
};

typedef struct tdTPM_QUOTE_INFO2 tdTPM_QUOTE_INFO2, *PtdTPM_QUOTE_INFO2;

struct tdTPM_QUOTE_INFO2 {
    TPM_STRUCTURE_TAG tag;
    UINT8 fixed[4];
    TPM_NONCE externalData;
    TPM_PCR_INFO_SHORT infoShort;
};

typedef struct tdTPM_RQU_COMMAND_HDR tdTPM_RQU_COMMAND_HDR, *PtdTPM_RQU_COMMAND_HDR;

struct tdTPM_RQU_COMMAND_HDR {
    TPM_STRUCTURE_TAG tag;
    UINT32 paramSize;
    TPM_COMMAND_CODE ordinal;
};

typedef struct tdTPM_RSP_COMMAND_HDR tdTPM_RSP_COMMAND_HDR, *PtdTPM_RSP_COMMAND_HDR;

struct tdTPM_RSP_COMMAND_HDR {
    TPM_STRUCTURE_TAG tag;
    UINT32 paramSize;
    TPM_RESULT returnCode;
};

typedef struct tdTPM_SEALED_DATA tdTPM_SEALED_DATA, *PtdTPM_SEALED_DATA;

struct tdTPM_SEALED_DATA {
    TPM_PAYLOAD_TYPE payload;
    TPM_SECRET authData;
    TPM_NONCE tpmProof;
    TPM_DIGEST storedDigest;
    UINT32 dataSize;
    UINT8 *data;
};

typedef struct tdTPM_SELECT_SIZE tdTPM_SELECT_SIZE, *PtdTPM_SELECT_SIZE;

struct tdTPM_SELECT_SIZE {
    UINT8 major;
    UINT8 minor;
    UINT16 reqSize;
};

typedef struct tdTPM_SIGN_INFO tdTPM_SIGN_INFO, *PtdTPM_SIGN_INFO;

struct tdTPM_SIGN_INFO {
    TPM_STRUCTURE_TAG tag;
    UINT8 fixed[4];
    TPM_NONCE replay;
    UINT32 dataLen;
    UINT8 *data;
};

typedef struct tdTPM_STANY_FLAGS tdTPM_STANY_FLAGS, *PtdTPM_STANY_FLAGS;

typedef UINT32 TPM_MODIFIER_INDICATOR;

struct tdTPM_STANY_FLAGS {
    TPM_STRUCTURE_TAG tag;
    BOOLEAN postInitialise;
    TPM_MODIFIER_INDICATOR localityModifier;
    BOOLEAN transportExclusive;
    BOOLEAN TOSPresent;
};

typedef struct tdTPM_STCLEAR_DATA tdTPM_STCLEAR_DATA, *PtdTPM_STCLEAR_DATA;

typedef UINT32 TPM_COUNT_ID;

struct tdTPM_STCLEAR_DATA {
    TPM_STRUCTURE_TAG tag;
    TPM_NONCE contextNonceKey;
    TPM_COUNT_ID countID;
    UINT32 ownerReference;
    BOOLEAN disableResetLock;
    TPM_PCRVALUE PCR[16];
    UINT32 deferredPhysicalPresence;
};

typedef struct tdTPM_STCLEAR_FLAGS tdTPM_STCLEAR_FLAGS, *PtdTPM_STCLEAR_FLAGS;

struct tdTPM_STCLEAR_FLAGS {
    TPM_STRUCTURE_TAG tag;
    BOOLEAN deactivated;
    BOOLEAN disableForceClear;
    BOOLEAN physicalPresence;
    BOOLEAN physicalPresenceLock;
    BOOLEAN bGlobalLock;
};

typedef struct tdTPM_STORE_ASYMKEY tdTPM_STORE_ASYMKEY, *PtdTPM_STORE_ASYMKEY;

typedef struct tdTPM_STORE_PRIVKEY tdTPM_STORE_PRIVKEY, *PtdTPM_STORE_PRIVKEY;

typedef struct tdTPM_STORE_PRIVKEY TPM_STORE_PRIVKEY;

struct tdTPM_STORE_PRIVKEY {
    UINT32 keyLength;
    UINT8 *key;
};

struct tdTPM_STORE_ASYMKEY {
    TPM_PAYLOAD_TYPE payload;
    TPM_SECRET usageAuth;
    TPM_SECRET migrationAuth;
    TPM_DIGEST pubDataDigest;
    TPM_STORE_PRIVKEY privKey;
};

typedef struct tdTPM_STORED_DATA tdTPM_STORED_DATA, *PtdTPM_STORED_DATA;

struct tdTPM_STORED_DATA {
    TPM_STRUCT_VER ver;
    UINT32 sealInfoSize;
    UINT8 *sealInfo;
    UINT32 encDataSize;
    UINT8 *encData;
};

typedef struct tdTPM_STORED_DATA12 tdTPM_STORED_DATA12, *PtdTPM_STORED_DATA12;

typedef UINT16 TPM_ENTITY_TYPE;

struct tdTPM_STORED_DATA12 {
    TPM_STRUCTURE_TAG tag;
    TPM_ENTITY_TYPE et;
    UINT32 sealInfoSize;
    UINT8 *sealInfo;
    UINT32 encDataSize;
    UINT8 *encData;
};

typedef struct tdTPM_SYM_CA_ATTESTATION tdTPM_SYM_CA_ATTESTATION, *PtdTPM_SYM_CA_ATTESTATION;

struct tdTPM_SYM_CA_ATTESTATION {
    UINT32 credSize;
    TPM_KEY_PARMS algorithm;
    UINT8 *credential;
};

typedef struct tdTPM_TRANSPORT_AUTH tdTPM_TRANSPORT_AUTH, *PtdTPM_TRANSPORT_AUTH;

struct tdTPM_TRANSPORT_AUTH {
    TPM_STRUCTURE_TAG tag;
    TPM_AUTHDATA authData;
};

typedef struct tdTPM_TRANSPORT_INTERNAL tdTPM_TRANSPORT_INTERNAL, *PtdTPM_TRANSPORT_INTERNAL;

typedef struct tdTPM_TRANSPORT_PUBLIC tdTPM_TRANSPORT_PUBLIC, *PtdTPM_TRANSPORT_PUBLIC;

typedef struct tdTPM_TRANSPORT_PUBLIC TPM_TRANSPORT_PUBLIC;

typedef UINT32 TPM_TRANSHANDLE;

typedef UINT32 TPM_TRANSPORT_ATTRIBUTES;

struct tdTPM_TRANSPORT_PUBLIC {
    TPM_STRUCTURE_TAG tag;
    TPM_TRANSPORT_ATTRIBUTES transAttributes;
    TPM_ALGORITHM_ID algId;
    TPM_ENC_SCHEME encScheme;
};

struct tdTPM_TRANSPORT_INTERNAL {
    TPM_STRUCTURE_TAG tag;
    TPM_AUTHDATA authData;
    TPM_TRANSPORT_PUBLIC transPublic;
    TPM_TRANSHANDLE transHandle;
    TPM_NONCE transNonceEven;
    TPM_DIGEST transDigest;
};

typedef struct tdTPM_TRANSPORT_LOG_IN tdTPM_TRANSPORT_LOG_IN, *PtdTPM_TRANSPORT_LOG_IN;

struct tdTPM_TRANSPORT_LOG_IN {
    TPM_STRUCTURE_TAG tag;
    TPM_DIGEST parameters;
    TPM_DIGEST pubKeyHash;
};

typedef struct tdTPM_TRANSPORT_LOG_OUT tdTPM_TRANSPORT_LOG_OUT, *PtdTPM_TRANSPORT_LOG_OUT;

typedef struct tdTPM_CURRENT_TICKS TPM_CURRENT_TICKS;

struct tdTPM_TRANSPORT_LOG_OUT {
    TPM_STRUCTURE_TAG tag;
    TPM_CURRENT_TICKS currentTicks;
    TPM_DIGEST parameters;
    TPM_MODIFIER_INDICATOR locality;
};

typedef struct tdTPM_ASYM_CA_CONTENTS TPM_ASYM_CA_CONTENTS;

typedef struct tdTPM_AUDIT_EVENT_IN TPM_AUDIT_EVENT_IN;

typedef struct tdTPM_AUDIT_EVENT_OUT TPM_AUDIT_EVENT_OUT;

typedef TPM_DIGEST TPM_AUDITDIGEST;

typedef UINT32 TPM_AUTHHANDLE;

typedef struct tdTPM_BOUND_DATA TPM_BOUND_DATA;

typedef struct tdTPM_CAP_VERSION_INFO TPM_CAP_VERSION_INFO;

typedef UINT32 TPM_CAPABILITY_AREA;

typedef struct tdTPM_CERTIFY_INFO TPM_CERTIFY_INFO;

typedef struct tdTPM_CERTIFY_INFO2 TPM_CERTIFY_INFO2;

typedef struct tdTPM_CHANGEAUTH_VALIDATE TPM_CHANGEAUTH_VALIDATE;

typedef struct tdTPM_CMK_AUTH TPM_CMK_AUTH;

typedef UINT32 TPM_CMK_DELEGATE;

typedef struct tdTPM_CMK_MA_APPROVAL TPM_CMK_MA_APPROVAL;

typedef struct tdTPM_CMK_MIGAUTH TPM_CMK_MIGAUTH;

typedef struct tdTPM_CMK_SIGTICKET TPM_CMK_SIGTICKET;

typedef struct tdTPM_CONTEXT_BLOB TPM_CONTEXT_BLOB;

typedef struct tdTPM_CONTEXT_SENSITIVE TPM_CONTEXT_SENSITIVE;

typedef struct tdTPM_DA_INFO TPM_DA_INFO;

typedef struct tdTPM_DA_INFO_LIMITED TPM_DA_INFO_LIMITED;

typedef struct tdTPM_DAA_BLOB TPM_DAA_BLOB;

typedef struct tdTPM_DAA_CONTEXT TPM_DAA_CONTEXT;

typedef struct tdTPM_DAA_ISSUER TPM_DAA_ISSUER;

typedef struct tdTPM_DAA_JOINDATA TPM_DAA_JOINDATA;

typedef struct tdTPM_DAA_SENSITIVE TPM_DAA_SENSITIVE;

typedef struct tdTPM_DAA_TPM TPM_DAA_TPM;

typedef TPM_NONCE TPM_DAA_TPM_SEED;

typedef UINT32 TPM_DELEGATE_INDEX;

typedef struct tdTPM_DELEGATE_KEY_BLOB TPM_DELEGATE_KEY_BLOB;

typedef struct tdTPM_DELEGATE_OWNER_BLOB TPM_DELEGATE_OWNER_BLOB;

typedef struct tdTPM_DELEGATE_SENSITIVE TPM_DELEGATE_SENSITIVE;

typedef struct tdTPM_DELEGATE_TABLE TPM_DELEGATE_TABLE;

typedef UINT32 TPM_DIRINDEX;

typedef TPM_DIGEST TPM_DIRVALUE;

typedef struct tdTPM_EK_BLOB TPM_EK_BLOB;

typedef struct tdTPM_EK_BLOB_ACTIVATE TPM_EK_BLOB_ACTIVATE;

typedef struct tdTPM_EK_BLOB_AUTH TPM_EK_BLOB_AUTH;

typedef TPM_AUTHDATA TPM_ENCAUTH;

typedef UINT32 TPM_FAMILY_OPERATION;

typedef struct tdTPM_FAMILY_TABLE TPM_FAMILY_TABLE;

typedef TPM_DIGEST TPM_HMAC;

typedef struct tdTPM_IDENTITY_CONTENTS TPM_IDENTITY_CONTENTS;

typedef struct tdTPM_IDENTITY_PROOF TPM_IDENTITY_PROOF;

typedef struct tdTPM_IDENTITY_REQ TPM_IDENTITY_REQ;

typedef struct tdTPM_KEY TPM_KEY;

typedef struct tdTPM_KEY12 TPM_KEY12;

typedef UINT32 TPM_KEY_CONTROL;

typedef enum tdTPM_KEY_FLAGS TPM_KEY_FLAGS_BITS;

typedef struct tdTPM_KEY_HANDLE_LIST TPM_KEY_HANDLE_LIST;

typedef struct tdTPM_MIGRATE_ASYMKEY TPM_MIGRATE_ASYMKEY;

typedef struct tdTPM_MIGRATIONKEYAUTH TPM_MIGRATIONKEYAUTH;

typedef struct tdTPM_MSA_COMPOSITE TPM_MSA_COMPOSITE;

typedef struct tdTPM_NV_DATA_PUBLIC TPM_NV_DATA_PUBLIC;

typedef struct tdTPM_PCR_ATTRIBUTES TPM_PCR_ATTRIBUTES;

typedef struct tdTPM_PCR_COMPOSITE TPM_PCR_COMPOSITE;

typedef struct tdTPM_PCR_INFO TPM_PCR_INFO;

typedef struct tdTPM_PCR_INFO_LONG TPM_PCR_INFO_LONG;

typedef UINT32 TPM_PCRINDEX;

typedef struct tdTPM_PERMANENT_FLAGS TPM_PERMANENT_FLAGS;

typedef UINT16 TPM_PHYSICAL_PRESENCE;

typedef UINT16 TPM_PLATFORM_SPECIFIC;

typedef UINT16 TPM_PROTOCOL_ID;

typedef struct tdTPM_QUOTE_INFO TPM_QUOTE_INFO;

typedef struct tdTPM_QUOTE_INFO2 TPM_QUOTE_INFO2;

typedef UINT32 TPM_REDIT_COMMAND;

typedef struct tdTPM_RQU_COMMAND_HDR TPM_RQU_COMMAND_HDR;

typedef struct tdTPM_RSP_COMMAND_HDR TPM_RSP_COMMAND_HDR;

typedef struct tdTPM_SEALED_DATA TPM_SEALED_DATA;

typedef struct tdTPM_SELECT_SIZE TPM_SELECT_SIZE;

typedef struct tdTPM_SIGN_INFO TPM_SIGN_INFO;

typedef struct tdTPM_STANY_FLAGS TPM_STANY_FLAGS;

typedef UINT32 TPM_STARTUP_EFFECTS;

typedef UINT16 TPM_STARTUP_TYPE;

typedef struct tdTPM_STCLEAR_DATA TPM_STCLEAR_DATA;

typedef struct tdTPM_STCLEAR_FLAGS TPM_STCLEAR_FLAGS;

typedef struct tdTPM_STORE_ASYMKEY TPM_STORE_ASYMKEY;

typedef struct tdTPM_STORED_DATA TPM_STORED_DATA;

typedef struct tdTPM_STORED_DATA12 TPM_STORED_DATA12;

typedef struct tdTPM_SYM_CA_ATTESTATION TPM_SYM_CA_ATTESTATION;

typedef UINT32 TPM_SYM_MODE;

typedef UINT16 TPM_TAG;

typedef struct tdTPM_TRANSPORT_AUTH TPM_TRANSPORT_AUTH;

typedef struct tdTPM_TRANSPORT_INTERNAL TPM_TRANSPORT_INTERNAL;

typedef struct tdTPM_TRANSPORT_LOG_IN TPM_TRANSPORT_LOG_IN;

typedef struct tdTPM_TRANSPORT_LOG_OUT TPM_TRANSPORT_LOG_OUT;

#define ACTIVE_SESSION_FIRST 50331648

#define ACTIVE_SESSION_LAST 50331711

#define ALG_ID_FIRST 1

#define ALG_ID_LAST 68

#define BUFFER_ALIGNMENT 4

#define CLEAR 0

#define CONTEXT_ENCRYPT_ALG 6

#define CONTEXT_ENCRYPT_KEY_BITS 128

#define CONTEXT_ENCRYPT_KEY_BYTES 16

#define CONTEXT_INTEGRITY_HASH_ALG 11

#define CONTEXT_INTEGRITY_HASH_SIZE 32

#define CRT_FORMAT_RSA 1

#define DRTM_PCR 17

#define HASH_COUNT 5

#define HMAC_SESSION_FIRST 33554432

#define HMAC_SESSION_LAST 33554495

#define HR_HANDLE_MASK 16777215

#define HR_HMAC_SESSION 33554432

#define HR_NV_INDEX 16777216

#define HR_PCR 0

#define HR_PERMANENT 1073741824

#define HR_PERSISTENT 2164260864

#define HR_POLICY_SESSION 50331648

#define HR_RANGE_MASK 4278190080

#define HR_SHIFT 24

#define HR_TRANSIENT 2147483648

#define IMPLEMENTATION_PCR 24

#define LOADED_SESSION_FIRST 33554432

#define LOADED_SESSION_LAST 33554495

#define MAX_ACTIVE_SESSIONS 64

#define MAX_AES_BLOCK_SIZE_BYTES 16

#define MAX_AES_KEY_BITS 128

#define MAX_AES_KEY_BYTES 16

#define MAX_ALG_LIST_SIZE 64

#define MAX_CAP_BUFFER 1024

#define MAX_COMMAND_SIZE 4096

#define MAX_CONTEXT_SIZE 4000

#define MAX_DIGEST_BUFFER 1024

#define MAX_ECC_KEY_BITS 256

#define MAX_ECC_KEY_BYTES 32

#define MAX_HANDLE_NUM 3

#define MAX_LOADED_OBJECTS 3

#define MAX_LOADED_SESSIONS 3

#define MAX_NV_INDEX_SIZE 1024

#define MAX_ORDERLY_COUNT 255

#define MAX_RESPONSE_SIZE 4096

#define MAX_RNG_ENTROPY_SIZE 64

#define MAX_RSA_KEY_BITS 2048

#define MAX_RSA_KEY_BYTES 256

#define MAX_SESSION_NUM 3

#define MAX_SESSION_NUMBER 3

#define MAX_SM4_BLOCK_SIZE_BYTES 16

#define MAX_SM4_KEY_BITS 128

#define MAX_SM4_KEY_BYTES 16

#define MAX_SYM_BLOCK_SIZE 16

#define MAX_SYM_DATA 128

#define MAX_SYM_KEY_BITS 128

#define MAX_SYM_KEY_BYTES 16

#define MIN_EVICT_OBJECTS 2

#define NO 0

#define NUM_AUTHVALUE_PCR_GROUP 1

#define NUM_LOCALITIES 5

#define NUM_POLICY_PCR 1

#define NUM_POLICY_PCR_GROUP 1

#define NUM_STATIC_PCR 16

#define NV_CLOCK_UPDATE_INTERVAL 12

#define NV_INDEX_FIRST 16777216

#define NV_INDEX_LAST 33554431

#define NV_MEMORY_SIZE 16384

#define ORDERLY_BITS 8

#define PCR_FIRST 0

#define PCR_LAST 23

#define PCR_SELECT_MAX 3

#define PCR_SELECT_MIN 3

#define PERMANENT_FIRST 1073741824

#define PERMANENT_LAST 1073741836

#define PERSISTENT_FIRST 2164260864

#define PERSISTENT_LAST 2181038079

#define PLATFORM_PCR 24

#define PLATFORM_PERSISTENT 2172649472

#define POLICY_SESSION_FIRST 50331648

#define POLICY_SESSION_LAST 50331711

#define PRIMARY_SEED_SIZE 32

#define PRIVATE_VENDOR_SPECIFIC_BYTES 640

#define PROOF_SIZE 32

#define PT_FIXED 256

#define PT_GROUP 256

#define PT_VAR 512

#define RAM_INDEX_SPACE 512

#define RC_FMT1 128

#define RC_MAX_FM0 383

#define RC_VER1 256

#define RC_WARN 2304

#define RSA_DEFAULT_PUBLIC_EXPONENT 65537

#define SET 1

#define SHA1_BLOCK_SIZE 64

#define SHA1_DIGEST_SIZE 20

#define SHA256_BLOCK_SIZE 64

#define SHA256_DIGEST_SIZE 32

#define SHA384_BLOCK_SIZE 128

#define SHA384_DIGEST_SIZE 48

#define SHA512_BLOCK_SIZE 128

#define SHA512_DIGEST_SIZE 64

#define SM3_256_BLOCK_SIZE 64

#define SM3_256_DIGEST_SIZE 32

#define TIMER_PRESCALE 100000

#define TPM_ALG_AES 6

#define TPM_ALG_CBC 66

#define TPM_ALG_CFB 67

#define TPM_ALG_CTR 64

#define TPM_ALG_ECB 68

#define TPM_ALG_ECC 35

#define TPM_ALG_ECDAA 26

#define TPM_ALG_ECDH 25

#define TPM_ALG_ECDSA 24

#define TPM_ALG_ECMQV 29

#define TPM_ALG_ECSCHNORR 28

#define TPM_ALG_ERROR 0

#define TPM_ALG_FIRST 1

#define TPM_ALG_KDF1_SP800_108 34

#define TPM_ALG_KDF1_SP800_56a 32

#define TPM_ALG_KDF2 33

#define TPM_ALG_KEYEDHASH 8

#define TPM_ALG_LAST 68

#define TPM_ALG_NULL 16

#define TPM_ALG_OAEP 23

#define TPM_ALG_OFB 65

#define TPM_ALG_RSAES 21

#define TPM_ALG_RSAPSS 22

#define TPM_ALG_RSASSA 20

#define TPM_ALG_SHA1 4

#define TPM_ALG_SHA256 11

#define TPM_ALG_SHA384 12

#define TPM_ALG_SHA512 13

#define TPM_ALG_SM2 27

#define TPM_ALG_SM3_256 18

#define TPM_ALG_SM4 19

#define TPM_ALG_SYMCIPHER 37

#define TPM_CAP_ALGS 0

#define TPM_CAP_AUDIT_COMMANDS 4

#define TPM_CAP_COMMANDS 2

#define TPM_CAP_ECC_CURVES 8

#define TPM_CAP_FIRST 0

#define TPM_CAP_HANDLES 1

#define TPM_CAP_LAST 8

#define TPM_CAP_PCR_PROPERTIES 7

#define TPM_CAP_PCRS 5

#define TPM_CAP_PP_COMMANDS 3

#define TPM_CAP_TPM_PROPERTIES 6

#define TPM_CAP_VENDOR_PROPERTY 256

#define TPM_CC_ActivateCredential 327

#define TPM_CC_Certify 328

#define TPM_CC_CertifyCreation 330

#define TPM_CC_ChangeEPS 292

#define TPM_CC_ChangePPS 293

#define TPM_CC_Clear 294

#define TPM_CC_ClearControl 295

#define TPM_CC_ClockRateAdjust 304

#define TPM_CC_ClockSet 296

#define TPM_CC_Commit 395

#define TPM_CC_ContextLoad 353

#define TPM_CC_ContextSave 354

#define TPM_CC_Create 339

#define TPM_CC_CreatePrimary 305

#define TPM_CC_DictionaryAttackLockReset 313

#define TPM_CC_DictionaryAttackParameters 314

#define TPM_CC_Duplicate 331

#define TPM_CC_EC_Ephemeral 398

#define TPM_CC_ECC_Parameters 376

#define TPM_CC_ECDH_KeyGen 355

#define TPM_CC_ECDH_ZGen 340

#define TPM_CC_EncryptDecrypt 356

#define TPM_CC_EventSequenceComplete 389

#define TPM_CC_EvictControl 288

#define TPM_CC_FieldUpgradeData 321

#define TPM_CC_FieldUpgradeStart 303

#define TPM_CC_FirmwareRead 377

#define TPM_CC_FIRST 287

#define TPM_CC_FlushContext 357

#define TPM_CC_GetCapability 378

#define TPM_CC_GetCommandAuditDigest 307

#define TPM_CC_GetRandom 379

#define TPM_CC_GetSessionAuditDigest 333

#define TPM_CC_GetTestResult 380

#define TPM_CC_GetTime 332

#define TPM_CC_Hash 381

#define TPM_CC_HashSequenceStart 390

#define TPM_CC_HierarchyChangeAuth 297

#define TPM_CC_HierarchyControl 289

#define TPM_CC_HMAC 341

#define TPM_CC_HMAC_Start 347

#define TPM_CC_Import 342

#define TPM_CC_IncrementalSelfTest 322

#define TPM_CC_LAST 398

#define TPM_CC_Load 343

#define TPM_CC_LoadExternal 359

#define TPM_CC_MakeCredential 360

#define TPM_CC_NV_Certify 388

#define TPM_CC_NV_ChangeAuth 315

#define TPM_CC_NV_DefineSpace 298

#define TPM_CC_NV_Extend 310

#define TPM_CC_NV_GlobalWriteLock 306

#define TPM_CC_NV_Increment 308

#define TPM_CC_NV_Read 334

#define TPM_CC_NV_ReadLock 335

#define TPM_CC_NV_ReadPublic 361

#define TPM_CC_NV_SetBits 309

#define TPM_CC_NV_UndefineSpace 290

#define TPM_CC_NV_UndefineSpaceSpecial 287

#define TPM_CC_NV_Write 311

#define TPM_CC_NV_WriteLock 312

#define TPM_CC_ObjectChangeAuth 336

#define TPM_CC_PCR_Allocate 299

#define TPM_CC_PCR_Event 316

#define TPM_CC_PCR_Extend 386

#define TPM_CC_PCR_Read 382

#define TPM_CC_PCR_Reset 317

#define TPM_CC_PCR_SetAuthPolicy 300

#define TPM_CC_PCR_SetAuthValue 387

#define TPM_CC_PolicyAuthorize 362

#define TPM_CC_PolicyAuthValue 363

#define TPM_CC_PolicyCommandCode 364

#define TPM_CC_PolicyCounterTimer 365

#define TPM_CC_PolicyCpHash 366

#define TPM_CC_PolicyDuplicationSelect 392

#define TPM_CC_PolicyGetDigest 393

#define TPM_CC_PolicyLocality 367

#define TPM_CC_PolicyNameHash 368

#define TPM_CC_PolicyNV 329

#define TPM_CC_PolicyOR 369

#define TPM_CC_PolicyPassword 396

#define TPM_CC_PolicyPCR 383

#define TPM_CC_PolicyPhysicalPresence 391

#define TPM_CC_PolicyRestart 384

#define TPM_CC_PolicySecret 337

#define TPM_CC_PolicySigned 352

#define TPM_CC_PolicyTicket 370

#define TPM_CC_PP_Commands 301

#define TPM_CC_PP_FIRST 287

#define TPM_CC_PP_LAST 306

#define TPM_CC_Quote 344

#define TPM_CC_ReadClock 385

#define TPM_CC_ReadPublic 371

#define TPM_CC_Rewrap 338

#define TPM_CC_RSA_Decrypt 345

#define TPM_CC_RSA_Encrypt 372

#define TPM_CC_SelfTest 323

#define TPM_CC_SequenceComplete 318

#define TPM_CC_SequenceUpdate 348

#define TPM_CC_SetAlgorithmSet 319

#define TPM_CC_SetCommandCodeAuditStatus 320

#define TPM_CC_SetPrimaryPolicy 302

#define TPM_CC_Shutdown 325

#define TPM_CC_Sign 349

#define TPM_CC_StartAuthSession 374

#define TPM_CC_Startup 324

#define TPM_CC_StirRandom 326

#define TPM_CC_TestParms 394

#define TPM_CC_Unseal 350

#define TPM_CC_VerifySignature 375

#define TPM_CC_ZGen_2Phase 397

#define TPM_CLOCK_COARSE_FASTER 3

#define TPM_CLOCK_COARSE_SLOWER -3

#define TPM_CLOCK_FINE_FASTER 1

#define TPM_CLOCK_FINE_SLOWER -1

#define TPM_CLOCK_MEDIUM_FASTER 2

#define TPM_CLOCK_MEDIUM_SLOWER -2

#define TPM_CLOCK_NO_CHANGE 0

#define TPM_ECC_BN_P256 16

#define TPM_ECC_BN_P638 17

#define TPM_ECC_NIST_P192 1

#define TPM_ECC_NIST_P224 2

#define TPM_ECC_NIST_P256 3

#define TPM_ECC_NIST_P384 4

#define TPM_ECC_NIST_P521 5

#define TPM_ECC_NONE 0

#define TPM_ECC_SM2_P256 32

#define TPM_EO_BITCLEAR 11

#define TPM_EO_BITSET 10

#define TPM_EO_EQ 0

#define TPM_EO_NEQ 1

#define TPM_EO_SIGNED_GE 6

#define TPM_EO_SIGNED_GT 2

#define TPM_EO_SIGNED_LE 8

#define TPM_EO_SIGNED_LT 4

#define TPM_EO_UNSIGNED_GE 7

#define TPM_EO_UNSIGNED_GT 3

#define TPM_EO_UNSIGNED_LE 9

#define TPM_EO_UNSIGNED_LT 5

#define TPM_GENERATED_VALUE 4283712327

#define TPM_HT_ACTIVE_SESSION 3

#define TPM_HT_HMAC_SESSION 2

#define TPM_HT_LOADED_SESSION 2

#define TPM_HT_NV_INDEX 1

#define TPM_HT_PCR 0

#define TPM_HT_PERMANENT 64

#define TPM_HT_PERSISTENT 129

#define TPM_HT_POLICY_SESSION 3

#define TPM_HT_TRANSIENT 128

#define TPM_PS_AUTHENTICATION 8

#define TPM_PS_CELL_PHONE 3

#define TPM_PS_EMBEDDED 9

#define TPM_PS_HARDCOPY 10

#define TPM_PS_INFRASTRUCTURE 11

#define TPM_PS_MAIN 0

#define TPM_PS_MULTI_TENANT 14

#define TPM_PS_PC 1

#define TPM_PS_PDA 2

#define TPM_PS_PERIPHERAL 5

#define TPM_PS_SERVER 4

#define TPM_PS_STORAGE 7

#define TPM_PS_TC 15

#define TPM_PS_TNC 13

#define TPM_PS_TSS 6

#define TPM_PS_VIRTUALIZATION 12

#define TPM_PT_ACTIVE_SESSIONS_MAX 273

#define TPM_PT_ALGORITHM_SET 524

#define TPM_PT_AUDIT_COUNTER_0 531

#define TPM_PT_AUDIT_COUNTER_1 532

#define TPM_PT_CLOCK_UPDATE 281

#define TPM_PT_CONTEXT_GAP_MAX 276

#define TPM_PT_CONTEXT_HASH 282

#define TPM_PT_CONTEXT_SYM 283

#define TPM_PT_CONTEXT_SYM_SIZE 284

#define TPM_PT_DAY_OF_YEAR 259

#define TPM_PT_FAMILY_INDICATOR 256

#define TPM_PT_FIRMWARE_VERSION_1 267

#define TPM_PT_FIRMWARE_VERSION_2 268

#define TPM_PT_HR_ACTIVE 517

#define TPM_PT_HR_ACTIVE_AVAIL 518

#define TPM_PT_HR_LOADED 515

#define TPM_PT_HR_LOADED_AVAIL 516

#define TPM_PT_HR_LOADED_MIN 272

#define TPM_PT_HR_NV_INDEX 514

#define TPM_PT_HR_PERSISTENT 520

#define TPM_PT_HR_PERSISTENT_AVAIL 521

#define TPM_PT_HR_PERSISTENT_MIN 271

#define TPM_PT_HR_TRANSIENT_AVAIL 519

#define TPM_PT_HR_TRANSIENT_MIN 270

#define TPM_PT_INPUT_BUFFER 269

#define TPM_PT_LEVEL 257

#define TPM_PT_LIBRARY_COMMANDS 298

#define TPM_PT_LOADED_CURVES 525

#define TPM_PT_LOCKOUT_COUNTER 526

#define TPM_PT_LOCKOUT_INTERVAL 528

#define TPM_PT_LOCKOUT_RECOVERY 529

#define TPM_PT_MANUFACTURER 261

#define TPM_PT_MAX_AUTH_FAIL 527

#define TPM_PT_MAX_COMMAND_SIZE 286

#define TPM_PT_MAX_DIGEST 288

#define TPM_PT_MAX_OBJECT_CONTEXT 289

#define TPM_PT_MAX_RESPONSE_SIZE 287

#define TPM_PT_MAX_SESSION_CONTEXT 290

#define TPM_PT_MEMORY 280

#define TPM_PT_NONE 0

#define TPM_PT_NV_COUNTERS 522

#define TPM_PT_NV_COUNTERS_AVAIL 523

#define TPM_PT_NV_COUNTERS_MAX 278

#define TPM_PT_NV_INDEX_MAX 279

#define TPM_PT_NV_WRITE_RECOVERY 530

#define TPM_PT_ORDERLY_COUNT 285

#define TPM_PT_PCR_AUTH 20

#define TPM_PT_PCR_COUNT 274

#define TPM_PT_PCR_DRTM_RESET 18

#define TPM_PT_PCR_EXTEND_L0 1

#define TPM_PT_PCR_EXTEND_L1 3

#define TPM_PT_PCR_EXTEND_L2 5

#define TPM_PT_PCR_EXTEND_L3 7

#define TPM_PT_PCR_EXTEND_L4 9

#define TPM_PT_PCR_FIRST 0

#define TPM_PT_PCR_LAST 20

#define TPM_PT_PCR_NO_INCREMENT 17

#define TPM_PT_PCR_POLICY 19

#define TPM_PT_PCR_RESET_L0 2

#define TPM_PT_PCR_RESET_L1 4

#define TPM_PT_PCR_RESET_L2 6

#define TPM_PT_PCR_RESET_L3 8

#define TPM_PT_PCR_RESET_L4 10

#define TPM_PT_PCR_SAVE 0

#define TPM_PT_PCR_SELECT_MIN 275

#define TPM_PT_PERMANENT 512

#define TPM_PT_PS_DAY_OF_YEAR 294

#define TPM_PT_PS_FAMILY_INDICATOR 291

#define TPM_PT_PS_LEVEL 292

#define TPM_PT_PS_REVISION 293

#define TPM_PT_PS_YEAR 295

#define TPM_PT_REVISION 258

#define TPM_PT_SPLIT_MAX 296

#define TPM_PT_STARTUP_CLEAR 513

#define TPM_PT_TOTAL_COMMANDS 297

#define TPM_PT_VENDOR_COMMANDS 299

#define TPM_PT_VENDOR_STRING_1 262

#define TPM_PT_VENDOR_STRING_2 263

#define TPM_PT_VENDOR_STRING_3 264

#define TPM_PT_VENDOR_STRING_4 265

#define TPM_PT_VENDOR_TPM_TYPE 266

#define TPM_PT_YEAR 260

#define TPM_RC_1 256

#define TPM_RC_2 512

#define TPM_RC_3 768

#define TPM_RC_4 1024

#define TPM_RC_5 1280

#define TPM_RC_6 1536

#define TPM_RC_7 1792

#define TPM_RC_8 2048

#define TPM_RC_9 2304

#define TPM_RC_A 2560

#define TPM_RC_ASYMMETRIC 129

#define TPM_RC_ATTRIBUTES 130

#define TPM_RC_AUTH_CONTEXT 325

#define TPM_RC_AUTH_FAIL 142

#define TPM_RC_AUTH_MISSING 293

#define TPM_RC_AUTH_TYPE 292

#define TPM_RC_AUTH_UNAVAILABLE 303

#define TPM_RC_AUTHSIZE 324

#define TPM_RC_B 2816

#define TPM_RC_BAD_AUTH 162

#define TPM_RC_BAD_CONTEXT 336

#define TPM_RC_BAD_TAG 48

#define TPM_RC_BINDING 165

#define TPM_RC_C 3072

#define TPM_RC_CANCELED 2313

#define TPM_RC_COMMAND_CODE 323

#define TPM_RC_COMMAND_SIZE 322

#define TPM_RC_CONTEXT_GAP 2305

#define TPM_RC_CPHASH 337

#define TPM_RC_CURVE 166

#define TPM_RC_D 3328

#define TPM_RC_DISABLED 288

#define TPM_RC_E 3584

#define TPM_RC_ECC_POINT 167

#define TPM_RC_EXCLUSIVE 289

#define TPM_RC_EXPIRED 163

#define TPM_RC_F 3840

#define TPM_RC_FAILURE 257

#define TPM_RC_H 0

#define TPM_RC_HANDLE 139

#define TPM_RC_HASH 131

#define TPM_RC_HIERARCHY 133

#define TPM_RC_HMAC 281

#define TPM_RC_INITIALIZE 256

#define TPM_RC_INSUFFICIENT 154

#define TPM_RC_INTEGRITY 159

#define TPM_RC_KDF 140

#define TPM_RC_KEY 156

#define TPM_RC_KEY_SIZE 135

#define TPM_RC_LOCALITY 2311

#define TPM_RC_LOCKOUT 2337

#define TPM_RC_MEMORY 2308

#define TPM_RC_MGF 136

#define TPM_RC_MODE 137

#define TPM_RC_N_MASK 3840

#define TPM_RC_NEEDS_TEST 339

#define TPM_RC_NO_RESULT 340

#define TPM_RC_NONCE 143

#define TPM_RC_NOT_USED 2431

#define TPM_RC_NV_AUTHORIZATION 329

#define TPM_RC_NV_DEFINED 332

#define TPM_RC_NV_LOCKED 328

#define TPM_RC_NV_RANGE 326

#define TPM_RC_NV_RATE 2336

#define TPM_RC_NV_SIZE 327

#define TPM_RC_NV_SPACE 331

#define TPM_RC_NV_UNAVAILABLE 2339

#define TPM_RC_NV_UNINITIALIZED 330

#define TPM_RC_OBJECT_HANDLES 2310

#define TPM_RC_OBJECT_MEMORY 2306

#define TPM_RC_P 64

#define TPM_RC_PARENT 338

#define TPM_RC_PCR 295

#define TPM_RC_PCR_CHANGED 296

#define TPM_RC_POLICY 294

#define TPM_RC_POLICY_CC 164

#define TPM_RC_POLICY_FAIL 157

#define TPM_RC_PP 144

#define TPM_RC_PRIVATE 267

#define TPM_RC_RANGE 141

#define TPM_RC_REBOOT 304

#define TPM_RC_REFERENCE_H0 2320

#define TPM_RC_REFERENCE_H1 2321

#define TPM_RC_REFERENCE_H2 2322

#define TPM_RC_REFERENCE_H3 2323

#define TPM_RC_REFERENCE_H4 2324

#define TPM_RC_REFERENCE_H5 2325

#define TPM_RC_REFERENCE_H6 2326

#define TPM_RC_REFERENCE_S0 2328

#define TPM_RC_REFERENCE_S1 2329

#define TPM_RC_REFERENCE_S2 2330

#define TPM_RC_REFERENCE_S3 2331

#define TPM_RC_REFERENCE_S4 2332

#define TPM_RC_REFERENCE_S5 2333

#define TPM_RC_REFERENCE_S6 2334

#define TPM_RC_RESERVED_BITS 161

#define TPM_RC_RETRY 2338

#define TPM_RC_S 2048

#define TPM_RC_SCHEME 146

#define TPM_RC_SELECTOR 152

#define TPM_RC_SENSITIVE 341

#define TPM_RC_SEQUENCE 259

#define TPM_RC_SESSION_HANDLES 2309

#define TPM_RC_SESSION_MEMORY 2307

#define TPM_RC_SIGNATURE 155

#define TPM_RC_SIZE 149

#define TPM_RC_SUCCESS 0

#define TPM_RC_SYMMETRIC 150

#define TPM_RC_TAG 151

#define TPM_RC_TESTING 2314

#define TPM_RC_TICKET 160

#define TPM_RC_TOO_MANY_CONTEXTS 302

#define TPM_RC_TYPE 138

#define TPM_RC_UNBALANCED 305

#define TPM_RC_UPGRADE 301

#define TPM_RC_VALUE 132

#define TPM_RC_YIELDED 2312

#define TPM_RH_ADMIN 1073741829

#define TPM_RH_EK 1073741830

#define TPM_RH_ENDORSEMENT 1073741835

#define TPM_RH_FIRST 1073741824

#define TPM_RH_LAST 1073741836

#define TPM_RH_LOCKOUT 1073741834

#define TPM_RH_NULL 1073741831

#define TPM_RH_OPERATOR 1073741828

#define TPM_RH_OWNER 1073741825

#define TPM_RH_PLATFORM 1073741836

#define TPM_RH_REVOKE 1073741826

#define TPM_RH_SRK 1073741824

#define TPM_RH_TRANSPORT 1073741827

#define TPM_RH_UNASSIGNED 1073741832

#define TPM_RS_PW 1073741833

#define TPM_SE_HMAC 0

#define TPM_SE_POLICY 1

#define TPM_SE_TRIAL 3

#define TPM_ST_ATTEST_CERTIFY 32791

#define TPM_ST_ATTEST_COMMAND_AUDIT 32789

#define TPM_ST_ATTEST_CREATION 32794

#define TPM_ST_ATTEST_NV 32788

#define TPM_ST_ATTEST_QUOTE 32792

#define TPM_ST_ATTEST_SESSION_AUDIT 32790

#define TPM_ST_ATTEST_TIME 32793

#define TPM_ST_AUTH_SECRET 32803

#define TPM_ST_AUTH_SIGNED 32805

#define TPM_ST_CREATION 32801

#define TPM_ST_FU_MANIFEST 32809

#define TPM_ST_HASHCHECK 32804

#define TPM_ST_NO_SESSIONS 32769

#define TPM_ST_NULL 32768

#define TPM_ST_RSP_COMMAND 196

#define TPM_ST_SESSIONS 32770

#define TPM_ST_VERIFIED 32802

#define TPM_SU_CLEAR 0

#define TPM_SU_STATE 1

#define TRANSIENT_FIRST 2147483648

#define TRANSIENT_LAST 2147483650

#define YES 1

typedef struct _ID_OBJECT _ID_OBJECT, *P_ID_OBJECT;

typedef struct TPM2B_DIGEST TPM2B_DIGEST, *PTPM2B_DIGEST;

struct TPM2B_DIGEST {
    UINT16 size;
    byte *buffer;
};

struct _ID_OBJECT {
    struct TPM2B_DIGEST integrityHMAC;
    struct TPM2B_DIGEST encIdentity;
};

typedef struct _PRIVATE _PRIVATE, *P_PRIVATE;

typedef struct TPMT_SENSITIVE TPMT_SENSITIVE, *PTPMT_SENSITIVE;

typedef UINT16 TPM_ALG_ID;

typedef TPM_ALG_ID TPMI_ALG_PUBLIC;

typedef struct TPM2B_DIGEST TPM2B_AUTH;

typedef union TPMU_SENSITIVE_COMPOSITE TPMU_SENSITIVE_COMPOSITE, *PTPMU_SENSITIVE_COMPOSITE;

typedef struct TPM2B_PRIVATE_KEY_RSA TPM2B_PRIVATE_KEY_RSA, *PTPM2B_PRIVATE_KEY_RSA;

typedef struct TPM2B_ECC_PARAMETER TPM2B_ECC_PARAMETER, *PTPM2B_ECC_PARAMETER;

typedef struct TPM2B_SENSITIVE_DATA TPM2B_SENSITIVE_DATA, *PTPM2B_SENSITIVE_DATA;

typedef struct TPM2B_SYM_KEY TPM2B_SYM_KEY, *PTPM2B_SYM_KEY;

typedef struct TPM2B_PRIVATE_VENDOR_SPECIFIC TPM2B_PRIVATE_VENDOR_SPECIFIC, *PTPM2B_PRIVATE_VENDOR_SPECIFIC;


/* WARNING! conflicting data type names: /Tpm20.h/BYTE - /WinDef.h/BYTE */

struct TPM2B_SENSITIVE_DATA {
    UINT16 size;
    byte buffer[256];
};

struct TPM2B_SYM_KEY {
    UINT16 size;
    BYTE buffer[16];
};

struct TPM2B_PRIVATE_VENDOR_SPECIFIC {
    UINT16 size;
    BYTE buffer[640];
};

struct TPM2B_PRIVATE_KEY_RSA {
    UINT16 size;
    BYTE buffer[128];
};

struct TPM2B_ECC_PARAMETER {
    UINT16 size;
    BYTE buffer[32];
};

union TPMU_SENSITIVE_COMPOSITE {
    struct TPM2B_PRIVATE_KEY_RSA rsa;
    struct TPM2B_ECC_PARAMETER ecc;
    struct TPM2B_SENSITIVE_DATA bits;
    struct TPM2B_SYM_KEY sym;
    struct TPM2B_PRIVATE_VENDOR_SPECIFIC any;
};

struct TPMT_SENSITIVE {
    TPMI_ALG_PUBLIC sensitiveType;
    TPM2B_AUTH authValue;
    struct TPM2B_DIGEST seedValue;
    union TPMU_SENSITIVE_COMPOSITE sensitive;
};

struct _PRIVATE {
    struct TPM2B_DIGEST integrityOuter;
    struct TPM2B_DIGEST integrityInner;
    struct TPMT_SENSITIVE sensitive;
};


/* WARNING! conflicting data type names: /Tpm20.h/BOOL - /WinDef.h/BOOL */

typedef UINT16 BSIZE;

typedef UINT64 CONTEXT_COUNTER;

typedef UINT16 CONTEXT_SLOT;

typedef struct TPM2_COMMAND_HEADER TPM2_COMMAND_HEADER, *PTPM2_COMMAND_HEADER;

typedef UINT32 TPM_CC;

struct TPM2_COMMAND_HEADER {
    TPM_ST tag;
    UINT32 paramSize;
    TPM_CC commandCode;
};

typedef struct TPM2_Create TPM2_Create, *PTPM2_Create;

typedef struct TPMT_PUBLIC TPMT_PUBLIC, *PTPMT_PUBLIC;

typedef TPM_ALG_ID TPMI_ALG_HASH;

typedef struct TPMA_OBJECT TPMA_OBJECT, *PTPMA_OBJECT;

typedef union TPMU_PUBLIC_PARMS TPMU_PUBLIC_PARMS, *PTPMU_PUBLIC_PARMS;

typedef struct TPMS_KEYEDHASH_PARMS TPMS_KEYEDHASH_PARMS, *PTPMS_KEYEDHASH_PARMS;

typedef struct TPMT_SYM_DEF_OBJECT TPMT_SYM_DEF_OBJECT, *PTPMT_SYM_DEF_OBJECT;

typedef struct TPMS_RSA_PARMS TPMS_RSA_PARMS, *PTPMS_RSA_PARMS;

typedef struct TPMS_ECC_PARMS TPMS_ECC_PARMS, *PTPMS_ECC_PARMS;

typedef struct TPMS_ASYM_PARMS TPMS_ASYM_PARMS, *PTPMS_ASYM_PARMS;

typedef struct TPMT_KEYEDHASH_SCHEME TPMT_KEYEDHASH_SCHEME, *PTPMT_KEYEDHASH_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_SYM_OBJECT;

typedef union TPMU_SYM_KEY_BITS TPMU_SYM_KEY_BITS, *PTPMU_SYM_KEY_BITS;

typedef union TPMU_SYM_MODE TPMU_SYM_MODE, *PTPMU_SYM_MODE;

typedef struct TPMT_RSA_SCHEME TPMT_RSA_SCHEME, *PTPMT_RSA_SCHEME;

typedef UINT16 TPM_KEY_BITS;

typedef TPM_KEY_BITS TPMI_RSA_KEY_BITS;

typedef struct TPMT_ECC_SCHEME TPMT_ECC_SCHEME, *PTPMT_ECC_SCHEME;

typedef UINT16 TPM_ECC_CURVE;

typedef TPM_ECC_CURVE TPMI_ECC_CURVE;

typedef struct TPMT_KDF_SCHEME TPMT_KDF_SCHEME, *PTPMT_KDF_SCHEME;

typedef struct TPMT_ASYM_SCHEME TPMT_ASYM_SCHEME, *PTPMT_ASYM_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;

typedef union TPMU_SCHEME_KEYEDHASH TPMU_SCHEME_KEYEDHASH, *PTPMU_SCHEME_KEYEDHASH;

typedef TPM_KEY_BITS TPMI_AES_KEY_BITS;

typedef TPM_KEY_BITS TPMI_SM4_KEY_BITS;

typedef TPM_ALG_ID TPMI_ALG_SYM_MODE;

typedef TPM_ALG_ID TPMI_ALG_RSA_SCHEME;

typedef union TPMU_ASYM_SCHEME TPMU_ASYM_SCHEME, *PTPMU_ASYM_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_ECC_SCHEME;

typedef union TPMU_SIG_SCHEME TPMU_SIG_SCHEME, *PTPMU_SIG_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_KDF;

typedef union TPMU_KDF_SCHEME TPMU_KDF_SCHEME, *PTPMU_KDF_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_ASYM_SCHEME;

typedef struct TPMS_SCHEME_SIGHASH TPMS_SCHEME_SIGHASH, *PTPMS_SCHEME_SIGHASH;

typedef struct TPMS_SCHEME_SIGHASH TPMS_SCHEME_HMAC;

typedef struct TPMS_SCHEME_XOR TPMS_SCHEME_XOR, *PTPMS_SCHEME_XOR;

typedef struct TPMS_SCHEME_SIGHASH TPMS_SCHEME_RSASSA;

typedef struct TPMS_SCHEME_SIGHASH TPMS_SCHEME_RSAPSS;

typedef struct TPMS_SCHEME_OAEP TPMS_SCHEME_OAEP, *PTPMS_SCHEME_OAEP;

typedef struct TPMS_SCHEME_SIGHASH TPMS_SCHEME_ECDSA;

typedef struct TPMS_SCHEME_ECDAA TPMS_SCHEME_ECDAA, *PTPMS_SCHEME_ECDAA;

typedef struct TPMS_SCHEME_SIGHASH TPMS_SCHEME_ECSCHNORR;

typedef struct TPMS_SCHEME_MGF1 TPMS_SCHEME_MGF1, *PTPMS_SCHEME_MGF1;

typedef struct TPMS_SCHEME_KDF1_SP800_56a TPMS_SCHEME_KDF1_SP800_56a, *PTPMS_SCHEME_KDF1_SP800_56a;

typedef struct TPMS_SCHEME_KDF2 TPMS_SCHEME_KDF2, *PTPMS_SCHEME_KDF2;

typedef struct TPMS_SCHEME_KDF1_SP800_108 TPMS_SCHEME_KDF1_SP800_108, *PTPMS_SCHEME_KDF1_SP800_108;

struct TPMS_SCHEME_KDF1_SP800_56a {
    TPMI_ALG_HASH hashAlg;
};

union TPMU_SYM_MODE {
    TPMI_ALG_SYM_MODE aes;
    TPMI_ALG_SYM_MODE SM4;
    TPMI_ALG_SYM_MODE sym;
};

union TPMU_SYM_KEY_BITS {
    TPMI_AES_KEY_BITS aes;
    TPMI_SM4_KEY_BITS SM4;
    TPM_KEY_BITS sym;
    TPMI_ALG_HASH xor;
};

struct TPMT_SYM_DEF_OBJECT {
    TPMI_ALG_SYM_OBJECT algorithm;
    union TPMU_SYM_KEY_BITS keyBits;
    union TPMU_SYM_MODE mode;
};

struct TPMS_SCHEME_ECDAA {
    TPMI_ALG_HASH hashAlg;
    UINT16 count;
};

struct TPMS_SCHEME_OAEP {
    TPMI_ALG_HASH hashAlg;
};

struct TPMS_SCHEME_SIGHASH {
    TPMI_ALG_HASH hashAlg;
};

union TPMU_ASYM_SCHEME {
    TPMS_SCHEME_RSASSA rsassa;
    TPMS_SCHEME_RSAPSS rsapss;
    struct TPMS_SCHEME_OAEP oaep;
    TPMS_SCHEME_ECDSA ecdsa;
    struct TPMS_SCHEME_ECDAA ecdaa;
    TPMS_SCHEME_ECSCHNORR ecSchnorr;
    struct TPMS_SCHEME_SIGHASH anySig;
};

struct TPMT_ASYM_SCHEME {
    TPMI_ALG_ASYM_SCHEME scheme;
    union TPMU_ASYM_SCHEME details;
};

struct TPMS_ASYM_PARMS {
    struct TPMT_SYM_DEF_OBJECT symmetric;
    struct TPMT_ASYM_SCHEME scheme;
};

struct TPMA_OBJECT {
    UINT32 reserved1:1;
    UINT32 fixedTPM:1;
    UINT32 stClear:1;
    UINT32 reserved4:1;
    UINT32 fixedParent:1;
    UINT32 sensitiveDataOrigin:1;
    UINT32 userWithAuth:1;
    UINT32 adminWithPolicy:1;
    UINT32 reserved8_9:2;
    UINT32 noDA:1;
    UINT32 encryptedDuplication:1;
    UINT32 reserved12_15:4;
    UINT32 restricted:1;
    UINT32 decrypt:1;
    UINT32 sign:1;
    UINT32 reserved19_31:13;
};

struct TPMT_RSA_SCHEME {
    TPMI_ALG_RSA_SCHEME scheme;
    union TPMU_ASYM_SCHEME details;
};

struct TPMS_RSA_PARMS {
    struct TPMT_SYM_DEF_OBJECT symmetric;
    struct TPMT_RSA_SCHEME scheme;
    TPMI_RSA_KEY_BITS keyBits;
    UINT32 exponent;
};

struct TPMS_SCHEME_XOR {
    TPMI_ALG_HASH hashAlg;
    TPMI_ALG_KDF kdf;
};

union TPMU_SCHEME_KEYEDHASH {
    TPMS_SCHEME_HMAC hmac;
    struct TPMS_SCHEME_XOR xor;
};

struct TPMT_KEYEDHASH_SCHEME {
    TPMI_ALG_KEYEDHASH_SCHEME scheme;
    union TPMU_SCHEME_KEYEDHASH details;
};

struct TPMS_KEYEDHASH_PARMS {
    struct TPMT_KEYEDHASH_SCHEME scheme;
};

union TPMU_SIG_SCHEME {
    TPMS_SCHEME_RSASSA rsassa;
    TPMS_SCHEME_RSAPSS rsapss;
    TPMS_SCHEME_ECDSA ecdsa;
    struct TPMS_SCHEME_ECDAA ecdaa;
    TPMS_SCHEME_ECSCHNORR ecSchnorr;
    TPMS_SCHEME_HMAC hmac;
    struct TPMS_SCHEME_SIGHASH any;
};

struct TPMT_ECC_SCHEME {
    TPMI_ALG_ECC_SCHEME scheme;
    union TPMU_SIG_SCHEME details;
};

struct TPMS_SCHEME_MGF1 {
    TPMI_ALG_HASH hashAlg;
};

struct TPMS_SCHEME_KDF1_SP800_108 {
    TPMI_ALG_HASH hashAlg;
};

struct TPMS_SCHEME_KDF2 {
    TPMI_ALG_HASH hashAlg;
};

union TPMU_KDF_SCHEME {
    struct TPMS_SCHEME_MGF1 mgf1;
    struct TPMS_SCHEME_KDF1_SP800_56a kdf1_SP800_56a;
    struct TPMS_SCHEME_KDF2 kdf2;
    struct TPMS_SCHEME_KDF1_SP800_108 kdf1_sp800_108;
};

struct TPMT_KDF_SCHEME {
    TPMI_ALG_KDF scheme;
    union TPMU_KDF_SCHEME details;
};

struct TPMS_ECC_PARMS {
    struct TPMT_SYM_DEF_OBJECT symmetric;
    struct TPMT_ECC_SCHEME scheme;
    TPMI_ECC_CURVE curveID;
    struct TPMT_KDF_SCHEME kdf;
};

union TPMU_PUBLIC_PARMS {
    struct TPMS_KEYEDHASH_PARMS keyedHashDetail;
    struct TPMT_SYM_DEF_OBJECT symDetail;
    struct TPMS_RSA_PARMS rsaDetail;
    struct TPMS_ECC_PARMS eccDetail;
    struct TPMS_ASYM_PARMS asymDetail;
};

struct TPMT_PUBLIC {
    TPMI_ALG_PUBLIC type;
    TPMI_ALG_HASH nameAlg;
    struct TPMA_OBJECT objectAttributes;
    struct TPMW82B_BUFFER authPolicy;
    union TPMU_PUBLIC_PARMS parameters;
    struct TPM2B_DIGEST keyedHash;
};

struct TPM2_Create {
    byte field0_0x0[56];
    struct TPMT_PUBLIC public;
    undefined field2_0xa4;
    undefined field3_0xa5;
    undefined field4_0xa6;
    undefined field5_0xa7;
    undefined field6_0xa8;
    undefined field7_0xa9;
    undefined field8_0xaa;
    undefined field9_0xab;
    undefined field10_0xac;
    undefined field11_0xad;
    undefined field12_0xae;
    undefined field13_0xaf;
    undefined field14_0xb0;
    undefined field15_0xb1;
    undefined field16_0xb2;
    undefined field17_0xb3;
    undefined field18_0xb4;
    undefined field19_0xb5;
    undefined field20_0xb6;
    undefined field21_0xb7;
    undefined field22_0xb8;
    undefined field23_0xb9;
    undefined field24_0xba;
    undefined field25_0xbb;
    undefined field26_0xbc;
    undefined field27_0xbd;
    undefined field28_0xbe;
    undefined field29_0xbf;
    undefined field30_0xc0;
    undefined field31_0xc1;
    undefined field32_0xc2;
    undefined field33_0xc3;
    undefined field34_0xc4;
    undefined field35_0xc5;
    undefined field36_0xc6;
    undefined field37_0xc7;
    undefined field38_0xc8;
    undefined field39_0xc9;
    undefined field40_0xca;
    undefined field41_0xcb;
    undefined field42_0xcc;
    undefined field43_0xcd;
    undefined field44_0xce;
    undefined field45_0xcf;
    undefined field46_0xd0;
    undefined field47_0xd1;
    undefined field48_0xd2;
    undefined field49_0xd3;
    undefined field50_0xd4;
    undefined field51_0xd5;
    undefined field52_0xd6;
    undefined field53_0xd7;
    undefined field54_0xd8;
    undefined field55_0xd9;
    undefined field56_0xda;
    undefined field57_0xdb;
    undefined field58_0xdc;
    undefined field59_0xdd;
    undefined field60_0xde;
    undefined field61_0xdf;
    undefined field62_0xe0;
    undefined field63_0xe1;
    undefined field64_0xe2;
    undefined field65_0xe3;
    undefined field66_0xe4;
    undefined field67_0xe5;
    undefined field68_0xe6;
    undefined field69_0xe7;
    undefined field70_0xe8;
    undefined field71_0xe9;
    undefined field72_0xea;
    undefined field73_0xeb;
    undefined field74_0xec;
    undefined field75_0xed;
    undefined field76_0xee;
    undefined field77_0xef;
    undefined field78_0xf0;
    undefined field79_0xf1;
    undefined field80_0xf2;
    undefined field81_0xf3;
    undefined field82_0xf4;
    undefined field83_0xf5;
    undefined field84_0xf6;
    undefined field85_0xf7;
    undefined field86_0xf8;
    undefined field87_0xf9;
    undefined field88_0xfa;
    undefined field89_0xfb;
    undefined field90_0xfc;
    undefined field91_0xfd;
    undefined field92_0xfe;
    undefined field93_0xff;
    undefined field94_0x100;
    undefined field95_0x101;
    undefined field96_0x102;
    undefined field97_0x103;
    undefined field98_0x104;
    undefined field99_0x105;
    undefined field100_0x106;
    undefined field101_0x107;
    undefined field102_0x108;
    undefined field103_0x109;
    undefined field104_0x10a;
    undefined field105_0x10b;
    undefined field106_0x10c;
    undefined field107_0x10d;
    undefined field108_0x10e;
    undefined field109_0x10f;
    undefined field110_0x110;
    undefined field111_0x111;
    undefined field112_0x112;
    undefined field113_0x113;
    undefined field114_0x114;
    undefined field115_0x115;
    undefined field116_0x116;
    undefined field117_0x117;
    undefined field118_0x118;
    undefined field119_0x119;
    undefined field120_0x11a;
    undefined field121_0x11b;
    undefined field122_0x11c;
    undefined field123_0x11d;
    undefined field124_0x11e;
    undefined field125_0x11f;
    undefined field126_0x120;
    undefined field127_0x121;
    undefined field128_0x122;
    undefined field129_0x123;
    undefined field130_0x124;
    undefined field131_0x125;
    undefined field132_0x126;
    undefined field133_0x127;
    undefined field134_0x128;
    undefined field135_0x129;
    undefined field136_0x12a;
    undefined field137_0x12b;
    undefined field138_0x12c;
    undefined field139_0x12d;
    undefined field140_0x12e;
    undefined field141_0x12f;
    undefined field142_0x130;
    undefined field143_0x131;
    undefined field144_0x132;
    undefined field145_0x133;
    undefined field146_0x134;
    undefined field147_0x135;
    undefined field148_0x136;
    undefined field149_0x137;
    undefined field150_0x138;
    undefined field151_0x139;
    undefined field152_0x13a;
    undefined field153_0x13b;
    undefined field154_0x13c;
    undefined field155_0x13d;
    undefined field156_0x13e;
    undefined field157_0x13f;
    undefined field158_0x140;
    undefined field159_0x141;
    undefined field160_0x142;
    undefined field161_0x143;
    undefined field162_0x144;
    undefined field163_0x145;
    undefined field164_0x146;
    undefined field165_0x147;
    undefined field166_0x148;
    undefined field167_0x149;
    undefined field168_0x14a;
    undefined field169_0x14b;
    undefined field170_0x14c;
    undefined field171_0x14d;
    undefined field172_0x14e;
    undefined field173_0x14f;
    undefined field174_0x150;
    undefined field175_0x151;
    undefined field176_0x152;
    undefined field177_0x153;
    undefined field178_0x154;
    undefined field179_0x155;
    undefined field180_0x156;
    undefined field181_0x157;
    undefined field182_0x158;
    undefined field183_0x159;
    undefined field184_0x15a;
    undefined field185_0x15b;
    undefined field186_0x15c;
    undefined field187_0x15d;
    undefined field188_0x15e;
    undefined field189_0x15f;
    undefined field190_0x160;
    undefined field191_0x161;
    undefined field192_0x162;
    undefined field193_0x163;
    undefined field194_0x164;
    undefined field195_0x165;
    undefined field196_0x166;
    undefined field197_0x167;
    undefined field198_0x168;
    undefined field199_0x169;
    undefined field200_0x16a;
    undefined field201_0x16b;
    undefined field202_0x16c;
    undefined field203_0x16d;
    undefined field204_0x16e;
    undefined field205_0x16f;
    undefined field206_0x170;
    undefined field207_0x171;
    undefined field208_0x172;
    undefined field209_0x173;
    undefined field210_0x174;
    undefined field211_0x175;
    undefined field212_0x176;
    undefined field213_0x177;
    undefined field214_0x178;
    undefined field215_0x179;
    undefined field216_0x17a;
    undefined field217_0x17b;
    undefined field218_0x17c;
    undefined field219_0x17d;
    undefined field220_0x17e;
    undefined field221_0x17f;
    undefined field222_0x180;
    undefined field223_0x181;
    undefined field224_0x182;
    undefined field225_0x183;
    undefined field226_0x184;
    undefined field227_0x185;
    undefined field228_0x186;
    undefined field229_0x187;
    undefined field230_0x188;
    undefined field231_0x189;
    undefined field232_0x18a;
    undefined field233_0x18b;
    undefined field234_0x18c;
    undefined field235_0x18d;
    undefined field236_0x18e;
    undefined field237_0x18f;
    undefined field238_0x190;
    undefined field239_0x191;
    undefined field240_0x192;
    undefined field241_0x193;
    undefined field242_0x194;
    undefined field243_0x195;
    undefined field244_0x196;
    undefined field245_0x197;
    undefined field246_0x198;
    undefined field247_0x199;
    undefined field248_0x19a;
    undefined field249_0x19b;
    undefined field250_0x19c;
    undefined field251_0x19d;
    undefined field252_0x19e;
    undefined field253_0x19f;
    undefined field254_0x1a0;
    undefined field255_0x1a1;
    undefined field256_0x1a2;
    undefined field257_0x1a3;
    undefined field258_0x1a4;
    undefined field259_0x1a5;
    undefined field260_0x1a6;
    undefined field261_0x1a7;
    undefined field262_0x1a8;
    undefined field263_0x1a9;
    undefined field264_0x1aa;
    undefined field265_0x1ab;
    undefined field266_0x1ac;
    undefined field267_0x1ad;
    undefined field268_0x1ae;
    undefined field269_0x1af;
    undefined field270_0x1b0;
    undefined field271_0x1b1;
    undefined field272_0x1b2;
    undefined field273_0x1b3;
    undefined field274_0x1b4;
    undefined field275_0x1b5;
    undefined field276_0x1b6;
    undefined field277_0x1b7;
    undefined field278_0x1b8;
    undefined field279_0x1b9;
    undefined field280_0x1ba;
    undefined field281_0x1bb;
    undefined field282_0x1bc;
    undefined field283_0x1bd;
    undefined field284_0x1be;
    undefined field285_0x1bf;
    undefined field286_0x1c0;
    undefined field287_0x1c1;
    undefined field288_0x1c2;
    undefined field289_0x1c3;
    undefined field290_0x1c4;
    undefined field291_0x1c5;
    undefined field292_0x1c6;
    undefined field293_0x1c7;
    undefined field294_0x1c8;
    undefined field295_0x1c9;
    undefined field296_0x1ca;
    undefined field297_0x1cb;
    undefined field298_0x1cc;
    undefined field299_0x1cd;
    undefined field300_0x1ce;
    undefined field301_0x1cf;
    undefined field302_0x1d0;
    undefined field303_0x1d1;
    undefined field304_0x1d2;
    undefined field305_0x1d3;
    undefined field306_0x1d4;
    undefined field307_0x1d5;
    undefined field308_0x1d6;
    undefined field309_0x1d7;
    undefined field310_0x1d8;
    undefined field311_0x1d9;
    undefined field312_0x1da;
    undefined field313_0x1db;
    undefined field314_0x1dc;
    undefined field315_0x1dd;
    undefined field316_0x1de;
    undefined field317_0x1df;
    undefined field318_0x1e0;
    undefined field319_0x1e1;
    undefined field320_0x1e2;
    undefined field321_0x1e3;
    undefined field322_0x1e4;
    undefined field323_0x1e5;
    undefined field324_0x1e6;
    undefined field325_0x1e7;
    undefined field326_0x1e8;
    undefined field327_0x1e9;
    undefined field328_0x1ea;
    undefined field329_0x1eb;
    undefined field330_0x1ec;
    undefined field331_0x1ed;
    undefined field332_0x1ee;
    undefined field333_0x1ef;
    undefined field334_0x1f0;
    undefined field335_0x1f1;
    undefined field336_0x1f2;
    undefined field337_0x1f3;
    undefined field338_0x1f4;
    undefined field339_0x1f5;
    undefined field340_0x1f6;
    undefined field341_0x1f7;
    undefined field342_0x1f8;
    undefined field343_0x1f9;
    undefined field344_0x1fa;
    undefined field345_0x1fb;
    undefined field346_0x1fc;
    undefined field347_0x1fd;
    undefined field348_0x1fe;
    undefined field349_0x1ff;
    undefined field350_0x200;
    undefined field351_0x201;
    undefined field352_0x202;
    undefined field353_0x203;
    undefined field354_0x204;
    undefined field355_0x205;
    undefined field356_0x206;
    undefined field357_0x207;
    undefined field358_0x208;
    undefined field359_0x209;
    undefined field360_0x20a;
    undefined field361_0x20b;
    undefined field362_0x20c;
    undefined field363_0x20d;
    undefined field364_0x20e;
    undefined field365_0x20f;
    undefined field366_0x210;
    undefined field367_0x211;
    undefined field368_0x212;
    undefined field369_0x213;
};

typedef struct TPM2_RESPONSE_HEADER TPM2_RESPONSE_HEADER, *PTPM2_RESPONSE_HEADER;

typedef UINT32 TPM_RC;

struct TPM2_RESPONSE_HEADER {
    TPM_ST tag;
    UINT32 paramSize;
    TPM_RC responseCode;
};

typedef struct TPM2B_ATTEST TPM2B_ATTEST, *PTPM2B_ATTEST;

struct TPM2B_ATTEST {
    UINT16 size;
    BYTE attestationData[1263];
};

typedef struct TPM2B_CONTEXT_DATA TPM2B_CONTEXT_DATA, *PTPM2B_CONTEXT_DATA;

struct TPM2B_CONTEXT_DATA {
    UINT16 size;
    BYTE buffer[4068];
};

typedef struct TPM2B_CONTEXT_SENSITIVE TPM2B_CONTEXT_SENSITIVE, *PTPM2B_CONTEXT_SENSITIVE;

struct TPM2B_CONTEXT_SENSITIVE {
    UINT16 size;
    BYTE buffer[4000];
};

typedef struct TPM2B_CREATION_DATA TPM2B_CREATION_DATA, *PTPM2B_CREATION_DATA;

typedef struct TPMS_CREATION_DATA TPMS_CREATION_DATA, *PTPMS_CREATION_DATA;

typedef struct TPML_PCR_SELECTION TPML_PCR_SELECTION, *PTPML_PCR_SELECTION;

typedef struct TPMA_LOCALITY TPMA_LOCALITY, *PTPMA_LOCALITY;

typedef struct TPM2B_NAME TPM2B_NAME, *PTPM2B_NAME;

typedef struct TPM2B_DATA TPM2B_DATA, *PTPM2B_DATA;

typedef struct TPMS_PCR_SELECTION TPMS_PCR_SELECTION, *PTPMS_PCR_SELECTION;

struct TPM2B_NAME {
    UINT16 size;
    BYTE name[66];
};

struct TPMA_LOCALITY {
    UINT8 locZero:1;
    UINT8 locOne:1;
    UINT8 locTwo:1;
    UINT8 locThree:1;
    UINT8 locFour:1;
    UINT8 Extended:3;
};

struct TPM2B_DATA {
    UINT16 size;
    BYTE buffer[66];
};

struct TPMS_PCR_SELECTION {
    TPMI_ALG_HASH hash;
    UINT8 sizeofSelect;
    BYTE pcrSelect[3];
};

struct TPML_PCR_SELECTION {
    UINT32 count;
    struct TPMS_PCR_SELECTION pcrSelections[5];
};

struct TPMS_CREATION_DATA {
    struct TPML_PCR_SELECTION pcrSelect;
    struct TPM2B_DIGEST pcrDigest;
    struct TPMA_LOCALITY locality;
    TPM_ALG_ID parentNameAlg;
    struct TPM2B_NAME parentName;
    struct TPM2B_NAME parentQualifiedName;
    struct TPM2B_DATA outsideInfo;
};

struct TPM2B_CREATION_DATA {
    UINT16 size;
    struct TPMS_CREATION_DATA creationData;
};

typedef struct TPM2B_DIGEST_VALUES TPM2B_DIGEST_VALUES, *PTPM2B_DIGEST_VALUES;

struct TPM2B_DIGEST_VALUES {
    UINT16 size;
    BYTE buffer[334];
};

typedef struct TPM2B_ECC_POINT TPM2B_ECC_POINT, *PTPM2B_ECC_POINT;

typedef struct TPMS_ECC_POINT TPMS_ECC_POINT, *PTPMS_ECC_POINT;

struct TPMS_ECC_POINT {
    struct TPM2B_ECC_PARAMETER x;
    struct TPM2B_ECC_PARAMETER y;
};

struct TPM2B_ECC_POINT {
    UINT16 size;
    struct TPMS_ECC_POINT point;
};

typedef struct TPM2B_ENCRYPTED_SECRET TPM2B_ENCRYPTED_SECRET, *PTPM2B_ENCRYPTED_SECRET;

struct TPM2B_ENCRYPTED_SECRET {
    UINT16 size;
    BYTE secret[256];
};

typedef struct TPM2B_EVENT TPM2B_EVENT, *PTPM2B_EVENT;

struct TPM2B_EVENT {
    UINT16 size;
    BYTE buffer[1024];
};

typedef struct TPM2B_ID_OBJECT TPM2B_ID_OBJECT, *PTPM2B_ID_OBJECT;

struct TPM2B_ID_OBJECT {
    UINT16 size;
    BYTE credential[132];
};

typedef struct TPM2B_IV TPM2B_IV, *PTPM2B_IV;

struct TPM2B_IV {
    UINT16 size;
    BYTE buffer[16];
};

typedef struct TPM2B_MAX_BUFFER TPM2B_MAX_BUFFER, *PTPM2B_MAX_BUFFER;

struct TPM2B_MAX_BUFFER {
    UINT16 size;
    BYTE buffer[1024];
};

typedef struct TPM2B_MAX_NV_BUFFER TPM2B_MAX_NV_BUFFER, *PTPM2B_MAX_NV_BUFFER;

struct TPM2B_MAX_NV_BUFFER {
    UINT16 size;
    BYTE buffer[1024];
};

typedef struct TPM2B_DIGEST TPM2B_NONCE;

typedef struct TPM2B_NV_PUBLIC TPM2B_NV_PUBLIC, *PTPM2B_NV_PUBLIC;

typedef struct TPMS_NV_PUBLIC TPMS_NV_PUBLIC, *PTPMS_NV_PUBLIC;

typedef TPM_HANDLE TPMI_RH_NV_INDEX;

typedef struct TPMA_NV TPMA_NV, *PTPMA_NV;

struct TPMA_NV {
    UINT32 TPMA_NV_PPWRITE:1;
    UINT32 TPMA_NV_OWNERWRITE:1;
    UINT32 TPMA_NV_AUTHWRITE:1;
    UINT32 TPMA_NV_POLICYWRITE:1;
    UINT32 TPMA_NV_COUNTER:1;
    UINT32 TPMA_NV_BITS:1;
    UINT32 TPMA_NV_EXTEND:1;
    UINT32 reserved7_9:3;
    UINT32 TPMA_NV_POLICY_DELETE:1;
    UINT32 TPMA_NV_WRITELOCKED:1;
    UINT32 TPMA_NV_WRITEALL:1;
    UINT32 TPMA_NV_WRITEDEFINE:1;
    UINT32 TPMA_NV_WRITE_STCLEAR:1;
    UINT32 TPMA_NV_GLOBALLOCK:1;
    UINT32 TPMA_NV_PPREAD:1;
    UINT32 TPMA_NV_OWNERREAD:1;
    UINT32 TPMA_NV_AUTHREAD:1;
    UINT32 TPMA_NV_POLICYREAD:1;
    UINT32 reserved20_24:5;
    UINT32 TPMA_NV_NO_DA:1;
    UINT32 TPMA_NV_ORDERLY:1;
    UINT32 TPMA_NV_CLEAR_STCLEAR:1;
    UINT32 TPMA_NV_READLOCKED:1;
    UINT32 TPMA_NV_WRITTEN:1;
    UINT32 TPMA_NV_PLATFORMCREATE:1;
    UINT32 TPMA_NV_READ_STCLEAR:1;
};

struct TPMS_NV_PUBLIC {
    TPMI_RH_NV_INDEX nvIndex;
    TPMI_ALG_HASH nameAlg;
    struct TPMA_NV attributes;
    struct TPM2B_DIGEST authPolicy;
    UINT16 dataSize;
};

struct TPM2B_NV_PUBLIC {
    UINT16 size;
    struct TPMS_NV_PUBLIC nvPublic;
};

typedef struct TPM2B_DIGEST TPM2B_OPERAND;

typedef struct TPM2B_PRIVATE TPM2B_PRIVATE, *PTPM2B_PRIVATE;

struct TPM2B_PRIVATE {
    UINT16 size;
    BYTE buffer[908];
};

typedef struct TPM2B_PUBLIC TPM2B_PUBLIC, *PTPM2B_PUBLIC;

struct TPM2B_PUBLIC {
    UINT16 size;
    struct TPMT_PUBLIC publicArea;
};

typedef struct TPM2B_PUBLIC_KEY_RSA TPM2B_PUBLIC_KEY_RSA, *PTPM2B_PUBLIC_KEY_RSA;

struct TPM2B_PUBLIC_KEY_RSA {
    UINT16 size;
    BYTE buffer[256];
};

typedef struct TPM2B_SENSITIVE TPM2B_SENSITIVE, *PTPM2B_SENSITIVE;

struct TPM2B_SENSITIVE {
    UINT16 size;
    struct TPMT_SENSITIVE sensitiveArea;
};

typedef struct TPM2B_SENSITIVE_CREATE TPM2B_SENSITIVE_CREATE, *PTPM2B_SENSITIVE_CREATE;

typedef struct TPMS_SENSITIVE_CREATE TPMS_SENSITIVE_CREATE, *PTPMS_SENSITIVE_CREATE;

struct TPMS_SENSITIVE_CREATE {
    TPM2B_AUTH userAuth;
    struct TPM2B_SENSITIVE_DATA data;
};

struct TPM2B_SENSITIVE_CREATE {
    UINT16 size;
    struct TPMS_SENSITIVE_CREATE sensitive;
};

typedef struct TPM2B_TIMEOUT TPM2B_TIMEOUT, *PTPM2B_TIMEOUT;

struct TPM2B_TIMEOUT {
    UINT16 size;
    BYTE buffer[8];
};

typedef UINT32 TPM_AUTHORIZATION_SIZE;

typedef UINT32 TPM_CAP;

typedef INT8 TPM_CLOCK_ADJUST;

typedef UINT16 TPM_EO;

typedef UINT32 TPM_GENERATED;

typedef TPM_HANDLE TPM_HC;

typedef UINT8 TPM_HT;

typedef UINT16 TPM_KEY_SIZE;

typedef UINT32 TPM_PARAMETER_SIZE;

typedef UINT32 TPM_PS;

typedef UINT32 TPM_PT;

typedef UINT32 TPM_PT_PCR;

typedef UINT32 TPM_RH;

typedef UINT8 TPM_SE;

typedef UINT16 TPM_SU;

typedef struct TPMA_ALGORITHM TPMA_ALGORITHM, *PTPMA_ALGORITHM;

struct TPMA_ALGORITHM {
    UINT32 asymmetric:1;
    UINT32 symmetric:1;
    UINT32 hash:1;
    UINT32 object:1;
    UINT32 reserved4_7:4;
    UINT32 signing:1;
    UINT32 encrypting:1;
    UINT32 method:1;
    UINT32 reserved11_31:21;
};

typedef struct TPMA_CC TPMA_CC, *PTPMA_CC;

struct TPMA_CC {
    UINT32 commandIndex:16;
    UINT32 reserved16_21:6;
    UINT32 nv:1;
    UINT32 extensive:1;
    UINT32 flushed:1;
    UINT32 cHandles:3;
    UINT32 rHandle:1;
    UINT32 V:1;
    UINT32 Res:2;
};

typedef struct TPMA_MEMORY TPMA_MEMORY, *PTPMA_MEMORY;

struct TPMA_MEMORY {
    UINT32 sharedRAM:1;
    UINT32 sharedNV:1;
    UINT32 objectCopiedToRam:1;
    UINT32 reserved3_31:29;
};

typedef struct TPMA_PERMANENT TPMA_PERMANENT, *PTPMA_PERMANENT;

struct TPMA_PERMANENT {
    UINT32 ownerAuthSet:1;
    UINT32 endorsementAuthSet:1;
    UINT32 lockoutAuthSet:1;
    UINT32 reserved3_7:5;
    UINT32 disableClear:1;
    UINT32 inLockout:1;
    UINT32 tpmGeneratedEPS:1;
    UINT32 reserved11_31:21;
};

typedef struct TPMA_SESSION TPMA_SESSION, *PTPMA_SESSION;

struct TPMA_SESSION {
    UINT8 continueSession:1;
    UINT8 auditExclusive:1;
    UINT8 auditReset:1;
    UINT8 reserved3_4:2;
    UINT8 decrypt:1;
    UINT8 encrypt:1;
    UINT8 audit:1;
};

typedef struct TPMA_STARTUP_CLEAR TPMA_STARTUP_CLEAR, *PTPMA_STARTUP_CLEAR;

struct TPMA_STARTUP_CLEAR {
    UINT32 phEnable:1;
    UINT32 shEnable:1;
    UINT32 ehEnable:1;
    UINT32 reserved3_30:28;
    UINT32 orderly:1;
};

typedef TPM_ALG_ID TPMI_ALG_ASYM;

typedef TPM_ALG_ID TPMI_ALG_RSA_DECRYPT;

typedef TPM_ALG_ID TPMI_ALG_SIG_SCHEME;

typedef TPM_ALG_ID TPMI_ALG_SYM;

typedef TPM_HANDLE TPMI_DH_CONTEXT;

typedef TPM_HANDLE TPMI_DH_ENTITY;

typedef TPM_HANDLE TPMI_DH_OBJECT;

typedef TPM_HANDLE TPMI_DH_PCR;

typedef TPM_HANDLE TPMI_DH_PERSISTENT;

typedef TPM_ALG_ID TPMI_ECC_KEY_EXCHANGE;

typedef TPM_HANDLE TPMI_RH_CLEAR;

typedef TPM_HANDLE TPMI_RH_ENDORSEMENT;

typedef TPM_HANDLE TPMI_RH_HIERARCHY;

typedef TPM_HANDLE TPMI_RH_HIERARCHY_AUTH;

typedef TPM_HANDLE TPMI_RH_LOCKOUT;

typedef TPM_HANDLE TPMI_RH_NV_AUTH;

typedef TPM_HANDLE TPMI_RH_OWNER;

typedef TPM_HANDLE TPMI_RH_PLATFORM;

typedef TPM_HANDLE TPMI_RH_PROVISION;

typedef TPM_HANDLE TPMI_SH_AUTH_SESSION;

typedef TPM_HANDLE TPMI_SH_HMAC;

typedef TPM_HANDLE TPMI_SH_POLICY;

typedef TPM_ST TPMI_ST_ATTEST;

typedef BYTE TPMI_YES_NO;

typedef struct TPML_ALG TPML_ALG, *PTPML_ALG;

struct TPML_ALG {
    UINT32 count;
    TPM_ALG_ID algorithms[64];
};

typedef struct TPML_ALG_PROPERTY TPML_ALG_PROPERTY, *PTPML_ALG_PROPERTY;

typedef struct TPMS_ALG_PROPERTY TPMS_ALG_PROPERTY, *PTPMS_ALG_PROPERTY;

struct TPMS_ALG_PROPERTY {
    TPM_ALG_ID alg;
    struct TPMA_ALGORITHM algProperties;
};

struct TPML_ALG_PROPERTY {
    UINT32 count;
    struct TPMS_ALG_PROPERTY algProperties[169];
};

typedef struct TPML_CC TPML_CC, *PTPML_CC;

struct TPML_CC {
    UINT32 count;
    TPM_CC commandCodes[254];
};

typedef struct TPML_CCA TPML_CCA, *PTPML_CCA;

struct TPML_CCA {
    UINT32 count;
    struct TPMA_CC commandAttributes[254];
};

typedef struct TPML_DIGEST TPML_DIGEST, *PTPML_DIGEST;

struct TPML_DIGEST {
    UINT32 count;
    struct TPM2B_DIGEST digests[8];
};

typedef struct TPML_DIGEST_VALUES TPML_DIGEST_VALUES, *PTPML_DIGEST_VALUES;

typedef struct TPMT_HA TPMT_HA, *PTPMT_HA;

typedef union TPMU_HA TPMU_HA, *PTPMU_HA;

union TPMU_HA {
    BYTE sha1[20];
    BYTE sha256[32];
    BYTE sm3_256[32];
    BYTE sha384[48];
    BYTE sha512[64];
};

struct TPMT_HA {
    TPMI_ALG_HASH hashAlg;
    union TPMU_HA digest;
};

struct TPML_DIGEST_VALUES {
    UINT32 count;
    struct TPMT_HA digests[5];
};

typedef struct TPML_ECC_CURVE TPML_ECC_CURVE, *PTPML_ECC_CURVE;

struct TPML_ECC_CURVE {
    UINT32 count;
    TPM_ECC_CURVE eccCurves[508];
};

typedef struct TPML_HANDLE TPML_HANDLE, *PTPML_HANDLE;

struct TPML_HANDLE {
    UINT32 count;
    TPM_HANDLE handle[254];
};

typedef struct TPML_TAGGED_PCR_PROPERTY TPML_TAGGED_PCR_PROPERTY, *PTPML_TAGGED_PCR_PROPERTY;

typedef struct TPMS_TAGGED_PCR_SELECT TPMS_TAGGED_PCR_SELECT, *PTPMS_TAGGED_PCR_SELECT;

struct TPMS_TAGGED_PCR_SELECT {
    TPM_PT tag;
    UINT8 sizeofSelect;
    BYTE pcrSelect[3];
};

struct TPML_TAGGED_PCR_PROPERTY {
    UINT32 count;
    struct TPMS_TAGGED_PCR_SELECT pcrProperty[127];
};

typedef struct TPML_TAGGED_TPM_PROPERTY TPML_TAGGED_TPM_PROPERTY, *PTPML_TAGGED_TPM_PROPERTY;

typedef struct TPMS_TAGGED_PROPERTY TPMS_TAGGED_PROPERTY, *PTPMS_TAGGED_PROPERTY;

struct TPMS_TAGGED_PROPERTY {
    TPM_PT property;
    UINT32 value;
};

struct TPML_TAGGED_TPM_PROPERTY {
    UINT32 count;
    struct TPMS_TAGGED_PROPERTY tpmProperty[127];
};

typedef struct TPMS_ALGORITHM_DESCRIPTION TPMS_ALGORITHM_DESCRIPTION, *PTPMS_ALGORITHM_DESCRIPTION;

struct TPMS_ALGORITHM_DESCRIPTION {
    TPM_ALG_ID alg;
    struct TPMA_ALGORITHM attributes;
};

typedef struct TPMS_ALGORITHM_DETAIL_ECC TPMS_ALGORITHM_DETAIL_ECC, *PTPMS_ALGORITHM_DETAIL_ECC;

struct TPMS_ALGORITHM_DETAIL_ECC {
    TPM_ECC_CURVE curveID;
    UINT16 keySize;
    struct TPMT_KDF_SCHEME kdf;
    struct TPMT_ECC_SCHEME sign;
    struct TPM2B_ECC_PARAMETER p;
    struct TPM2B_ECC_PARAMETER a;
    struct TPM2B_ECC_PARAMETER b;
    struct TPM2B_ECC_PARAMETER gX;
    struct TPM2B_ECC_PARAMETER gY;
    struct TPM2B_ECC_PARAMETER n;
    struct TPM2B_ECC_PARAMETER h;
};

typedef struct TPMS_ATTEST TPMS_ATTEST, *PTPMS_ATTEST;

typedef struct TPMS_CLOCK_INFO TPMS_CLOCK_INFO, *PTPMS_CLOCK_INFO;

typedef union TPMU_ATTEST TPMU_ATTEST, *PTPMU_ATTEST;

typedef struct TPMS_CERTIFY_INFO TPMS_CERTIFY_INFO, *PTPMS_CERTIFY_INFO;

typedef struct TPMS_CREATION_INFO TPMS_CREATION_INFO, *PTPMS_CREATION_INFO;

typedef struct TPMS_QUOTE_INFO TPMS_QUOTE_INFO, *PTPMS_QUOTE_INFO;

typedef struct TPMS_COMMAND_AUDIT_INFO TPMS_COMMAND_AUDIT_INFO, *PTPMS_COMMAND_AUDIT_INFO;

typedef struct TPMS_SESSION_AUDIT_INFO TPMS_SESSION_AUDIT_INFO, *PTPMS_SESSION_AUDIT_INFO;

typedef struct TPMS_TIME_ATTEST_INFO TPMS_TIME_ATTEST_INFO, *PTPMS_TIME_ATTEST_INFO;

typedef struct TPMS_NV_CERTIFY_INFO TPMS_NV_CERTIFY_INFO, *PTPMS_NV_CERTIFY_INFO;

typedef struct TPMS_TIME_INFO TPMS_TIME_INFO, *PTPMS_TIME_INFO;

struct TPMS_CERTIFY_INFO {
    struct TPM2B_NAME name;
    struct TPM2B_NAME qualifiedName;
};

struct TPMS_CLOCK_INFO {
    UINT64 clock;
    UINT32 resetCount;
    UINT32 restartCount;
    TPMI_YES_NO safe;
};

struct TPMS_TIME_INFO {
    UINT64 time;
    struct TPMS_CLOCK_INFO clockInfo;
};

struct TPMS_TIME_ATTEST_INFO {
    struct TPMS_TIME_INFO time;
    UINT64 firmwareVersion;
};

struct TPMS_COMMAND_AUDIT_INFO {
    UINT64 auditCounter;
    TPM_ALG_ID digestAlg;
    struct TPM2B_DIGEST auditDigest;
    struct TPM2B_DIGEST commandDigest;
};

struct TPMS_CREATION_INFO {
    struct TPM2B_NAME objectName;
    struct TPM2B_DIGEST creationHash;
};

struct TPMS_NV_CERTIFY_INFO {
    struct TPM2B_NAME indexName;
    UINT16 offset;
    struct TPM2B_MAX_NV_BUFFER nvContents;
};

struct TPMS_SESSION_AUDIT_INFO {
    TPMI_YES_NO exclusiveSession;
    struct TPM2B_DIGEST sessionDigest;
};

struct TPMS_QUOTE_INFO {
    struct TPML_PCR_SELECTION pcrSelect;
    struct TPM2B_DIGEST pcrDigest;
};

union TPMU_ATTEST {
    struct TPMS_CERTIFY_INFO certify;
    struct TPMS_CREATION_INFO creation;
    struct TPMS_QUOTE_INFO quote;
    struct TPMS_COMMAND_AUDIT_INFO commandAudit;
    struct TPMS_SESSION_AUDIT_INFO sessionAudit;
    struct TPMS_TIME_ATTEST_INFO time;
    struct TPMS_NV_CERTIFY_INFO nv;
};

struct TPMS_ATTEST {
    TPM_GENERATED magic;
    TPMI_ST_ATTEST type;
    struct TPM2B_NAME qualifiedSigner;
    struct TPM2B_DATA extraData;
    struct TPMS_CLOCK_INFO clockInfo;
    UINT64 firmwareVersion;
    union TPMU_ATTEST attested;
};

typedef struct TPMS_AUTH_COMMAND TPMS_AUTH_COMMAND, *PTPMS_AUTH_COMMAND;

struct TPMS_AUTH_COMMAND {
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2B_NONCE nonce;
    struct TPMA_SESSION sessionAttributes;
    TPM2B_AUTH hmac;
};

typedef struct TPMS_AUTH_RESPONSE TPMS_AUTH_RESPONSE, *PTPMS_AUTH_RESPONSE;

struct TPMS_AUTH_RESPONSE {
    TPM2B_NONCE nonce;
    struct TPMA_SESSION sessionAttributes;
    TPM2B_AUTH hmac;
};

typedef struct TPMS_CAPABILITY_DATA TPMS_CAPABILITY_DATA, *PTPMS_CAPABILITY_DATA;

typedef union TPMU_CAPABILITIES TPMU_CAPABILITIES, *PTPMU_CAPABILITIES;

union TPMU_CAPABILITIES {
    struct TPML_ALG_PROPERTY algorithms;
    struct TPML_HANDLE handles;
    struct TPML_CCA command;
    struct TPML_CC ppCommands;
    struct TPML_CC auditCommands;
    struct TPML_PCR_SELECTION assignedPCR;
    struct TPML_TAGGED_TPM_PROPERTY tpmProperties;
    struct TPML_TAGGED_PCR_PROPERTY pcrProperties;
    struct TPML_ECC_CURVE eccCurves;
};

struct TPMS_CAPABILITY_DATA {
    TPM_CAP capability;
    union TPMU_CAPABILITIES data;
};

typedef struct TPMS_CONTEXT TPMS_CONTEXT, *PTPMS_CONTEXT;

struct TPMS_CONTEXT {
    UINT64 sequence;
    TPMI_DH_CONTEXT savedHandle;
    TPMI_RH_HIERARCHY hierarchy;
    struct TPM2B_CONTEXT_DATA contextBlob;
};

typedef struct TPMS_CONTEXT_DATA TPMS_CONTEXT_DATA, *PTPMS_CONTEXT_DATA;

struct TPMS_CONTEXT_DATA {
    struct TPM2B_DIGEST integrity;
    struct TPM2B_CONTEXT_SENSITIVE encrypted;
};

typedef struct TPMS_PCR_SELECT TPMS_PCR_SELECT, *PTPMS_PCR_SELECT;

struct TPMS_PCR_SELECT {
    UINT8 sizeofSelect;
    BYTE pcrSelect[3];
};

typedef struct TPMS_SCHEME_ECDH TPMS_SCHEME_ECDH, *PTPMS_SCHEME_ECDH;

struct TPMS_SCHEME_ECDH {
    TPMI_ALG_HASH hashAlg;
};

typedef struct TPMS_SCHEME_SIGHASH TPMS_SCHEME_SM2;

typedef struct TPMS_SIGNATURE_ECDSA TPMS_SIGNATURE_ECDSA, *PTPMS_SIGNATURE_ECDSA;

struct TPMS_SIGNATURE_ECDSA {
    TPMI_ALG_HASH hash;
    struct TPM2B_ECC_PARAMETER signatureR;
    struct TPM2B_ECC_PARAMETER signatureS;
};

typedef struct TPMS_SIGNATURE_RSAPSS TPMS_SIGNATURE_RSAPSS, *PTPMS_SIGNATURE_RSAPSS;

struct TPMS_SIGNATURE_RSAPSS {
    TPMI_ALG_HASH hash;
    struct TPM2B_PUBLIC_KEY_RSA sig;
};

typedef struct TPMS_SIGNATURE_RSASSA TPMS_SIGNATURE_RSASSA, *PTPMS_SIGNATURE_RSASSA;

struct TPMS_SIGNATURE_RSASSA {
    TPMI_ALG_HASH hash;
    struct TPM2B_PUBLIC_KEY_RSA sig;
};

typedef struct TPMS_SYMCIPHER_PARMS TPMS_SYMCIPHER_PARMS, *PTPMS_SYMCIPHER_PARMS;

struct TPMS_SYMCIPHER_PARMS {
    struct TPMT_SYM_DEF_OBJECT sym;
};

typedef struct TPMT_PUBLIC_PARMS TPMT_PUBLIC_PARMS, *PTPMT_PUBLIC_PARMS;

struct TPMT_PUBLIC_PARMS {
    TPMI_ALG_PUBLIC type;
    union TPMU_PUBLIC_PARMS parameters;
};

typedef struct TPMT_RSA_DECRYPT TPMT_RSA_DECRYPT, *PTPMT_RSA_DECRYPT;

struct TPMT_RSA_DECRYPT {
    TPMI_ALG_RSA_DECRYPT scheme;
    union TPMU_ASYM_SCHEME details;
};

typedef struct TPMT_SIG_SCHEME TPMT_SIG_SCHEME, *PTPMT_SIG_SCHEME;

struct TPMT_SIG_SCHEME {
    TPMI_ALG_SIG_SCHEME scheme;
    union TPMU_SIG_SCHEME details;
};

typedef struct TPMT_SIGNATURE TPMT_SIGNATURE, *PTPMT_SIGNATURE;

typedef union TPMU_SIGNATURE TPMU_SIGNATURE, *PTPMU_SIGNATURE;

union TPMU_SIGNATURE {
    struct TPMS_SIGNATURE_RSASSA rsassa;
    struct TPMS_SIGNATURE_RSAPSS rsapss;
    struct TPMS_SIGNATURE_ECDSA ecdsa;
    struct TPMS_SIGNATURE_ECDSA sm2;
    struct TPMS_SIGNATURE_ECDSA ecdaa;
    struct TPMS_SIGNATURE_ECDSA ecschnorr;
    struct TPMT_HA hmac;
    struct TPMS_SCHEME_SIGHASH any;
};

struct TPMT_SIGNATURE {
    TPMI_ALG_SIG_SCHEME sigAlg;
    union TPMU_SIGNATURE signature;
};

typedef struct TPMT_SYM_DEF TPMT_SYM_DEF, *PTPMT_SYM_DEF;

struct TPMT_SYM_DEF {
    TPMI_ALG_SYM algorithm;
    union TPMU_SYM_KEY_BITS keyBits;
    union TPMU_SYM_MODE mode;
};

typedef struct TPMT_TK_AUTH TPMT_TK_AUTH, *PTPMT_TK_AUTH;

struct TPMT_TK_AUTH {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    struct TPM2B_DIGEST digest;
};

typedef struct TPMT_TK_CREATION TPMT_TK_CREATION, *PTPMT_TK_CREATION;

struct TPMT_TK_CREATION {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    struct TPM2B_DIGEST digest;
};

typedef struct TPMT_TK_HASHCHECK TPMT_TK_HASHCHECK, *PTPMT_TK_HASHCHECK;

struct TPMT_TK_HASHCHECK {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    struct TPM2B_DIGEST digest;
};

typedef struct TPMT_TK_VERIFIED TPMT_TK_VERIFIED, *PTPMT_TK_VERIFIED;

struct TPMT_TK_VERIFIED {
    TPM_ST tag;
    TPMI_RH_HIERARCHY hierarchy;
    struct TPM2B_DIGEST digest;
};

typedef union TPMU_ENCRYPTED_SECRET TPMU_ENCRYPTED_SECRET, *PTPMU_ENCRYPTED_SECRET;

union TPMU_ENCRYPTED_SECRET {
    BYTE ecc[68];
    BYTE rsa[256];
    BYTE symmetric[66];
    BYTE keyedHash[66];
};

typedef union TPMU_NAME TPMU_NAME, *PTPMU_NAME;

union TPMU_NAME {
    struct TPMT_HA digest;
    TPM_HANDLE handle;
};

typedef union TPMU_PUBLIC_ID TPMU_PUBLIC_ID, *PTPMU_PUBLIC_ID;

union TPMU_PUBLIC_ID {
    struct TPM2B_DIGEST keyedHash;
    struct TPM2B_DIGEST sym;
    struct TPM2B_PUBLIC_KEY_RSA rsa;
    struct TPMS_ECC_POINT ecc;
};

typedef char *va_list;

#define WINAPI_FAMILY 100

#define WINAPI_FAMILY_APP 2

#define WINAPI_FAMILY_DESKTOP_APP 100

#define WINAPI_FAMILY_PC_APP 2

#define WINAPI_FAMILY_PHONE_APP 3

#define WINAPI_FAMILY_SERVER 5

#define WINAPI_FAMILY_SYSTEM 4

#define WINAPI_PARTITION_DESKTOP 1

#define WINAPI_PARTITION_PC_APP 1

#define WINAPI_PARTITION_PHONE 0

#define WINAPI_PARTITION_PHONE_APP 0

typedef struct _BY_HANDLE_FILE_INFORMATION _BY_HANDLE_FILE_INFORMATION, *P_BY_HANDLE_FILE_INFORMATION;

struct _BY_HANDLE_FILE_INFORMATION {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
};

typedef enum _COMPUTER_NAME_FORMAT {
    ComputerNameNetBIOS=0,
    ComputerNameDnsHostname=1,
    ComputerNameDnsDomain=2,
    ComputerNameDnsFullyQualified=3,
    ComputerNamePhysicalNetBIOS=4,
    ComputerNamePhysicalDnsHostname=5,
    ComputerNamePhysicalDnsDomain=6,
    ComputerNamePhysicalDnsFullyQualified=7,
    ComputerNameMax=8
} _COMPUTER_NAME_FORMAT;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef union _union_540 _union_540, *P_union_540;

typedef struct _struct_541 _struct_541, *P_struct_541;

struct _struct_541 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_540 {
    struct _struct_541 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_540 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef struct _SYSTEMTIME SYSTEMTIME;

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

typedef enum _COMPUTER_NAME_FORMAT COMPUTER_NAME_FORMAT;

typedef struct _BY_HANDLE_FILE_INFORMATION *LPBY_HANDLE_FILE_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef struct _TIME_ZONE_INFORMATION *LPTIME_ZONE_INFORMATION;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _WIN32_FIND_DATAW *LPWIN32_FIND_DATAW;

typedef union _RTL_RUN_ONCE _RTL_RUN_ONCE, *P_RTL_RUN_ONCE;

typedef union _RTL_RUN_ONCE *PRTL_RUN_ONCE;

typedef PRTL_RUN_ONCE PINIT_ONCE;

union _RTL_RUN_ONCE {
    PVOID Ptr;
};

typedef BOOL (*PINIT_ONCE_FN)(PINIT_ONCE, PVOID, PVOID *);

typedef struct _RTL_SRWLOCK _RTL_SRWLOCK, *P_RTL_SRWLOCK;

typedef struct _RTL_SRWLOCK RTL_SRWLOCK;

typedef RTL_SRWLOCK *PSRWLOCK;

struct _RTL_SRWLOCK {
    PVOID Ptr;
};

typedef struct _SYSTEMTIME *PSYSTEMTIME;


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_CHAIN_CONTEXT - /CONFLICTS python2.h/_CERT_CHAIN_CONTEXT */


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_CHAIN_ELEMENT - /CONFLICTS python2.h/_CERT_CHAIN_ELEMENT */


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_CONTEXT - /CONFLICTS python2.h/_CERT_CONTEXT */


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_INFO - /CONFLICTS python2.h/_CERT_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_REVOCATION_CRL_INFO - /CONFLICTS python2.h/_CERT_REVOCATION_CRL_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_REVOCATION_INFO - /CONFLICTS python2.h/_CERT_REVOCATION_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_SIMPLE_CHAIN - /CONFLICTS python2.h/_CERT_SIMPLE_CHAIN */


/* WARNING! conflicting data type names: /wincrypt.h/_CERT_TRUST_LIST_INFO - /CONFLICTS python2.h/_CERT_TRUST_LIST_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/_CMSG_SIGNER_INFO - /CONFLICTS python2.h/_CMSG_SIGNER_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/_CRL_CONTEXT - /CONFLICTS python2.h/_CRL_CONTEXT */


/* WARNING! conflicting data type names: /wincrypt.h/_CRL_ENTRY - /CONFLICTS python2.h/_CRL_ENTRY */


/* WARNING! conflicting data type names: /wincrypt.h/_CRL_INFO - /CONFLICTS python2.h/_CRL_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/_CRYPT_ATTRIBUTE - /CONFLICTS python2.h/_CRYPT_ATTRIBUTE */


/* WARNING! conflicting data type names: /wincrypt.h/_CRYPT_ATTRIBUTES - /CONFLICTS python2.h/_CRYPT_ATTRIBUTES */


/* WARNING! conflicting data type names: /wincrypt.h/_CTL_CONTEXT - /CONFLICTS python2.h/_CTL_CONTEXT */


/* WARNING! conflicting data type names: /wincrypt.h/_CTL_ENTRY - /CONFLICTS python2.h/_CTL_ENTRY */


/* WARNING! conflicting data type names: /wincrypt.h/_CTL_INFO - /CONFLICTS python2.h/_CTL_INFO */

typedef union _union_1463 _union_1463, *P_union_1463;

union _union_1463 {
    DWORD dwNumBits;
    DWORD dwTableSize;
};

typedef union _union_1473 _union_1473, *P_union_1473;

union _union_1473 {
    DWORD dwPredefined;
    LPSTR pszObjId;
};

typedef union _union_1489 _union_1489, *P_union_1489;

union _union_1489 {
    DWORD dwValue;
    ALG_ID Algid;
    DWORD dwLength;
};

typedef union _union_1492 _union_1492, *P_union_1492;

union _union_1492 {
    CERT_ISSUER_SERIAL_NUMBER IssuerSerialNumber;
    CRYPT_HASH_BLOB KeyId;
    CRYPT_HASH_BLOB HashId;
};

typedef union _union_1524 _union_1524, *P_union_1524;

union _union_1524 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

typedef union _union_1547 _union_1547, *P_union_1547;

union _union_1547 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

typedef union _union_1551 _union_1551, *P_union_1551;

union _union_1551 {
    HKEY hKeyBase;
    void *pvBase;
};

typedef union _union_1552 _union_1552, *P_union_1552;

union _union_1552 {
    void *pvSystemStore;
    LPCSTR pszSystemStore;
    LPCWSTR pwszSystemStore;
};

typedef union _union_1578 _union_1578, *P_union_1578;

union _union_1578 {
    HCRYPTPROV hCryptProv;
    NCRYPT_KEY_HANDLE hNCryptKey;
};

typedef union _union_1615 _union_1615, *P_union_1615;

union _union_1615 {
    DWORD cbStruct;
    DWORD cbSize;
};

typedef struct _AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _PUBLICKEYSTRUC BLOBHEADER;

typedef CERT_STORE_PROV_FIND_INFO CCERT_STORE_PROV_FIND_INFO;

typedef struct _CRYPT_OID_INFO CRYPT_OID_INFO;

typedef CRYPT_OID_INFO CCRYPT_OID_INFO;

typedef struct _CERT_AUTHORITY_KEY_ID_INFO CERT_AUTHORITY_KEY_ID_INFO;

typedef struct _CERT_BASIC_CONSTRAINTS2_INFO CERT_BASIC_CONSTRAINTS2_INFO;

typedef struct _CERT_BASIC_CONSTRAINTS_INFO CERT_BASIC_CONSTRAINTS_INFO;

typedef struct _CERT_BIOMETRIC_DATA CERT_BIOMETRIC_DATA;


/* WARNING! conflicting data type names: /wincrypt.h/CERT_CHAIN_CONTEXT - /CONFLICTS python2.h/CERT_CHAIN_CONTEXT */

typedef struct _CERT_CHAIN_PARA CERT_CHAIN_PARA;

typedef struct _CERT_CHAIN_POLICY_PARA CERT_CHAIN_POLICY_PARA;

typedef struct _CERT_CHAIN_POLICY_STATUS CERT_CHAIN_POLICY_STATUS;


/* WARNING! conflicting data type names: /wincrypt.h/CERT_CONTEXT - /CONFLICTS python2.h/CERT_CONTEXT */

typedef struct _CERT_CREATE_CONTEXT_PARA CERT_CREATE_CONTEXT_PARA;

typedef struct _CERT_DH_PARAMETERS CERT_DH_PARAMETERS;

typedef struct _CERT_DSS_PARAMETERS CERT_DSS_PARAMETERS;

typedef struct _CERT_ECC_SIGNATURE CERT_ECC_SIGNATURE;

typedef struct _CERT_EXTENSION CERT_EXTENSION;

typedef struct _CERT_FORTEZZA_DATA_PROP CERT_FORTEZZA_DATA_PROP;

typedef struct _CERT_KEY_CONTEXT CERT_KEY_CONTEXT;

typedef struct _CERT_KEYGEN_REQUEST_INFO CERT_KEYGEN_REQUEST_INFO;

typedef struct _CERT_LDAP_STORE_OPENED_PARA CERT_LDAP_STORE_OPENED_PARA;

typedef struct _CERT_LOGOTYPE_AUDIO_INFO CERT_LOGOTYPE_AUDIO_INFO;

typedef struct _CERT_LOGOTYPE_IMAGE_INFO CERT_LOGOTYPE_IMAGE_INFO;

typedef struct _CERT_NAME_VALUE CERT_NAME_VALUE;

typedef struct _CERT_OR_CRL_BLOB CERT_OR_CRL_BLOB;

typedef struct _CERT_OTHER_NAME CERT_OTHER_NAME;

typedef struct _CERT_PAIR CERT_PAIR;

typedef struct _CERT_PHYSICAL_STORE_INFO CERT_PHYSICAL_STORE_INFO;

typedef struct _CERT_POLICY95_QUALIFIER1 CERT_POLICY95_QUALIFIER1;

typedef struct _CERT_POLICY_CONSTRAINTS_INFO CERT_POLICY_CONSTRAINTS_INFO;

typedef struct _CERT_POLICY_ID CERT_POLICY_ID;

typedef struct _CERT_POLICY_MAPPING CERT_POLICY_MAPPING;

typedef struct _CERT_POLICY_QUALIFIER_USER_NOTICE CERT_POLICY_QUALIFIER_USER_NOTICE;

typedef struct _CERT_PRIVATE_KEY_VALIDITY CERT_PRIVATE_KEY_VALIDITY;

typedef struct _CERT_QC_STATEMENT CERT_QC_STATEMENT;

typedef struct _CERT_RDN_ATTR CERT_RDN_ATTR;

typedef struct _CERT_REGISTRY_STORE_CLIENT_GPT_PARA CERT_REGISTRY_STORE_CLIENT_GPT_PARA;

typedef struct _CERT_REGISTRY_STORE_ROAMING_PARA CERT_REGISTRY_STORE_ROAMING_PARA;

typedef struct _CERT_REVOCATION_STATUS CERT_REVOCATION_STATUS;

typedef struct _CERT_SIGNED_CONTENT_INFO CERT_SIGNED_CONTENT_INFO;

typedef struct _CERT_STORE_PROV_INFO CERT_STORE_PROV_INFO;

typedef struct _CERT_SYSTEM_STORE_INFO CERT_SYSTEM_STORE_INFO;

typedef struct _CERT_SYSTEM_STORE_RELOCATE_PARA CERT_SYSTEM_STORE_RELOCATE_PARA;

typedef struct _CERT_TEMPLATE_EXT CERT_TEMPLATE_EXT;

typedef struct _CERT_X942_DH_VALIDATION_PARAMS CERT_X942_DH_VALIDATION_PARAMS;

typedef struct _CMC_PEND_INFO CMC_PEND_INFO;

typedef struct _CMC_TAGGED_CERT_REQUEST CMC_TAGGED_CERT_REQUEST;

typedef struct _CMC_TAGGED_CONTENT_INFO CMC_TAGGED_CONTENT_INFO;

typedef struct _CMC_TAGGED_OTHER_MSG CMC_TAGGED_OTHER_MSG;

typedef struct _CMS_DH_KEY_INFO CMS_DH_KEY_INFO;

typedef struct _CMS_KEY_INFO CMS_KEY_INFO;

typedef struct _CMSG_CNG_CONTENT_DECRYPT_INFO CMSG_CNG_CONTENT_DECRYPT_INFO;

typedef struct _CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA;

typedef struct _CMSG_CTRL_DECRYPT_PARA CMSG_CTRL_DECRYPT_PARA;

typedef struct _CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA;

typedef struct _CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA;

typedef struct _CMSG_ENCRYPTED_ENCODE_INFO CMSG_ENCRYPTED_ENCODE_INFO;

typedef struct _CMSG_HASHED_ENCODE_INFO CMSG_HASHED_ENCODE_INFO;

typedef struct _CMSG_KEY_AGREE_KEY_ENCRYPT_INFO CMSG_KEY_AGREE_KEY_ENCRYPT_INFO;

typedef struct _CMSG_KEY_TRANS_ENCRYPT_INFO CMSG_KEY_TRANS_ENCRYPT_INFO;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO;

typedef struct _CMSG_KEY_TRANS_RECIPIENT_INFO CMSG_KEY_TRANS_RECIPIENT_INFO;

typedef struct _CMSG_MAIL_LIST_ENCRYPT_INFO CMSG_MAIL_LIST_ENCRYPT_INFO;

typedef struct _CMSG_RC2_AUX_INFO CMSG_RC2_AUX_INFO;

typedef struct _CMSG_RC4_AUX_INFO CMSG_RC4_AUX_INFO;


/* WARNING! conflicting data type names: /wincrypt.h/CMSG_SIGNER_INFO - /CONFLICTS python2.h/CMSG_SIGNER_INFO */

typedef struct _CMSG_SP3_COMPATIBLE_AUX_INFO CMSG_SP3_COMPATIBLE_AUX_INFO;

typedef struct _CMSG_STREAM_INFO CMSG_STREAM_INFO;

typedef struct _CRYPTOAPI_BLOB CRL_BLOB;


/* WARNING! conflicting data type names: /wincrypt.h/CRL_CONTEXT - /CONFLICTS python2.h/CRL_CONTEXT */

typedef struct _CRYPT_AES_128_KEY_STATE CRYPT_AES_128_KEY_STATE;

typedef struct _CRYPT_AES_256_KEY_STATE CRYPT_AES_256_KEY_STATE;

typedef struct _CRYPT_ASYNC_RETRIEVAL_COMPLETION CRYPT_ASYNC_RETRIEVAL_COMPLETION;


/* WARNING! conflicting data type names: /wincrypt.h/CRYPT_ATTRIBUTES - /CONFLICTS python2.h/CRYPT_ATTRIBUTES */

typedef struct _CRYPT_CONTENT_INFO CRYPT_CONTENT_INFO;

typedef struct _CRYPT_CREDENTIALS CRYPT_CREDENTIALS;

typedef struct _CRYPT_CSP_PROVIDER CRYPT_CSP_PROVIDER;

typedef struct _CRYPT_DECODE_PARA CRYPT_DECODE_PARA;

typedef struct _CRYPT_DECRYPT_MESSAGE_PARA CRYPT_DECRYPT_MESSAGE_PARA;

typedef struct _CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA CRYPT_DEFAULT_CONTEXT_MULTI_OID_PARA;

typedef struct _CRYPT_ECC_CMS_SHARED_INFO CRYPT_ECC_CMS_SHARED_INFO;

typedef struct _CRYPT_ENCODE_PARA CRYPT_ENCODE_PARA;

typedef struct _CRYPT_ENCRYPT_MESSAGE_PARA CRYPT_ENCRYPT_MESSAGE_PARA;

typedef struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO CRYPT_ENCRYPTED_PRIVATE_KEY_INFO;

typedef struct _CRYPT_ENROLLMENT_NAME_VALUE_PAIR CRYPT_ENROLLMENT_NAME_VALUE_PAIR;

typedef struct _CRYPT_HASH_INFO CRYPT_HASH_INFO;

typedef struct _CRYPT_HASH_MESSAGE_PARA CRYPT_HASH_MESSAGE_PARA;

typedef struct _CRYPT_KEY_PROV_PARAM CRYPT_KEY_PROV_PARAM;

typedef struct _CRYPT_KEY_SIGN_MESSAGE_PARA CRYPT_KEY_SIGN_MESSAGE_PARA;

typedef struct _CRYPT_KEY_VERIFY_MESSAGE_PARA CRYPT_KEY_VERIFY_MESSAGE_PARA;

typedef struct _CRYPT_OBJID_TABLE CRYPT_OBJID_TABLE;

typedef struct _CRYPT_OID_FUNC_ENTRY CRYPT_OID_FUNC_ENTRY;

typedef struct _CRYPT_PASSWORD_CREDENTIALSA CRYPT_PASSWORD_CREDENTIALSA;

typedef CRYPT_PASSWORD_CREDENTIALSA CRYPT_PASSWORD_CREDENTIALS;

typedef struct _CRYPT_PASSWORD_CREDENTIALSW CRYPT_PASSWORD_CREDENTIALSW;

typedef struct _CRYPT_PKCS12_PBE_PARAMS CRYPT_PKCS12_PBE_PARAMS;

typedef struct _CRYPT_PKCS8_EXPORT_PARAMS CRYPT_PKCS8_EXPORT_PARAMS;

typedef struct _CRYPT_RC2_CBC_PARAMETERS CRYPT_RC2_CBC_PARAMETERS;

typedef struct _CRYPT_RSA_SSA_PSS_PARAMETERS CRYPT_RSA_SSA_PSS_PARAMETERS;

typedef struct _CRYPT_RSAES_OAEP_PARAMETERS CRYPT_RSAES_OAEP_PARAMETERS;

typedef struct _CRYPT_SMART_CARD_ROOT_INFO CRYPT_SMART_CARD_ROOT_INFO;

typedef struct _CRYPT_SMIME_CAPABILITY CRYPT_SMIME_CAPABILITY;

typedef struct _CRYPT_URL_ARRAY CRYPT_URL_ARRAY;

typedef struct _CRYPT_URL_INFO CRYPT_URL_INFO;

typedef struct _CRYPT_X942_OTHER_INFO CRYPT_X942_OTHER_INFO;

typedef struct _CRYPTNET_URL_CACHE_FLUSH_INFO CRYPTNET_URL_CACHE_FLUSH_INFO;

typedef struct _CRYPTNET_URL_CACHE_PRE_FETCH_INFO CRYPTNET_URL_CACHE_PRE_FETCH_INFO;

typedef struct _CRYPTNET_URL_CACHE_RESPONSE_INFO CRYPTNET_URL_CACHE_RESPONSE_INFO;

typedef struct _CRYPTPROTECT_PROMPTSTRUCT CRYPTPROTECT_PROMPTSTRUCT;

typedef struct _CTL_ANY_SUBJECT_INFO CTL_ANY_SUBJECT_INFO;


/* WARNING! conflicting data type names: /wincrypt.h/CTL_CONTEXT - /CONFLICTS python2.h/CTL_CONTEXT */

typedef struct _CTL_USAGE_MATCH CTL_USAGE_MATCH;

typedef struct _CTL_VERIFY_USAGE_PARA CTL_VERIFY_USAGE_PARA;

typedef struct _CRYPTOAPI_BLOB DATA_BLOB;

typedef struct _PRIVKEYVER3 DHPRIVKEY_VER3;

typedef struct _PUBKEY DHPUBKEY;

typedef struct _PUBKEYVER3 DHPUBKEY_VER3;

typedef struct _PRIVKEYVER3 DSSPRIVKEY_VER3;

typedef struct _PUBKEY DSSPUBKEY;

typedef struct _PUBKEYVER3 DSSPUBKEY_VER3;

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_PARA EV_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _EV_EXTRA_CERT_CHAIN_POLICY_STATUS EV_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef void *HCERT_SERVER_OCSP_RESPONSE;

typedef HANDLE HCRYPTASYNC;

typedef void *HCRYPTDEFAULTCONTEXT;

typedef ULONG_PTR HCRYPTHASH;

typedef void *HCRYPTOIDFUNCSET;

typedef ULONG_PTR HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;

typedef struct _HMAC_Info HMAC_INFO;

typedef struct _HTTPSPolicyCallbackData HTTPSPolicyCallbackData;

typedef struct _PUBKEY KEAPUBKEY;

typedef struct _OCSP_BASIC_REVOKED_INFO OCSP_BASIC_REVOKED_INFO;

typedef struct _OCSP_RESPONSE_INFO OCSP_RESPONSE_INFO;


/* WARNING! conflicting data type names: /wincrypt.h/PCCERT_CHAIN_CONTEXT - /CONFLICTS python2.h/PCCERT_CHAIN_CONTEXT */


/* WARNING! conflicting data type names: /wincrypt.h/PCCERT_CONTEXT - /CONFLICTS python2.h/PCCERT_CONTEXT */

typedef CERT_ENHKEY_USAGE *PCCERT_ENHKEY_USAGE;

typedef CERT_EXTENSION *PCCERT_EXTENSION;


/* WARNING! conflicting data type names: /wincrypt.h/PCCRL_CONTEXT - /CONFLICTS python2.h/PCCRL_CONTEXT */

typedef CRYPT_OID_INFO *PCCRYPT_OID_INFO;


/* WARNING! conflicting data type names: /wincrypt.h/PCCTL_CONTEXT - /CONFLICTS python2.h/PCCTL_CONTEXT */

typedef CTL_USAGE *PCCTL_USAGE;


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_CHAIN_ELEMENT - /CONFLICTS python2.h/PCERT_CHAIN_ELEMENT */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_CHAIN_POLICY_PARA - /CONFLICTS python2.h/PCERT_CHAIN_POLICY_PARA */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_CHAIN_POLICY_STATUS - /CONFLICTS python2.h/PCERT_CHAIN_POLICY_STATUS */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_ENHKEY_USAGE - /CONFLICTS python2.h/PCERT_ENHKEY_USAGE */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_EXTENSION - /CONFLICTS python2.h/PCERT_EXTENSION */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_INFO - /CONFLICTS python2.h/PCERT_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_PUBLIC_KEY_INFO - /CONFLICTS python2.h/PCERT_PUBLIC_KEY_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_REVOCATION_CRL_INFO - /CONFLICTS python2.h/PCERT_REVOCATION_CRL_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_REVOCATION_INFO - /CONFLICTS python2.h/PCERT_REVOCATION_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_SIMPLE_CHAIN - /CONFLICTS python2.h/PCERT_SIMPLE_CHAIN */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_TRUST_LIST_INFO - /CONFLICTS python2.h/PCERT_TRUST_LIST_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/PCERT_USAGE_MATCH - /CONFLICTS python2.h/PCERT_USAGE_MATCH */


/* WARNING! conflicting data type names: /wincrypt.h/PCRL_ENTRY - /CONFLICTS python2.h/PCRL_ENTRY */


/* WARNING! conflicting data type names: /wincrypt.h/PCRL_INFO - /CONFLICTS python2.h/PCRL_INFO */


/* WARNING! conflicting data type names: /wincrypt.h/PCRYPT_ATTR_BLOB - /CONFLICTS python2.h/PCRYPT_ATTR_BLOB */


/* WARNING! conflicting data type names: /wincrypt.h/PCRYPT_ATTRIBUTE - /CONFLICTS python2.h/PCRYPT_ATTRIBUTE */


/* WARNING! conflicting data type names: /wincrypt.h/PCRYPT_DECODE_PARA - /CONFLICTS python2.h/PCRYPT_DECODE_PARA */


/* WARNING! conflicting data type names: /wincrypt.h/PCTL_ENTRY - /CONFLICTS python2.h/PCTL_ENTRY */


/* WARNING! conflicting data type names: /wincrypt.h/PCTL_INFO - /CONFLICTS python2.h/PCTL_INFO */

typedef BOOL (*PFN_CANCEL_ASYNC_RETRIEVAL_FUNC)(HCRYPTASYNC);

typedef BOOL (*PFN_CERT_ENUM_SYSTEM_STORE_LOCATION)(LPCWSTR, DWORD, void *, void *);

typedef void (*PFN_CERT_STORE_PROV_CLOSE)(HCERTSTOREPROV, DWORD);

typedef BOOL (*PFN_CERT_STORE_PROV_CONTROL)(HCERTSTOREPROV, DWORD, DWORD, void *);

typedef void (*PFN_CRYPT_ASYNC_PARAM_FREE_FUNC)(LPSTR, LPVOID);

typedef BOOL (*PFN_CRYPT_CANCEL_RETRIEVAL)(DWORD, void *);

typedef BOOL (*PFN_CRYPT_ENUM_KEYID_PROP)(CRYPT_HASH_BLOB *, DWORD, void *, void *, DWORD, DWORD *, void **, DWORD *);

typedef BOOL (*PFN_CRYPT_ENUM_OID_FUNC)(DWORD, LPCSTR, LPCSTR, DWORD, DWORD *, LPCWSTR *, BYTE **, DWORD *, void *);

typedef BOOL (*PFN_CRYPT_ENUM_OID_INFO)(PCCRYPT_OID_INFO, void *);

typedef HANDLE *PHCRYPTASYNC;

typedef struct _PROV_ENUMALGS PROV_ENUMALGS;

typedef struct _PROV_ENUMALGS_EX PROV_ENUMALGS_EX;

typedef struct _PUBLICKEYSTRUC PUBLICKEYSTRUC;

typedef struct _RSAPUBKEY RSAPUBKEY;

typedef struct _SCHANNEL_ALG SCHANNEL_ALG;

typedef struct _HTTPSPolicyCallbackData SSL_EXTRA_CERT_CHAIN_POLICY_PARA;

typedef struct _PUBKEY TEKPUBKEY;

typedef INT_PTR (*FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HANDLE HLOCAL;

typedef HINSTANCE HMODULE;

typedef BOOL *LPBOOL;

typedef BYTE *LPBYTE;

typedef void *LPCVOID;

typedef DWORD *LPDWORD;

typedef long *LPLONG;

typedef BOOL *PBOOL;

typedef HKEY *PHKEY;

typedef int *PINT;

typedef uint *PUINT;

typedef USHORT *PUSHORT;

typedef struct _ACL _ACL, *P_ACL;

struct _ACL {
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
};

typedef struct _ACTIVATION_CONTEXT _ACTIVATION_CONTEXT, *P_ACTIVATION_CONTEXT;

struct _ACTIVATION_CONTEXT {
};

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_238 _union_238, *P_union_238;

union _union_238 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_238 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef union _union_61 _union_61, *P_union_61;

typedef union _union_63 _union_63, *P_union_63;

typedef struct _M128A *PM128A;

typedef struct _struct_62 _struct_62, *P_struct_62;

typedef struct _struct_64 _struct_64, *P_struct_64;

struct _struct_62 {
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

union _union_61 {
    PM128A FloatingContext[16];
    struct _struct_62 s;
};

struct _struct_64 {
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_63 {
    PDWORD64 IntegerContext[16];
    struct _struct_64 s;
};

struct _KNONVOLATILE_CONTEXT_POINTERS {
    union _union_61 u;
    union _union_63 u2;
};


/* WARNING! conflicting data type names: /winnt.h/_LARGE_INTEGER - /ntdef.h/_LARGE_INTEGER */


/* WARNING! conflicting data type names: /winnt.h/_LUID - /ntdef.h/_LUID */

typedef struct _LUID_AND_ATTRIBUTES _LUID_AND_ATTRIBUTES, *P_LUID_AND_ATTRIBUTES;


/* WARNING! conflicting data type names: /winnt.h/LUID - /ntdef.h/LUID */

struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    DWORD Attributes;
};

typedef struct _OSVERSIONINFOW _OSVERSIONINFOW, *P_OSVERSIONINFOW;

struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
};

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous=0,
    SecurityIdentification=1,
    SecurityImpersonation=2,
    SecurityDelegation=3
} _SECURITY_IMPERSONATION_LEVEL;

typedef struct _SID_IDENTIFIER_AUTHORITY _SID_IDENTIFIER_AUTHORITY, *P_SID_IDENTIFIER_AUTHORITY;

struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
};

typedef struct _struct_19 _struct_19, *P_struct_19;

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

typedef struct _struct_402 _struct_402, *P_struct_402;

struct _struct_402 {
    DWORD LongFunction:1;
    DWORD Persistent:1;
    DWORD Private:30;
};

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser=1,
    TokenGroups=2,
    TokenPrivileges=3,
    TokenOwner=4,
    TokenPrimaryGroup=5,
    TokenDefaultDacl=6,
    TokenSource=7,
    TokenType=8,
    TokenImpersonationLevel=9,
    TokenStatistics=10,
    TokenRestrictedSids=11,
    TokenSessionId=12,
    TokenGroupsAndPrivileges=13,
    TokenSessionReference=14,
    TokenSandBoxInert=15,
    TokenAuditPolicy=16,
    TokenOrigin=17,
    TokenElevationType=18,
    TokenLinkedToken=19,
    TokenElevation=20,
    TokenHasRestrictions=21,
    TokenAccessInformation=22,
    TokenVirtualizationAllowed=23,
    TokenVirtualizationEnabled=24,
    TokenIntegrityLevel=25,
    TokenUIAccess=26,
    TokenMandatoryPolicy=27,
    TokenLogonSid=28,
    MaxTokenInfoClass=29
} _TOKEN_INFORMATION_CLASS;

typedef struct _TOKEN_PRIVILEGES _TOKEN_PRIVILEGES, *P_TOKEN_PRIVILEGES;

typedef struct _LUID_AND_ATTRIBUTES LUID_AND_ATTRIBUTES;

struct _TOKEN_PRIVILEGES {
    DWORD PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
};

typedef enum _TOKEN_TYPE {
    TokenPrimary=1,
    TokenImpersonation=2
} _TOKEN_TYPE;

typedef struct _TP_CALLBACK_ENVIRON_V3 _TP_CALLBACK_ENVIRON_V3, *P_TP_CALLBACK_ENVIRON_V3;

typedef DWORD TP_VERSION;

typedef struct _TP_POOL _TP_POOL, *P_TP_POOL;

typedef struct _TP_POOL *PTP_POOL;

typedef struct _TP_CLEANUP_GROUP _TP_CLEANUP_GROUP, *P_TP_CLEANUP_GROUP;

typedef struct _TP_CLEANUP_GROUP *PTP_CLEANUP_GROUP;

typedef void (*PTP_CLEANUP_GROUP_CANCEL_CALLBACK)(PVOID, PVOID);

typedef struct _TP_CALLBACK_INSTANCE _TP_CALLBACK_INSTANCE, *P_TP_CALLBACK_INSTANCE;

typedef struct _TP_CALLBACK_INSTANCE *PTP_CALLBACK_INSTANCE;

typedef void (*PTP_SIMPLE_CALLBACK)(PTP_CALLBACK_INSTANCE, PVOID);

typedef union _union_401 _union_401, *P_union_401;

typedef enum _TP_CALLBACK_PRIORITY {
    TP_CALLBACK_PRIORITY_HIGH=0,
    TP_CALLBACK_PRIORITY_NORMAL=1,
    TP_CALLBACK_PRIORITY_LOW=2,
    TP_CALLBACK_PRIORITY_INVALID=3
} _TP_CALLBACK_PRIORITY;

typedef enum _TP_CALLBACK_PRIORITY TP_CALLBACK_PRIORITY;

struct _TP_CLEANUP_GROUP {
};

union _union_401 {
    DWORD Flags;
    struct _struct_402 s;
};

struct _TP_CALLBACK_ENVIRON_V3 {
    TP_VERSION Version;
    PTP_POOL Pool;
    PTP_CLEANUP_GROUP CleanupGroup;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
    PVOID RaceDll;
    struct _ACTIVATION_CONTEXT *ActivationContext;
    PTP_SIMPLE_CALLBACK FinalizationCallback;
    union _union_401 u;
    TP_CALLBACK_PRIORITY CallbackPriority;
    DWORD Size;
};

struct _TP_CALLBACK_INSTANCE {
};

struct _TP_POOL {
};

typedef struct _TP_TIMER _TP_TIMER, *P_TP_TIMER;

struct _TP_TIMER {
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _RUNTIME_FUNCTION *PRUNTIME_FUNCTION;

struct _UNWIND_HISTORY_TABLE_ENTRY {
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef DWORD ACCESS_MASK;

typedef struct _ACL ACL;


/* WARNING! conflicting data type names: /winnt.h/BOOLEAN - /ntdef.h/BOOLEAN */

typedef ULONGLONG DWORDLONG;


/* WARNING! conflicting data type names: /winnt.h/EXCEPTION_ROUTINE - /ntdef.h/EXCEPTION_ROUTINE */

typedef struct _FLOAT128 FLOAT128;


/* WARNING! conflicting data type names: /winnt.h/LARGE_INTEGER - /ntdef.h/LARGE_INTEGER */

typedef CHAR *LPCCH;

typedef CHAR *LPCH;

typedef LPCCH LPCTCH;

typedef LPCSTR LPCTSTR;

typedef LPCSTR LPCUTSTR;

typedef WCHAR *LPCUWCHAR;

typedef WCHAR *LPCUWSTR;

typedef WCHAR *LPCWCH;

typedef WCHAR *LPCWCHAR;

typedef struct _OSVERSIONINFOW *LPOSVERSIONINFOW;

typedef LPCH LPTCH;

typedef LPSTR LPTSTR;

typedef LPSTR LPUTSTR;

typedef WCHAR *LPUWSTR;

typedef WCHAR *LPWCH;

typedef CHAR *NPSTR;

typedef WCHAR *NWPSTR;

typedef ACL *PACL;

typedef CHAR *PCCH;

typedef CHAR *PCH;

typedef CHAR *PCHAR;

typedef CHAR *PCNZCH;

typedef PCNZCH PCNZTCH;

typedef WCHAR *PCNZWCH;

typedef LPCCH PCTCH;

typedef LPCSTR PCTSTR;

typedef ulong UCSCHAR;

typedef UCSCHAR *PCUCSCHAR;

typedef UCSCHAR *PCUCSSTR;

typedef PCNZCH PCUNZTCH;

typedef WCHAR *PCUNZWCH;

typedef LPCSTR PCUTSTR;

typedef UCSCHAR *PCUUCSCHAR;

typedef UCSCHAR *PCUUCSSTR;

typedef WCHAR *PCUWCHAR;

typedef WCHAR *PCUWSTR;

typedef CHAR *PCZZSTR;

typedef PCZZSTR PCUZZTSTR;

typedef WCHAR *PCUZZWSTR;

typedef WCHAR *PCWCH;

typedef WCHAR *PCWCHAR;

typedef PSTR *PCZPSTR;

typedef PWSTR *PCZPWSTR;

typedef PCZZSTR PCZZTSTR;

typedef WCHAR *PCZZWSTR;

typedef DWORDLONG *PDWORDLONG;


/* WARNING! conflicting data type names: /winnt.h/PEXCEPTION_ROUTINE - /ntdef.h/PEXCEPTION_ROUTINE */

typedef FLOAT128 *PFLOAT128;

typedef HANDLE *PHANDLE;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS *PKNONVOLATILE_CONTEXT_POINTERS;


/* WARNING! conflicting data type names: /winnt.h/PLARGE_INTEGER - /ntdef.h/PLARGE_INTEGER */

typedef LONG *PLONG;

typedef LONGLONG *PLONGLONG;

typedef CHAR *PNZCH;

typedef PNZCH PNZTCH;

typedef WCHAR *PNZWCH;

typedef PVOID PSECURITY_DESCRIPTOR;

typedef SHORT *PSHORT;

typedef PVOID PSID;

typedef struct _SID_IDENTIFIER_AUTHORITY *PSID_IDENTIFIER_AUTHORITY;

typedef LPCH PTCH;

typedef char *PTCHAR;

typedef struct _TOKEN_PRIVILEGES *PTOKEN_PRIVILEGES;

typedef struct _TP_CALLBACK_ENVIRON_V3 TP_CALLBACK_ENVIRON_V3;

typedef TP_CALLBACK_ENVIRON_V3 *PTP_CALLBACK_ENVIRON;

typedef struct _TP_TIMER *PTP_TIMER;

typedef void (*PTP_TIMER_CALLBACK)(PTP_CALLBACK_INSTANCE, PVOID, PTP_TIMER);

typedef LPSTR PTSTR;

typedef UCSCHAR *PUCSCHAR;

typedef UCSCHAR *PUCSSTR;

typedef ULONGLONG *PULONGLONG;

typedef struct _UNWIND_HISTORY_TABLE *PUNWIND_HISTORY_TABLE;

typedef PNZCH PUNZTCH;

typedef WCHAR *PUNZWCH;

typedef LPSTR PUTSTR;

typedef UCSCHAR *PUUCSCHAR;

typedef UCSCHAR *PUUCSSTR;

typedef WCHAR *PUWSTR;

typedef CHAR *PZZSTR;

typedef PZZSTR PUZZTSTR;

typedef WCHAR *PUZZWSTR;

typedef void *PVOID64;

typedef WCHAR *PWCH;

typedef WCHAR *PWCHAR;

typedef PCSTR *PZPCSTR;

typedef PCWSTR *PZPCWSTR;

typedef PWSTR *PZPWSTR;

typedef PZZSTR PZZTSTR;

typedef WCHAR *PZZWSTR;

typedef enum _SECURITY_IMPERSONATION_LEVEL SECURITY_IMPERSONATION_LEVEL;

typedef DWORD SECURITY_INFORMATION;

typedef char TCHAR;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

typedef enum _TOKEN_TYPE TOKEN_TYPE;

typedef LONGLONG USN;

#define WINAPI_PARTITION_PKG_APPRUNTIME 0

#define WINAPI_PARTITION_PKG_BOOTABLESKU 0

#define WINAPI_PARTITION_PKG_CMD 0

#define WINAPI_PARTITION_PKG_CMDTOOLS 0

#define WINAPI_PARTITION_PKG_CORESETUP 0

#define WINAPI_PARTITION_PKG_DISM 0

#define WINAPI_PARTITION_PKG_ESENT 0

#define WINAPI_PARTITION_PKG_EVENTLOGSERVICE 0

#define WINAPI_PARTITION_PKG_PERFCOUNTER 0

#define WINAPI_PARTITION_PKG_REMOTEFS 0

#define WINAPI_PARTITION_PKG_SECURESTARTUP 0

#define WINAPI_PARTITION_PKG_VHD 0

#define WINAPI_PARTITION_PKG_WEBSERVICES 0

#define WINAPI_PARTITION_PKG_WINMGMT 0

#define WINAPI_PARTITION_PKG_WINTRUST 0

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef struct _CRYPT_PROVIDER_CERT _CRYPT_PROVIDER_CERT, *P_CRYPT_PROVIDER_CERT;

struct _CRYPT_PROVIDER_CERT {
    DWORD cbStruct;
    PCCERT_CONTEXT pCert;
    BOOL fCommercial;
    BOOL fTrustedRoot;
    BOOL fSelfSigned;
    BOOL fTestCert;
    DWORD dwRevokedReason;
    DWORD dwConfidence;
    DWORD dwError;
    CTL_CONTEXT *pTrustListContext;
    BOOL fTrustListSignerCert;
    PCCTL_CONTEXT pCtlContext;
    DWORD dwCtlError;
    BOOL fIsCyclic;
    PCERT_CHAIN_ELEMENT pChainElement;
};

typedef struct _CRYPT_PROVIDER_DATA _CRYPT_PROVIDER_DATA, *P_CRYPT_PROVIDER_DATA;

typedef struct _WINTRUST_DATA _WINTRUST_DATA, *P_WINTRUST_DATA;

typedef struct _WINTRUST_DATA WINTRUST_DATA;

typedef struct _CRYPT_PROVIDER_FUNCTIONS _CRYPT_PROVIDER_FUNCTIONS, *P_CRYPT_PROVIDER_FUNCTIONS;

typedef struct _CRYPT_PROVIDER_SGNR _CRYPT_PROVIDER_SGNR, *P_CRYPT_PROVIDER_SGNR;

typedef struct _CRYPT_PROVIDER_PRIVDATA _CRYPT_PROVIDER_PRIVDATA, *P_CRYPT_PROVIDER_PRIVDATA;

typedef union _union_5426 _union_5426, *P_union_5426;

typedef union _union_5394 _union_5394, *P_union_5394;

typedef void * (*PFN_CPD_MEM_ALLOC)(DWORD);

typedef void (*PFN_CPD_MEM_FREE)(void *);

typedef BOOL (*PFN_CPD_ADD_STORE)(struct _CRYPT_PROVIDER_DATA *, HCERTSTORE);

typedef BOOL (*PFN_CPD_ADD_SGNR)(struct _CRYPT_PROVIDER_DATA *, BOOL, DWORD, struct _CRYPT_PROVIDER_SGNR *);

typedef BOOL (*PFN_CPD_ADD_CERT)(struct _CRYPT_PROVIDER_DATA *, DWORD, BOOL, DWORD, PCCERT_CONTEXT);

typedef BOOL (*PFN_CPD_ADD_PRIVDATA)(struct _CRYPT_PROVIDER_DATA *, struct _CRYPT_PROVIDER_PRIVDATA *);

typedef HRESULT (*PFN_PROVIDER_INIT_CALL)(struct _CRYPT_PROVIDER_DATA *);

typedef HRESULT (*PFN_PROVIDER_OBJTRUST_CALL)(struct _CRYPT_PROVIDER_DATA *);

typedef HRESULT (*PFN_PROVIDER_SIGTRUST_CALL)(struct _CRYPT_PROVIDER_DATA *);

typedef HRESULT (*PFN_PROVIDER_CERTTRUST_CALL)(struct _CRYPT_PROVIDER_DATA *);

typedef HRESULT (*PFN_PROVIDER_FINALPOLICY_CALL)(struct _CRYPT_PROVIDER_DATA *);

typedef BOOL (*PFN_PROVIDER_CERTCHKPOLICY_CALL)(struct _CRYPT_PROVIDER_DATA *, DWORD, BOOL, DWORD);

typedef HRESULT (*PFN_PROVIDER_TESTFINALPOLICY_CALL)(struct _CRYPT_PROVIDER_DATA *);

typedef struct _CRYPT_PROVUI_FUNCS _CRYPT_PROVUI_FUNCS, *P_CRYPT_PROVUI_FUNCS;

typedef HRESULT (*PFN_PROVIDER_CLEANUP_CALL)(struct _CRYPT_PROVIDER_DATA *);

typedef struct _PROVDATA_SIP _PROVDATA_SIP, *P_PROVDATA_SIP;

typedef struct WINTRUST_FILE_INFO_ WINTRUST_FILE_INFO_, *PWINTRUST_FILE_INFO_;

typedef struct WINTRUST_CATALOG_INFO_ WINTRUST_CATALOG_INFO_, *PWINTRUST_CATALOG_INFO_;

typedef struct WINTRUST_BLOB_INFO_ WINTRUST_BLOB_INFO_, *PWINTRUST_BLOB_INFO_;

typedef struct WINTRUST_SGNR_INFO_ WINTRUST_SGNR_INFO_, *PWINTRUST_SGNR_INFO_;

typedef struct WINTRUST_CERT_INFO_ WINTRUST_CERT_INFO_, *PWINTRUST_CERT_INFO_;

typedef struct _CRYPT_PROVUI_DATA _CRYPT_PROVUI_DATA, *P_CRYPT_PROVUI_DATA;

typedef BOOL (*PFN_PROVUI_CALL)(HWND, struct _CRYPT_PROVIDER_DATA *);

union _union_5394 {
    struct WINTRUST_FILE_INFO_ *pFile;
    struct WINTRUST_CATALOG_INFO_ *pCatalog;
    struct WINTRUST_BLOB_INFO_ *pBlob;
    struct WINTRUST_SGNR_INFO_ *pSgnr;
    struct WINTRUST_CERT_INFO_ *pCert;
};

struct _WINTRUST_DATA {
    DWORD cbStruct;
    LPVOID pPolicyCallbackData;
    LPVOID pSIPClientData;
    DWORD dwUIChoice;
    DWORD fdwRevocationChecks;
    DWORD dwUnionChoice;
    union _union_5394 field6_0x28;
    DWORD dwStateAction;
    HANDLE hWVTStateData;
    WCHAR *pwszURLReference;
    DWORD dwProvFlags;
    DWORD dwUIContext;
};

struct _CRYPT_PROVUI_FUNCS {
    DWORD cbStruct;
    struct _CRYPT_PROVUI_DATA *psUIData;
    PFN_PROVUI_CALL pfnOnMoreInfoClick;
    PFN_PROVUI_CALL pfnOnMoreInfoClickDefault;
    PFN_PROVUI_CALL pfnOnAdvancedClick;
    PFN_PROVUI_CALL pfnOnAdvancedClickDefault;
};

struct _PROVDATA_SIP {
    DWORD cbStruct;
    GUID gSubject;
    struct SIP_DISPATCH_INFO_ *pSip;
    struct SIP_DISPATCH_INFO_ *pCATSip;
    struct SIP_SUBJECTINFO_ *psSipSubjectInfo;
    struct SIP_SUBJECTINFO_ *psSipCATSubjectInfo;
    struct SIP_INDIRECT_DATA_ *psIndirectData;
};

struct _CRYPT_PROVUI_DATA {
    DWORD cbStruct;
    DWORD dwFinalError;
    WCHAR *pYesButtonText;
    WCHAR *pNoButtonText;
    WCHAR *pMoreInfoButtonText;
    WCHAR *pAdvancedLinkText;
    WCHAR *pCopyActionText;
    WCHAR *pCopyActionTextNoTS;
    WCHAR *pCopyActionTextNotSigned;
};

union _union_5426 {
    struct _PROVDATA_SIP *pPDSip;
};

struct _CRYPT_PROVIDER_DATA {
    DWORD cbStruct;
    WINTRUST_DATA *pWintrustData;
    BOOL fOpenedFile;
    HWND hWndParent;
    GUID *pgActionID;
    HCRYPTPROV hProv;
    DWORD dwError;
    DWORD dwRegSecuritySettings;
    DWORD dwRegPolicySettings;
    struct _CRYPT_PROVIDER_FUNCTIONS *psPfns;
    DWORD cdwTrustStepErrors;
    DWORD *padwTrustStepErrors;
    DWORD chStores;
    HCERTSTORE *pahStores;
    DWORD dwEncoding;
    HCRYPTMSG hMsg;
    DWORD csSigners;
    struct _CRYPT_PROVIDER_SGNR *pasSigners;
    DWORD csProvPrivData;
    struct _CRYPT_PROVIDER_PRIVDATA *pasProvPrivData;
    DWORD dwSubjectChoice;
    union _union_5426 field21_0xa0;
    char *pszUsageOID;
    BOOL fRecallWithState;
    FILETIME sftSystemTime;
    char *pszCTLSignerUsageOID;
    DWORD dwProvFlags;
    DWORD dwFinalError;
    PCERT_USAGE_MATCH pRequestUsage;
    DWORD dwTrustPubSettings;
    DWORD dwUIStateFlags;
};

struct WINTRUST_FILE_INFO_ {
    DWORD cbStruct;
    LPCWSTR pcwszFilePath;
    HANDLE hFile;
    GUID *pgKnownSubject;
};

struct _CRYPT_PROVIDER_FUNCTIONS {
    DWORD cbStruct;
    PFN_CPD_MEM_ALLOC pfnAlloc;
    PFN_CPD_MEM_FREE pfnFree;
    PFN_CPD_ADD_STORE pfnAddStore2Chain;
    PFN_CPD_ADD_SGNR pfnAddSgnr2Chain;
    PFN_CPD_ADD_CERT pfnAddCert2Chain;
    PFN_CPD_ADD_PRIVDATA pfnAddPrivData2Chain;
    PFN_PROVIDER_INIT_CALL pfnInitialize;
    PFN_PROVIDER_OBJTRUST_CALL pfnObjectTrust;
    PFN_PROVIDER_SIGTRUST_CALL pfnSignatureTrust;
    PFN_PROVIDER_CERTTRUST_CALL pfnCertificateTrust;
    PFN_PROVIDER_FINALPOLICY_CALL pfnFinalPolicy;
    PFN_PROVIDER_CERTCHKPOLICY_CALL pfnCertCheckPolicy;
    PFN_PROVIDER_TESTFINALPOLICY_CALL pfnTestFinalPolicy;
    struct _CRYPT_PROVUI_FUNCS *psUIpfns;
    PFN_PROVIDER_CLEANUP_CALL pfnCleanupPolicy;
};

struct _CRYPT_PROVIDER_PRIVDATA {
    DWORD cbStruct;
    GUID gProviderID;
    DWORD cbProvData;
    void *pvProvData;
};

struct WINTRUST_CATALOG_INFO_ {
    DWORD cbStruct;
    DWORD dwCatalogVersion;
    LPCWSTR pcwszCatalogFilePath;
    LPCWSTR pcwszMemberTag;
    LPCWSTR pcwszMemberFilePath;
    HANDLE hMemberFile;
    BYTE *pbCalculatedFileHash;
    DWORD cbCalculatedFileHash;
    PCCTL_CONTEXT pcCatalogContext;
};

struct _CRYPT_PROVIDER_SGNR {
    DWORD cbStruct;
    FILETIME sftVerifyAsOf;
    DWORD csCertChain;
    struct _CRYPT_PROVIDER_CERT *pasCertChain;
    DWORD dwSignerType;
    CMSG_SIGNER_INFO *psSigner;
    DWORD dwError;
    DWORD csCounterSigners;
    struct _CRYPT_PROVIDER_SGNR *pasCounterSigners;
    PCCERT_CHAIN_CONTEXT pChainContext;
};

struct WINTRUST_CERT_INFO_ {
    DWORD cbStruct;
    LPCWSTR pcwszDisplayName;
    CERT_CONTEXT *psCertContext;
    DWORD chStores;
    HCERTSTORE *pahStores;
    DWORD dwFlags;
    FILETIME *psftVerifyAsOf;
};

struct WINTRUST_SGNR_INFO_ {
    DWORD cbStruct;
    LPCWSTR pcwszDisplayName;
    CMSG_SIGNER_INFO *psSignerInfo;
    DWORD chStores;
    HCERTSTORE *pahStores;
};

struct WINTRUST_BLOB_INFO_ {
    DWORD cbStruct;
    GUID gSubject;
    LPCWSTR pcwszDisplayName;
    DWORD cbMemObject;
    BYTE *pbMemObject;
    DWORD cbMemSignedMsg;
    BYTE *pbMemSignedMsg;
};

typedef struct _CRYPT_PROVIDER_DATA CRYPT_PROVIDER_DATA;

typedef struct _CRYPT_PROVIDER_SGNR CRYPT_PROVIDER_SGNR;


/* WARNING! conflicting data type names: /wtypes.h/BOOLEAN - /ntdef.h/BOOLEAN */

typedef USHORT LANGID;

typedef ulonglong __uint64;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

struct _s__RTTIBaseClassDescriptor {
    ImageBaseOffset32 pTypeDescriptor; /* ref to TypeDescriptor (RTTI 0) for class */
    dword numContainedBases; /* count of extended classes in BaseClassArray (RTTI 2) */
    struct PMD where; /* member displacement structure */
    dword attributes; /* bit flags */
    ImageBaseOffset32 pClassHierarchyDescriptor; /* ref to ClassHierarchyDescriptor (RTTI 3) for class */
};

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef RTTIBaseClassDescriptor *RTTIBaseClassDescriptor *32 __((image-base-relative));

typedef RTTIBaseClassDescriptor *32 __((image-base-relative)) *RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative));

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; /* bit flags */
    dword numBaseClasses; /* number of base classes (i.e. rtti1Count) */
    RTTIBaseClassDescriptor *32 __((image-base-relative)) *32 __((image-base-relative)) pBaseClassArray; /* ref to BaseClassArray (RTTI 2) */
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; /* offset of vbtable within class */
    dword cdOffset; /* constructor displacement offset */
    ImageBaseOffset32 pTypeDescriptor; /* ref to TypeDescriptor (RTTI 0) for class */
    ImageBaseOffset32 pClassDescriptor; /* ref to ClassHierarchyDescriptor (RTTI 3) */
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    ImageBaseOffset32 dispUnwindMap;
    uint nTryBlocks;
    ImageBaseOffset32 dispTryBlockMap;
    uint nIPMapEntries;
    ImageBaseOffset32 dispIPToStateMap;
    int dispUnwindHelp;
    ImageBaseOffset32 dispESTypeList;
    int EHFlags;
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType {
    uint adjectives;
    ImageBaseOffset32 dispType;
    int dispCatchObj;
    ImageBaseOffset32 dispOfHandler;
    dword dispFrame;
};

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

struct _s_IPToStateMapEntry {
    ImageBaseOffset32 Ip;
    __ehstate_t state;
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    ImageBaseOffset32 dispHandlerArray;
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    ImageBaseOffset32 action;
};

typedef struct CFveHardwareEncryptionSettings CFveHardwareEncryptionSettings, *PCFveHardwareEncryptionSettings;

struct CFveHardwareEncryptionSettings { /* PlaceHolder Class Structure */
};

typedef struct CFvePolicy CFvePolicy, *PCFvePolicy;

struct CFvePolicy { /* PlaceHolder Class Structure */
};

typedef struct CFvePolicyImpl CFvePolicyImpl, *PCFvePolicyImpl;

struct CFvePolicyImpl { /* PlaceHolder Class Structure */
};

typedef struct CFvePolicyReader CFvePolicyReader, *PCFvePolicyReader;

struct CFvePolicyReader { /* PlaceHolder Class Structure */
};

typedef struct CFvePolicySettings CFvePolicySettings, *PCFvePolicySettings;

struct CFvePolicySettings { /* PlaceHolder Class Structure */
};

typedef struct CFveRecoverySettings CFveRecoverySettings, *PCFveRecoverySettings;

struct CFveRecoverySettings { /* PlaceHolder Class Structure */
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo FuncInfo;

typedef struct _s_HandlerType HandlerType;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

