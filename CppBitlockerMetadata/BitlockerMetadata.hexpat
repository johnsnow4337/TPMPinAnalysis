#pragma author johnsnow4337
#pragma description Bitlocker Metadata

import type.guid;
import type.time;
import std.io;
import std.string;
import std.time;
import std.core;
using BitfieldOrder = std::core::BitfieldOrder;

fn byteToHex(auto byte){
    return std::format("0x{:X}", byte);
};

fn byteArrToHex(auto bytes){
    u64 arraySize = sizeof(bytes) / sizeof(bytes[0]);
    str output = "";
    // Printing each byte in hexadecimal format
    for (u64 i = 0, i < arraySize, i = i + 1) {
        output += std::format("{:02X}", bytes[i]);
        if (i % 2 == 1){
            output +=" ";
        }
    }
    return output;
};

fn FILETIMEtoString(type::FILETIME time){
    return type::impl::format_time_t( std::time::filetime_to_unix(time));
};

//--- Used in modified TPM20.h ---//
fn ArraySize(auto bytes){
    return std::format("[{}]", sizeof(bytes));
};
fn ArrayEntries(auto arr){
    return std::format("[{}]", std::core::member_count(arr));
};

fn readDigest(auto digest){

  return byteArrToHex(digest.buffer);
};
fn OnlyEnum(auto enumIn){
    str enumName = std::format("{}", enumIn);
    return enumName;
};

//-------------------------------------------------------------------------------------
//--- Altered version of WerWolv's Drive File System (fs.hexpat)
//--- Altered using format from http://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc

enum MEDIA : char
{
    FLOPPY                        = 0xf0,
    HARD_DRIVE                    = 0xf8,
    FLOPPY_320K_1                 = 0xfa,
    FLOPPY_640K                   = 0xfb,
    FLOPPY_180K                   = 0xfc,
    FLOPPY_360K                   = 0xfd,
    FLOPPY_160K                   = 0xfe,
    FLOPPY_320K_2                 = 0xff,
};
namespace fat32 {

	u64 bytesPerCluster;
    u64 tmp;
    u32 stringEnd;
    


    //--- From https://www.cs.cmu.edu/~ralf/interrupt-list/inter61a.zip INTERUP.B
    fn readDriveNumber(u8 driveNum){
        str driveType = "";
        u8 driveOrd = 0;
        if (driveNum >> 7){
            driveType = "Hard Drive";
            driveOrd = driveNum - 0x80;
        }
        else{
            driveType = "Floppy Disk";
            driveOrd = driveNum;
        }
        return std::format("{} {}",driveType, driveOrd);
    };
    
    struct jumpCodeStruct{
        u8 opcode [[format_read("byteToHex")]];
        u8 hex1 [[format_read("byteToHex")]];
        u8 hex2 [[format_read("byteToHex")]];
        if (opcode != 0xeb && opcode != 0xe9){
            std::error(std::format("Invalid jump instruction 0x{:X}.", opcode));
        }
        else if (opcode == 0xeb && hex2 != 0x90){
            std::error(std::format("Short jump (0xEB) ends with 0x{:X} instead of NOP (0x90).", hex2));
        }
    };
    
    fn readJump(jumpCodeStruct value){
        u16 jumpAddr = 0;
        str nop = "";
        
        if (value.opcode == 0xeb){
            jumpAddr = value.hex1 + 0x2;
            nop = "; NOP";
        }
        else if (value.opcode == 0xe9){
            jumpAddr = (value.hex1 | (value.hex2 << 8)) + 0x5;
        }
        // Format the bytes as hex values
        return std::format("JMP {:X}{}", jumpAddr, nop);
    };
    
    
    
    //--- Flags from FAT_BOOTSECTOR from Drive.bt 010 editor template---//
    bitfield ExtFlags {
            ActiveFatIndex : 4; // zero-based index of the active FAT
            padding : 3; 
            TransactionFat : 1; // 1 means only one FAT active, as indicated by ActiveFatIndex; 0 means both FATs are mirrored
            padding : 8;
    };
    
	struct Partition {
	    //---Boot Sector Start---//
	    jumpCodeStruct BS_jmpBoot [[format_read("fat32::readJump"), single_color]];
		char BS_OEMName[8];
		
		//---BIOS Parameter Block Start---//
		u16 BPB_BytesPerSector;
		if (BPB_BytesPerSector != 512 && BPB_BytesPerSector != 1024 
		      && BPB_BytesPerSector != 2048 && BPB_BytesPerSector != 4096 ) {
		      std::error(std::format("Invalid bytesPerSector : {}, must be 512. 1024, 2048 or 4096.", BPB_BytesPerSector));
		}
		
		u8 BPB_SectorsPerCluster;
		if (BPB_SectorsPerCluster != 1 && BPB_SectorsPerCluster != 2 
		      && BPB_SectorsPerCluster != 4 && BPB_SectorsPerCluster != 8 
		          && BPB_SectorsPerCluster != 16 && BPB_SectorsPerCluster != 32
		              && BPB_SectorsPerCluster != 64 && BPB_SectorsPerCluster != 128 ) {
		      std::error(std::format("Invalid sectorsPerCluster: {}, must be a power of 2 greater than 0 and less than 128.", BPB_SectorsPerCluster));
		}
		
		if (BPB_BytesPerSector * BPB_SectorsPerCluster> 32 * 1024){
    		  std::error(std::format("Bytes per cluster (bytesPerSector * sectorsPerCluster) {}, greater than 32K.", BPB_BytesPerSector * BPB_SectorsPerCluster));
		}
		
        //---------------------------------		
		//--- Usually 0 for Bitlocker Volumes, deviating from FAT32 format requiring non-zero values
		u16 BPB_ReservedSectorCount;
		u8 BPB_NumFATs;
        //-------------------------------//
		u16 BPB_RootEntryCount; //---Zero in accordance with FAT32 format---//
		u16 BPB_TotalSectors16_LGC;
		MEDIA BPB_MediaType;
		u16 BPB_FATSize16_LGC;
		u16 BPB_SectorsPerTrack;
		u16 BPB_NumHeadPerCylinder;
		u32 BPB_HiddSec; //--- Described as fsOffset in https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Drive/vbr.h#L28 ---//
		u32 BPB_TotalSectors32; //--- Usually 0 for Bitlocker Volumes, deviating from FAT32 format requiring non-zero values ---//
		
		//---FAT32 Extended BIOS Parameter Block Start---//
		u32 FAT32BPB_FATSize32;
		ExtFlags FAT32BPB_ExtFlags;
		u16 FAT32BPB_FSVersion; //---Must be zero---//
		u32 FAT32BPB_RootCluster; //---Usually zero for Bitlocker but usually 2 for FAT32---//
		u16 FAT32BPB_FSInfoSector; //---Usually 1---//
		u16 FAT32BPB_BackupBootSector; //---Usually 6---//
		padding[12];
		
		//---FAT Extended Boot Sector Start---// 
		u8 FATBS_DriveNumber [[format_read("fat32::readDriveNumber")]];
		padding[1];
		u8 FATBS_BootSignature [[format_read("byteToHex")]];
		if (FATBS_BootSignature == 0x29){
		  u32 FATBS_VolumeID;
		  char FATBS_VolumeLab[11];
		  char FATBS_FileSystemType[8];
		}
		tmp = 510- addressof(FATBS_FileSystemType)-110 - 8;
		//--------------------------------------
        //--- Added Bitlocker Specific Metadata as shown in:
        //--- https://github.com/libyal/libbde/blob/main/libbde/bde_volume.h#L153-L273 (Metz, 2022)
        //--- https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Drive/vbr.h#L15-L49 (thewhiteninja, 2022)
        //--- https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/metadata.priv.h#L53-L107 (Coltel and Consultants, 2022)
        padding [70];
    
        //----------------//
        //--- GUID Seemingly fixed at {4967d63b-2e29- 4ad8-8399-f6a339e3d00} corroborated by:
        //--- https://link.springer.com/chapter/10.1007/978-3-319-14289-0_2 (Shabana Subair et al., 2014)
		type::GUID BitlockerGUID;
		//----------------//
		
        u64 FVEMetatdata1 [[format_read("byteToHex")]];
        u64 FVEMetatdata2 [[format_read("byteToHex")]];
        u64 FVEMetatdata3 [[format_read("byteToHex")]];
        
        padding [tmp-3];
        u8 stringOffsets[3];
		u16 signature[[format_read("byteToHex")]];
		//if (signature != 0xaa55){
		 // std::error(std::format("Signature at offset 511 is {:X} not 0xaa55", signature));
		//}
		
		bytesPerCluster = (BPB_SectorsPerCluster * 1024) * BPB_BytesPerSector;
		stringEnd = std::mem::find_sequence_in_range(0, 0x100+stringOffsets[0], 0x100+stringOffsets[1], 0xFF);
		char string1[stringEnd-(0x100+stringOffsets[0])] @ 0x100+stringOffsets[0] [[color("00009F")]];
        stringEnd = std::mem::find_sequence_in_range(0, 0x100+stringOffsets[1], 0x100+stringOffsets[2], 0xFF);
        char string2[stringEnd-(0x100+stringOffsets[1])] @ 0x100+stringOffsets[1] [[color("009F00")]];
        stringEnd = std::mem::find_sequence_in_range(0, 0x100+stringOffsets[2], addressof(stringOffsets), 0x00);
        char string3[stringEnd-(0x100+stringOffsets[2])] @ 0x100+stringOffsets[2]  [[color("9F0000")]];
        //u8 BootCode2 [addressof(stringOffsets)-stringEnd] @ stringEnd;
	};

}
fat32::Partition BootSector @ 0x00;
//-----------------------------------------------------------------------------------//

//---------------------------------------
//--- TPM20.h from:
//--- https://github.com/tianocore/edk2/tree/master/MdePkg/Include/IndustryStandard (Intel, 2015)
//--- With modifications for the ImHex pattern file syntax and operation, including modifying TPM12.h (Intel, 2008)
#include <tpm20.h>
//---------------------------------------//

using short = u16;
using uint16 = u16;
using uint32 = u32;
using int64 = u64;
using uint64 = u64;
using int = u32;
using uint = u32;
using WORD = u16;
using byte = u8;
using long = u64;

//---------------------------------------
//--- Enum converted directly from:
//--- https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Utils/constant_names.cpp#L360-L373 (thewhiteninja, 2021)
//--- And https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/metadata.priv.h#L138-L148 (Coltel and Consultants, 2022)
//--- Not indepedently verified
enum BITLOCKER_STATE : u16{
    _NULL = 0x00,
    DECRYPTED,
    SWITCHING_ENCRYPTION,
    EOW_ACTIVATED,
    ENCRYPTED,
    SWITCH_ENCRYPTION_PAUSED
};
//--------------------------------------//

//---------------------------------------
//--- Bitlocker structure version: 1 for Vista, 2 for Windows 7 and later from:
//--- https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc#5-fve-metadata-block (Metz, 2022)
enum BITLOCKER_VERSION : u16{
    VISTA = 1,
    WIN_7_PLUS = 2
};
//--------------------------------------//
/*---
//--- Structure for datum types global (inferred from fveapi.dll source code and data layout)---//

struct DatumTypeStruct{
    short   DatumHeaderSize;
    bool    isNested;
}

#define MAX_DATUM_TYPES 22
typedef DatumTypeStruct* DatumTypes[MAX_DATUM_TYPES];

//--- An array of the values in fveapi.dll's Global
local DatumTypeStruct DatumTypes[MAX_DATUM_TYPES] = {
//---FveDatumErasedTypeProp, 0,              {08h,0},
//---FveDatumKeyTypeProp, 1                  {0Ch,0},
//---FveDatumUnicodeTypeProp, 2              {08h,0},
//---FveDatumStretchKeyTypeProp, 3           {1Ch,true},
//---FveDatumUseKeyTypeProp, 4               {0Ch,true},
//---FveDatumAesCcmEncTypeProp, 5            {24h,0},
//---FveDatumTpmEncBlobTypeProp, 6           {0Ch,0},
//---FveDatumValidationInfoTypeProp, 7       {08h,0},
//---FveDatumVmkInfoTypeProp, 8              {24h,true},    
//---FveDatumExternalInfoTypeProp, 9         {20h,true},     
//---FveDatumUpdateTypeProp, 10              {2Ch,true},    
//---FveDatumErrorTypeProp, 11               {34h,0},   

//--- According to https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/datums.h#L269 (Coltel and Consultants, 2022)
//--- The below datums were added with Windows 7  
//---FveDatumAsymEncTypeProp, 12             {08h,0},
//---FveDatumExportedKeyTypeProp, 13         {08h,0},
//---FveDatumPublicKeyInfoTypeProp, 14,      {08h,0},
//---FveDatumVirtualizationInfoTypeProp, 15, {18h,0},
//---FveDatumSimpleTypeProp1, 16,            {0Ch,0},
//---FveDatumSimpleTypeProp2, 17,            {0Ch,0},
//---FveDatumConcatHashKeyTypeProp, 18,      {1Ch,0},
//---FveDatumSimpleTypeProp3, 19,            {0Ch,0},
//---FveDatumSimpleLargeTypeProp, 20,        {10h,0},
//---FveDatumBackupInfoTypeProp, 21,         {1Ch,0}
};
---*/

//---------------------------------------
//--- These structures are taken from an fveapi.dll Global at virtual offset: 0x1800bae90 with structure DatumTypes (see above), 
//--- The datum names are taken from fveapi.pdb with FveDatumSimpleTypePropX enumerated.
//--- The same DatumTypes structure is found in bootmgfw.efi Global at virtual offset: 0x10013490.
//--- This Global is referenced in FveDatumHeaderSafe in both executables among other references.
enum DATUM_TYPES : WORD{
    FveDatumErasedTypeProp = 0,
    FveDatumKeyTypeProp,
    FveDatumUnicodeTypeProp,
    FveDatumStretchKeyTypeProp,
    FveDatumUseKeyTypeProp,
    FveDatumAesCcmEncTypeProp,
    FveDatumTpmEncBlobTypeProp,
    FveDatumValidationInfoTypeProp,
    FveDatumVmkInfoTypeProp,  
    FveDatumExternalInfoTypeProp,    
    FveDatumUpdateTypeProp, 
    FveDatumErrorTypeProp,   
    FveDatumAsymEncTypeProp,
    FveDatumExportedKeyTypeProp,
    FveDatumPublicKeyInfoTypeProp,
    FveDatumVirtualizationInfoTypeProp,
    FveDatumSimpleTypeProp1,
    FveDatumSimpleTypeProp2,
    FveDatumConcatHashKeyTypeProp,
    FveDatumSimpleTypeProp3,
    FveDatumSimpleLargeTypeProp,
    FveDatumBackupInfoTypeProp
};
//-------------------------------------------//


//-------------------------------------------------
//--- Enum of Datum 'roles'
//--- Created from:
//--- https://github.com/mbroz/cryptsetup/blob/main/lib/bitlk/bitlk.h#L57-L65 (Trefny, Broz and Hat, 2024)
//--- https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Bitlocker/fve.h#L28 (thewhiteninja, 2022)
//--- https://github.com/libyal/libbde/blob/main/libbde/libbde_definitions.h.in#L106-L121 (Metz, 2022)
//--- https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/datums.h#L78-L93 (Coltel and Consultants, 2022)

//--- TPM + PIN specific roles are validated independently (denoted with //*//)
enum ROLE_TYPES : WORD{
    PROPERTY        = 0x0, //*//

    VMK             = 0x2, //*//
    FVEK            = 0x3, 
    VALIDATION_0    = 0x4,
    
    //---------------------
    //--- Inferred from unsealed TPM only VMK ---//
    //--- https://github.com/PSPReverse/ftpm_attack/tree/master?tab=readme-ov-file#tpm-object-decryption (Jacob et al., 2023b)---//
    TPM_SEALED      = 0x5, 
    //--------------------//
    
    EXT_KEY         = 0x6,
    DESCRIPTION     = 0x7, //*//

    FVEK_BAK        = 0xb, //--- AKA AUTO_UNLOCK in thewhiteninja (2022) ---//

    VOL_HEAD        = 0xf,

    VALIDATION_1    = 0x11, //--- Only seen with FveDatumValidationInfoTypeProp (structure out of scope) ---//

    //---Exclusively listed in Trefny, Broz and Hat (2024)---//
    VOL_GUID        = 0x19
};
//-----------------------------------------------//

//-----------------------------------------------------------------
//--- Adapted from https://github.com/Aorimn/dislocker/blob/master/include/dislocker/encryption/encommon.h#L31-L50 (Coltel and Consultants, 2022)
//--- Cross-referencing using:
//--- https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Utils/constant_names.cpp#L375-L406 (thewhiteninja, 2021)
enum ENC_TYPES : WORD
{
    //--------------------------------------------------
    //----- These Encryption types verified from RE of functions:
    //----- FveVmkInfoConvertCreateParams, FveVmkInfoCreate and FveDatumPerformConcatHash
    //----- in fveapi.dll (function names from fveapi.pdb)
	STRETCH_RECOVERY_PASSWORD       = 0x1000,
    STRETCH_KEY_PASSPHRASE          = 0x1001,

	AES_CCM_256_0                   = 0x2000,
	AES_CCM_256_1                   = 0x2001,
	AES_CCM_256_EXTERN_KEY          = 0x2002,
	AES_CCM_256_VMK                 = 0x2003,
	AES_CCM_256_PIN                 = 0x2004,
    
    //--- From FveDatumPerformConcatHash ---//
	AES_CCM_256_CONCAT_HASH         = 0x2005,

	AES_CCM_256_PUBLIC_KEY          = 0x2006,
	AES_CCM_256_PASSPHRASE          = 0x2007,
    AES_CCM_256_RECOVERY_PASSWORD   = 0x2008,
    //-------------------------------------------------//
    
    //-------------------
    //--- Inferred from below reverse engineering and Coltel and Consultants (2022)
	AES_128_WITH_DIFFUSER           = 0x8000,
	AES_256_WITH_DIFFUSER           = 0x8001,
    //------------------//

    //-------------------
    //--- Confirmed using GetEncryptionMethod in Win32_EncryptableVolume (Microsoft, 2021a)
    //--- And CFveApiBase::MapFveMethodToFvekType from fveapi.dll
	AES_128                         = 0x8002,
	AES_256                         = 0x8003,
	XTS_AES_128                     = 0x8004,
	XTS_AES_256                     = 0x8005,
    //------------------//

    //--- Directly from Coltel and Consultants (2022) (not confirmed) ---//
	DIS_CIPHER_LOWEST_SUPPORTED     = 0x8000,
	DIS_CIPHER_HIGHEST_SUPPORTED    = 0x8005,
};
//----------------------------------------------------------------//

//---------------------------------------
//---Key Flags suggested by
//---FveDatumVmkQueryIsEnhancedPinOrEnhancedCrypto and FveDatumFromPin
//---Supported by testing
enum KEY_FLAGS : u16{
    EnhancedPin  = 0x4,
    NonEnhancedPin = 0x10  
};


namespace BitlockerStructs{
    
    
    //---------------------------------------
    //--- Initial BDE metadata header from https://github.com/libyal/libbde/blob/main/libbde/bde_metadata.h#L90-L152 (Metz, 2022)
    //--- Retyped for the 010 editor template, unknowns inferred from other references:
    //--- https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Bitlocker/bitlocker.h#L19-L31 (thewhiteninja, 2021)
    //--- https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/metadata.priv.h#L156-L183 (Coltel and Consultants, 2022)
    struct FVE_METADATA_HEADER 
    {
        //--- Must be '-FVE-FS-' ---//
    	char signature[8];
    
        //---------------------------------------
        //--- Size of FVE metadata (from above signature) not including validation data ---//
        //--- According to Coltel and Consultants (2022) this:
        //--- "has to be multiplied by 16 when the version is 2"
        //--- This is likely correct
    	short size [[format_read("byteToHex")]];
        //--------------------------------------//
    
        //---------------------------------------
        //--- Bitlocker structure version: 1 for Vista, 2 for Windows 7 and later from:
        //--- https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc#5-fve-metadata-block (Metz, 2022)
    	BITLOCKER_VERSION version;
        //--------------------------------------//
    
        //---Taken from thewhiteninja (2021) and Coltel and Consultants (2022)
    	BITLOCKER_STATE currState;
    	BITLOCKER_STATE nextState;
    
    	//--- Size of the encrypted volume ---//
    	int64 encVolSize [[format_read("byteToHex")]];
    
        
        //---------------------------------------
        //--- From Coltel and Consultants (2022)
            /*
            * The following size describes a virtualized region. This region is only
            * checked when this->curr_state == 2. It begins at the offset described by
            * this->encrypted_volume_size
            */
    	int ConvertSize;
        //--------------------------------------//
    
        //--- Likely number of sectors in decrypted volume, though sources differ on their interpretation --//
    	int VolHeadSecNo;
    
    	/* The first FVE metadata offset
    	 * Consists of 8 bytes
    	 */
    	int64 FVEMetatdata1 [[format_read("byteToHex")]];
    
    	/* The second FVE metadata offset
    	 * Consists of 8 bytes
    	 */
    	int64 FVEMetatdata2 [[format_read("byteToHex")]];
    
    	/* The third FVE metadata offset
    	 * Consists of 8 bytes
    	 */
    	int64 FVEMetatdata3 [[format_read("byteToHex")]];
    
    	//--- Volume header (backup) offset ---//
    	int64 VolHeadOffset [[format_read("byteToHex")]];
    };
    
    using _FVE_DATUM_TEMP;
    //-----------------------------------------------------------------
    //--- From https://github.com/Wack0/CVE-2022-21894/blob/main/tools/FveAddMetadataForPolicy.c (’Wack0’, 2023)
    //--- Correlated against https://github.com/libyal/libbde/blob/main/libbde/bde_metadata.h#L156-L203 (Metz, 2022)
    //--- https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Bitlocker/bitlocker.h#L33-L44 (thewhiteninja, 2022)
    //--- https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/metadata.priv.h#L116-L130 (Coltel and Consultants, 2022)
    //--- The name FVE Dataset is corroborated with symbols present in fveapi.pdb
    //--- RE of FveDatasetGetNext confirms the function of certain values
    struct _FVE_DATASET
    {
      uint DataSetSize [[format_read("byteToHex")]];
      uint DataSetVersion;
      uint DataSetStart [[format_read("byteToHex")]];
      uint DataSetEnd [[format_read("byteToHex")]];
      type::GUID FveIdentification;
      uint NonceCounter;
      //-----------------
      //--- Changed from unsigned __int16 to ENC_TYPES
      ENC_TYPES FvekType;
      ENC_TYPES FvekPrefType;
      //----------------//
      type::FILETIME DateTime [[format_read("FILETIMEtoString")]];
      Datums = BitlockerStructs::GetNoOfDatums(DataSetSize - DataSetStart);
      _FVE_DATUM_TEMP DATUMS[Datums] [[format_read_entries("BitlockerStructs::READ_DATUM_TYPE"), format_read("ArrayEntries")]];
    };
    
    //--- The name FVE Datum is corroborated with symbols present in fveapi.pdb
    struct  _FVE_DATUM
    {
      WORD DatumSize [[format_read("byteToHex")]];
      
      //-----------------
      //--- Changed from WORD to ROLE_TYPES and DATUM_TYPES
      ROLE_TYPES Role;
      DATUM_TYPES Type;
      //----------------//
    
      WORD Flags;
    } [[inline]];
    

    #define VMK_SIZE 32
    #define IK_SIZE  32
    
    bool isVMKorIK = 0;
    
    struct FVE_DATUM_KEY_DUMMY{
        _FVE_DATUM h ;             //---Example Values
        //    WORD DatumSize; // 0x002c
        //    ROLE_TYPES Role;    // 0x0000
        //    DATUM_TYPES Type;   // 0x0001
        //    WORD Flags;         // 0x0000
        
        ENC_TYPES KeyType; //---AES_CCM_256_VMK---//
        KEY_FLAGS KeyFlags;   //---0x0000---//
        if (isVMKorIK == 0){
            BYTE VMK[VMK_SIZE] [[format_read("ArraySize")]];
        }else if (isVMKorIK == 1){
            BYTE IK[IK_SIZE] [[format_read("ArraySize")]];
        }
    };
    
    
    struct FVE_DATUM_AESCCM_ENC_DUMMY  {
        _FVE_DATUM h;      //---Example Values
        //    WORD DatumSize; // 0x0050
        //    ROLE_TYPES Role;    // 0x0000
        //    DATUM_TYPES Type;   // 0x0005
        //    WORD Flags;         // 0x0000
        type::FILETIME nonceTime [[format_read("FILETIMEtoString")]];
        int nonceCounter;
        byte HMAC[16] [[format_read("ArraySize")]];
        
        isVMKorIK = 1;
        
        //--- Intermediate key AES-CCM Encrypted with stretched PIN ----//
        FVE_DATUM_KEY_DUMMY EncIKKeyDatum [[format_read("ArraySize")]];
    };
    //---------------------------------------------------------------//
    
    //-----------------
    //--- Directly from https://github.com/Aorimn/dislocker/blob/845e20c76147b12f52be531b34242922a0661771/include/dislocker/metadata/extended_info.h#L36 (Coltel and Consultants, 2022)
    //--- Out of scope of independent analysis
    struct extended_info_t {
    	uint16 unknown1;
    	uint16 size;
    	uint32 unknown2;
    	uint64 flags;
    	uint64 convertlog_addr;
    	uint32 convertlog_size;
    	uint32 sector_size1;
    	uint32 sector_size2;
    } ;
    //----------------//
    
    //--- Reverse engineered from fveapi.dll functions:
    //--- VMKInfoCreate; FvepVmkInfoAddExternallyManagedKey
    //--- FvepVmkInfoAddTpmEnhancedAuthData; FvepVmkInfoAddPublicKey;
    //--- FvepVmkInfoAddPin; CFveApiBase::WorksetHasClearKey
    //--- And calls to CFveApiBase::FindKeyPriorityRangeWithDeleteOption
    bitfield PROTECTOR_TYPES{
        byte    UKNOWN_0;   //--- Possibly protectors introduced in post Windows 10 versions will be placed here ---//
        TPM             :   1;
        EXTERNAL_KEY    :   1;
        PIN             :   1;
        RECOVERY_PASSWD :   1;
        PUBLIC_KEY      :   1;
        PASSPHRASE      :   1;
        EXTERNLY_MGD    :   1; //--- Unknown what protector from Win32_EncryptableVolume::GetKeyProtectorType this refers to
        UKNOWN_1        :   1;    
        //--- A protector type of 0x0000 likely represents a clear key
    };
    
    //--- Produces readable output in 010 editor ---//
    fn READ_PROTECTOR_TYPE(PROTECTOR_TYPES flag){
        str RetStr = "";
        if (flag.TPM){
            RetStr += "TPM";
        }
        if (flag.PIN){
            RetStr +=" + PIN";
            }
        if (flag.EXTERNAL_KEY){
            if (RetStr == ""){
                RetStr += "USB";
                }
            else{
                RetStr +=" + USB";
                }
            }
        if (flag.RECOVERY_PASSWD){
            RetStr+="Recovery Password";
        }
        if (flag.PUBLIC_KEY){
            RetStr+="Public Key";
        }
        if (flag.EXTERNLY_MGD){
            RetStr+="Externally Managed";
        }
        if (flag.PASSPHRASE){
            RetStr+="PassPhrase";
        }
        return RetStr;
    };
    

    //---------------------------------------//
    
    //---Forward declaration
    using PCR_BITMAP;
    //--- Procduces readable output of PCRs used ---//
    fn readPCR_BITMAP(PCR_BITMAP pcrs){
        str outstr = "PCRs: ";
        if (pcrs.PCR_0){
            outstr+="0, ";
            }
        if (pcrs.PCR_1){
            outstr+="1, ";
        }
        if (pcrs.PCR_2){
            outstr+="2, ";
        } 
        if (pcrs.PCR_3){
            outstr+="3, ";
        }
        if (pcrs.PCR_4){
            outstr+="4, ";
        }
        if (pcrs.PCR_5){
            outstr+="5, ";
        } 
        if (pcrs.PCR_6){
            outstr+="6, ";
        } 
        if (pcrs.PCR_7){
            outstr+="7, ";
        } 
        if (pcrs.PCR_8){
            outstr+="8, ";
        } 
        if (pcrs.PCR_9){
            outstr+="9, ";
        } 
        if (pcrs.PCR_10){
            outstr+="10, ";
        } 
        if (pcrs.PCR_11){
            outstr+="11, ";
        } 
        if (pcrs.PCR_12){
            outstr+="12, ";
        } 
        if (pcrs.PCR_13){
            outstr+="13, ";
        } 
        if (pcrs.PCR_14){
            outstr+="14, ";
        } 
        if (pcrs.PCR_15){
            outstr+="15, ";
        } 
        if (pcrs.PCR_16){
            outstr+="16, ";
        } 
        if (pcrs.PCR_17){
            outstr+="17, ";
        }
        if (pcrs.PCR_18){
            outstr+="18, ";
        } 
        if (pcrs.PCR_19){
            outstr+="19, ";
        } 
        if (pcrs.PCR_20){
            outstr+="20, ";
        } 
        if (pcrs.PCR_21){
            outstr+="21, ";
        } 
        if (pcrs.PCR_22){
            outstr+="22, ";
        } 
        if (pcrs.PCR_23){
            outstr+="23, ";
        } 
        outstr = std::string::substr(outstr,0,std::string::length(outstr)-2);
        return outstr;
        };
    
    //--- PCR bitmap from TPM 2.0 Part 2 Page 110 (TCG, 2024b:110) ---//
    bitfield PCR_BITMAP{
        PCR_0 : 1;
         PCR_1 : 1;
         PCR_2 : 1;
         PCR_3 : 1;
         PCR_4 : 1;
         PCR_5 : 1;
         PCR_6 : 1;
         PCR_7 : 1;
         PCR_8 : 1;
         PCR_9 : 1;
         PCR_10 : 1;
         PCR_11 : 1;
         PCR_12 : 1;
         PCR_13 : 1;
         PCR_14 : 1;
         PCR_15 : 1;
         PCR_16 : 1;
         PCR_17 : 1;
         PCR_18 : 1;
         PCR_19 : 1;
         PCR_20 : 1;
         PCR_21 : 1;
         PCR_22 : 1;
         PCR_23 : 1;
        } [[format_read("BitlockerStructs::readPCR_BITMAP")]];


    long encSize;
    //---------------------------------------
    //--- Encrypted data dummy structure, including Bitlocker specific structs
    //--- This structure assumes that the encrypted data size is the same as the plaintext data size
    //--- This may not always be the case but appears to be consistent with Bitlocker test data
    struct TPM2B_SENSITIVE_DATA_DUMMY{
        be UINT16    bits_size;
        encSize -= sizeof(bits_size);
    
        //--- Expected TPM Only protected VMK ---//
        if (encSize == 44){
            isVMKorIK = 0;
            le FVE_DATUM_KEY_DUMMY VMKKeyDatum [[format_read("ArraySize")]];
    
        //-- -Expected TPM + PIN protected Intemediate Key ---//
        }else if (encSize == 80){
            le FVE_DATUM_AESCCM_ENC_DUMMY AESCCMEncIK [[format_read("ArraySize")]];
        }else{
        //--- Non Bitlocker TPM encrypted data ---//
            BYTE      EncryptedDatums[encSize] [[format_read("ArraySize")]];
        }
    };
    //--------------------------------------//
    
    //--- TPMU_SENSITIVE_COMPOSITE_DUMMY will be a data field in Bitlocker ---//
    using TPMU_SENSITIVE_COMPOSITE_DUMMY  = TPM2B_SENSITIVE_DATA_DUMMY;
    
    //---------------------------------------
    //--- "When the TPM returns a TPM2B_PRIVATE structure, the TPM pads the TPM2B_AUTH to its maximum size."
    //--- The maximum size of the structure is denoted by outPublic.publicArea.nameAlg
    //--- TPM 2.0 Part 1 Page 186 (TCG, 2024a:186)
    //--- Bitlocker's nameAlg is TPM_ALG_SHA256 (11)
    //--- Therefore the authValue size will be 256 bits or 32 bytes
    struct TPM2B_AUTH_DUMMY{
        be UINT16    authValue_size;
        be BYTE      authValue_buffer[SHA256_DIGEST_SIZE] [[format_read("ArraySize")]];
    };
    //---------------------------------------//
    
    //---------------------------------------
    //--- Size taken from outPublic.publicArea.nameAlg
    //--- TPM 2.0 Part 1 Page 186 (TCG, 2024a:186)
    //--- Bitlocker's nameAlg is TPM_ALG_SHA256 (11)
    //--- Therefore the authValue size will be 256 bits or 32 bytes
    struct TPM2B_DIGEST_DUMMY{
        be UINT16    seedValue_size;
        be BYTE      seedValue_buffer[SHA256_DIGEST_SIZE] [[format_read("ArraySize")]];
    };
    //---------------------------------------//
    
    
    //--- Dummy Structure wrapper ---//
    struct TPMT_SENSITIVE_DUMMY{
        //---------------------------------------
        //--- sensitiveType is the same as outPublic.publicArea.Type 
        //--- TPM 2.0 Part 2 Page 158 (TCG, 2024b:158)
        be TPMI_ALG_PUBLIC                   sensitiveType;
        //---------------------------------------//
    
        be TPM2B_AUTH_DUMMY                  authValue [[format_read("ArraySize")]];
        be TPM2B_DIGEST_DUMMY                seedValue [[format_read("ArraySize")]];
        encSize = parent.parent.outPrivate_size
                                -sizeof(parent.parent.integrityOuter)-sizeof(parent.parent.integrityInner)
                                    -sizeof(parent.sensitive_size)-sizeof(sensitiveType)
                                        -sizeof(authValue.authValue_size)-sizeof(authValue.authValue_buffer)
                                            -sizeof(seedValue.seedValue_size)-sizeof(seedValue.seedValue_buffer);
        
        be TPMU_SENSITIVE_COMPOSITE_DUMMY    sensitive_dummy [[format_read("ArraySize")]];
    };
    
    //---------------------------------------
    //--- This strucutre is created to map the structure of the encrypted data to the decrypted TPM2B_SENSITIVE structure
    //--- This allows us to approximate the size of the user input data
    struct TPM2B_SENSITIVE_DUMMY {
        //--- Dummy TPM2B_SENSITIVE structure to work out size of encrypted data ---//
        be UINT16               sensitive_size;
        be TPMT_SENSITIVE_DUMMY sensitiveArea [[format_read("ArraySize")]];
               
    };
    
    struct TPM2B_PRIVATE_DUMMY{
        //-------------------------------
        //--- Unencrypted portion of TPM2B_Private
          be UINT16    outPrivate_size;
          
          // _PRIVATE buffer[size]:
            be TPM2B_DIGEST      integrityOuter [[format_read("ArraySize")]];
            be TPM2B_DIGEST      integrityInner [[format_read("ArraySize")]];
        //-------------------------------//
    
            // byte    encryptedSensitive[size-integrityOuter.size-integrityInner.size-4]:
            be TPM2B_SENSITIVE_DUMMY    encryptedSensitiveArea [[format_read("ArraySize")]];
        };
    
    //--- Forward declaration for recursion
    using _FVE_DATUM_TEMP;
    
    
    int Datums;
    //--- Key types aren't split into different structs to avoid another drop-down in data type viewer
    struct _FVE_DATUM_TEMP
    {
      _FVE_DATUM h;  
      
      if (h.Type == DATUM_TYPES::FveDatumKeyTypeProp){
        ENC_TYPES KeyType;
        //--- May not be the same flags as the stretch key flags ---//
        KEY_FLAGS KeyFlags;
        byte KeyData[h.DatumSize-12] [[format_read("ArraySize")]];
        }
      else if (h.Type == DATUM_TYPES::FveDatumUnicodeTypeProp){
        char16 UnicodeData[(h.DatumSize-8)/2];
      }
      else if (h.Type == DATUM_TYPES::FveDatumStretchKeyTypeProp){
        //--- Stretch encryption method (seen 0x1000 for recovery password and 0x2004 for TPM + PIN) ---//
    	ENC_TYPES encryption_method;
        
        //-------------------------------
        //--- Likely represents whether suggested by
        //--- FveDatumVmkQueryIsEnhancedPinOrEnhancedCrypto and FveDatumFromPin
        //------------------------------//
        KEY_FLAGS  keyFlags; 
    
    	byte salt[16] [[format_read("byteArrToHex")]];
        
        //--- Nested datums as denoted by DatumTypes ---//
        Datums = BitlockerStructs::GetNoOfDatums(h.DatumSize-28);
        _FVE_DATUM_TEMP StretchDatums[Datums] [[format_read_entries("BitlockerStructs::READ_DATUM_TYPE"), format_read("ArrayEntries")]];
      }
      else if (h.Type == DATUM_TYPES::FveDatumUseKeyTypeProp){
          //--- Header size is _FVE_DATUM + 4 as denoted by DatumTypes ---//
          byte UseKeyData[4] [[format_read("byteArrToHex")]];
          byte DatumData[h.DatumSize-12] [[format_read("ArraySize")]];
      }
      else if (h.Type == DATUM_TYPES::FveDatumAesCcmEncTypeProp){
          //------------------------------------------
          //--- From structure determined from:
          //--- https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/datums.h#L176-L182 (Coltel and Consultants, 2022)
          //--- https://github.com/thewhiteninja/ntfstool/blob/master/Sources/Bitlocker/bitlocker.h#L79-L85 (thewhiteninja, 2021)
          //--- and corroborated by independed RE
          type::FILETIME nonceTime [[format_read("FILETIMEtoString")]];
          int nonceCounter;
          byte HMAC[16] [[format_read("byteArrToHex")]];
          byte AesCCMData[h.DatumSize-36] [[format_read("ArraySize")]];  
          //----------------------------------------//
      }
      else if (h.Type == DATUM_TYPES::FveDatumTpmEncBlobTypeProp){
          //--- Presumably here for Bitlocker to easily read the selected PCRs ---//
          PCR_BITMAP PCRBitmap;
          byte zero; //---Potentially always 0x00---//
          
          //----------------------------------------------------------
          //----- Structure from individual RE starting from previous efforts:
          //----- https://itm4n.github.io/tpm-based-bitlocker/ (Labro, 2024)
          //----- https://github.com/PSPReverse/ftpm_attack/blob/master/tools/amd_ftpm2_unseal.py (Jacob et al., 2023b)
          //----- https://youtu.be/EXyDAWWHeYY?si=PPai64ODUD4RoPCS&t=1852 (Han et al., 2019)
            
          //--- Can be uncommented but latter structure is used to determine encrypted data size ---//
          // TPM2B_PRIVATE outPrivate; 
    
          be TPM2B_PRIVATE_DUMMY outPrivateDummy [[format_read("ArraySize")]];
    
          be TPM2B_PUBLIC outPublic [[format_read("ArraySize")]];
          be TPM2B_DIGEST pcrDigest [[format_read("readDigest")]];

          byte sizeofSelect [[format_read("byteToHex")]];
          PCR_BITMAP pcrSelect;
          //---------------------------------------------------------//
      }
      else if (h.Type == DATUM_TYPES::FveDatumVmkInfoTypeProp){
            //--------------------------------
            //--- Inital structure from https://github.com/Wack0/CVE-2022-21894/blob/main/tools/FveAddMetadataForPolicy.c (’Wack0’, 2023)
            //--- Modified with protector types and nested datums
            type::GUID Identifier;
            type::FILETIME ProtectionTime [[format_read("FILETIMEtoString")]];
            WORD VmkHints;
            PROTECTOR_TYPES ProtectionType [[format_read("BitlockerStructs::READ_PROTECTOR_TYPE")]];
            Datums = BitlockerStructs::GetNoOfDatums(h.DatumSize-36);
            _FVE_DATUM_TEMP VMKDatums[Datums]  [[format_read_entries("BitlockerStructs::READ_DATUM_TYPE"), format_read("ArrayEntries")]];
            //------------------------------//
      }
      else if (h.Type == DATUM_TYPES::FveDatumVirtualizationInfoTypeProp){
            //----------------------------
            //--- From https://github.com/Aorimn/dislocker/blob/master/include/dislocker/metadata/datums.h#L211-L223 (Coltel and Consultants, 2022)
            //--- Likely correct but not independently analysed
            UINT64 NTFSBootSectorsAddr;
    	    UINT64 BackupBytes;
            extended_info_t ExtendedInfo; 
            byte ExtExtInfo[h.DatumSize-sizeof(_FVE_DATUM)-sizeof(UINT64)-sizeof(UINT64)-sizeof(extended_info_t)];
            //---------------------------//
      }
      else if (h.Type == DATUM_TYPES::FveDatumConcatHashKeyTypeProp){
        char ConcatHashKey[(h.DatumSize-8)];
      }
      else{
        //--- Any other types are out of scope for TPM + PIN analysis ---//
        //--- Or have no useful information aside from the header ---//
        byte KeyData[h.DatumSize-8] [[format_read("ArraySize")]];
      }
    };
    fn READ_DATUM_TYPE(_FVE_DATUM_TEMP datum){
        str RetStr = "";
        RetStr += std::format("{}",datum.h.Role);
        RetStr += "     ";
        RetStr += std::format("{}",datum.h.Type);
        return RetStr;
    };
    
    //--- Determine the number of datums by subtracting the size of each datum with total metadata size ---//
    fn GetNoOfDatums(uint size){
        uint currOffset = $;
        uint sizeLeft = size;
        int count = 0;
        int sizeStore = 0;
        while (sizeLeft>0){
            sizeStore = std::mem::read_unsigned(currOffset,2);
            currOffset += sizeStore;
            sizeLeft-=sizeStore;
            count+=1;
        }
        return count;
    };
    
    struct FveHeaderBlock{
        FVE_METADATA_HEADER FVEBlockHeader;
        _FVE_DATASET FVEDataset;
        //------------------------
        //--- Only mentioned by:
        //--- https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20(BDE)%20format.asciidoc#5-fve-metadata-block (Metz, 2022)
        padding [FVEBlockHeader.size*16-FVEDataset.DataSetSize-0x40];
        //-----------------------//
    };
}
BitlockerStructs::FveHeaderBlock FVEHeaderBlock1 @ BootSector.FVEMetatdata1;