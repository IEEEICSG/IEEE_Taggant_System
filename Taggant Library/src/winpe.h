/* ====================================================================
 * Copyright (c) 2012 IEEE.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the IEEE Industry
 *    Connections Security Group (ICSG)".
 *
 * 4. The name "IEEE" must not be used to endorse or promote products
 *    derived from this software without prior written permission from
 *    the IEEE Standards Association (stds.ipr@ieee.org).
 *
 * 5. Products derived from this software may not contain "IEEE" in
 *    their names without prior written permission from the IEEE Standards
 *    Association (stds.ipr@ieee.org).
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the IEEE Industry
 *    Connections Security Group (ICSG)".
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND "WITH ALL FAULTS." IEEE AND ITS
 * CONTRIBUTORS EXPRESSLY DISCLAIM ALL WARRANTIES AND REPRESENTATIONS,
 * EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION:  (A) THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE;
 * (B) ANY WARRANTY OF NON-INFRINGEMENT; AND (C) ANY WARRANTY WITH RESPECT
 * TO THE QUALITY, ACCURACY, EFFECTIVENESS, CURRENCY OR COMPLETENESS OF
 * THE SOFTWARE.
 *
 * IN NO EVENT SHALL IEEE OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR CONSEQUENTIAL DAMAGES,
 * (INCLUDING, BUT NOT LIMITED TO,  PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE AND REGARDLESS OF WHETHER SUCH DAMAGE WAS
 * FORESEEABLE.
 *
 * THIS SOFTWARE USES STRONG CRYPTOGRAPHY, WHICH MAY BE SUBJECT TO LAWS
 * AND REGULATIONS GOVERNING ITS USE, EXPORTATION OR IMPORTATION. YOU ARE
 * SOLELY RESPONSIBLE FOR COMPLYING WITH ALL APPLICABLE LAWS AND
 * REGULATIONS, INCLUDING, BUT NOT LIMITED TO, ANY THAT GOVERN YOUR USE,
 * EXPORTATION OR IMPORTATION OF THIS SOFTWARE. IEEE AND ITS CONTRIBUTORS
 * DISCLAIM ALL LIABILITY ARISING FROM YOUR USE OF THE SOFTWARE IN
 * VIOLATION OF ANY APPLICABLE LAWS OR REGULATIONS.
 * ====================================================================
 */


#ifndef WINPE_HEADER
#define WINPE_HEADER

#include "types.h"
#include "taggant_types.h"

#define TAGGANT_ADDRESS_JMP 0x08EB
#define TAGGANT_ADDRESS_JMP_SIZE 2

/* Minimum sizes of PE files */
#define MINIMUM_PE32_FILE_SIZE 97
#define MINIMUM_PE64_FILE_SIZE 268

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define IMAGE_FILE_MACHINE_I386		0x014c /* Intel 386 or later processors */
#define IMAGE_FILE_MACHINE_AMD64	0x8664 /* x64 */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

#define IMAGE_SIZEOF_SHORT_NAME 8

#define IMAGE_DIRECTORY_ENTRY_SECURITY 4


#pragma pack(push,1)

typedef struct _TAG_IMAGE_DOS_HEADER {
	UNSIGNED16 e_magic;
	UNSIGNED8 Reserved[58];
	/* Uncomment necessary values
	UNSIGNED16 e_cblp;
	UNSIGNED16 e_cp;
	UNSIGNED16 e_crlc;
	UNSIGNED16 e_cparhdr;
	UNSIGNED16 e_minalloc;
	UNSIGNED16 e_maxalloc;
	UNSIGNED16 e_ss;
	UNSIGNED16 e_sp;
	UNSIGNED16 e_csum;
	UNSIGNED16 e_ip;
	UNSIGNED16 e_cs;
	UNSIGNED16 e_lfarlc;
	UNSIGNED16 e_ovno;
	UNSIGNED16 e_res[4];
	UNSIGNED16 e_oemid;
	UNSIGNED16 e_oeminfo;
	UNSIGNED16 e_res2[10];
	*/
	SIGNED32 e_lfanew;
} TAG_IMAGE_DOS_HEADER,*PTAG_IMAGE_DOS_HEADER;

typedef struct _TAG_IMAGE_FILE_HEADER {
	UNSIGNED16 Machine;
	UNSIGNED16 NumberOfSections;
	UNSIGNED8 Reserved1[12];
	/* Uncomment necessary values
	UNSIGNED32 TimeDateStamp;
	UNSIGNED32 PointerToSymbolTable;
	UNSIGNED32 NumberOfSymbols;
	*/
	UNSIGNED16 SizeOfOptionalHeader;
	UNSIGNED8 Reserved2[2];
	/* Uncomment necessary values
	UNSIGNED16 Characteristics;
	*/
} TAG_IMAGE_FILE_HEADER, *PTAG_IMAGE_FILE_HEADER;

typedef struct _TAG_IMAGE_DATA_DIRECTORY {
	UNSIGNED32 VirtualAddress;
	UNSIGNED32 Size;
} TAG_IMAGE_DATA_DIRECTORY,*PTAG_IMAGE_DATA_DIRECTORY;

typedef struct _TAG_IMAGE_OPTIONAL_HEADER32 {
	UNSIGNED16 Magic;
	UNSIGNED8 Reserved1[14];
	/* Uncomment necessary values
	UNSIGNED8 MajorLinkerVersion;
	UNSIGNED8 MinorLinkerVersion;
	UNSIGNED32 SizeOfCode;
	UNSIGNED32 SizeOfInitializedData;
	UNSIGNED32 SizeOfUninitializedData;
	 */
	UNSIGNED32 AddressOfEntryPoint;
	UNSIGNED8 Reserved2[12];
	/* Uncomment necessary values
	UNSIGNED32 BaseOfCode;
	UNSIGNED32 BaseOfData;
	UNSIGNED32 ImageBase;
	 */
	UNSIGNED32 SectionAlignment;
	UNSIGNED32 FileAlignment;
	UNSIGNED8 Reserved3[52];
	/* Uncomment necessary values
	UNSIGNED16 MajorOperatingSystemVersion;
	UNSIGNED16 MinorOperatingSystemVersion;
	UNSIGNED16 MajorImageVersion;
	UNSIGNED16 MinorImageVersion;
	UNSIGNED16 MajorSubsystemVersion;
	UNSIGNED16 MinorSubsystemVersion;
	UNSIGNED32 Win32VersionValue;
	UNSIGNED32 SizeOfImage;
	UNSIGNED32 SizeOfHeaders;
	UNSIGNED32 CheckSum;
	UNSIGNED16 Subsystem;
	UNSIGNED16 DllCharacteristics;
	UNSIGNED32 SizeOfStackReserve;
	UNSIGNED32 SizeOfStackCommit;
	UNSIGNED32 SizeOfHeapReserve;
	UNSIGNED32 SizeOfHeapCommit;
	UNSIGNED32 LoaderFlags;
	 */
	UNSIGNED32 NumberOfRvaAndSizes;
	TAG_IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} TAG_IMAGE_OPTIONAL_HEADER32,*PTAG_IMAGE_OPTIONAL_HEADER32;

typedef struct _TAG_IMAGE_OPTIONAL_HEADER64 {
	UNSIGNED16 Magic;
	UNSIGNED8 Reserved1[14];
	/* Uncomment necessary values
	UNSIGNED8 MajorLinkerVersion;
	UNSIGNED8 MinorLinkerVersion;
	UNSIGNED32 SizeOfCode;
	UNSIGNED32 SizeOfInitializedData;
	UNSIGNED32 SizeOfUninitializedData;
	 */
	UNSIGNED32 AddressOfEntryPoint;
	UNSIGNED8 Reserved2[12];
	/* Uncomment necessary values
	UNSIGNED32 BaseOfCode;
	UNSIGNED64 ImageBase;
	 */
	UNSIGNED32 SectionAlignment;
	UNSIGNED32 FileAlignment;
	UNSIGNED8 Reserved3[68];
	/* Uncomment necessary values
	UNSIGNED16 MajorOperatingSystemVersion;
	UNSIGNED16 MinorOperatingSystemVersion;
	UNSIGNED16 MajorImageVersion;
	UNSIGNED16 MinorImageVersion;
	UNSIGNED16 MajorSubsystemVersion;
	UNSIGNED16 MinorSubsystemVersion;
	UNSIGNED32 Win32VersionValue;
	UNSIGNED32 SizeOfImage;
	UNSIGNED32 SizeOfHeaders;
	UNSIGNED32 CheckSum;
	UNSIGNED16 Subsystem;
	UNSIGNED16 DllCharacteristics;
	UNSIGNED64 SizeOfStackReserve;
	UNSIGNED64 SizeOfStackCommit;
	UNSIGNED64 SizeOfHeapReserve;
	UNSIGNED64 SizeOfHeapCommit;
	UNSIGNED32 LoaderFlags;
	 */
	UNSIGNED32 NumberOfRvaAndSizes;
	TAG_IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} TAG_IMAGE_OPTIONAL_HEADER64,*PTAG_IMAGE_OPTIONAL_HEADER64;

typedef struct _TAG_IMAGE_SECTION_HEADER {
	UNSIGNED8 Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		UNSIGNED32 PhysicalAddress;
		UNSIGNED32 VirtualSize;
	} Misc;
	UNSIGNED32 VirtualAddress;
	UNSIGNED32 SizeOfRawData;
	UNSIGNED32 PointerToRawData;
	UNSIGNED8 Reserved[16];
	/* Uncomment necessary values
	UNSIGNED32 PointerToRelocations;
	UNSIGNED32 PointerToLinenumbers;
	UNSIGNED16 NumberOfRelocations;
	UNSIGNED16 NumberOfLinenumbers;
	UNSIGNED32 Characteristics;
	*/
} TAG_IMAGE_SECTION_HEADER,*PTAG_IMAGE_SECTION_HEADER;

#pragma pack(pop)

typedef struct _PE_ALL_HEADERS {
	TAG_IMAGE_DOS_HEADER dh;
	UNSIGNED32 signature;
	TAG_IMAGE_FILE_HEADER fh;
	union {
		TAG_IMAGE_OPTIONAL_HEADER32 pe32;
		TAG_IMAGE_OPTIONAL_HEADER64 pe64;
	} oh;
} PE_ALL_HEADERS,*PPE_ALL_HEADERS;

/* checks file header if the file is correct PE file
   returns 1 is PE file is valid */
int winpe_is_correct_pe_file(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh);

/* returns a physical file offset of file entry point
   PE file has to be valid
   function returns 0 if entry point is not found */
int winpe_entry_point_physical_offset(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, UNSIGNED64 *ep_offset);

/* function returns the taggant physical offset inside the file
   it returns 0 if taggant is not found */
int winpe_taggant_physical_offset(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, UNSIGNED64 ep_physical_offset, UNSIGNED64 *tag_offset);

int winpe_is_pe64(PE_ALL_HEADERS* peh);

#endif /* WINPE_HEADER */
