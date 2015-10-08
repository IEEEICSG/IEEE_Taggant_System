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

#ifndef TYPES_HEADER
#define TYPES_HEADER

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/ts.h>
#include "taggant_types.h"

#ifdef TAGGANT_LIBRARY

/* Maximum buffer for conversion of X509 to binary */
#define MAX_INTEGER 0x7FFFFFFF

#define HASH_SHA256_DIGEST_SIZE 32

#define HASHBLOB_VERSION1 1
#define TAGGANTBLOB_VERSION1 1
#define HASHBLOB_VERSION2 1
#define TAGGANTBLOB_VERSION2 1
#define TAGGANT_VERSION1 1
#define TAGGANT_VERSION2 2
#define TAGGANT_MARKER_BEGIN 0x47474154 /* 'T'A'G'G' */
#define TAGGANT_MARKER_END 0x53544E41   /* 'A'N'T'S' */
#define HASHMAP_MAXIMUM_ENTRIES 100     /* TODO: Correct this value after testing with real certification system */

typedef enum
{
    TAGGANT_HASBLOB_DEFAULT = 0,
    TAGGANT_HASBLOB_EXTENDED = 1,
    TAGGANT_HASBLOB_HASHMAP = 2,
} TAGGANTHASHBLOBTYPE;

#pragma pack(push,2)

typedef struct
{
    UNSIGNED16 Length;
    /* not implemented in the current specification
    char Data[0]; */
} EXTRABLOB, *PEXTRABLOB;

typedef struct
{
    UNSIGNED16 Length;
    PVOID Data;
} EXTRABLOB2, *PEXTRABLOB2;

typedef struct
{
    UNSIGNED16 Length;
    UNSIGNED16 Type;
    UNSIGNED16 Version;
    unsigned char Hash[HASH_SHA256_DIGEST_SIZE];
} HASHBLOB_HEADER, *PHASHBLOB_HEADER;

typedef struct
{
    HASHBLOB_HEADER Header;
} HASHBLOB_DEFAULT, *PHASHBLOB_DEFAULT;

typedef struct
{
    HASHBLOB_HEADER Header;
    UNSIGNED64 PhysicalEnd;
} HASHBLOB_EXTENDED, *PHASHBLOB_EXTENDED;

typedef struct
{
    HASHBLOB_HEADER Header;
    UNSIGNED16 Entries;
    /* Offset to doubles array from begin of TAGGANTBLOB structure */
    UNSIGNED16 DoublesOffset;
} HASHBLOB_HASHMAP, *PHASHBLOB_HASHMAP;

typedef struct
{
    HASHBLOB_DEFAULT DefaultHash;
    HASHBLOB_EXTENDED ExtendedHash;
} HASHBLOB_FULLFILE, *PHASHBLOB_FULLFILE;

typedef struct
{
    HASHBLOB_FULLFILE FullFile;
    HASHBLOB_HASHMAP Hashmap;
} HASHBLOB, *PHASHBLOB;

typedef struct
{
    UNSIGNED16 Length;
    UNSIGNED16 Version;
    PACKERINFO PackerInfo;
} TAGGANTBLOB_HEADER, *PTAGGANTBLOB_HEADER;

typedef struct
{
    TAGGANTBLOB_HEADER Header;
    HASHBLOB Hash;
    EXTRABLOB Extrablob;
    /* Array of hash map doubles
    HASHBLOB_HASHMAP_DOUBLE pHashMapDoubles[1]; */
} TAGGANTBLOB, *PTAGGANTBLOB;

typedef struct
{
    TAGGANTBLOB_HEADER Header;
    HASHBLOB Hash;
    EXTRABLOB2 Extrablob;
    /* Array of hash map doubles */
    PHASHBLOB_HASHMAP_DOUBLE pHashMapDoubles;
} TAGGANTBLOB2, *PTAGGANTBLOB2;

typedef struct
{	
    UNSIGNED32 MarkerBegin;
    UNSIGNED32 TaggantLength;
    UNSIGNED32 CMSLength;
    UNSIGNED16 Version;
} TAGGANT_HEADER, *PTAGGANT_HEADER;

typedef struct
{	
    UNSIGNED16 Version;
    UNSIGNED32 CMSLength;
    UNSIGNED32 TaggantLength;
    UNSIGNED32 MarkerBegin;
} TAGGANT_HEADER2, *PTAGGANT_HEADER2;

typedef struct
{
    EXTRABLOB Extrablob;
    UNSIGNED32 MarkerEnd;
} TAGGANT_FOOTER, *PTAGGANT_FOOTER;

typedef struct
{
    UNSIGNED32 MarkerEnd;
} TAGGANT_FOOTER2, *PTAGGANT_FOOTER2;

typedef struct
{
    /* taggant offset from the beginning of the file */
    UNSIGNED64 offset;
    TAGGANT_HEADER Header;
    PVOID CMSBuffer;
    TAGGANT_FOOTER Footer;
} TAGGANT1, *PTAGGANT1;

typedef struct
{
    TAGGANT_HEADER2 Header;
    PVOID CMSBuffer;
    UNSIGNED32 CMSBufferSize;
    TAGGANT_FOOTER2 Footer;
    /* the current file position to check for a next taggant */
    UNSIGNED64 fileend;
    /* end of full file hash, the size of the file without taggants */
    UNSIGNED64 ffhend;
    /* type of the file currently processed */
    TAGGANTCONTAINER tagganttype;
} TAGGANT2, *PTAGGANT2;

typedef struct
{
#ifdef SSV_LIBRARY
    /* for SSV only, contains a taggant version that the library should search */
    UNSIGNED64 uVersion;
    TAGGANTCONTAINER tagganttype;
#endif
    PTAGGANT1 pTag1;
    PTAGGANT2 pTag2;
} TAGGANT, *PTAGGANT;

#pragma pack(pop)

typedef struct
{
    CMS_ContentInfo* CMS;
    TS_RESP* TSResponse;
    PTAGGANTBLOB pTagBlob;
    UNSIGNED32 uTaggantSize;
} TAGGANTOBJ1, *PTAGGANTOBJ1;

typedef struct
{
    CMS_ContentInfo* CMS;
    TS_RESP* TSResponse;
    TAGGANTBLOB2 tagBlob;
    UNSIGNED64 fileend;
    TAGGANTCONTAINER tagganttype;
} TAGGANTOBJ2, *PTAGGANTOBJ2;

typedef struct
{
#ifdef SSV_LIBRARY
    PTAGGANT tagParent;
#endif
#ifdef SPV_LIBRARY
    /* for SPV only, determines the version of the library that it is working for */
    UNSIGNED64 uVersion;
#endif
    PTAGGANTOBJ1 tagObj1;
    PTAGGANTOBJ2 tagObj2;
} TAGGANTOBJ, *PTAGGANTOBJ;

#endif /* TAGGANT_LIBRARY */

#endif /* TYPES_HEADER */

 
