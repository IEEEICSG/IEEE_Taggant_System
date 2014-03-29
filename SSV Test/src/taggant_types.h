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

#ifndef COMMON_TYPES_HEADER
#define COMMON_TYPES_HEADER

/* Do not remove this include because it is necessary for size_t type
   definition for MinGW compiler */
#include <stdio.h>

/* TAGGANT_MINIMUM_SIZE should be greater than sum of sizeof(TAGGANT_HEADER) and sizeof(TAGGANT_FOOTER) */
#define TAGGANT_MINIMUM_SIZE 0x00002000
#define TAGGANT_MAXIMUM_SIZE 0x0000FFFF

#define PFILEOBJECT void*

#define UNSIGNED8 unsigned char
#define UNSIGNED16 unsigned short
#define SIGNED32 int
#define UNSIGNED32 unsigned long

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
typedef unsigned __int64 UNSIGNED64;
typedef __int64 SIGNED64;
#elif defined(__arch64__)
typedef unsigned long UNSIGNED64;
typedef long SIGNED64;
#else
typedef unsigned long long UNSIGNED64;
typedef long long SIGNED64;
#endif

#define PVOID void*
#define PINFO char*

typedef enum
{
	TAGGANT_PEFILE = 0
} TAGGANTCONTAINER;

typedef enum
{
	ETAGGANTBLOB = 0,
	ESPVCERT = 1,
	EUSERCERT = 2,
	EFILEEND = 3
} ENUMTAGINFO;

#ifdef WIN32
#	define __DECLARATION __stdcall
#else
#	define __DECLARATION
#endif

#pragma pack(push,2)

typedef struct
{
	UNSIGNED64 AbsoluteOffset;
	UNSIGNED64 Length;
} HASHBLOB_HASHMAP_DOUBLE, *PHASHBLOB_HASHMAP_DOUBLE;

typedef struct
{
	UNSIGNED32 PackerId;
	UNSIGNED16 VersionMajor;
	UNSIGNED16 VersionMinor;
	UNSIGNED16 VersionBuild;
	UNSIGNED16 Reserved;
} PACKERINFO, *PPACKERINFO;

typedef struct
{
	int size;
	/* File IO callbacks */
	size_t (__DECLARATION *FileReadCallBack)(PFILEOBJECT, void*, size_t);
	int (__DECLARATION *FileSeekCallBack)(PFILEOBJECT, UNSIGNED64, int);
	UNSIGNED64 (__DECLARATION *FileTellCallBack)(PFILEOBJECT);
} TAGGANTCONTEXT, *PTAGGANTCONTEXT;

typedef struct
{
	int size;
	/* Memory callbacks */
	void* (__DECLARATION *MemoryAllocCallBack)(size_t);
	void* (__DECLARATION *MemoryReallocCallBack)(void*, size_t);
	void (__DECLARATION *MemoryFreeCallBack)(void*);
} TAGGANTFUNCTIONS, *PTAGGANTFUNCTIONS;


#pragma pack(pop)

#ifndef TAGGANT_LIBRARY

#define PTAGGANT PVOID
#define PTAGGANTOBJ PVOID

#endif

#define TNOERR 0
#define TTYPE 1
#define TNOTAGGANTS 2
#define TMEMORY 3
#define TFILEERROR 4
#define TBADKEY 5
#define TMISMATCH 6
#define TERRORKEY 7
#define TNONET 8
#define TTIMEOUT 9
#define TINTERNALERROR 10
#define TSERVERERROR 11
#define TERROR 12
#define TNOTIME 13
#define TINVALID 14
#define TLIBNOTINIT 15
#define TINVALIDPEFILE 16
#define TINVALIDPEENTRYPOINT 17
#define TINVALIDTAGGANTOFFSET 18
#define TINVALIDTAGGANT 19
#define TFILEACCESSDENIED 20
#define TENTRIESEXCEED 21
#define TINSUFFICIENTBUFFER 22

#endif /* COMMON_TYPES_HEADER */
