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

#ifndef TAGGANTLIB_HEADER
#define TAGGANTLIB_HEADER

#include "taggant_types.h"
#ifdef TAGGANT_LIBRARY
#include "types.h"
#endif

#ifdef _WIN32
#	define STDCALL __stdcall
#else
#	define STDCALL
#endif
#if defined(_WIN32) && !defined(TAGGANT_STATIC)
#	ifdef __cplusplus
#		define EXPORT extern "C" __declspec (dllexport)
#	else
#		define EXPORT __declspec (dllexport)
#	endif
#else
#	ifdef __cplusplus
#		define EXPORT extern "C"
#	else
#		define EXPORT
#	endif
#endif

#ifdef __GNUC__
#define DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: DEPRECATED attribute is not supported by the compiler")
#define DEPRECATED
#endif


/* #define SSV_LIBRARY */
/* #define SPV_LIBRARY */

EXPORT UNSIGNED32 STDCALL TaggantInitializeLibrary(__in_opt TAGGANTFUNCTIONS *pFuncs, __out UNSIGNED64 *puVersion);
EXPORT void STDCALL TaggantFinalizeLibrary(void);
EXPORT PTAGGANTOBJ STDCALL TaggantObjectNew(__in_opt PTAGGANT pTaggant);
EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantObjectNewEx(__in_opt PTAGGANT pTaggant, UNSIGNED64 uVersion, TAGGANTCONTAINER eTaggantType, __out PTAGGANTOBJ *pTaggantObj);
EXPORT void STDCALL TaggantObjectFree(__deref PTAGGANTOBJ pTaggantObj);
EXPORT PTAGGANTCONTEXT STDCALL TaggantContextNew(void);
EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantContextNewEx(__out PTAGGANTCONTEXT *pCtx);
EXPORT void STDCALL TaggantContextFree(__deref PTAGGANTCONTEXT pTaggantCtx);

/* Deprecated function, use TaggantGetInfo/TaggantPutInfo with EPACKERINFO parameter instead */
EXPORT DEPRECATED PPACKERINFO STDCALL TaggantPackerInfo(__in PTAGGANTOBJ pTaggantObj);

#ifdef SSV_LIBRARY
EXPORT __success(return > 0) UNSIGNED16 STDCALL TaggantGetHashMapDoubles(__in PTAGGANTOBJ pTaggantObj, __out PHASHBLOB_HASHMAP_DOUBLE *pDoubles);
EXPORT UNSIGNED32 STDCALL TaggantValidateDefaultHashes(__in PTAGGANTCONTEXT pCtx, __in PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd);
EXPORT UNSIGNED32 STDCALL TaggantValidateHashMap(__in PTAGGANTCONTEXT pCtx, __in PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile);
EXPORT UNSIGNED32 STDCALL TaggantGetTaggant(__in PTAGGANTCONTEXT pCtx, __in PFILEOBJECT hFile, TAGGANTCONTAINER eContainer, __inout PTAGGANT *pTaggant);
EXPORT void STDCALL TaggantFreeTaggant(__deref PTAGGANT pTaggant);
EXPORT UNSIGNED32 STDCALL TaggantValidateSignature(__in PTAGGANTOBJ pTaggantObj, __in PTAGGANT pTaggant, __in PVOID pRootCert);
EXPORT UNSIGNED32 STDCALL TaggantGetInfo(__in PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, __inout UNSIGNED32 *pSize, __out_bcount_full_opt(*pSize) PINFO pInfo);
EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantGetTimestamp(__in PTAGGANTOBJ pTaggantObj, __out UNSIGNED64 *pTime, __in PVOID pTSRootCert);
EXPORT UNSIGNED32 STDCALL TaggantCheckCertificate(__in PVOID pCert);
#endif

#ifdef SPV_LIBRARY
EXPORT UNSIGNED32 STDCALL TaggantPutInfo(__inout PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 pSize, __in_bcount(pSize) PINFO pInfo);
EXPORT UNSIGNED32 STDCALL TaggantComputeHashes(__in PTAGGANTCONTEXT pCtx, __inout PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd, UNSIGNED32 uTaggantSize);
EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantGetLicenseExpirationDate(__in const PVOID pLicense, __out UNSIGNED64 *pTime);
EXPORT UNSIGNED32 STDCALL TaggantAddHashRegion(__inout PTAGGANTOBJ pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength);
EXPORT UNSIGNED32 STDCALL TaggantPrepare(__inout PTAGGANTOBJ pTaggantObj, __in const PVOID pLicense, __out_bcount_part(*uTaggantReservedSize, *uTaggantReservedSize) PVOID pTaggantOut, __inout UNSIGNED32 *uTaggantReservedSize);
EXPORT UNSIGNED32 STDCALL TaggantPutTimestamp(__inout PTAGGANTOBJ pTaggantObj, __in const char* pTSUrl, UNSIGNED32 uTimeout);
#endif


#endif /* TAGGANTLIB_HEADER */
