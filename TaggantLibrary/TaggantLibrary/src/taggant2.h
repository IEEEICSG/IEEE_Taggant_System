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


#ifndef TAGGANT2_HEADER
#define TAGGANT2_HEADER

/* Number of hash regions for PE file for taggant v2 */
#define HASHMAP2_MAX_LENGTH 3

#include "types.h"
#include "taggant_types.h"

void taggant2_free_taggant(PTAGGANT2 pTaggant);
UNSIGNED32 taggant2_read_binary(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, PTAGGANT2* pTaggant, TAGGANTCONTAINER filetype);
UNSIGNED32 taggant2_read_textual(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, PTAGGANT2* pTaggant, TAGGANTCONTAINER filetype, char *beginmarker, int beginmarkersize, char *endmarker, int endmarkersize);
UNSIGNED32 taggant2_compute_default_hash_pe(EVP_MD_CTX *pEvp, PTAGGANTCONTEXT pCtx, PHASHBLOB_DEFAULT pDefaultHash, PFILEOBJECT hFile, PE_ALL_HEADERS *peh, UNSIGNED64 uObjectEnd);
UNSIGNED32 taggant2_compute_extended_hash_pe(EVP_MD_CTX *pEvp, PTAGGANTCONTEXT pCtx, PHASHBLOB_EXTENDED pExtendedHash, PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd);
UNSIGNED32 taggant2_compute_hash_raw(PTAGGANTCONTEXT pCtx, PHASHBLOB pHash, PFILEOBJECT hFile, UNSIGNED64 uFileEnd, PHASHBLOB_HASHMAP_DOUBLE pHmDoubles);
UNSIGNED32 taggant2_compute_hash_map(PTAGGANTCONTEXT pCtx, PFILEOBJECT hFile, PHASHBLOB_HASHMAP pHm, PHASHBLOB_HASHMAP_DOUBLE pHmDoubles);
UNSIGNED32 taggant2_put_extrainfo(PEXTRABLOB2 pExtrablob, ENUMTAGINFO eKey, UNSIGNED32 uSize, PINFO pInfo);
void taggant2_free_taggantobj_content(PTAGGANTOBJ2 pTaggantObj);

#ifdef SSV_LIBRARY
UNSIGNED32 taggant2_validate_signature(PTAGGANTOBJ2 pTaggantObj, PTAGGANT2 pTaggant, PVOID pRootCert);
UNSIGNED32 taggant2_validate_default_hashes_pe(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd);
UNSIGNED32 taggant2_validate_default_hashes_js(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uFileEnd);
UNSIGNED32 taggant2_validate_default_hashes_txt(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uFileEnd);
UNSIGNED32 taggant2_validate_default_hashes_bin(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uFileEnd);
UNSIGNED32 taggant2_validate_hashmap(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile);
UNSIGNED32 taggant2_get_timestamp(PTAGGANTOBJ2 pTaggantObj, UNSIGNED64 *pTime, PVOID pTSRootCert);
UNSIGNED32 taggant2_get_info(PTAGGANTOBJ2 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 *pSize, PINFO pInfo);
#endif

#ifdef SPV_LIBRARY
UNSIGNED32 taggant2_put_timestamp(PTAGGANTOBJ2 pTaggantObj, const char* pTSUrl, UNSIGNED32 uTimeout);
UNSIGNED32 taggant2_add_hash_region(PTAGGANTOBJ2 pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength);
UNSIGNED32 taggant2_put_info(PTAGGANTOBJ2 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 pSize, PINFO pInfo);
UNSIGNED32 taggant2_prepare(PTAGGANTOBJ2 pTaggantObj, const PVOID pLicense, TAGGANTCONTAINER TaggantType, PVOID pTaggantOut, UNSIGNED32 *uTaggantReservedSize);
#endif

#endif /* TAGGANT2_HEADER */
