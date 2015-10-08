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


#ifndef TAGGANT1_HEADER
#define TAGGANT1_HEADER

#define HASHMAP_MAX_LENGTH 4
#define HASH_READ_BLOCK 65536
#define CERTIFICATES_IN_TAGGANT_CHAIN 2

#include "types.h"
#include "winpe.h"
#include "taggant_types.h"

#ifdef SSV_LIBRARY
/*
 * Create X509 certificate from the buffer.
 * Buffer must contain base64 encoded certificate (PEM format)
 * Caller must free returned certificate after usage
 */
X509* buffer_to_X509(PVOID pCert);
UNSIGNED32 taggant_validate_signature(PTAGGANTOBJ1 pTaggantObj, PTAGGANT1 pTaggant, PVOID pRootCert);
UNSIGNED32 taggant_validate_default_hashes(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ1 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd);
UNSIGNED32 taggant_validate_hashmap(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ1 pTaggantObj, PFILEOBJECT hFile);
UNSIGNED32 taggant_get_timestamp(PTAGGANTOBJ1 pTaggantObj, UNSIGNED64 *pTime, PVOID pTSRootCert);
UNSIGNED32 taggant_get_info(PTAGGANTOBJ1 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 *pSize, PINFO pInfo);
#endif

#ifdef SPV_LIBRARY
UNSIGNED32 taggant_put_timestamp(PTAGGANTOBJ1 pTaggantObj, const char* pTSUrl, UNSIGNED32 uTimeout);
UNSIGNED32 taggant_add_hash_region(PTAGGANTOBJ1 pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength);
UNSIGNED32 taggant_put_info(PTAGGANTOBJ1 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 pSize, PINFO pInfo);
UNSIGNED32 taggant_prepare(PTAGGANTOBJ1 pTaggantObj, const PVOID pLicense, PVOID pTaggantOut, UNSIGNED32 *uTaggantReservedSize);
#endif

void taggant_free_taggant(PTAGGANT1 pTaggant);
UNSIGNED32 taggant_compute_hash_map(PTAGGANTCONTEXT pCtx, PFILEOBJECT hFile, PTAGGANTBLOB pTagBlob);
void bubblesort_hashmap(PHASHBLOB_HASHMAP_DOUBLE regions, UNSIGNED32 lenindex);
int exclude_region_from_hashmap(PHASHBLOB_HASHMAP_DOUBLE regions, UNSIGNED64 offset, UNSIGNED64 size);
UNSIGNED32 compute_region_hash(PTAGGANTCONTEXT pCtx, PFILEOBJECT hFile, EVP_MD_CTX* evp, HASHBLOB_HASHMAP_DOUBLE* region, char* buf);
UNSIGNED32 taggant_compute_default_hash(PTAGGANTCONTEXT pCtx, PHASHBLOB_FULLFILE pHash, PFILEOBJECT hFile, PE_ALL_HEADERS *peh, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd, UNSIGNED32 uTaggantSize);
UNSIGNED32 taggant_read_binary(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PTAGGANT1 *pTaggant);
void taggant_free_taggantobj_content(PTAGGANTOBJ1 pTaggantObj);

#endif /* TAGGANT1_HEADER */
