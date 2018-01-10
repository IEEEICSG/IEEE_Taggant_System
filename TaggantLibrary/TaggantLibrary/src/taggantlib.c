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

#include "global.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "js.h"
#include "txt.h"
#include "taggantlib.h"
#include "timestamp.h"
#include "callbacks.h"
#include "winpe.h"
#include "winpe2.h"
#include "types.h"
#include "taggant.h"
#include "taggant2.h"
#include "miscellaneous.h"
#include "endianness.h"

#include <openssl/ts.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

/* Current version of the library */
#define TAGGANT_LIBRARY_CURRENTVERSION TAGGANT_LIBRARY_VERSION2

/* global variable determines if the library is initialized */
int lib_initialized = 0;

UNSIGNED64 get_lib_version(PTAGGANTOBJ tagobj)
{
#ifdef SPV_LIBRARY
    /* return the version of the library that it is set to working for */
    return tagobj->uVersion;
#endif
    
#ifdef SSV_LIBRARY
    /* return the version of the library to process the current taggant while enumeration */
    return tagobj->tagParent->uVersion;
#endif
}

EXPORT UNSIGNED32 STDCALL TaggantInitializeLibrary(__in_opt TAGGANTFUNCTIONS *pFuncs, __out UNSIGNED64 *puVersion)
{
    /* Get the pointer to callbacks structure */
    TAGGANTFUNCTIONS* callbacks = get_callbacks();
    /* Initialize structure  */
    memset(callbacks, 0, sizeof(TAGGANTFUNCTIONS));
    if (pFuncs != NULL)
    {
        memcpy((char*)callbacks, (char*)pFuncs, get_min((unsigned long)pFuncs->size, sizeof(TAGGANTFUNCTIONS)));
    }
    callbacks->size = sizeof(TAGGANTFUNCTIONS);
    /* If any of memory callbacks are NULL then redirect them to internal callbacks */
    if (callbacks->MemoryAllocCallBack == NULL || callbacks->MemoryFreeCallBack == NULL || callbacks->MemoryReallocCallBack == NULL)
    {
        callbacks->MemoryAllocCallBack = (void* (__DECLARATION*)(size_t))&internal_alloc;
        callbacks->MemoryFreeCallBack = (void (__DECLARATION*)(void*))&internal_free;
        callbacks->MemoryReallocCallBack = (void* (__DECLARATION*)(void*, size_t))&internal_realloc;
    }
    CRYPTO_set_mem_functions(memory_alloc, memory_realloc, memory_free);
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* Return the maximim version number supported by the library */
    *puVersion = TAGGANT_LIBRARY_CURRENTVERSION;

    lib_initialized = 1;
    return TNOERR;
}

EXPORT void STDCALL TaggantFinalizeLibrary(void)
{
    lib_initialized = 0;
    OBJ_cleanup();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
}

#ifdef SPV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantAddHashRegion(__inout PTAGGANTOBJ pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_add_hash_region(pTaggantObj->tagObj1, uOffset, uLength);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_add_hash_region(pTaggantObj->tagObj2, uOffset, uLength);
        break;
    }

    return res;
}

#endif

#ifdef SSV_LIBRARY

EXPORT void STDCALL TaggantFreeTaggant(__deref PTAGGANT pTaggant)
{
    if (pTaggant)
    {
        /* free buffer of taggant v2 */
        taggant2_free_taggant(pTaggant->pTag2);
        /* free buffer of taggant v1 */
        taggant_free_taggant(pTaggant->pTag1);
        /* free buffer of taggant itself */
        memory_free(pTaggant);
    }
}

EXPORT UNSIGNED32 STDCALL TaggantGetTaggant(__in PTAGGANTCONTEXT pCtx, __in PFILEOBJECT hFile, TAGGANTCONTAINER eContainer, __inout PTAGGANT *pTaggant)
{
    UNSIGNED32 res = TNOERR;
    PTAGGANT taggant;
    /* the current file position to check for a next taggant */
    UNSIGNED64 fileend;
    /* end of full file hash, the size of the file without taggants */
    UNSIGNED64 ffhend;
    UNSIGNED64 dsoffset;
    PE_ALL_HEADERS peh;
    UNSIGNED32 ds_offset, ds_size;
    PTAGGANT2 taggant2;
    int err, stoploop = 0;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    taggant = *pTaggant;
    /* create the taggant if it is empty */
    if (!taggant)
    {
        taggant = (PTAGGANT)memory_alloc(sizeof(TAGGANT));
        if (taggant)
        {
            memset(taggant, 0, sizeof(TAGGANT));
            taggant->uVersion = TAGGANT_LIBRARY_CURRENTVERSION;
            taggant->tagganttype = eContainer;
        }
        else
        {
            res = TMEMORY;
        }
    }
    else
    {
        /* ignore eContainer if we are looking for next taggant */
        eContainer = taggant->tagganttype;
    }

    if (res == TNOERR)
    {
        if (taggant->uVersion == TAGGANT_LIBRARY_VERSION2)
        {
            switch (eContainer)
            {
            case TAGGANT_JSFILE:
            {
                /* It is a JavaScript file */
                if (taggant->pTag2)
                {
                    fileend = taggant->pTag2->fileend;
                    ffhend = taggant->pTag2->ffhend;
                    /* Free the taggant object */
                    taggant2_free_taggant(taggant->pTag2);
                    taggant->pTag2 = NULL;
                }
                else
                {
                    fileend = get_file_size(pCtx, hFile);
                    /* exclude digital signature */
                    if (js_get_ds_offset(pCtx, hFile, &dsoffset))
                    {
                        fileend = dsoffset;
                    }
                    /* go through all taggants to get the end of full file hash */
                    ffhend = fileend;
                    while (taggant2_read_textual(pCtx, hFile, ffhend, &taggant2, TAGGANT_JSFILE, JS_COMMENT_BEGIN, (int) strlen(JS_COMMENT_BEGIN), JS_COMMENT_END, (int) strlen(JS_COMMENT_END)) == TNOERR)
                    {
                        ffhend -= strlen(JS_COMMENT_BEGIN) + taggant2->Header.TaggantLength + strlen(JS_COMMENT_END);
                        /* Free the taggant object */
                        taggant2_free_taggant(taggant2);
                    }
                }
                res = taggant2_read_textual(pCtx, hFile, fileend, &taggant->pTag2, TAGGANT_JSFILE, JS_COMMENT_BEGIN, (int) strlen(JS_COMMENT_BEGIN), JS_COMMENT_END, (int) strlen(JS_COMMENT_END));
                if (res == TNOERR)
                {
                    taggant->pTag2->fileend = fileend - (strlen(JS_COMMENT_BEGIN) + taggant->pTag2->Header.TaggantLength + strlen(JS_COMMENT_END));
                    taggant->pTag2->ffhend = ffhend;
                }
                break;
            }
            case TAGGANT_PEFILE:
            {
                /* Assume it is PE file and make sure it is correct
                * If taggant2 points to existing object then PE file had been already verified
                * do not verify it again to save the time
                */
                err = 0;
                if (taggant->pTag2)
                {
                    fileend = taggant->pTag2->fileend;
                    ffhend = taggant->pTag2->ffhend;
                    /* Free the taggant object */
                    taggant2_free_taggant(taggant->pTag2);
                    taggant->pTag2 = NULL;
                }
                else
                {
                    fileend = get_file_size(pCtx, hFile);
                    err = winpe_is_correct_pe_file(pCtx, hFile, &peh) ? 0 : 1;
                    if (!err)
                    {
                        /* exclude digital signature */
                        if (winpe_is_pe64(&peh))
                        {
                            ds_offset = (UNSIGNED32)peh.oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                            ds_size = (UNSIGNED32)peh.oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                        }
                        else
                        {
                            ds_offset = (UNSIGNED32)peh.oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                            ds_size = (UNSIGNED32)peh.oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                        }
                        if (ds_offset != 0 && ds_size != 0)
                        {
                            if ((ds_offset + ds_size) == fileend)
                            {
                                unsigned char tmpbuff[7];

                                fileend -= ds_size;

                                /* account for the zero-padding that the digital certificate might have added prior to being attached */

                                if (file_seek(pCtx, hFile, fileend - sizeof(tmpbuff), SEEK_SET)
                                 && file_read_buffer(pCtx, hFile, tmpbuff, sizeof(tmpbuff))
                                   )
                                {
                                    int i;

                                    for (i = sizeof(tmpbuff) - 1; i >= 0 && !tmpbuff[i]; i--)
                                    {
                                        --fileend;
                                    }
                                }
                            }
                        }
                        ffhend = fileend;
                        while (taggant2_read_binary(pCtx, hFile, ffhend, &taggant2, TAGGANT_PEFILE) == TNOERR)
                        {
                            ffhend -= taggant2->Header.TaggantLength;
                            /* Free the taggant object */
                            taggant2_free_taggant(taggant2);
                        }
                    }
                }
                if (!err)
                {
                    res = taggant2_read_binary(pCtx, hFile, fileend, &taggant->pTag2, TAGGANT_PEFILE);
                    if (res == TNOERR)
                    {
                        taggant->pTag2->fileend = fileend - taggant->pTag2->Header.TaggantLength;
                        taggant->pTag2->ffhend = ffhend;
                    }
                    else
                        if (res == TNOTAGGANTS)
                        {
                            /* try to read taggant v1 */
                            taggant->uVersion = TAGGANT_LIBRARY_VERSION1;
                        }
                }
                else
                {
                    res = TINVALIDPEFILE;
                }
                break;
            }
            case TAGGANT_TXTFILE:
            {
                /* It is a text file */
                if (taggant->pTag2)
                {
                    fileend = taggant->pTag2->fileend;
                    ffhend = taggant->pTag2->ffhend;
                    /* Free the taggant object */
                    taggant2_free_taggant(taggant->pTag2);
                    taggant->pTag2 = NULL;
                }
                else
                {
                    fileend = get_file_size(pCtx, hFile);
                    /* go through all taggants to get the end of full file hash */
                    ffhend = fileend;
                    while (taggant2_read_textual(pCtx, hFile, ffhend, &taggant2, TAGGANT_TXTFILE, NULL, 0, NULL, 0) == TNOERR)
                    {
                        ffhend -= taggant2->Header.TaggantLength;
                        /* Free the taggant object */
                        taggant2_free_taggant(taggant2);
                    }
                }
                res = taggant2_read_textual(pCtx, hFile, fileend, &taggant->pTag2, TAGGANT_TXTFILE, NULL, 0, NULL, 0);
                if (res == TNOERR)
                {
                    taggant->pTag2->fileend = fileend - taggant->pTag2->Header.TaggantLength;
                    taggant->pTag2->ffhend = ffhend;
                }
                break;
            }
            case TAGGANT_BINFILE:
            {
                if (taggant->pTag2)
                {
                    fileend = taggant->pTag2->fileend;
                    ffhend = taggant->pTag2->ffhend;
                    /* Free the taggant object */
                    taggant2_free_taggant(taggant->pTag2);
                    taggant->pTag2 = NULL;
                }
                else
                {
                    fileend = get_file_size(pCtx, hFile);
                    ffhend = fileend;
                    while (taggant2_read_binary(pCtx, hFile, ffhend, &taggant2, TAGGANT_BINFILE) == TNOERR)
                    {
                        ffhend -= taggant2->Header.TaggantLength;
                        /* Free the taggant object */
                        taggant2_free_taggant(taggant2);
                    }
                }
                res = taggant2_read_binary(pCtx, hFile, fileend, &taggant->pTag2, TAGGANT_BINFILE);
                if (res == TNOERR)
                {
                    taggant->pTag2->fileend = fileend - taggant->pTag2->Header.TaggantLength;
                    taggant->pTag2->ffhend = ffhend;
                }
                break;
            }
            default:
            {
                res = TTYPE;
                break;
            }
            }
        }
        else
            if(taggant->uVersion == TAGGANT_LIBRARY_VERSION1 && !stoploop)
            {
                /* if we already processed taggant v1 then stop the enumeration */
                res = TNOTAGGANTS;
                stoploop = 1;
            }
        if (taggant->uVersion == TAGGANT_LIBRARY_VERSION1 && !stoploop)
        {
            if (eContainer == TAGGANT_PEFILE)
            {
                res = taggant_read_binary(pCtx, hFile, &taggant->pTag1);
            }
            else
            {
                res = TTYPE;
            }			
        }
    }
    *pTaggant = taggant;
    return res;
}
#endif

#ifdef SSV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantValidateSignature(__in PTAGGANTOBJ pTaggantObj, __in PTAGGANT pTaggant, __in PVOID pRootCert)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_validate_signature(pTaggantObj->tagObj1, pTaggant->pTag1, pRootCert);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_validate_signature(pTaggantObj->tagObj2, pTaggant->pTag2, pRootCert);
        break;
    }

    return res;
}

#endif


#ifdef SPV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantComputeHashes(__in PTAGGANTCONTEXT pCtx, __inout PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile,
        UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd, UNSIGNED32 uTaggantSize)
{
    PE_ALL_HEADERS peh;
    UNSIGNED32 res = TINVALIDPEFILE;
    UNSIGNED64 objectend, fileend = uFileEnd;
    PTAGGANT1 taggant1 = NULL;
    PTAGGANT2 taggant2 = NULL;
    int found = 0;
    EVP_MD_CTX evp;
    UNSIGNED8 prevtag;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        /* Check if the file is correct win_pe file */
        if (winpe_is_correct_pe_file(pCtx, hFile, &peh))
        {
            /* Compute default hash */
            res = taggant_compute_default_hash(pCtx, &pTaggantObj->tagObj1->pTagBlob->Hash.FullFile, hFile, &peh, uObjectEnd, fileend, uTaggantSize);
            if (res == TNOERR && pTaggantObj->tagObj1->pTagBlob->Hash.Hashmap.Entries > 0)
            {
                /* Compute hashmap */
                res = taggant_compute_hash_map(pCtx, hFile, pTaggantObj->tagObj1->pTagBlob);
            }
        }
        else
        {
            res = TINVALIDPEFILE;
        }
        break;
    case TAGGANT_LIBRARY_VERSION2:		
        switch (pTaggantObj->tagObj2->tagganttype)
        {
        case TAGGANT_JSFILE:
        {
            /* It is a JavaScript file */
            if (!fileend)
            {
                fileend = get_file_size(pCtx, hFile);
            }
            /* Get the file end exclude existing taggants
            * Walk through all taggants in file and take offset of the file without taggants
            * Take offset and size of the latest taggant to include it into hash map
            */
            res = TNOERR;
            found = 0;
            while (res == TNOERR && taggant2_read_textual(pCtx, hFile, fileend, &taggant2, TAGGANT_JSFILE, JS_COMMENT_BEGIN, (int) strlen(JS_COMMENT_BEGIN), JS_COMMENT_END, (int) strlen(JS_COMMENT_END)) == TNOERR)
            {
                fileend -= strlen(JS_COMMENT_BEGIN) + taggant2->Header.TaggantLength + strlen(JS_COMMENT_END);
                /* Get the offset and size of the first found taggant to add it into hashmap */
                if (!found)
                {
                    /* remember that there is a previous taggant in the file */
                    prevtag = 1;                    
                    if ((res = taggant2_put_extrainfo(&pTaggantObj->tagObj2->tagBlob.Extrablob, ETAGPREV, sizeof(prevtag), (char*)&prevtag)) == TNOERR)
                    {
                        /* add a hash region of the previous taggant */
                        if ((res = taggant2_add_hash_region(pTaggantObj->tagObj2, fileend, strlen(JS_COMMENT_BEGIN) + taggant2->Header.TaggantLength + strlen(JS_COMMENT_END))) == TNOERR)
                        {
                            found++;
                        }
                    }
                }
                /* Free the taggant object */
                taggant2_free_taggant(taggant2);
            }
            if (res == TNOERR)
            {
                res = taggant2_compute_hash_raw(pCtx, &pTaggantObj->tagObj2->tagBlob.Hash, hFile, fileend, pTaggantObj->tagObj2->tagBlob.pHashMapDoubles);
            }
            break;
        }
        case TAGGANT_TXTFILE:
        {
            /* It is a text file */
            if (!fileend)
            {
                fileend = get_file_size(pCtx, hFile);
            }
            /* Get the file end exclude existing taggants
            * Walk through all taggants in file and take offset of the file without taggants
            * Take offset and size of the latest taggant to include it into hash map
            */
            res = TNOERR;
            found = 0;
            while (res == TNOERR && taggant2_read_textual(pCtx, hFile, fileend, &taggant2, TAGGANT_TXTFILE, NULL, 0, NULL, 0) == TNOERR)
            {
                fileend -= taggant2->Header.TaggantLength;
                /* Get the offset and size of the first found taggant to add it into hashmap */
                if (!found)
                {
                    /* remember that there is a previous taggant in the file */
                    prevtag = 1;
                    if ((res = taggant2_put_extrainfo(&pTaggantObj->tagObj2->tagBlob.Extrablob, ETAGPREV, sizeof(prevtag), (char*)&prevtag)) == TNOERR)
                    {
                        /* add a hash region of the previous taggant */
                        if ((res = taggant2_add_hash_region(pTaggantObj->tagObj2, fileend, taggant2->Header.TaggantLength)) == TNOERR)
                        {
                            found++;
                        }
                    }
                }
                /* Free the taggant object */
                taggant2_free_taggant(taggant2);
            }
            if (res == TNOERR)
            {
                res = taggant2_compute_hash_raw(pCtx, &pTaggantObj->tagObj2->tagBlob.Hash, hFile, fileend, pTaggantObj->tagObj2->tagBlob.pHashMapDoubles);
            }
            break;
        }
        case TAGGANT_PEFILE:
        {
            /* Assume it is PE file and make sure it is correct */
            if (winpe_is_correct_pe_file(pCtx, hFile, &peh))
            {
                /* Get the object end of PE file */
                objectend = winpe2_object_end(pCtx, hFile, &peh);
                /* Get the file end excluding existing taggants
                * Walk through all taggants in file and take offset of the file without taggants
                * Take offset and size of the latest taggant to include it into hash map
                */
                if (!fileend)
                {
                    fileend = get_file_size(pCtx, hFile);
                }
                res = TNOERR;
                found = 0;
                while (res == TNOERR && taggant2_read_binary(pCtx, hFile, fileend, &taggant2, TAGGANT_PEFILE) == TNOERR)
                {
                    fileend -= taggant2->Header.TaggantLength;
                    /* Get the offset and size of the first found taggant to add it into hashmap */
                    if (!found)
                    {
                        /* remember that there is a previous taggant in the file */
                        prevtag = 1;
                        if ((res = taggant2_put_extrainfo(&pTaggantObj->tagObj2->tagBlob.Extrablob, ETAGPREV, sizeof(prevtag), (char*)&prevtag)) == TNOERR)
                        {
                            /* add a hash region of the previous taggant */
                            if ((res = taggant2_add_hash_region(pTaggantObj->tagObj2, fileend, taggant2->Header.TaggantLength)) == TNOERR)
                            {
                                found++;
                            }
                        }
                    }
                    /* Free the taggant object */
                    taggant2_free_taggant(taggant2);
                }
                if (res == TNOERR)
                {
                    /* if taggant v2 is not found, try to find taggant v1 to add it to hashmap */
                    if (!found)
                    {
                        if (taggant_read_binary(pCtx, hFile, &taggant1) == TNOERR)
                        {
                            /* remember that there is a previous taggant in the file */
                            prevtag = 1;
                            if ((res = taggant2_put_extrainfo(&pTaggantObj->tagObj2->tagBlob.Extrablob, ETAGPREV, sizeof(prevtag), (char*)&prevtag)) == TNOERR)
                            {
                                /* add a hash region of the previous taggant */
                                if ((res = taggant2_add_hash_region(pTaggantObj->tagObj2, taggant1->offset, (UNSIGNED64)taggant1->Header.TaggantLength)) == TNOERR)
                                {
                                    found++;
                                }
                            }
                            /* Free the taggant object */
                            taggant_free_taggant(taggant1);
                        }
                    }
                    if (res == TNOERR)
                    {
                        /* compute file hashes */
                        if (fileend >= uObjectEnd)
                        {
                            /* Compute hash */
                            EVP_MD_CTX_init(&evp);
                            EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
                            /* Compute default hash */
                            if ((res = taggant2_compute_default_hash_pe(&evp, pCtx, &pTaggantObj->tagObj2->tagBlob.Hash.FullFile.DefaultHash, hFile, &peh, objectend)) == TNOERR)
                            {
                                /* Compute extended hash */
                                if ((res = taggant2_compute_extended_hash_pe(&evp, pCtx, &pTaggantObj->tagObj2->tagBlob.Hash.FullFile.ExtendedHash, hFile, objectend, fileend)) == TNOERR)
                                {
                                    if (pTaggantObj->tagObj2->tagBlob.Hash.Hashmap.Entries > 0)
                                    {
                                        /* Compute hashmap */
                                        res = taggant2_compute_hash_map(pCtx, hFile, &pTaggantObj->tagObj2->tagBlob.Hash.Hashmap, pTaggantObj->tagObj2->tagBlob.pHashMapDoubles);
                                    }
                                }
                            }
                            /* Clean hash context */
                            EVP_MD_CTX_cleanup(&evp);
                        }
                        else
                        {
                            res = TFILEERROR;
                        }
                    }
                }
            }
            else
            {
                res = TINVALIDPEFILE;
            }
            break;
        }
        case TAGGANT_BINFILE:
        {
            /* Get the file end excluding existing taggants
            * Walk through all taggants in file and take offset of the file without taggants
            * Take offset and size of the latest taggant to include it into hash map
            */
            if (!fileend)
            {
                fileend = get_file_size(pCtx, hFile);
            }
            res = TNOERR;
            found = 0;
            while (res == TNOERR && taggant2_read_binary(pCtx, hFile, fileend, &taggant2, TAGGANT_BINFILE) == TNOERR)
            {
                fileend -= taggant2->Header.TaggantLength;
                /* Get the offset and size of the first found taggant to add it into hashmap */
                if (!found)
                {
                    /* remember that there is a previous taggant in the file */
                    prevtag = 1;
                    if ((res = taggant2_put_extrainfo(&pTaggantObj->tagObj2->tagBlob.Extrablob, ETAGPREV, sizeof(prevtag), (char*)&prevtag)) == TNOERR)
                    {
                        /* add a hash region of the previous taggant */
                        if ((res = taggant2_add_hash_region(pTaggantObj->tagObj2, fileend, taggant2->Header.TaggantLength)) == TNOERR)
                        {
                            found++;
                        }
                    }
                }
                /* Free the taggant object */
                taggant2_free_taggant(taggant2);
            }
            if (res == TNOERR)
            {
                res = taggant2_compute_hash_raw(pCtx, &pTaggantObj->tagObj2->tagBlob.Hash, hFile, fileend, pTaggantObj->tagObj2->tagBlob.pHashMapDoubles);
            }
            break;
        }
        default:
        {
            res = TTYPE;
        }
        }
        break;
    default:
        res = TNOTIMPLEMENTED;
        break;
    }

    return res;
}

EXPORT UNSIGNED32 STDCALL TaggantPutInfo(__inout PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 pSize, __in_bcount(pSize) PINFO pInfo)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_put_info(pTaggantObj->tagObj1, eKey, pSize, pInfo);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_put_info(pTaggantObj->tagObj2, eKey, pSize, pInfo);
        break;
    }

    return res;
}

#endif

#ifdef SSV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantGetInfo(__in PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, __inout UNSIGNED32 *pSize, __out_bcount_full_opt(*pSize) PINFO pInfo)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_get_info(pTaggantObj->tagObj1, eKey, pSize, pInfo);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_get_info(pTaggantObj->tagObj2, eKey, pSize, pInfo);
        break;
    }

    return res;
}

#endif

#ifdef SPV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantPrepare(__inout PTAGGANTOBJ pTaggantObj, __in const PVOID pLicense, __out_bcount_part(*uTaggantReservedSize, *uTaggantReservedSize) PVOID pTaggantOut, __inout UNSIGNED32 *uTaggantReservedSize)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    if (!pLicense)
    {
        return TBADKEY;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_prepare(pTaggantObj->tagObj1, pLicense, pTaggantOut, uTaggantReservedSize);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_prepare(pTaggantObj->tagObj2, pLicense, pTaggantObj->tagObj2->tagganttype, pTaggantOut, uTaggantReservedSize);
        break;
    }
    return res;
}

#endif

#ifdef SSV_LIBRARY

EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantGetTimestamp(__in PTAGGANTOBJ pTaggantObj, __out UNSIGNED64 *pTime, __in PVOID pTSRootCert)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    if (!pTSRootCert)
    {
        return TBADKEY;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_get_timestamp(pTaggantObj->tagObj1, pTime, pTSRootCert);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_get_timestamp(pTaggantObj->tagObj2, pTime, pTSRootCert);
        break;
    }

    return res;
}

#endif

#ifdef SPV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantPutTimestamp(__inout PTAGGANTOBJ pTaggantObj, __in const char* pTSUrl, UNSIGNED32 uTimeout)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_put_timestamp(pTaggantObj->tagObj1, pTSUrl, uTimeout);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_put_timestamp(pTaggantObj->tagObj2, pTSUrl, uTimeout);
        break;
    }

    return res;
}

#endif

EXPORT PTAGGANTOBJ STDCALL TaggantObjectNew(__in_opt PTAGGANT pTaggant)
{
    PTAGGANTOBJ pTaggantObj;
    return TaggantObjectNewEx(pTaggant, TAGGANT_LIBRARY_CURRENTVERSION, TAGGANT_PEFILE, &pTaggantObj) == TNOERR ? pTaggantObj : NULL;
}


EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantObjectNewEx(__in_opt PTAGGANT pTaggant, UNSIGNED64 uVersion, TAGGANTCONTAINER eTaggantType, __out PTAGGANTOBJ *pTaggantObj)
{
#ifdef SSV_LIBRARY
    PTAGGANT taggant = (PTAGGANT)pTaggant;
#endif
    UNSIGNED32 res = TNOERR;
    PTAGGANTOBJ tagObj;
    UNSIGNED64 ver = TAGGANT_LIBRARY_CURRENTVERSION;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }
#ifdef SSV_LIBRARY
    ver = taggant->uVersion;
#endif

#ifdef SPV_LIBRARY
    /* accept version number for spv only, for ssv works as latest library version */
    ver = uVersion;
    if (ver == TAGGANT_LIBRARY_VERSION1 && (eTaggantType == TAGGANT_JSFILE || eTaggantType == TAGGANT_TXTFILE || eTaggantType == TAGGANT_BINFILE))
    {
        return TTYPE;
    }
#endif

    tagObj = memory_alloc(sizeof(TAGGANTOBJ));
    if (tagObj)
    {
        memset(tagObj, 0, sizeof(TAGGANTOBJ));		
        if (ver == TAGGANT_LIBRARY_VERSION1)
        {
            tagObj->tagObj1 = (PTAGGANTOBJ1)memory_alloc(sizeof(TAGGANTOBJ1));
            if (tagObj->tagObj1)
            {
                memset(tagObj->tagObj1, 0, sizeof(TAGGANTOBJ1));

                /* Allocate intial memory for taggant blob and initialize it */
                tagObj->tagObj1->pTagBlob = (PTAGGANTBLOB)memory_alloc(sizeof(TAGGANTBLOB));
                if (tagObj->tagObj1->pTagBlob)
                {

                    memset(tagObj->tagObj1->pTagBlob, 0, sizeof(TAGGANTBLOB));
                    /* Initialize taggant blob */
                    tagObj->tagObj1->pTagBlob->Header.Version = TAGGANTBLOB_VERSION1;
                    tagObj->tagObj1->pTagBlob->Header.Length = sizeof(TAGGANTBLOB);

                    /* Set the size of the taggant, required for SSV only */
#ifdef SSV_LIBRARY
                    tagObj->tagObj1->uTaggantSize = taggant->pTag1->Header.TaggantLength;
#endif
                    res = TNOERR;
                }
                else
                {
                    memory_free(tagObj->tagObj1);
                    tagObj->tagObj1 = NULL;
                    res = TMEMORY;
                }
            }
            else
            {
                res = TMEMORY;
            }
        }
        else
            if (ver == TAGGANT_LIBRARY_VERSION2)
            {
                
                tagObj->tagObj2 = (PTAGGANTOBJ2)memory_alloc(sizeof(TAGGANTOBJ2));
                if (tagObj->tagObj2)
                {
                    memset(tagObj->tagObj2, 0, sizeof(TAGGANTOBJ2));
                    /* Initialize taggant blob */
                    tagObj->tagObj2->tagBlob.Header.Version = TAGGANTBLOB_VERSION2;
                    /* Remember the fileend and taggant type values */
#ifdef SSV_LIBRARY
                    tagObj->tagObj2->fileend = taggant->pTag2->fileend;
                    tagObj->tagObj2->tagganttype = taggant->pTag2->tagganttype;
#endif
#ifdef SPV_LIBRARY
                    tagObj->tagObj2->tagganttype = eTaggantType;
#endif
                    res = TNOERR;
                }
                else
                {
                    res = TMEMORY;
                }
            }
            else
            {
                res = TNOTIMPLEMENTED;
            }
    }
    else
    {
        res = TMEMORY;
    }
    if (res == TNOERR)
    {
#ifdef SSV_LIBRARY
        tagObj->tagParent = pTaggant;
#endif
#ifdef SPV_LIBRARY
        tagObj->uVersion = ver;
#endif
        /* Return TAGGANT object */
        *pTaggantObj = (void*)tagObj;
    }
    else
    {
        memory_free(tagObj);
    }
    return res;
}

EXPORT void STDCALL TaggantObjectFree(__deref PTAGGANTOBJ pTaggantObj)
{
    if (!lib_initialized)
    {
        return;
    }

    if (pTaggantObj)
    {
        if (pTaggantObj->tagObj1)
        {
            taggant_free_taggantobj_content(pTaggantObj->tagObj1);
            /* Free memory of taggant object */
            memory_free(pTaggantObj->tagObj1);
        }
        if (pTaggantObj->tagObj2)
        {
            taggant2_free_taggantobj_content(pTaggantObj->tagObj2);
            /* Free memory of taggant object */
            memory_free(pTaggantObj->tagObj2);
        }
        memory_free(pTaggantObj);
    }

    return;
}

EXPORT PTAGGANTCONTEXT STDCALL TaggantContextNew(void)
{
    PTAGGANTCONTEXT pCtx;
    return TaggantContextNewEx(&pCtx) == TNOERR ? pCtx : NULL;
}

EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantContextNewEx(__out PTAGGANTCONTEXT *pCtx)
{
    PTAGGANTCONTEXT ctx = NULL;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }
    ctx = (PTAGGANTCONTEXT)memory_alloc(sizeof(TAGGANTCONTEXT));
    if (!ctx)
    {
        return TMEMORY;
    }
    ctx->size = sizeof(TAGGANTCONTEXT);
    ctx->FileReadCallBack = (size_t (__DECLARATION *)(PFILEOBJECT, void*, size_t))&internal_fread;
    ctx->FileSeekCallBack = (int (__DECLARATION *)(PFILEOBJECT, UNSIGNED64, int))&internal_fseek;
    ctx->FileTellCallBack = (UNSIGNED64 (__DECLARATION *)(PFILEOBJECT))&internal_ftell;
    /* Return TAGGANT context */
    *pCtx = ctx;
    return TNOERR;
}

EXPORT void STDCALL TaggantContextFree(__deref PTAGGANTCONTEXT pTaggantCtx)
{
    if (!lib_initialized)
    {
        return;
    }
    if (pTaggantCtx)
    {
        /* Free memory of taggant context */
        memory_free(pTaggantCtx);
    }
    return;
}

#ifdef SPV_LIBRARY

EXPORT __success(return == TNOERR) UNSIGNED32 STDCALL TaggantGetLicenseExpirationDate(__in const PVOID pLicense, __out UNSIGNED64 *pTime)
{
    UNSIGNED32 res = TBADKEY;
    BIO *licbio = NULL;
    X509 *liccert = NULL, *licspv = NULL;
    EVP_PKEY *lickey = NULL;
    ASN1_TIME *exp_date = NULL;
    ASN1_GENERALIZEDTIME *gn_time = NULL;
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    if (!pLicense)
    {
        return TBADKEY;
    }

    /* Load user license certificate and private key */
    licbio = BIO_new(BIO_s_mem());
    if (licbio)
    {
        BIO_write(licbio, pLicense, (int)strlen((const char*)pLicense));
        /* Load SPV certificate and make sure it is valid */
        licspv = PEM_read_bio_X509(licbio, NULL, 0, NULL);
        if (licspv)
        {
            /* Free SPV certificate */
            X509_free(licspv);
            /* Load USER certificate and make sure it is valid */
            liccert = PEM_read_bio_X509(licbio, NULL, 0, NULL);
            if (liccert)
            {
                /* Load User private key and make sure it is valid */
                lickey = PEM_read_bio_PrivateKey(licbio, NULL, 0, NULL);
                if (lickey)
                {
                    /* Free private key */
                    EVP_PKEY_free(lickey);
                    /* Get expiration date of User certificate */
                    exp_date = X509_get_notAfter(liccert);
                    if (exp_date)
                    {
                        gn_time = ASN1_TIME_to_generalizedtime(exp_date, NULL);
                        if (gn_time)
                        {
                            if (sscanf((const char*)ASN1_STRING_data((ASN1_STRING*)gn_time), "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &minute, &second) == 6)
                            {
                                *pTime = time_as_unsigned64(year, month, day, hour, minute, second);
                                res = TNOERR;
                            }
                            ASN1_GENERALIZEDTIME_free(gn_time);
                        }
                    }
                }
                X509_free(liccert);
            }
        }
        BIO_free(licbio);
    }
    return res;
}

#endif

#ifdef SSV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantCheckCertificate(__in PVOID pCert)
{
    BIO* certbio = NULL;
    X509* cert = NULL;
    UNSIGNED32 res;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    /* Check if certificate buffer is empty */
    if (!pCert)
    {
        return TINVALID;
    }

    /* Load certificate to bio */
    res = TMEMORY;
    certbio = BIO_new(BIO_s_mem());
    if (certbio)
    {
        res = TINVALID;
        BIO_write(certbio, pCert, (int)strlen((const char*)pCert));

        /* Load certificate */
        cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
        if (cert)
        {
            /* Certificate is valid */
            res = TNOERR;

            /* Free certificate */
            X509_free(cert);
        }
        /* Free bio */
        BIO_free(certbio);
    }

    return res;
}

#endif

#ifdef SSV_LIBRARY

EXPORT __success(return > 0) UNSIGNED16 STDCALL TaggantGetHashMapDoubles(__in PTAGGANTOBJ pTaggantObj, __out PHASHBLOB_HASHMAP_DOUBLE *pDoubles)
{
    UNSIGNED16 res = 0;

    if (lib_initialized)
    {
        switch (get_lib_version(pTaggantObj))
        {
        case TAGGANT_LIBRARY_VERSION1:			
            if (pTaggantObj->tagObj1->pTagBlob->Hash.Hashmap.Entries
             && ((pTaggantObj->tagObj1->pTagBlob->Hash.Hashmap.DoublesOffset + (pTaggantObj->tagObj1->pTagBlob->Hash.Hashmap.Entries * sizeof(HASHBLOB_HASHMAP_DOUBLE))) <= pTaggantObj->tagObj1->pTagBlob->Header.Length))
            {
                *pDoubles = (PHASHBLOB_HASHMAP_DOUBLE)((char*)pTaggantObj->tagObj1->pTagBlob + pTaggantObj->tagObj1->pTagBlob->Hash.Hashmap.DoublesOffset);
                res = pTaggantObj->tagObj1->pTagBlob->Hash.Hashmap.Entries;
            }
            break;
        case TAGGANT_LIBRARY_VERSION2:			
            if (pTaggantObj->tagObj2->tagBlob.Hash.Hashmap.Entries
             && ((pTaggantObj->tagObj2->tagBlob.Hash.Hashmap.DoublesOffset + (pTaggantObj->tagObj2->tagBlob.Hash.Hashmap.Entries * sizeof(HASHBLOB_HASHMAP_DOUBLE))) <= pTaggantObj->tagObj2->tagBlob.Header.Length))
            {
                *pDoubles = pTaggantObj->tagObj2->tagBlob.pHashMapDoubles;
                res = pTaggantObj->tagObj2->tagBlob.Hash.Hashmap.Entries;
            }
            break;
        }
    }

    return res;	
}

#endif

EXPORT PPACKERINFO STDCALL TaggantPackerInfo(__in PTAGGANTOBJ pTaggantObj)
{
    PPACKERINFO res = NULL;

    if (lib_initialized)
    {
        switch (get_lib_version(pTaggantObj))
        {
        case TAGGANT_LIBRARY_VERSION1:
            res = &pTaggantObj->tagObj1->pTagBlob->Header.PackerInfo;
            break;
        case TAGGANT_LIBRARY_VERSION2:
            res = &pTaggantObj->tagObj2->tagBlob.Header.PackerInfo;
            break;
        }
    }
    return res;	
}

#ifdef SSV_LIBRARY

EXPORT UNSIGNED32 STDCALL TaggantValidateDefaultHashes(__in PTAGGANTCONTEXT pCtx, __in PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;
    UNSIGNED64 filend = uFileEnd;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_validate_default_hashes(pCtx, pTaggantObj->tagObj1, hFile, uObjectEnd, uFileEnd);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        if (!filend)
        {
            filend = pTaggantObj->tagParent->pTag2->ffhend;
        }
        switch (pTaggantObj->tagObj2->tagganttype)
        {
        case TAGGANT_JSFILE:
        {
            res = taggant2_validate_default_hashes_js(pCtx, pTaggantObj->tagObj2, hFile, filend);
            break;
        }
        case TAGGANT_TXTFILE:
        {
            res = taggant2_validate_default_hashes_txt(pCtx, pTaggantObj->tagObj2, hFile, filend);
            break;
        }
        case TAGGANT_PEFILE:
        {
            res = taggant2_validate_default_hashes_pe(pCtx, pTaggantObj->tagObj2, hFile, uObjectEnd, filend);
            break;
        }
        case TAGGANT_BINFILE:
        {
            res = taggant2_validate_default_hashes_bin(pCtx, pTaggantObj->tagObj2, hFile, filend);
            break;
        }
        default:
        {
            res = TTYPE;
        }
        }
        break;
    }

    return res;
}

EXPORT UNSIGNED32 STDCALL TaggantValidateHashMap(__in PTAGGANTCONTEXT pCtx, __in PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile)
{
    UNSIGNED32 res = TNOTIMPLEMENTED;

    if (!lib_initialized)
    {
        return TLIBNOTINIT;
    }

    switch (get_lib_version(pTaggantObj))
    {
    case TAGGANT_LIBRARY_VERSION1:
        res = taggant_validate_hashmap(pCtx, pTaggantObj->tagObj1, hFile);
        break;
    case TAGGANT_LIBRARY_VERSION2:
        res = taggant2_validate_hashmap(pCtx, pTaggantObj->tagObj2, hFile);
        break;
    }

    return res;
}

#endif
