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
#include "types.h"
#include "taggant.h"
#include "taggant2.h"
#include "winpe.h"
#include "miscellaneous.h"
#include "callbacks.h"
#include "endianness.h"
#include "taggant_types.h"
#include "verify_helper.h"
#include "timestamp.h"
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#ifdef SSV_LIBRARY

/*
 * Create X509 certificate from the buffer.
 * Buffer must contain base64 encoded certificate (PEM format)
 * Caller must free returned certificate after usage
 */
X509* buffer_to_X509(PVOID pCert)
{
    BIO* certbio = NULL;
    X509* cert = NULL;

    if (pCert)
    {
        certbio = BIO_new(BIO_s_mem());
        if (certbio)
        {
            BIO_write(certbio, pCert, (int)strlen((const char*)pCert));
            /* Load certificate */
            cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
            /* Free bio */
            BIO_free(certbio);
        }
    }
    return cert;
}

/* Check if the "null area" contains only zeros
 * Null area is a region between end of CMS and end of pTaggant.CMS structure
 */
int check_null_area(PTAGGANT1 pTaggant)
{
    int i;

    /* pTaggant->Header.TaggantLength is always greater than the sum of sizeof(TAGGANT_HEADER) and sizeof(TAGGANT_FOOTER) */
    for (i = (int)pTaggant->Header.CMSLength; i < (int)(pTaggant->Header.TaggantLength - sizeof(TAGGANT_HEADER) - sizeof(TAGGANT_FOOTER)); i++)
    {
        if (((char*)pTaggant->CMSBuffer)[i] != '\0')
        {
            return 0;
        }
    }
    return 1;
}

UNSIGNED32 taggant_compare_hash_map(PTAGGANTBLOB pTagBlob1, PTAGGANTBLOB pTagBlob2)
{
    UNSIGNED32 res = TMISMATCH;

    if (pTagBlob1->Hash.Hashmap.Header.Version == pTagBlob2->Hash.Hashmap.Header.Version &&
        pTagBlob1->Hash.Hashmap.Header.Version == HASHBLOB_VERSION1 &&
        pTagBlob1->Hash.Hashmap.Header.Type == pTagBlob2->Hash.Hashmap.Header.Type &&
        pTagBlob1->Hash.Hashmap.Header.Type == TAGGANT_HASBLOB_HASHMAP &&
        pTagBlob1->Hash.Hashmap.Entries == pTagBlob2->Hash.Hashmap.Entries &&
        (memcmp((char*)pTagBlob1 + pTagBlob1->Hash.Hashmap.DoublesOffset, (char*)pTagBlob2 + pTagBlob2->Hash.Hashmap.DoublesOffset, pTagBlob1->Hash.Hashmap.Entries * sizeof(HASHBLOB_HASHMAP_DOUBLE)) == 0) &&
        (memcmp(&pTagBlob1->Hash.Hashmap.Header.Hash, &pTagBlob2->Hash.Hashmap.Header.Hash, sizeof(pTagBlob1->Hash.Hashmap.Header.Hash)) == 0))
    {
        res = TNOERR;
    }
    return res;
}


#endif

void taggant_free_taggant(PTAGGANT1 pTaggant)
{
    /* Make sure taggant object is not null */
    if (pTaggant)
    {
        if (pTaggant->CMSBuffer)
        {
            memory_free(pTaggant->CMSBuffer);
        }
        memory_free(pTaggant);
    }
}

UNSIGNED32 compute_region_hash(PTAGGANTCONTEXT pCtx, PFILEOBJECT hFile, EVP_MD_CTX* evp, HASHBLOB_HASHMAP_DOUBLE* region, char* buf)
{
    UNSIGNED64 bytestoread;
    UNSIGNED64 bytesread;

    if (file_seek(pCtx, hFile, region->AbsoluteOffset, SEEK_SET))
    {
        bytestoread = region->Length;
        while (bytestoread != 0)
        {
            bytesread = (bytestoread >= HASH_READ_BLOCK) ? HASH_READ_BLOCK : bytestoread;
            if (file_read_buffer(pCtx, hFile, buf, (size_t)bytesread))
            {
                EVP_DigestUpdate(evp, buf, (size_t)bytesread);
                bytestoread -= bytesread;
            } else
            {
                return TFILEACCESSDENIED;
            }
        }
        return TNOERR;
    }
    return TFILEACCESSDENIED;
}

/*
 * Bubble sort an array of hashmap doubles.
 * lenindex contains "array length" - 1 value.
 */
void bubblesort_hashmap(PHASHBLOB_HASHMAP_DOUBLE regions, UNSIGNED32 lenindex)
{
    int i, j;
    HASHBLOB_HASHMAP_DOUBLE t;

    if (lenindex)
    {
        for (i = (int)lenindex; i >= 0; i--)
        {
            for (j = 0; j <= (int)lenindex - 1; j++)
            {
                if (regions[j].AbsoluteOffset > regions[j + 1].AbsoluteOffset)
                {
                    t = regions[j];
                    regions[j] = regions[j + 1];
                    regions[j + 1] = t;
                }
            }
        }
    }
}

int exclude_region_from_hashmap(PHASHBLOB_HASHMAP_DOUBLE regions, UNSIGNED64 offset, UNSIGNED64 size)
{
    int i = 0, j = 0;
    int arraylen = 0, newarraylen = 0;
    HASHBLOB_HASHMAP_DOUBLE t;

    if (size)
    {
        /* search the index that has to be divided and free index */
        for (i = 0; i < HASHMAP_MAX_LENGTH; i++)
        {
            if (regions[i].AbsoluteOffset || regions[i].Length)
            {
                if (offset > regions[i].AbsoluteOffset && offset < (regions[i].AbsoluteOffset + regions[i].Length) && (offset + size) < (regions[i].AbsoluteOffset + regions[i].Length))
                {
                    /* Find free region */
                    for (j = 0; j < HASHMAP_MAX_LENGTH; j++)
                    {
                        if (regions[j].AbsoluteOffset == 0 && regions[j].Length == 0)
                        {
                            /* divide the region */
                            regions[j].AbsoluteOffset = offset + size;
                            regions[j].Length = (regions[i].AbsoluteOffset + regions[i].Length) - regions[j].AbsoluteOffset;
                            arraylen = j + 1;
                            break;
                        }
                    }
                    regions[i].Length = offset - regions[i].AbsoluteOffset;
                    /* Break the loop */
                    break;
                } else
                if (offset <= regions[i].AbsoluteOffset && (offset + size) > regions[i].AbsoluteOffset && (offset + size) < (regions[i].AbsoluteOffset + regions[i].Length))
                {
                    /* Truncate region from begin */
                    regions[i].Length -= (offset + size) - regions[i].AbsoluteOffset;
                    regions[i].AbsoluteOffset = offset + size;
                } else
                if (offset >= regions[i].AbsoluteOffset && offset < (regions[i].AbsoluteOffset + regions[i].Length) && (offset + size) >= (regions[i].AbsoluteOffset + regions[i].Length))
                {
                    /* Truncate region from end */
                    regions[i].Length = offset - regions[i].AbsoluteOffset;
                } else
                if (offset <= regions[i].AbsoluteOffset && (offset + size) >= (regions[i].AbsoluteOffset + regions[i].Length))
                {
                    /* Delete region at all */
                    regions[i].AbsoluteOffset = 0;
                    regions[i].Length = 0;
                }
                arraylen++;
            } else
            {
                break;
            }
        }
        newarraylen = 0;
        /* Sort regions and move items with zero size at the end of array */
        for (i = arraylen-1; i >= 0; i--)
        {
            for (j = 0; j <= arraylen - 2; j++)
            {
                if (regions[j].Length < regions[j + 1].Length)
                {
                    t = regions[j];
                    regions[j] = regions[j + 1];
                    regions[j + 1] = t;
                }
            }
        }
        newarraylen = 0;
        for (i = 0; i < arraylen; i++)
        {
            if (regions[i].Length == 0)
            {
                regions[i].AbsoluteOffset = 0;
            }
            else
            {
                newarraylen++;
            }
        }
        if (newarraylen)
        {
            bubblesort_hashmap(regions, newarraylen - 1);
        }
    } else
    {
        for (i = 0; i < HASHMAP_MAX_LENGTH; i++)
        {
            if (regions[i].AbsoluteOffset != 0 || regions[i].Length != 0)
            {
                newarraylen++;
            }
        }
    }
    return newarraylen;
}

UNSIGNED32 taggant_compute_default_hash(PTAGGANTCONTEXT pCtx, PHASHBLOB_FULLFILE pHash, PFILEOBJECT hFile, PE_ALL_HEADERS *peh, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd, UNSIGNED32 uTaggantSize)
{
    UNSIGNED32 res = TINVALIDPEFILE;
    /* for the default hash there are HASHMAP_MAX_LENGTH number of regions is needed
     * Full File Hash contains from a hash of two regions:
     * - from file start to end of PE file (default hash)
     * - from end of PE file to end of physical file (extended hash)
     *
     * For the first region we have to exclude from the hashing:
     * - Checksum from optinal header
     * - Digital Signature header from optinal header
     * - Taggant itself
     *
     * For the second region, we have to exclude from hashing:
     * - Taggant itself
     */
    HASHBLOB_HASHMAP_DOUBLE regions[HASHMAP_MAX_LENGTH];
    UNSIGNED64 fileend = uFileEnd, filesize;
    UNSIGNED64 epoffset;
    UNSIGNED64 taggantoffset;
    EVP_MD_CTX evp, evp_ext;
    char* buf = NULL;
    int i, len;

    filesize = get_file_size(pCtx, hFile);

    /* Check if the end of physical file is less then end of PE file */
    if (fileend == 0)
    {
        fileend = filesize;
    }

    if (fileend < uObjectEnd)
    {
        return TFILEERROR;
    }

    /* Calculate default hash */
    memset(&regions, 0, sizeof(regions));
    /* set the entire file region from file start to file end by default */
    regions[0].AbsoluteOffset = 0;
    regions[0].Length = uObjectEnd;
    /* exclude Checksum from region */
    exclude_region_from_hashmap(&regions[0], peh->dh.e_lfanew + sizeof(peh->signature) + sizeof(peh->fh) + 64, sizeof(UNSIGNED32));
    /* exclude PE Header Digital Signature */
    if (winpe_is_pe64(peh))
    {
        exclude_region_from_hashmap(&regions[0], peh->dh.e_lfanew + sizeof(peh->signature) + sizeof(peh->fh) + 144, sizeof(TAG_IMAGE_DATA_DIRECTORY));
    } else
    {
        exclude_region_from_hashmap(&regions[0], peh->dh.e_lfanew + sizeof(peh->signature) + sizeof(peh->fh) + 128, sizeof(TAG_IMAGE_DATA_DIRECTORY));
    }
    if (!winpe_entry_point_physical_offset(pCtx, hFile, peh, &epoffset))
    {
        return TINVALIDPEENTRYPOINT;
    }
    /* exclude taggant */
    if (!winpe_taggant_physical_offset(pCtx, hFile, peh, epoffset, &taggantoffset))
    {
        return TINVALIDTAGGANTOFFSET;
    }

    /* make sure that (taggant offset + taggant length) does not point outside of the file */
    if ((taggantoffset + uTaggantSize) > filesize)
    {
        return TINVALIDTAGGANTOFFSET;
    }
    len = exclude_region_from_hashmap(&regions[0], taggantoffset, uTaggantSize);

    /* allocate buffer for file reading */
    buf = (char*)memory_alloc(HASH_READ_BLOCK);
    if (!buf)
    {
        return TMEMORY;
    }

    /* calculate hash */
    EVP_MD_CTX_init (&evp);
    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
    for (i = 0; i < len; i++)
    {
        if ((res = compute_region_hash(pCtx, hFile, &evp, &regions[i], buf)) != TNOERR)
        {
            break;
        }
    }
    if (res == TNOERR)
    {
        memset(pHash, 0, sizeof(HASHBLOB_FULLFILE));
        pHash->DefaultHash.Header.Type = TAGGANT_HASBLOB_DEFAULT;
        pHash->DefaultHash.Header.Length = sizeof(HASHBLOB_DEFAULT);
        pHash->DefaultHash.Header.Version = HASHBLOB_VERSION1;
        /* Copy context before destroying it by calling EVP_DigestFinal_ex */
        EVP_MD_CTX_copy(&evp_ext, &evp);
        /* Get default file hash */
        EVP_DigestFinal_ex(&evp, pHash->DefaultHash.Header.Hash, NULL);

        /* Calculate extended hash */
        pHash->ExtendedHash.Header.Type = TAGGANT_HASBLOB_EXTENDED;
        pHash->ExtendedHash.Header.Length = sizeof(HASHBLOB_EXTENDED);
        pHash->ExtendedHash.Header.Version = HASHBLOB_VERSION1;
        /* remember the file end offset */
        pHash->ExtendedHash.PhysicalEnd = uFileEnd;
        memset(&regions, 0, sizeof(regions));
        /* set the initial region for extended file hash from end of PE file to end of physical file */
        regions[0].AbsoluteOffset = uObjectEnd;
        regions[0].Length = fileend - uObjectEnd;
        if (regions[0].Length != 0)
        {
            /* Exclude the taggant from the extended hash */
            len = exclude_region_from_hashmap(&regions[0], taggantoffset, uTaggantSize);
            for (i = 0; i < len; i++)
            {
                if ((res = compute_region_hash(pCtx, hFile, &evp_ext, &regions[i], buf)) != TNOERR)
                {
                    break;
                }
            }
            if (res == TNOERR)
            {
                EVP_DigestFinal_ex(&evp_ext, pHash->ExtendedHash.Header.Hash, NULL);
            }
        }
        /* Clean extended hashing context */
        EVP_MD_CTX_cleanup (&evp_ext);
    }
    memory_free(buf);
    /* Clean main hashing context */
    EVP_MD_CTX_cleanup (&evp);

    return res;
}

UNSIGNED32 taggant_compute_hash_map(PTAGGANTCONTEXT pCtx, PFILEOBJECT hFile, PTAGGANTBLOB pTagBlob)
{
    UNSIGNED32 res = TFILEACCESSDENIED;
    EVP_MD_CTX	evp;
    char* buf = NULL;
    int i;
    PHASHBLOB_HASHMAP_DOUBLE hmd;

    /* Compute hashes */
    EVP_MD_CTX_init (&evp);
    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
    /* allocate buffer for file reading */
    buf = (char*)memory_alloc(HASH_READ_BLOCK);
    if (buf)
    {
        /* compute hashmaps */
        hmd = (PHASHBLOB_HASHMAP_DOUBLE)((char*)pTagBlob + sizeof(TAGGANTBLOB));
        for (i = 0; i < pTagBlob->Hash.Hashmap.Entries; i++)
        {
            if ((res = compute_region_hash(pCtx, hFile, &evp, hmd, buf)) != TNOERR)
            {
                break;
            }
            hmd++;
        }
        memory_free(buf);
    }
    else
    {
        res = TMEMORY;
    }
    if (res == TNOERR)
    {
        pTagBlob->Hash.Hashmap.DoublesOffset = sizeof(TAGGANTBLOB);
        pTagBlob->Hash.Hashmap.Header.Type = TAGGANT_HASBLOB_HASHMAP;
        pTagBlob->Hash.Hashmap.Header.Length = sizeof(HASHBLOB_HASHMAP);
        pTagBlob->Hash.Hashmap.Header.Version = HASHBLOB_VERSION1;
        EVP_DigestFinal_ex(&evp, pTagBlob->Hash.Hashmap.Header.Hash, NULL);
    }
    EVP_MD_CTX_cleanup (&evp);
    return res;
}

#ifdef SPV_LIBRARY

UNSIGNED32 taggant_prepare(PTAGGANTOBJ1 pTaggantObj, const PVOID pLicense, PVOID pTaggantOut, UNSIGNED32 *uTaggantReservedSize)
{
    UNSIGNED32 res = TBADKEY;
    BIO* licbio = NULL;
    X509* liccert = NULL, * licspv = NULL;
    EVP_PKEY* lickey = NULL;
    BIO* inbio = NULL;
    BIO* cmsbio = NULL;
    UNSIGNED32 cmslength = 0;
    int maxlen = MAX_INTEGER;
    STACK_OF(X509) *intermediate = NULL;
    char *tmptb = NULL, *tagbuffer = NULL;

    /* Load user license certificate and private key */
    licbio = BIO_new(BIO_s_mem());
    if (licbio)
    {
        BIO_write(licbio, pLicense, (int)strlen((const char*)pLicense));
        licspv = PEM_read_bio_X509(licbio, NULL, 0, NULL);
        if (licspv)
        {
            liccert = PEM_read_bio_X509(licbio, NULL, 0, NULL);
            if (liccert)
            {
                lickey = PEM_read_bio_PrivateKey(licbio, NULL, 0, NULL);
                if (lickey)
                {
                    inbio = BIO_new(BIO_s_mem());
                    if (inbio)
                    {
                        /* Allocate buffer for copy of taggant blob */
                        tmptb = memory_alloc(pTaggantObj->pTagBlob->Header.Length);
                        if (tmptb)
                        {
                            /* Copy TAGGANTBLOB */
                            memcpy(tmptb, pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
                            if (IS_BIG_ENDIAN)
                            {
                                /* Convert TAGGANTBLOB to little endian */
                                TAGGANTBLOB_to_little_endian((PTAGGANTBLOB)tmptb, (PTAGGANTBLOB)tmptb);
                            }
                            BIO_write(inbio, tmptb, pTaggantObj->pTagBlob->Header.Length);
                            /* Push TSA response to the CMS signed data */
                            i2d_TS_RESP_bio(inbio, pTaggantObj->TSResponse);
                            /* Create store with intermediate certificate(s) */
                            intermediate = sk_X509_new_null();
                            if (intermediate)
                            {
                                if (sk_X509_push(intermediate, licspv))
                                {
                                    /* Sign CMS */
                                    pTaggantObj->CMS = CMS_sign(liccert, lickey, intermediate, inbio, CMS_BINARY);
                                    if (pTaggantObj->CMS)
                                    {
                                        cmsbio = BIO_new(BIO_s_mem());
                                        if (cmsbio)
                                        {
                                            if (i2d_CMS_bio(cmsbio, pTaggantObj->CMS))
                                            {
                                                /* Get bio size */
                                                maxlen = MAX_INTEGER;
                                                cmslength = (UNSIGNED32)BIO_read(cmsbio, NULL, maxlen);
                                                /* Make sure the buffer reserved for taggant is enough */
                                                if (*uTaggantReservedSize >= (sizeof(TAGGANT_HEADER) + cmslength + sizeof(TAGGANT_FOOTER))) 
                                                {
                                                    tagbuffer = pTaggantOut;
                                                    /* Clear buffer for taggant */
                                                    memset(tagbuffer, 0, *uTaggantReservedSize);													
                                                    /* Fill out taggant header */
                                                    ((PTAGGANT_HEADER)tagbuffer)->MarkerBegin = TAGGANT_MARKER_BEGIN;
                                                    ((PTAGGANT_HEADER)tagbuffer)->TaggantLength = *uTaggantReservedSize;
                                                    ((PTAGGANT_HEADER)tagbuffer)->CMSLength = cmslength;
                                                    ((PTAGGANT_HEADER)tagbuffer)->Version = TAGGANT_VERSION1;
                                                    tagbuffer += sizeof(TAGGANT_HEADER);
                                                    /* Fill out taggant CMS */
                                                    BIO_read(cmsbio, tagbuffer, cmslength);
                                                    tagbuffer += *uTaggantReservedSize - sizeof(TAGGANT_FOOTER) - sizeof(TAGGANT_HEADER);	
                                                    /* Fill out taggant footer */
                                                    ((PTAGGANT_FOOTER)tagbuffer)->Extrablob.Length = 0;
                                                    ((PTAGGANT_FOOTER)tagbuffer)->MarkerEnd = TAGGANT_MARKER_END;
                                                    if (IS_BIG_ENDIAN)
                                                    {
                                                        TAGGANT_to_little_endian(pTaggantOut, pTaggantOut);
                                                    }
                                                    /* return successful result */
                                                    res = TNOERR;
                                                } else 
                                                {
                                                    *uTaggantReservedSize = sizeof(TAGGANT_HEADER) + cmslength + sizeof(TAGGANT_FOOTER);
                                                    res = TINSUFFICIENTBUFFER;
                                                }
                                            }
                                            BIO_free(cmsbio);
                                        }
                                    }
                                }
                                sk_X509_free(intermediate);
                            }
                            memory_free(tmptb);
                        }
                        BIO_free(inbio);
                    }
                    EVP_PKEY_free(lickey);
                }
                X509_free(liccert);
            }
            X509_free(licspv);
        }
        BIO_free(licbio);
    }
    if (res != TNOERR)
    {
        if (pTaggantObj->CMS)
        {
            CMS_ContentInfo_free(pTaggantObj->CMS);
            pTaggantObj->CMS = NULL;
        }
    }
    return res;
}

#endif

UNSIGNED32 taggant_read_binary(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PTAGGANT1 *pTaggant)
{
    UNSIGNED32 res = TNOTAGGANTS;
    PE_ALL_HEADERS peh;
    UNSIGNED64 epoffset;
    UNSIGNED64 taggantoffset;
    PTAGGANT1 tagbuf = NULL;
    UNSIGNED32 tagsize;

    if (winpe_is_correct_pe_file(pCtx, fp, &peh))
    {
        if (winpe_entry_point_physical_offset(pCtx, fp, &peh, &epoffset))
        {
            if (winpe_taggant_physical_offset(pCtx, fp, &peh, epoffset, &taggantoffset))
            {
                /* seek from the file begin to the taggant */
                if (file_seek(pCtx, fp, taggantoffset, SEEK_SET))
                {					
                    /* allocate memory for taggant */
                    tagbuf = memory_alloc(sizeof(TAGGANT1));
                    if (tagbuf)
                    {
                        memset(tagbuf, 0, sizeof(TAGGANT1));
                        /* read taggant header */
                        if (file_read_buffer(pCtx, fp, &tagbuf->Header, sizeof(TAGGANT_HEADER)))
                        {
                            if (IS_BIG_ENDIAN)
                            {
                                TAGGANT_HEADER_to_big_endian(&tagbuf->Header, &tagbuf->Header);
                            }
                            if (tagbuf->Header.Version == TAGGANT_VERSION1 && tagbuf->Header.MarkerBegin == TAGGANT_MARKER_BEGIN && tagbuf->Header.TaggantLength >= TAGGANT_MINIMUM_SIZE && tagbuf->Header.TaggantLength <= TAGGANT_MAXIMUM_SIZE && tagbuf->Header.CMSLength && (tagbuf->Header.CMSLength <= (tagbuf->Header.TaggantLength - sizeof(TAGGANT_HEADER) - sizeof(TAGGANT_FOOTER))))
                            {
                                /* allocate buffer for CMS */
                                tagsize = tagbuf->Header.TaggantLength - sizeof(TAGGANT_HEADER) - sizeof(TAGGANT_FOOTER);
                                tagbuf->CMSBuffer = memory_alloc(tagsize);
                                if (tagbuf->CMSBuffer)
                                {
                                    memset(tagbuf->CMSBuffer, 0, tagsize);
                                    /* read CMS */
                                    if (file_read_buffer(pCtx, fp, tagbuf->CMSBuffer, tagsize))
                                    {
                                        /* read taggant footer */
                                        if (file_read_buffer(pCtx, fp, &tagbuf->Footer, sizeof(TAGGANT_FOOTER)))
                                        {
                                            if (IS_BIG_ENDIAN)
                                            {
                                                TAGGANT_FOOTER_to_big_endian(&tagbuf->Footer, &tagbuf->Footer);
                                            }
                                            if (tagbuf->Footer.MarkerEnd == TAGGANT_MARKER_END)
                                            {
                                                tagbuf->offset = taggantoffset;
                                                *pTaggant = tagbuf;
                                                res = TNOERR;
                                            }
                                            else
                                            {
                                                res = TNOTAGGANTS;
                                            }
                                        }
                                        else
                                        {
                                            res = TFILEACCESSDENIED;
                                        }
                                    }
                                    else
                                    {
                                        res = TFILEACCESSDENIED;
                                    }
                                }
                                else
                                {
                                    res = TMEMORY;
                                }
                            }
                            else
                            {
                                res = TNOTAGGANTS;
                            }
                        }
                        else
                        {
                            res = TFILEACCESSDENIED;
                        }
                        if (res != TNOERR) 
                        {
                            taggant_free_taggant(tagbuf);
                        }
                    }
                    else
                    {
                        res = TMEMORY;
                    }
                }
                else
                {
                    res = TFILEACCESSDENIED;
                }
            }
            else
            {
                res = TINVALIDTAGGANTOFFSET;
            }
        }
        else
        {
            res = TINVALIDPEENTRYPOINT;
        }
    }
    else
    {
        res = TINVALIDPEFILE;
    }    
    return res;
}

#ifdef SSV_LIBRARY

/* This function saves CMS to the BIO and returns it's size
 * It is used to check if the CMSLength parameter from TAGGANT_HEADER is correct */
UNSIGNED32 get_cms_size(CMS_ContentInfo *cms)
{
    UNSIGNED32 res = 0;
    BIO *bio = NULL;
    int maxlen = MAX_INTEGER;

    bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        if (i2d_CMS_bio(bio, cms))
        {
            /* Get bio size */
            res = (UNSIGNED32)BIO_read(bio, NULL, maxlen);
        }
        BIO_free(bio);
    }
    return res;
}

UNSIGNED32 taggant_validate_signature(PTAGGANTOBJ1 pTaggantObj, PTAGGANT1 pTaggant, PVOID pRootCert)
{
    UNSIGNED32 res = TBADKEY;
    BIO *cmsbio = NULL;
    BIO *signedbio = NULL;
    BIO *tsbio = NULL;
    STACK_OF(X509)* certs = NULL;
    X509 *root = NULL, *cer1 = NULL, *cer2 = NULL, *spv = NULL, *user = NULL;
    char *buf = NULL, *tmpbuf;
    int biolength = 0;
    int tagsize;
    int maxlen = MAX_INTEGER;

    res = TBADKEY;

    /* Load root certificate */
    root = buffer_to_X509(pRootCert);
    if (root)
    {
        /* Compare taggant version */
        if (pTaggant->Header.Version == TAGGANT_VERSION1 && pTaggant->Header.CMSLength > 0)
        {
            cmsbio = BIO_new(BIO_s_mem());
            if (cmsbio)
            {
                BIO_write(cmsbio, pTaggant->CMSBuffer, pTaggant->Header.CMSLength);
                pTaggantObj->CMS = d2i_CMS_bio(cmsbio, NULL);
                if (pTaggantObj->CMS)
                {
                    /* Check if CMS size matches the one from the header */
                    if (get_cms_size(pTaggantObj->CMS) == pTaggant->Header.CMSLength)
                    {
                        /* Check the "null area" */
                        if (check_null_area(pTaggant))
                        {
                            signedbio = BIO_new(BIO_s_mem());
                            if (signedbio)
                            {
                                /* Verify CMS, but do not verify signer certificates */
                                if (CMS_verify(pTaggantObj->CMS, NULL, NULL, NULL, signedbio, CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY))
                                {
                                    /* Check signer certificates */
                                    certs = CMS_get1_certs(pTaggantObj->CMS);
                                    if (certs)
                                    {
                                        /* There should be 2 certificates only: CA, SPV and USER */
                                        if (sk_X509_num(certs) == CERTIFICATES_IN_TAGGANT_CHAIN)
                                        {
                                            EVP_PKEY *rootpub;

                                            cer1 = sk_X509_value(certs, 0);
                                            cer2 = sk_X509_value(certs, 1);
                                            /* Check if the certificates chain is correct  */
                                            rootpub = X509_get_pubkey(root);
                                            if (rootpub)
                                            {
                                                /* Verify the first certificate against root public key */
                                                if (X509_verify(cer1, rootpub) == 1)
                                                {
                                                    spv = X509_dup(cer1);
                                                    user = X509_dup(cer2);
                                                }
                                                else
                                                {
                                                    /* Verify the second certificate against root public key */
                                                    if (X509_verify(cer2, rootpub) == 1)
                                                    {
                                                        spv = X509_dup(cer2);
                                                        user = X509_dup(cer1);
                                                    }
                                                }
                                                /* Verify user certificate against spv public key */
                                                if (spv && user)
                                                {
                                                    EVP_PKEY *spvpub;

                                                    spvpub = X509_get_pubkey(spv);
                                                    if (X509_verify(user, spvpub) == 1)
                                                    {
                                                        res = TNOERR;
                                                    }
                                                    EVP_PKEY_free(spvpub);
                                                }
                                                EVP_PKEY_free(rootpub);
                                            }
                                        }
                                        sk_X509_pop_free(certs, X509_free);
                                    }
                                    
                                    if (res == TNOERR)
                                    {
                                        res = TMEMORY;
                                        /* get size of the signed data */
                                        biolength = BIO_read(signedbio, NULL, maxlen);
                                        buf = (char*)memory_alloc(biolength);
                                        if (buf)
                                        {
                                            BIO_read(signedbio, buf, biolength);
                                            /* Check if buffer has enough size for taggant blob */
                                            if (biolength >= sizeof(TAGGANTBLOB))
                                            {
                                                tagsize = ((PTAGGANTBLOB)buf)->Header.Length;
                                                if (IS_BIG_ENDIAN)
                                                {
                                                    tagsize = UNSIGNED16_to_big_endian((char*)&tagsize);
                                                }
                                                if (biolength >= tagsize)
                                                {
                                                    tmpbuf = memory_realloc(pTaggantObj->pTagBlob, tagsize);
                                                    if (tmpbuf)
                                                    {
                                                        pTaggantObj->pTagBlob = (PTAGGANTBLOB)tmpbuf;
                                                        memcpy((char*)pTaggantObj->pTagBlob, buf, tagsize);
                                                        if (IS_BIG_ENDIAN)
                                                        {
                                                            TAGGANTBLOB_to_big_endian(pTaggantObj->pTagBlob, pTaggantObj->pTagBlob);
                                                        }
                                                        /* check if the timestamp response exists in the taggant */
                                                        if ((biolength - (int)pTaggantObj->pTagBlob->Header.Length) > 0)
                                                        {
                                                            /* load TS response, better to use d2i_TS_RESP instead of d2i_TS_RESP_bio */
                                                            tsbio = BIO_new(BIO_s_mem());
                                                            if (tsbio)
                                                            {
                                                                BIO_write(tsbio, buf + pTaggantObj->pTagBlob->Header.Length, biolength - pTaggantObj->pTagBlob->Header.Length);
                                                                pTaggantObj->TSResponse = d2i_TS_RESP_bio(tsbio, NULL);

                                                                BIO_free(tsbio);
                                                            }
                                                        }
                                                        res = TNOERR;
                                                    }
                                                }
                                            }
                                            /* free memory buffer */
                                            memory_free(buf);
                                        }
                                    }
                                }
                                BIO_free(signedbio);
                            }
                        }
                    }
                }
                BIO_free(cmsbio);
            }
        }
        X509_free(root);
    }

    if (res != TNOERR)
    {
        taggant_free_taggantobj_content(pTaggantObj);
    }
    return res;
}

UNSIGNED32 taggant_compare_default_hash(PHASHBLOB_DEFAULT pHash1, PHASHBLOB_DEFAULT pHash2)
{
    UNSIGNED32 res = TMISMATCH;

    /* Check if hashblob of default hashes matches */
    if (pHash1->Header.Version == pHash2->Header.Version &&
        pHash1->Header.Version == HASHBLOB_VERSION1 &&
        pHash1->Header.Type == pHash2->Header.Type &&
        pHash1->Header.Type == TAGGANT_HASBLOB_DEFAULT &&
        (memcmp(&pHash1->Header.Hash, &pHash2->Header.Hash, sizeof(pHash1->Header.Hash)) == 0)
        )
    {
        res = TNOERR;
    }
    return res;
}

UNSIGNED32 taggant_compare_extended_hash(PHASHBLOB_EXTENDED pHash1, PHASHBLOB_EXTENDED pHash2)
{
    UNSIGNED32 res = TMISMATCH;

    /* Check if extended hash matches */
    if (pHash1->Header.Version == pHash2->Header.Version &&
        pHash1->Header.Version == HASHBLOB_VERSION1 &&
        pHash1->Header.Type == pHash2->Header.Type &&
        pHash1->Header.Type == TAGGANT_HASBLOB_EXTENDED &&
        (memcmp(&pHash1->Header.Hash, &pHash2->Header.Hash, sizeof(pHash1->Header.Hash)) == 0) &&
        (!pHash1->PhysicalEnd ||
        (pHash1->PhysicalEnd == pHash2->PhysicalEnd))
        )
    {
        res = TNOERR;
    }

    return res;
}

UNSIGNED32 taggant_validate_default_hashes(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ1 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd)
{
    PE_ALL_HEADERS peh;
    UNSIGNED32 res = TMEMORY;
    HASHBLOB_FULLFILE tmphb;
    UNSIGNED32 ds_offset, ds_size;
    UNSIGNED64 fileend = uFileEnd;
    int valid_ds = 1;
    int valid_file = 0;
    PTAGGANT2 taggant2 = NULL;

    if (winpe_is_correct_pe_file(pCtx, hFile, &peh))
    {
        /* If PhysicalEnd value in the taggant = 0 then use file size as PhysicalEnd */
        if (pTaggantObj->pTagBlob->Hash.FullFile.ExtendedHash.PhysicalEnd == 0)
        {       
            /* if the fileend value is not specified, take the file size */
            if (!fileend)
            {
                fileend = get_file_size(pCtx, hFile);
            }
            /* Check if the file contains digital signature and if it is placed at the end of the file
             * If it is, then reduce fileend value to exclude digital signature, otherwise
             * mark file as there is no taggant
             */
            if (winpe_is_pe64(&peh))
            {
                ds_offset = (UNSIGNED32)peh.oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                ds_size = (UNSIGNED32)peh.oh.pe64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            } else
            {
                ds_offset = (UNSIGNED32)peh.oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                ds_size = (UNSIGNED32)peh.oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            }
            if (ds_offset != 0 && ds_size != 0)
            {
                if ((ds_offset + ds_size) != fileend)
                {
                    valid_ds = 0;
                } else
                {
                    fileend -= ds_size;
                }
            }
            valid_file = valid_ds;
            /* exclude taggant v2 */
            if (valid_file)
            {
                while (taggant2_read_binary(pCtx, hFile, fileend, &taggant2, TAGGANT_PEFILE) == TNOERR)
                {
                    fileend -= taggant2->Header.TaggantLength;
                    /* Free the taggant object */
                    taggant2_free_taggant(taggant2);
                }
            }
        } else
        {
            fileend = pTaggantObj->pTagBlob->Hash.FullFile.ExtendedHash.PhysicalEnd;
            valid_file = 1;
        }
    
        if (valid_file && (!uFileEnd || (uFileEnd && fileend <= uFileEnd)))
        {
            /* Allocate a copy of taggant blob */
            tmphb = pTaggantObj->pTagBlob->Hash.FullFile;
            /* Compute default hash */				
            if ((res = taggant_compute_default_hash(pCtx, &tmphb, hFile, &peh, uObjectEnd, fileend, pTaggantObj->uTaggantSize)) == TNOERR)
            {
                if ((res = taggant_compare_default_hash(&pTaggantObj->pTagBlob->Hash.FullFile.DefaultHash, &tmphb.DefaultHash)) == TNOERR)
                {
                    res = taggant_compare_extended_hash(&pTaggantObj->pTagBlob->Hash.FullFile.ExtendedHash, &tmphb.ExtendedHash);
                }
            }
        } else
        {
            res = TERROR;
        }
    } else
    {
        res = TINVALIDPEFILE;
    }
    return res;
}

UNSIGNED32 taggant_validate_hashmap(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ1 pTaggantObj, PFILEOBJECT hFile)
{
    UNSIGNED32 res = TMEMORY;
    PTAGGANTBLOB ptmpb = NULL;
    PHASHBLOB_HASHMAP_DOUBLE hmd;
    int i;

    if ((pTaggantObj->pTagBlob->Hash.Hashmap.DoublesOffset + (pTaggantObj->pTagBlob->Hash.Hashmap.Entries * sizeof(HASHBLOB_HASHMAP_DOUBLE))) > pTaggantObj->pTagBlob->Header.Length)
    {
        return TMEMORY;
    }

    /* Allocate a copy of taggant blob */
    ptmpb = (PTAGGANTBLOB)memory_alloc(pTaggantObj->pTagBlob->Header.Length);
    if (ptmpb)
    {
        res = TNOERR;
        memcpy(ptmpb, pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
        /* Make sure the regions in hashmap are ordered correctly (from lowest offset to highest) */
        hmd = (PHASHBLOB_HASHMAP_DOUBLE)((char*)ptmpb + sizeof(TAGGANTBLOB));
        for (i = 1; i < ptmpb->Hash.Hashmap.Entries; i++)
        {
            if (hmd[i - 1].AbsoluteOffset >= hmd[i].AbsoluteOffset)
            {
                res = TERROR;
                break;
            }
        }
        if (res == TNOERR)
        {
            /* Check if hashmap contains regions with zero size */
            for (i = 0; i < ptmpb->Hash.Hashmap.Entries; i++)
            {
                if (hmd[i].Length == 0)
                {
                    res = TERROR;
                    break;
                }
            }
        }
        if (res == TNOERR)
        {
            /* Compute hash map */
            res = taggant_compute_hash_map(pCtx, hFile, ptmpb);
            if (res == TNOERR)
            {
                res = taggant_compare_hash_map(pTaggantObj->pTagBlob, ptmpb);
            }
        }
        memory_free(ptmpb);
    }
    return res;
}

UNSIGNED32 taggant_get_timestamp(PTAGGANTOBJ1 pTaggantObj, UNSIGNED64 *pTime, PVOID pTSRootCert)
{
    UNSIGNED32 res = TERROR;
    char hash[HASH_SHA256_DIGEST_SIZE];
    char* ptmp = NULL;
    BIO *tmpbio;
    EVP_MD_CTX evp;
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    int temp;
    int err = 0;
    X509 *cert = NULL;
    X509_STORE *store;
    TS_TST_INFO* tstInfo = NULL;
    const ASN1_GENERALIZEDTIME* asn1Time = NULL;

    if (pTaggantObj->TSResponse == NULL)
    {
        return TNOTIME;
    }

    /* Calculate the hash of the taggant blob structure */
    err = 0;
    EVP_MD_CTX_init (&evp);
    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
    if (IS_BIG_ENDIAN)
    {
        /* Allocate a copy of taggant blob and convert it to little endian */
        ptmp = memory_alloc(pTaggantObj->pTagBlob->Header.Length);
        if (ptmp)
        {
            memcpy(ptmp, pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
            TAGGANTBLOB_to_little_endian((PTAGGANTBLOB)ptmp, (PTAGGANTBLOB)ptmp);
            EVP_DigestUpdate(&evp, ptmp, pTaggantObj->pTagBlob->Header.Length);
            memory_free(ptmp);
        } else
        {
            err = 1;
        }
    } else
    {
        EVP_DigestUpdate(&evp, pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
    }
    EVP_DigestFinal_ex(&evp, (unsigned char *)&hash, NULL);
    EVP_MD_CTX_cleanup (&evp);

    /* Load all provided certificates */
    if (!err)
    {
        tmpbio = BIO_new(BIO_s_mem());
        if (tmpbio)
        {
            BIO_write(tmpbio, pTSRootCert, (int)strlen((const char*)pTSRootCert));
            if ((store = X509_STORE_new()))
            {
                while ((cert = PEM_read_bio_X509(tmpbio, NULL, 0, NULL)))
                {
                    err = X509_STORE_add_cert(store, cert) ? 0 : 1;
                    X509_free(cert);
                    if (err)
                    {
                        X509_STORE_free(store);
                        break;
                    }
                }
                if (!err)
                {
                    if (check_time_stamp(pTaggantObj->TSResponse, store, (char*)&hash, sizeof(hash)))
                    {
                        tstInfo = TS_RESP_get_tst_info(pTaggantObj->TSResponse);
                        asn1Time = TS_TST_INFO_get_time(tstInfo);

                        temp = sscanf((const char*)ASN1_STRING_data((ASN1_STRING*)asn1Time), "%4d%2d%2d%2d%2d%2d", &year, &month, &day, &hour, &minute, &second);
                        if (temp == 6)
                        {
                            *pTime = time_as_unsigned64(year, month, day, hour, minute, second);
                            res = TNOERR;
                        }
                        else
                        {
                            res = TINVALID;
                        }
                    }
                    else
                    {
                        res = TINVALID;
                    }
                }
            }
            BIO_free(tmpbio);
        }
    }

    return res;
}

UNSIGNED32 taggant_get_info(PTAGGANTOBJ1 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 *pSize, PINFO pInfo)
{
    UNSIGNED32 res = TERRORKEY;
    STACK_OF(X509) *certs = NULL, *signers = NULL;
    int i = 0, brk = 0, biolength = 0;
    BIO *tmpbio = NULL;
    X509 *tmpcert = NULL, *signer = NULL;
    int maxlen = MAX_INTEGER;
    ASN1_INTEGER *signerser = NULL, *tmpser = NULL;
    BIGNUM *signerbn = NULL, *tmpbn = NULL;

    if (pTaggantObj->CMS == NULL || pTaggantObj->pTagBlob == NULL)
    {
        return TNOTAGGANTS;
    }
    switch (eKey)
    {
    case ETAGGANTBLOB:
        /* get the TAGGANTBLOB information
           Make sure input buffer is enough to store BIO data */
        if (*pSize >= pTaggantObj->pTagBlob->Header.Length && pInfo != NULL)
        {
            memcpy(pInfo, pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
            res = TNOERR;
        } else
        {
            res = TINSUFFICIENTBUFFER;
        }
        *pSize = pTaggantObj->pTagBlob->Header.Length;
        break;
    case ESPVCERT:
        res = TERROR;
        /* Get signer certificate */
        signers = CMS_get0_signers(pTaggantObj->CMS);
        if (signers)
        {
            /* Make sure there is 1 certificate */
            if (sk_X509_num(signers) == 1)
            {
                signer = sk_X509_value(signers, 0);
                if (signer)
                {
                    signerser = X509_get_serialNumber(signer);
                    if (signerser)
                    {
                        signerbn = ASN1_INTEGER_to_BN(signerser, NULL);
                        if (signerbn)
                        {
                            /* Get all certificates in CMS */
                            certs = CMS_get1_certs(pTaggantObj->CMS);
                            if (certs)
                            {
                                /* Make sure there are 2 certificates in the CMS chain */
                                if (sk_X509_num(certs) == CERTIFICATES_IN_TAGGANT_CHAIN)
                                {
                                    for (i = 0; i < CERTIFICATES_IN_TAGGANT_CHAIN; i++)
                                    {
                                        tmpcert = sk_X509_value(certs, i);
                                        if (tmpcert)
                                        {
                                            tmpser = X509_get_serialNumber(tmpcert);
                                            if (tmpser)
                                            {
                                                tmpbn = ASN1_INTEGER_to_BN(tmpser, NULL);
                                                if (tmpbn)
                                                {
                                                    if (BN_cmp(signerbn, tmpbn) != 0)
                                                    {
                                                        tmpbio = BIO_new(BIO_s_mem());
                                                        if (tmpbio)
                                                        {
                                                            if (i2d_X509_bio(tmpbio, tmpcert))
                                                            {
                                                                /* Get bio size */
                                                                maxlen = MAX_INTEGER;
                                                                biolength = BIO_read(tmpbio, NULL, maxlen);
                                                                if (biolength >= 0)
                                                                {
                                                                    /* Make sure input buffer is enough to store BIO data */
                                                                    if (*pSize >= (UNSIGNED32)biolength && pInfo != NULL)
                                                                    {
                                                                        BIO_read(tmpbio, pInfo, biolength);
                                                                        res = TNOERR;
                                                                    } else
                                                                    {
                                                                        res = TINSUFFICIENTBUFFER;
                                                                    }
                                                                    *pSize = (UNSIGNED32)biolength;
                                                                }
                                                            }
                                                            BIO_free(tmpbio);
                                                        }
                                                        else
                                                        {
                                                            res = TMEMORY;
                                                        }
                                                        brk = 1;
                                                    }
                                                    BN_free(tmpbn);
                                                    if (brk)
                                                    {
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                sk_X509_pop_free(certs, X509_free);
                            }
                            BN_free(signerbn);
                        }
                    }
                }
            }
            sk_X509_free(signers);			
        }
        break;
    case EUSERCERT:	
        res = TERROR;
        signers = CMS_get0_signers(pTaggantObj->CMS);
        if (signers)
        {
            /* Make sure there is 1 certificate */
            if (sk_X509_num(signers) == 1)
            {
                signer = sk_X509_value(signers, 0);
                if (signer)
                {
                    tmpbio = BIO_new(BIO_s_mem());
                    if (tmpbio)
                    {
                        if (i2d_X509_bio(tmpbio, signer))
                        {
                            /* Get bio size */
                            maxlen = MAX_INTEGER;
                            biolength = BIO_read(tmpbio, NULL, maxlen);
                            if (biolength >= 0)
                            {
                                /* Make sure input buffer is enough to store BIO data */
                                if (*pSize >= (UNSIGNED32)biolength && pInfo != NULL)
                                {
                                    BIO_read(tmpbio, pInfo, biolength);
                                    res = TNOERR;
                                } else
                                {
                                    res = TINSUFFICIENTBUFFER;
                                }
                                *pSize = (UNSIGNED32)biolength;
                            }
                        }
                        BIO_free(tmpbio);
                    }
                }
            }
            sk_X509_free(signers);
        }
        break;
    case EFILEEND:
        /* get the PhysicalEnd value from the taggant */
        if (*pSize >= sizeof(pTaggantObj->pTagBlob->Hash.FullFile.ExtendedHash.PhysicalEnd) && pInfo != NULL)
        {
            memcpy(pInfo, &pTaggantObj->pTagBlob->Hash.FullFile.ExtendedHash.PhysicalEnd, sizeof(pTaggantObj->pTagBlob->Hash.FullFile.ExtendedHash.PhysicalEnd));
            res = TNOERR;
        } else
        {
            res = TINSUFFICIENTBUFFER;
        }
        *pSize = sizeof(pTaggantObj->pTagBlob->Hash.FullFile.ExtendedHash.PhysicalEnd);
        break;
    case EPACKERINFO:
        /* get the packer information from the taggant */
        if (*pSize >= sizeof(PACKERINFO) && pInfo != NULL)
        {
            memcpy(pInfo, &pTaggantObj->pTagBlob->Header.PackerInfo, sizeof(PACKERINFO));
            res = TNOERR;
        }
        else
        {
            res = TINSUFFICIENTBUFFER;
        }
        *pSize = sizeof(PACKERINFO);
        break;
    }	
    return res;
}

#endif

#ifdef SPV_LIBRARY

UNSIGNED32 taggant_put_timestamp(PTAGGANTOBJ1 pTaggantObj, const char* pTSUrl, UNSIGNED32 uTimeout)
{
    UNSIGNED32 res = TNONET;
    char hash[HASH_SHA256_DIGEST_SIZE];
    EVP_MD_CTX evp;
    TS_RESP* tsResponse = NULL;
    char* ptmp = NULL;

    if (pTaggantObj->TSResponse != NULL)
    {
        TS_RESP_free(pTaggantObj->TSResponse);
        pTaggantObj->TSResponse = NULL;
    }
    /* Calculate the hash of the taggant blob structure */
    EVP_MD_CTX_init (&evp);
    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
    if (IS_BIG_ENDIAN)
    {
        /* Allocate a copy of taggant blob and convert it to little endian */
        ptmp = memory_alloc(pTaggantObj->pTagBlob->Header.Length);
        if (ptmp)
        {
            memcpy(ptmp, pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
            TAGGANTBLOB_to_little_endian((PTAGGANTBLOB)ptmp, (PTAGGANTBLOB)ptmp);
            EVP_DigestUpdate(&evp, ptmp, pTaggantObj->pTagBlob->Header.Length);
            memory_free(ptmp);
        } else
        {
            return TMEMORY;
        }
    } else
    {
        EVP_DigestUpdate(&evp, pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
    }
    EVP_DigestFinal_ex(&evp, (unsigned char *)&hash, NULL);
    EVP_MD_CTX_cleanup (&evp);
    if ((res = get_timestamp_response(pTSUrl, (char*)&hash, sizeof(hash), uTimeout, &tsResponse)) == TNOERR)
    {
        pTaggantObj->TSResponse = tsResponse;
    }
    return res;
}

UNSIGNED32 taggant_add_hash_region(PTAGGANTOBJ1 pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength)
{
    PHASHBLOB_HASHMAP_DOUBLE hmd;
    HASHBLOB_HASHMAP_DOUBLE t;
    int i, j;
    UNSIGNED16 count;
    UNSIGNED64 a, b, c, d;
    char *tmpbuf;

    /* Check if the number of existing regions does not exceed allowed */
    if (pTaggantObj->pTagBlob->Hash.Hashmap.Entries >= HASHMAP_MAXIMUM_ENTRIES)
    {
        return TENTRIESEXCEED;
    }

    /* Realloc taggant blob to contain sufficient buffer for additional region */
    tmpbuf = memory_realloc(pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length + sizeof(HASHBLOB_HASHMAP_DOUBLE));
    if (!tmpbuf)
    {
        return TMEMORY;
    }
    pTaggantObj->pTagBlob = (PTAGGANTBLOB)tmpbuf;
    
    hmd = (PHASHBLOB_HASHMAP_DOUBLE) ((char*)pTaggantObj->pTagBlob + sizeof(TAGGANTBLOB));
    hmd[pTaggantObj->pTagBlob->Hash.Hashmap.Entries].AbsoluteOffset = uOffset;
    hmd[pTaggantObj->pTagBlob->Hash.Hashmap.Entries].Length = uLength;
    /* bubble sort hashmap array */
    bubblesort_hashmap(hmd, pTaggantObj->pTagBlob->Hash.Hashmap.Entries);
    pTaggantObj->pTagBlob->Hash.Hashmap.Entries++;
    /* increase size of taggant blob */
    pTaggantObj->pTagBlob->Header.Length += sizeof(HASHBLOB_HASHMAP_DOUBLE);

    /* searching for overlapped regions */
    count = 0;
    for (i = 0; i < pTaggantObj->pTagBlob->Hash.Hashmap.Entries - 1; i++)
    {
        a = b = hmd[i].AbsoluteOffset;
        b += hmd[i].Length;
        c = d = hmd[i+1].AbsoluteOffset;
        d += hmd[i+1].Length;

        if (((a >= c) && (a <= d)) || ((b >= c) && (b <= d)) ||
            ((c >= a) && (c <= b)) || ((d >= a) && (d <= b)))
        {
            /* overlapping here */
            hmd[i+1].AbsoluteOffset = (a < c) ? a : c;
            hmd[i+1].Length = (b > d) ? b - hmd[i+1].AbsoluteOffset : d - hmd[i+1].AbsoluteOffset;

            hmd[i].AbsoluteOffset = 0;
            hmd[i].Length = 0;
            count++;
        }
    }
    /* if overlapped regions are found, then resize the array and remove zero size regions */
    if (count > 0)
    {
        /* sort in descending order to move zero size regions at the end of array */
        for (i = pTaggantObj->pTagBlob->Hash.Hashmap.Entries - 1; i >= 0; i--)
        {
            for (j = 0; j <= pTaggantObj->pTagBlob->Hash.Hashmap.Entries - 2; j++)
            {
                if (hmd[j].Length < hmd[j + 1].Length)
                {
                    t = hmd[j];
                    hmd[j] = hmd[j + 1];
                    hmd[j + 1] = t;
                }
            }
        }
        /* decrease Entries on a number of intersections */
        pTaggantObj->pTagBlob->Hash.Hashmap.Entries = pTaggantObj->pTagBlob->Hash.Hashmap.Entries - count;
        /* decrease the size of TaggantBlob */
        pTaggantObj->pTagBlob->Header.Length -= count * sizeof(HASHBLOB_HASHMAP_DOUBLE);
        /* sort regions array */
        bubblesort_hashmap(hmd, pTaggantObj->pTagBlob->Hash.Hashmap.Entries - 1);
        /* realloc TaggantBlob*/
        tmpbuf = memory_realloc(pTaggantObj->pTagBlob, pTaggantObj->pTagBlob->Header.Length);
        if (!tmpbuf)
        {			
            return TMEMORY;
        }
        pTaggantObj->pTagBlob = (PTAGGANTBLOB)tmpbuf;
    }
    return TNOERR;
}

UNSIGNED32 taggant_put_info(PTAGGANTOBJ1 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 uSize, PINFO pInfo)
{
    UNSIGNED32 res = TERRORKEY;

    switch (eKey)
    {
    case EPACKERINFO:
        /* set the packer information to the taggant */
        if (uSize >= sizeof(PACKERINFO) && pInfo != NULL)
        {
            memcpy(&pTaggantObj->pTagBlob->Header.PackerInfo, pInfo, sizeof(PACKERINFO));
            res = TNOERR;
        }
        else
        {
            res = TINSUFFICIENTBUFFER;
        }
        break;
    }
    return res;
}

#endif

void taggant_free_taggantobj_content(PTAGGANTOBJ1 pTaggantObj)
{
    /* Free taggant blob */
    if (pTaggantObj->pTagBlob)
    {
        memory_free(pTaggantObj->pTagBlob);
        pTaggantObj->pTagBlob = NULL;
    }
    /* Free CMS */
    if (pTaggantObj->CMS)
    {
        CMS_ContentInfo_free(pTaggantObj->CMS);
        pTaggantObj->CMS = NULL;
    }
    /* Free TSA response */
    if (pTaggantObj->TSResponse)
    {
        TS_RESP_free(pTaggantObj->TSResponse);
        pTaggantObj->TSResponse = NULL;
    }
}