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
#include "types.h"
#include "winpe.h"
#include "winpe2.h"
#include "taggant.h"
#include "taggant2.h"
#include "callbacks.h"
#include "endianness.h"
#include "miscellaneous.h"
#include "taggant_types.h"
#include "verify_helper.h"
#include "timestamp.h"
#include <openssl/pem.h>

#define umaxof(t) (((0x1ULL << ((sizeof(t) * 8ULL) - 1ULL)) - 1ULL) | \
                    (0xFULL << ((sizeof(t) * 8ULL) - 4ULL)))

UNSIGNED32 taggant2_get_extrainfo(PEXTRABLOB2 pExtrablob, ENUMTAGINFO eKey, UNSIGNED32 *pSize, PINFO pInfo)
{
    UNSIGNED32 res = TNOTFOUND;
    UNSIGNED16 vsize, vtype;
    char *buf;
    UNSIGNED16 size;
    int found;

    if ((UNSIGNED16)eKey >= 0x8000)
    {
        found = 0;        
        /* find this key in existing structure */
        if (pExtrablob->Data && pExtrablob->Length)
        {
            buf = pExtrablob->Data;
            size = pExtrablob->Length;
            while (size)
            {
                /* get type */
                vtype = *(UNSIGNED16*)buf;
                if (IS_BIG_ENDIAN)
                {
                    vtype = UNSIGNED16_to_big_endian((char*)&vtype);
                }
                buf += sizeof(UNSIGNED16);
                /* get size */
                vsize = *(UNSIGNED16*)buf;
                if (IS_BIG_ENDIAN)
                {
                    vsize = UNSIGNED16_to_big_endian((char*)&vsize);
                }
                buf += sizeof(UNSIGNED16);
                if (vtype == eKey)
                {
                    found = 1;
                    /* get the content */                    
                    if (*pSize >= vsize && pInfo != NULL)
                    {
                        memcpy(pInfo, buf, vsize);
                        /* succeeded */                        
                        res = TNOERR;
                    }
                    else
                    {
                        res = TINSUFFICIENTBUFFER;
                    }
                    *pSize = vsize;
                    break;
                }
                buf += vsize;
                /* decrease the size */
                size -= sizeof(UNSIGNED16) + sizeof(UNSIGNED16) + vsize;
            }
        }
        if (!found)
        {
            *pSize = 0;
        }
    }
    else
    {
        res = TERRORKEY;
    }
    return res;
}

UNSIGNED32 taggant2_put_extrainfo(PEXTRABLOB2 pExtrablob, ENUMTAGINFO eKey, UNSIGNED32 uSize, PINFO pInfo)
{
    UNSIGNED32 res = TNOERR;
    char *buf, *bufsrc, *bufdest;
    UNSIGNED16 sizesrc, tmpu16;
    UNSIGNED16 vsize = 0, vtype;
    UNSIGNED32 size;
    int found;

    if ((UNSIGNED16)eKey >= 0x8000)
    {
        size = (UNSIGNED32)pExtrablob->Length;
        found = 0;
        /* find this key in existing structure */
        if (pExtrablob->Data && pExtrablob->Length)
        {
            bufsrc = pExtrablob->Data;
            sizesrc = pExtrablob->Length;
            while (sizesrc)
            {
                /* get type */
                vtype = *(UNSIGNED16*)bufsrc;
                if (IS_BIG_ENDIAN)
                {
                    vtype = UNSIGNED16_to_big_endian((char*)&vtype);
                }
                bufsrc += sizeof(UNSIGNED16);
                /* get size */
                vsize = *(UNSIGNED16*)bufsrc;
                if (IS_BIG_ENDIAN)
                {
                    vsize = UNSIGNED16_to_big_endian((char*)&vsize);
                }
                if (vtype == eKey)
                {
                    found = 1;
                    break;
                }
                bufsrc += sizeof(UNSIGNED16) + vsize;
                /* decrease the size */
                sizesrc -= sizeof(UNSIGNED16) + sizeof(UNSIGNED16) + vsize;
            }
        }
        if (found)
        {
            if (uSize)
            {
                /* set the new item size and buffer */
                size += uSize - vsize;
                if (size <= umaxof(UNSIGNED16))
                {
                    buf = memory_alloc(size);
                    if (buf)
                    {
                        bufsrc = pExtrablob->Data;
                        bufdest = buf;
                        sizesrc = pExtrablob->Length;
                        while (sizesrc)
                        {
                            /* copy type */
                            vtype = *(UNSIGNED16*)bufsrc;
                            if (IS_BIG_ENDIAN)
                            {
                                vtype = UNSIGNED16_to_big_endian((char*)&vtype);
                            }
                            memcpy(bufdest, bufsrc, sizeof(UNSIGNED16));
                            bufsrc += sizeof(UNSIGNED16);
                            bufdest += sizeof(UNSIGNED16);
                            /* set size */
                            vsize = *(UNSIGNED16*)bufsrc;
                            if (IS_BIG_ENDIAN)
                            {
                                vsize = UNSIGNED16_to_big_endian((char*)&vsize);
                            }
                            if (vtype == eKey)
                            {
                                tmpu16 = (UNSIGNED16)uSize;
                                if (IS_BIG_ENDIAN)
                                {
                                    UNSIGNED16_to_little_endian(tmpu16, (char*)&tmpu16);
                                }
                                memcpy(bufdest, &tmpu16, sizeof(UNSIGNED16));
                            }
                            else
                            {
                                memcpy(bufdest, bufsrc, sizeof(UNSIGNED16));
                            }
                            bufsrc += sizeof(UNSIGNED16);
                            bufdest += sizeof(UNSIGNED16);
                            /* copy the buffer */
                            if (vtype == eKey)
                            {
                                memcpy(bufdest, pInfo, uSize);
                                bufdest += uSize;
                            }
                            else
                            {
                                memcpy(bufdest, bufsrc, vsize);
                                bufdest += vsize;
                            }
                            bufsrc += vsize;
                            /* decrease the size */
                            sizesrc -= sizeof(UNSIGNED16) + sizeof(UNSIGNED16) + vsize;
                        }
                        /* deallocate old buffer */
                        if (pExtrablob->Data)
                        {
                            memory_free(pExtrablob->Data);
                        }
                        pExtrablob->Data = buf;
                        pExtrablob->Length = (UNSIGNED16)size;
                    }
                    else
                    {
                        res = TMEMORY;
                    }
                }
                else
                {
                    res = TINSUFFICIENTBUFFER;
                }
            }
            else
            {
                /* eliminate the item */
                size -= sizeof(UNSIGNED16) + sizeof(UNSIGNED16) + vsize;
                if (size <= umaxof(UNSIGNED16))
                {
                    buf = memory_alloc(size);
                    if (buf)
                    {
                        bufsrc = pExtrablob->Data;
                        bufdest = buf;
                        sizesrc = pExtrablob->Length;
                        while (sizesrc)
                        {
                            /* copy type */
                            vtype = *(UNSIGNED16*)bufsrc;
                            if (IS_BIG_ENDIAN)
                            {
                                vtype = UNSIGNED16_to_big_endian((char*)&vtype);
                            }
                            if (vtype == eKey)
                            {
                                bufsrc += sizeof(UNSIGNED16);
                                /* get size */
                                vsize = *(UNSIGNED16*)bufsrc;
                                if (IS_BIG_ENDIAN)
                                {
                                    vsize = UNSIGNED16_to_big_endian((char*)&vsize);
                                }
                                bufsrc += sizeof(UNSIGNED16);
                                /* get content */
                                bufsrc += vsize;
                            }
                            else
                            {
                                memcpy(bufdest, bufsrc, sizeof(UNSIGNED16));
                                bufsrc += sizeof(UNSIGNED16);
                                bufdest += sizeof(UNSIGNED16);
                                /* get size */
                                vsize = *(UNSIGNED16*)bufsrc;
                                if (IS_BIG_ENDIAN)
                                {
                                    vsize = UNSIGNED16_to_big_endian((char*)&vsize);
                                }
                                memcpy(bufdest, bufsrc, sizeof(UNSIGNED16));
                                bufsrc += sizeof(UNSIGNED16);
                                bufdest += sizeof(UNSIGNED16);
                                /* copy the buffer */
                                memcpy(bufdest, bufsrc, vsize);
                                bufsrc += vsize;
                                bufdest += vsize;
                            }
                            /* decrease the size */
                            sizesrc -= sizeof(UNSIGNED16) + sizeof(UNSIGNED16) + vsize;
                        }
                        /* deallocate old buffer */
                        if (pExtrablob->Data)
                        {
                            memory_free(pExtrablob->Data);
                        }
                        pExtrablob->Data = buf;
                        pExtrablob->Length = (UNSIGNED16)size;
                    }
                    else
                    {
                        res = TMEMORY;
                    }
                }
                else
                {
                    res = TINSUFFICIENTBUFFER;
                }
            }            
        }
        else
        {
            if (uSize)
            {
                /* add the new item */
                size += sizeof(UNSIGNED16) + sizeof(UNSIGNED16) + uSize;
                if (size <= umaxof(UNSIGNED16))
                {
                    buf = memory_alloc(size);
                    if (buf)
                    {
                        bufdest = buf;
                        if (pExtrablob->Data && pExtrablob->Length)
                        {
                            /* copy original buffer */
                            memcpy(bufdest, pExtrablob->Data, pExtrablob->Length);
                            bufdest += pExtrablob->Length;
                        }
                        /* set type */
                        vtype = eKey;                        
                        tmpu16 = vtype;
                        if (IS_BIG_ENDIAN)
                        {
                            UNSIGNED16_to_little_endian(tmpu16, (char*)&tmpu16);
                        }
                        memcpy(bufdest, &tmpu16, sizeof(UNSIGNED16));
                        bufdest += sizeof(UNSIGNED16);
                        /* set size */
                        vsize = (UNSIGNED16)uSize;
                        tmpu16 = vsize;
                        if (IS_BIG_ENDIAN)
                        {
                            UNSIGNED16_to_little_endian(tmpu16, (char*)&tmpu16);
                        }
                        memcpy(bufdest, &tmpu16, sizeof(UNSIGNED16));
                        bufdest += sizeof(UNSIGNED16);
                        /* set buffer */
                        memcpy(bufdest, pInfo, vsize);
                        /* deallocate old buffer */
                        if (pExtrablob->Data)
                        {
                            memory_free(pExtrablob->Data);
                        }                        
                        pExtrablob->Data = buf;
                        pExtrablob->Length = (UNSIGNED16)size;
                    }
                    else
                    {
                        res = TMEMORY;
                    }
                }
                else
                {
                    res = TINSUFFICIENTBUFFER;
                }
            }            
        }
    }
    else
    {
        res = TERRORKEY;
    }

    return res;
}

void taggant2_free_taggant(PTAGGANT2 pTaggant)
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

UNSIGNED16 taggant2_taggantblob2_size(PTAGGANTBLOB2 pTagBlob)
{
    return sizeof(TAGGANTBLOB_HEADER) + sizeof(HASHBLOB) + sizeof(UNSIGNED16) + pTagBlob->Extrablob.Length + pTagBlob->Hash.Hashmap.Entries * sizeof(HASHBLOB_HASHMAP_DOUBLE);
}

UNSIGNED32 taggant2_read_textual(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, PTAGGANT2* pTaggant, TAGGANTCONTAINER filetype, char *beginmarker, int beginmarkersize, char *endmarker, int endmarkersize)
{
    UNSIGNED32 res = TNOERR;
    PTAGGANT2 tagbuf = NULL;
    UNSIGNED32 taghdrsize, cmssize, tagftrsize;
    char *bmarker = NULL;
    char *emarker = NULL;

    if (beginmarkersize)
    {
        bmarker = memory_alloc(beginmarkersize);
        if (!bmarker)
        {
            res = TMEMORY;
        }
    }

    if (res == TNOERR)
    {
        if (endmarkersize)
        {
            emarker = memory_alloc(endmarkersize);
            if (!emarker)
            {
                res = TMEMORY;
            }
        }
    }

    if (res == TNOERR)
    {
        /* allocate memory for taggant */
        tagbuf = memory_alloc(sizeof(TAGGANT2));
        if (tagbuf)
        {
            memset(tagbuf, 0, sizeof(TAGGANT2));
            /* remember the taggant type */
            tagbuf->tagganttype = filetype;
            /* read and check the end marker */
            if (endmarkersize)
            {
                offset -= endmarkersize;
                if (file_seek(pCtx, fp, offset, SEEK_SET))
                {
                    /* read comment's end marker */
                    if (file_read_buffer(pCtx, fp, emarker, endmarkersize))
                    {
                        if (strncmp(emarker, endmarker, endmarkersize) != 0)
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

            if (res == TNOERR)
            {
                /* read taggant header and return it's size in js file */
                if ((res = txt_read_taggant_header2(pCtx, fp, offset, &tagbuf->Header, &taghdrsize)) == TNOERR)
                {
                    if (tagbuf->Header.Version == TAGGANT_VERSION2 && tagbuf->Header.MarkerBegin == TAGGANT_MARKER_BEGIN && tagbuf->Header.CMSLength)
                    {
                        offset -= taghdrsize;
                        if ((res = txt_read_taggant_cms(pCtx, fp, offset, tagbuf->Header.CMSLength, &tagbuf->CMSBuffer, &cmssize)) == TNOERR)
                        {
                            /* read taggant footer and return it's size in js file */
                            offset -= tagbuf->Header.CMSLength;
                            if ((res = txt_read_taggant_footer2(pCtx, fp, offset, &tagbuf->Footer, &tagftrsize)) == TNOERR)
                            {
                                if (tagbuf->Footer.MarkerEnd == TAGGANT_MARKER_END)
                                {
                                    tagbuf->CMSBufferSize = cmssize;
                                    offset -= tagftrsize;
                                    if (beginmarkersize)
                                    {
                                        offset -= beginmarkersize;
                                        if (file_seek(pCtx, fp, offset, SEEK_SET))
                                        {
                                            /* read and check end marker */
                                            if (file_read_buffer(pCtx, fp, bmarker, beginmarkersize))
                                            {
                                                if (strncmp(bmarker, beginmarker, beginmarkersize) != 0)
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
                                    if (res == TNOERR)
                                    {
                                        if (tagbuf->Header.TaggantLength == taghdrsize + tagbuf->Header.CMSLength + tagftrsize)
                                        {
                                            *pTaggant = tagbuf;
                                            res = TNOERR;
                                        }
                                        else
                                        {
                                            res = TNOTAGGANTS;
                                        }
                                    }
                                }
                                else
                                {
                                    res = TNOTAGGANTS;
                                }
                            }
                        }
                    }
                    else
                    {
                        res = TNOTAGGANTS;
                    }
                }
            }
            if (res != TNOERR)
            {
                taggant2_free_taggant(tagbuf);
            }
        }
        else
        {
            res = TMEMORY;
        }
    }
    if (bmarker)
    {
        memory_free(bmarker);
    }
    if (emarker)
    {
        memory_free(emarker);
    }

    return res;
}

UNSIGNED32 taggant2_read_binary(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, PTAGGANT2* pTaggant, TAGGANTCONTAINER filetype)
{
    UNSIGNED32 res = TNOTAGGANTS;
    PTAGGANT2 tagbuf = NULL;

    /* seek to the specified offset */
    offset -= sizeof(TAGGANT_HEADER2);
    if (file_seek(pCtx, fp, offset, SEEK_SET))
    {
        /* allocate memory for taggant */
        tagbuf = memory_alloc(sizeof(TAGGANT2));
        if (tagbuf)
        {
            memset(tagbuf, 0, sizeof(TAGGANT2));
            /* remember the taggant type */
            tagbuf->tagganttype = filetype;
            /* read taggant header */
            if (file_read_buffer(pCtx, fp, &tagbuf->Header, sizeof(TAGGANT_HEADER2)))
            {
                if (IS_BIG_ENDIAN)
                {
                    TAGGANT_HEADER2_to_big_endian(&tagbuf->Header, &tagbuf->Header);
                }
                if (tagbuf->Header.Version == TAGGANT_VERSION2 && tagbuf->Header.MarkerBegin == TAGGANT_MARKER_BEGIN && tagbuf->Header.CMSLength)
                {
                    /* allocate buffer for CMS */				
                    tagbuf->CMSBuffer = memory_alloc(tagbuf->Header.CMSLength);
                    if (tagbuf->CMSBuffer)
                    {
                        memset(tagbuf->CMSBuffer, 0, tagbuf->Header.CMSLength);
                        tagbuf->CMSBufferSize = tagbuf->Header.CMSLength;
                        /* seek to the CMS offset */
                        offset -= tagbuf->Header.CMSLength;
                        if (file_seek(pCtx, fp, offset, SEEK_SET))
                        {
                            /* read CMS */
                            if (file_read_buffer(pCtx, fp, tagbuf->CMSBuffer, tagbuf->Header.CMSLength))
                            {
                                offset -= sizeof(UNSIGNED32);
                                if (file_seek(pCtx, fp, offset, SEEK_SET))
                                {
                                    /* read end marker */
                                    if (file_read_UNSIGNED32(pCtx, fp, &tagbuf->Footer.MarkerEnd))
                                    {
                                        if (IS_BIG_ENDIAN)
                                        {
                                            UNSIGNED32_to_big_endian((char*)&tagbuf->Footer.MarkerEnd);
                                        }
                                        /* check end marker */
                                        if (tagbuf->Footer.MarkerEnd == TAGGANT_MARKER_END)
                                        {
                                            /* make sure there is no appended data in cms */
                                            if (tagbuf->Header.TaggantLength == sizeof(TAGGANT_HEADER2) + tagbuf->Header.CMSLength + /* TAGGANT_FOOTER2 length */ sizeof(UNSIGNED32))
                                            {
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
                taggant2_free_taggant(tagbuf);
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
    return res;
}

UNSIGNED32 taggant2_compute_default_hash_pe(EVP_MD_CTX *evp, PTAGGANTCONTEXT pCtx, PHASHBLOB_DEFAULT pDefaultHash, PFILEOBJECT hFile, PE_ALL_HEADERS *peh, UNSIGNED64 uObjectEnd)
{
    UNSIGNED32 res = TINVALIDPEFILE;
    /* for the default hash there are HASHMAP2_MAX_LENGTH number of regions is needed
     * Full File Hash contains from a hash of two regions:
     * - from file start to end of PE file (default hash)
     * - from end of PE file to end of physical file (extended hash)
     *
     * For the first region we have to exclude from the hashing:
     * - Checksum from optinal header
     * - Digital Signature header from optinal header
     */
    HASHBLOB_HASHMAP_DOUBLE regions[HASHMAP2_MAX_LENGTH];
    EVP_MD_CTX evp_ext;
    char* buf = NULL;
    int i, len;

    /* Calculate default hash */
    memset(&regions, 0, sizeof(regions));
    /* set the entire file region from file start to file end by default */
    regions[0].AbsoluteOffset = 0;
    regions[0].Length = uObjectEnd;
    /* exclude Checksum from region */
    len = exclude_region_from_hashmap(&regions[0], peh->dh.e_lfanew + sizeof(peh->signature) + sizeof(peh->fh) + 64, sizeof(UNSIGNED32));
    /* exclude PE Header Digital Signature */
    if (winpe_is_pe64(peh))
    {
        len = exclude_region_from_hashmap(&regions[0], peh->dh.e_lfanew + sizeof(peh->signature) + sizeof(peh->fh) + 144, sizeof(TAG_IMAGE_DATA_DIRECTORY));
    } else
    {
        len = exclude_region_from_hashmap(&regions[0], peh->dh.e_lfanew + sizeof(peh->signature) + sizeof(peh->fh) + 128, sizeof(TAG_IMAGE_DATA_DIRECTORY));
    }

    /* allocate buffer for file reading */
    buf = (char*)memory_alloc(HASH_READ_BLOCK);
    if (!buf)
    {
        return TMEMORY;
    }
    
    for (i = 0; i < len; i++)
    {
        if ((res = compute_region_hash(pCtx, hFile, evp, &regions[i], buf)) != TNOERR)
        {
            break;
        }
    }

    if (res == TNOERR)
    {
        memset(pDefaultHash, 0, sizeof(HASHBLOB_DEFAULT));
        pDefaultHash->Header.Type = TAGGANT_HASBLOB_DEFAULT;
        pDefaultHash->Header.Length = sizeof(HASHBLOB_DEFAULT);
        pDefaultHash->Header.Version = HASHBLOB_VERSION2;
        /* Copy context before destroying it by calling EVP_DigestFinal_ex */
        EVP_MD_CTX_copy(&evp_ext, evp);
        /* Get default file hash */
        EVP_DigestFinal_ex(&evp_ext, pDefaultHash->Header.Hash, NULL);
        /* Clean extended hashing context */
        EVP_MD_CTX_cleanup(&evp_ext);
    }
    memory_free(buf);

    return res;
}

UNSIGNED32 taggant2_compute_extended_hash_pe(EVP_MD_CTX *evp, PTAGGANTCONTEXT pCtx, PHASHBLOB_EXTENDED pExtendedHash, PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd)
{
    UNSIGNED32 res = TNOERR;
    HASHBLOB_HASHMAP_DOUBLE region;
    EVP_MD_CTX evp_ext;
    char* buf = NULL;

    /* Calculate extended hash */
    memset(pExtendedHash, 0, sizeof(HASHBLOB_EXTENDED));
    pExtendedHash->Header.Type = TAGGANT_HASBLOB_EXTENDED;
    pExtendedHash->Header.Length = sizeof(HASHBLOB_EXTENDED);
    pExtendedHash->Header.Version = HASHBLOB_VERSION2;
    /* remember the file end offset */
    pExtendedHash->PhysicalEnd = uFileEnd;
    memset(&region, 0, sizeof(region));
    /* set the initial region for extended file hash from end of PE file to end of physical file */
    region.AbsoluteOffset = uObjectEnd;
    region.Length = uFileEnd - uObjectEnd;
    if (region.Length != 0)
    {
        /* allocate buffer for file reading */
        buf = (char*)memory_alloc(HASH_READ_BLOCK);
        if (buf)
        {
            if ((res = compute_region_hash(pCtx, hFile, evp, &region, buf)) == TNOERR)
            {
                /* Copy context before destroying it by calling EVP_DigestFinal_ex */
                EVP_MD_CTX_copy(&evp_ext, evp);
                /* Get default file hash */
                EVP_DigestFinal_ex(&evp_ext, pExtendedHash->Header.Hash, NULL);
                /* Clean extended hashing context */
                EVP_MD_CTX_cleanup(&evp_ext);
            }
            memory_free(buf);
        }
        else
        {
            res = TMEMORY;
        }
    }        

    return res;
}

UNSIGNED32 taggant2_to_binary(BIO* cmsBio, BIO* outBio)
{
    int inlen;
    UNSIGNED32 cmslength = 0;
    TAGGANT_FOOTER2 tagftr, tmptagftr;
    TAGGANT_HEADER2 taghdr;
    char inbuf[512];

    /* fill out taggant footer */
    memset(&tagftr, 0, sizeof(tagftr));
    tagftr.MarkerEnd = TAGGANT_MARKER_END;
    /* copy data to temporary buffer to convert it to little endian if necessary */
    tmptagftr = tagftr;
    if (IS_BIG_ENDIAN)
    {
        TAGGANT_FOOTER2_to_little_endian(&tmptagftr, &tmptagftr);
    }
    BIO_write(outBio, &tmptagftr.MarkerEnd, sizeof(UNSIGNED32));

    /* Fill out taggant CMS */
    while ((inlen = BIO_read(cmsBio, inbuf, 512)) > 0) 
    {
        BIO_write(outBio, inbuf, inlen);
        cmslength += inlen;
    }

    /* Fill out taggant header */
    taghdr.Version = TAGGANT_VERSION2;
    taghdr.CMSLength = cmslength;
    taghdr.TaggantLength = sizeof(TAGGANT_HEADER2) + cmslength + /* sizeof(TAGGANT_FOOTER2) */ sizeof(UNSIGNED32) /* sizeof(EndMarker) */;
    taghdr.MarkerBegin = TAGGANT_MARKER_BEGIN;													
    if (IS_BIG_ENDIAN)
    {
        TAGGANT_HEADER2_to_little_endian(&taghdr, &taghdr);
    }
    BIO_write(outBio, &taghdr, sizeof(TAGGANT_HEADER2));			

    return TNOERR;
}

UNSIGNED32 taggant2_to_textual(BIO* cmsBio, BIO* outBio)
{
    UNSIGNED32 cmslength, ftrlength;
    UNSIGNED32 res = TMEMORY;
    TAGGANT_FOOTER2 tagftr;
    TAGGANT_HEADER2 taghdr;

    /* fill out taggant footer */
    memset(&tagftr, 0, sizeof(TAGGANT_FOOTER2));
    tagftr.MarkerEnd = TAGGANT_MARKER_END;
    if (txt_write_taggant_footer2(&tagftr, outBio, &ftrlength))
    {
        if ((cmslength = txt_bio_base64_encode(cmsBio, outBio)) > 0)
        {
            /* fill out taggant header */
            memset(&taghdr, 0, sizeof(TAGGANT_HEADER2));
            taghdr.Version = TAGGANT_VERSION2;
            taghdr.CMSLength = cmslength;
            taghdr.TaggantLength = ftrlength + cmslength + txt_taggant_header2_size();
            taghdr.MarkerBegin = TAGGANT_MARKER_BEGIN;
            if (txt_write_taggant_header2(&taghdr, outBio))
            {
                res = TNOERR;
            }
        }
    }
    return res;
}

int taggant2_write_taggantblob2(BIO *inbio, PTAGGANTBLOB2 tagblob)
{
    TAGGANTBLOB_HEADER tmphdr;
    HASHBLOB tmpblob;
    UNSIGNED16 tmpu16;
    HASHBLOB_HASHMAP_DOUBLE tmpdbl;
    PHASHBLOB_HASHMAP_DOUBLE tmphm;
    int i;

    tagblob->Hash.Hashmap.DoublesOffset = sizeof(TAGGANTBLOB_HEADER) + sizeof(HASHBLOB) + sizeof(UNSIGNED16) + tagblob->Extrablob.Length;
    /* Write tagblob->Header */
    tmphdr = tagblob->Header;
    if (IS_BIG_ENDIAN)
    {
        TAGGANTBLOB_HEADER_to_little_endian(&tmphdr, &tmphdr);
    }
    BIO_write(inbio, &tmphdr, sizeof(TAGGANTBLOB_HEADER));
    /* Write tagblob->Hash */
    tmpblob = tagblob->Hash;
    if (IS_BIG_ENDIAN)
    {
        HASHBLOB_to_little_endian(&tmpblob, &tmpblob);
    }
    BIO_write(inbio, &tmpblob, sizeof(HASHBLOB));
    /* Write tagblob->Extrablob.Length */
    tmpu16 = tagblob->Extrablob.Length;
    if (IS_BIG_ENDIAN)
    {
        UNSIGNED16_to_little_endian(tmpu16, (char*)&tmpu16);
    }
    BIO_write(inbio, &tmpu16, sizeof(UNSIGNED16));
    if (tagblob->Extrablob.Length)
    {
        BIO_write(inbio, tagblob->Extrablob.Data, tagblob->Extrablob.Length);
    }
    /* Write tagblob->pHashMapDoubles */	
    tmphm = tagblob->pHashMapDoubles;
    for (i = 0; i < tagblob->Hash.Hashmap.Entries; i++)
    {
        tmpdbl = *tmphm;
        if (IS_BIG_ENDIAN)
        {
            HASHBLOB_HASHMAP_DOUBLE_to_little_endian(&tmpdbl, &tmpdbl);
        }
        BIO_write(inbio, &tmpdbl, sizeof(HASHBLOB_HASHMAP_DOUBLE));
        tmphm++;
    }
    return 1;
}

#ifdef SPV_LIBRARY

UNSIGNED32 taggant2_prepare(PTAGGANTOBJ2 pTaggantObj, const PVOID pLicense, TAGGANTCONTAINER TaggantType, PVOID pTaggantOut, UNSIGNED32 *uTaggantReservedSize)
{
    UNSIGNED32 res = TBADKEY;
    BIO* licbio = NULL;
    X509* liccert = NULL, * licspv = NULL;
    EVP_PKEY* lickey = NULL;
    BIO* inbio = NULL, *outbio = NULL;
    BIO* cmsbio = NULL;	
    STACK_OF(X509) *intermediate = NULL;
    int maxlen;
    UNSIGNED32 biolen;
    
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
                        /* Set the length of the taggantblob2 */
                        pTaggantObj->tagBlob.Header.Length = taggant2_taggantblob2_size(&pTaggantObj->tagBlob);
                        /* Write taggantblob2 */
                        if (taggant2_write_taggantblob2(inbio, &pTaggantObj->tagBlob))
                        {
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
                                                outbio = BIO_new(BIO_s_mem());
                                                if (outbio)
                                                {
                                                    switch (TaggantType)
                                                    {
                                                    case TAGGANT_PEFILE:
                                                    case TAGGANT_BINFILE:
                                                    {
                                                        res = taggant2_to_binary(cmsbio, outbio);
                                                        break;
                                                    }
                                                    case TAGGANT_JSFILE:
                                                    {
                                                        /* write comment's begin marker */
                                                        BIO_write(outbio, JS_COMMENT_BEGIN, (int)strlen(JS_COMMENT_BEGIN));
                                                        res = taggant2_to_textual(cmsbio, outbio);
                                                        /* write comment's end marker */
                                                        BIO_write(outbio, JS_COMMENT_END, (int)strlen(JS_COMMENT_END));
                                                        break;
                                                    }
                                                    case TAGGANT_TXTFILE:
                                                    {
                                                        res = taggant2_to_textual(cmsbio, outbio);
                                                        break;
                                                    }
                                                    default:
                                                    {
                                                        res = TTYPE;
                                                        break;
                                                    }
                                                    }
                                                    if (res == TNOERR)
                                                    {
                                                        res = TERROR;
                                                        /* Get bio size */
                                                        maxlen = MAX_INTEGER;
                                                        biolen = (UNSIGNED32)BIO_read(outbio, NULL, maxlen);
                                                        if (biolen)
                                                        {
                                                            if (*uTaggantReservedSize < biolen)
                                                            {																
                                                                res = TINSUFFICIENTBUFFER;
                                                            } else
                                                            {
                                                                /* read bio to buffer */
                                                                BIO_read(outbio, pTaggantOut, biolen);
                                                                res = TNOERR;
                                                            }
                                                            *uTaggantReservedSize = biolen;
                                                        }														
                                                    }
                                                    BIO_free(outbio);
                                                }
                                                else
                                                {
                                                    res = TMEMORY;
                                                }
                                            }
                                            BIO_free(cmsbio);
                                        }
                                        else
                                        {
                                            res = TMEMORY;
                                        }
                                    }
                                }
                                sk_X509_free(intermediate);
                            }
                        }
                        BIO_free(inbio);
                    }
                    else
                    {
                        res = TMEMORY;
                    }
                    EVP_PKEY_free(lickey);
                }
                else
                {
                    res = TBADKEY;
                }
                X509_free(liccert);
            }
            else
            {
                res = TBADKEY;
            }
            X509_free(licspv);
        }
        else
        {
            res = TBADKEY;
        }
        BIO_free(licbio);
    }
    else
    {
        res = TMEMORY;
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

UNSIGNED32 taggant2_compute_default_hash_raw(EVP_MD_CTX *pEvp, PTAGGANTCONTEXT pCtx, PHASHBLOB_DEFAULT pDefaultHash, PFILEOBJECT hFile, UNSIGNED64 uFileEnd)
{
    UNSIGNED32 res = TFILEERROR;

    HASHBLOB_HASHMAP_DOUBLE region;
    EVP_MD_CTX evp_ext;
    char* buf = NULL;

    /* Calculate default hash */
    region.AbsoluteOffset = 0;
    region.Length = uFileEnd;

    /* allocate buffer for file reading */
    buf = (char*)memory_alloc(HASH_READ_BLOCK);
    if (!buf)
    {
        return TMEMORY;
    }

    res = compute_region_hash(pCtx, hFile, pEvp, &region, buf);
    if (res == TNOERR)
    {
        memset(pDefaultHash, 0, sizeof(HASHBLOB_DEFAULT));
        pDefaultHash->Header.Type = TAGGANT_HASBLOB_DEFAULT;
        pDefaultHash->Header.Length = sizeof(HASHBLOB_DEFAULT);
        pDefaultHash->Header.Version = HASHBLOB_VERSION2;
        /* Copy context before destroying it by calling EVP_DigestFinal_ex */
        EVP_MD_CTX_copy(&evp_ext, pEvp);
        /* Get default file hash */
        EVP_DigestFinal_ex(&evp_ext, pDefaultHash->Header.Hash, NULL);
        /* Clean extended hashing context */
        EVP_MD_CTX_cleanup (&evp_ext);
    }
    memory_free(buf);

    return res;
}

UNSIGNED32 taggant2_compute_extended_hash_raw(PHASHBLOB_EXTENDED pExtendedHash, UNSIGNED64 uFileEnd)
{
    /* Calculate extended hash */
    pExtendedHash->Header.Type = TAGGANT_HASBLOB_EXTENDED;
    pExtendedHash->Header.Length = sizeof(HASHBLOB_EXTENDED);
    pExtendedHash->Header.Version = HASHBLOB_VERSION2;

    /* remember the file end offset */
    pExtendedHash->PhysicalEnd = uFileEnd;

    return TNOERR;
}

UNSIGNED32 taggant2_compute_hash_map(PTAGGANTCONTEXT pCtx, PFILEOBJECT hFile, PHASHBLOB_HASHMAP pHm, PHASHBLOB_HASHMAP_DOUBLE pHmDoubles)
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
        hmd = pHmDoubles;
        for (i = 0; i < pHm->Entries; i++)
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
        pHm->DoublesOffset = sizeof(TAGGANTBLOB);
        pHm->Header.Type = TAGGANT_HASBLOB_HASHMAP;
        pHm->Header.Length = sizeof(HASHBLOB_HASHMAP);
        pHm->Header.Version = HASHBLOB_VERSION2;
        EVP_DigestFinal_ex(&evp, pHm->Header.Hash, NULL);
    }
    EVP_MD_CTX_cleanup (&evp);
    return res;
}

UNSIGNED32 taggant2_compute_hash_raw(PTAGGANTCONTEXT pCtx, PHASHBLOB pHash, PFILEOBJECT hFile, UNSIGNED64 uFileEnd, PHASHBLOB_HASHMAP_DOUBLE pHmDoubles)
{
    EVP_MD_CTX evp;
    UNSIGNED32 res = TNOERR;

    /* Compute hash */
    EVP_MD_CTX_init(&evp);
    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
    /* Compute default hash */
    if ((res = taggant2_compute_default_hash_raw(&evp, pCtx, &pHash->FullFile.DefaultHash, hFile, uFileEnd)) == TNOERR)
    {
        /* Compute extended hash */
        if ((res = taggant2_compute_extended_hash_raw(&pHash->FullFile.ExtendedHash, uFileEnd)) == TNOERR)
        {
            if (pHash->Hashmap.Entries > 0)
            {
                /* Compute hashmap */
                res = taggant2_compute_hash_map(pCtx, hFile, &pHash->Hashmap, pHmDoubles);
            }
        }
    }
    /* Clean hash context */
    EVP_MD_CTX_cleanup(&evp);

    return res;
}

#ifdef SSV_LIBRARY

int check_binary_cms(CMS_ContentInfo *cms, UNSIGNED32 size)
{
    int res = 0;
    BIO *bio = NULL;
    int maxlen = MAX_INTEGER;

    bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        if (i2d_CMS_bio(bio, cms))
        {
            /* Get bio size */
            if ((UNSIGNED32)BIO_read(bio, NULL, maxlen) == size)
            {
                res = 1;
            }
        }
        BIO_free(bio);
    }
    return res;
}

int check_textual_cms(CMS_ContentInfo *cms, UNSIGNED32 size, UNSIGNED32 b64size)
{
    int res = 0;
    BIO *bio = NULL, *bio64 = NULL;
    int maxlen = MAX_INTEGER;

    bio = BIO_new(BIO_s_mem());
    if (bio)
    {
        if (i2d_CMS_bio(bio, cms))
        {
            /* Get bio size */
            if ((UNSIGNED32)BIO_read(bio, NULL, maxlen) == size)
            {
                bio64 = BIO_new(BIO_s_mem());
                if (bio64)
                {
                    if (txt_bio_base64_encode(bio, bio64) == b64size)
                    {
                        res = 1;
                    }
                    BIO_free(bio64);
                }
            }
        }
        BIO_free(bio);
    }
    return res;
}

UNSIGNED32 taggant2_read_taggantblob2(BIO *inbio, PTAGGANTBLOB2 tagblob)
{
    UNSIGNED32 res = TERROR;
    PHASHBLOB_HASHMAP_DOUBLE tmphm;
    int i, err;

    memset(tagblob, 0, sizeof(TAGGANTBLOB2));
    /* Read tagblob->Header */
    if (BIO_read(inbio, &tagblob->Header, sizeof(TAGGANTBLOB_HEADER)) == sizeof(TAGGANTBLOB_HEADER))
    {
        if (IS_BIG_ENDIAN)
        {
            TAGGANTBLOB_HEADER_to_big_endian(&tagblob->Header, &tagblob->Header);
        }	
        /* Check if the taggantblob header version is correct */
        if (tagblob->Header.Version == TAGGANTBLOB_VERSION2)
        {
            /* Read tagblob->Hash */
            if (BIO_read(inbio, &tagblob->Hash, sizeof(HASHBLOB)) == sizeof(HASHBLOB))
            {
                if (IS_BIG_ENDIAN)
                {
                    HASHBLOB_to_big_endian(&tagblob->Hash, &tagblob->Hash);
                }
                /* Read tagblob->Extrablob.Length */
                if (BIO_read(inbio, &tagblob->Extrablob.Length, sizeof(UNSIGNED16)) == sizeof(UNSIGNED16))
                {
                    if (IS_BIG_ENDIAN)
                    {
                        tagblob->Extrablob.Length = UNSIGNED16_to_big_endian((char*)&tagblob->Extrablob.Length);
                    }
                    /* Read tagblob->Extrablob */
                    err = 0;
                    if (tagblob->Extrablob.Length)
                    {
                        err = 1;
                        tagblob->Extrablob.Data = memory_alloc(tagblob->Extrablob.Length);
                        if (tagblob->Extrablob.Data)
                        {
                            if (BIO_read(inbio, tagblob->Extrablob.Data, tagblob->Extrablob.Length) == tagblob->Extrablob.Length)
                            {
                                err = 0;
                            }
                        }
                        else
                        {
                            res = TMEMORY;
                        }
                    }
                    if (!err)
                    {
                        /* Read tagblob->pHashMapDoubles */
                        if (tagblob->Hash.Hashmap.Entries)
                        {
                            tagblob->pHashMapDoubles = memory_alloc(tagblob->Hash.Hashmap.Entries * sizeof(HASHBLOB_HASHMAP_DOUBLE));
                            if (tagblob->pHashMapDoubles)
                            {
                                tmphm = tagblob->pHashMapDoubles;
                                for (i = 0; i < tagblob->Hash.Hashmap.Entries; i++)
                                {
                                    if (BIO_read(inbio, tmphm, sizeof(HASHBLOB_HASHMAP_DOUBLE)) != sizeof(HASHBLOB_HASHMAP_DOUBLE))
                                    {
                                        err = 1;
                                        break;
                                    }
                                    tmphm++;
                                }
                            }
                            else
                            {
                                res = TMEMORY;
                                err = 1;
                            }
                        }
                    }
                    if (!err)
                    {
                        /* Make sure taggant blob length is correct */
                        if (tagblob->Header.Length == taggant2_taggantblob2_size(tagblob))
                        {
                            res = TNOERR;
                        }
                    }
                }                
            }
        }

    }
    /* free memory that we allocated here in case of error */
    if (res != TNOERR)
    {
        if (tagblob->Extrablob.Data)
        {
            memory_free(tagblob->Extrablob.Data);
            tagblob->Extrablob.Data = NULL;
        }
        tagblob->Extrablob.Length = 0;
        if (tagblob->pHashMapDoubles)
        {
            memory_free(tagblob->pHashMapDoubles);
            tagblob->pHashMapDoubles = NULL;
        }
    }
    return res;
}

UNSIGNED32 taggant2_validate_signature(PTAGGANTOBJ2 pTaggantObj, PTAGGANT2 pTaggant, PVOID pRootCert)
{
    UNSIGNED32 res = TBADKEY;
    BIO *cmsbio = NULL;
    BIO *signedbio = NULL;
    BIO *tsbio = NULL;
    X509_STORE *trusted_store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    int biolength = 0;
    int maxlen = MAX_INTEGER;
    char inbuf[512];
    int inlen;
    X509* tmpcer;
    STACK_OF(X509) *cms_certs = NULL;
    EVP_PKEY *pkey;

    /* Load root certificate */    
    pTaggantObj->root = buffer_to_X509(pRootCert);
    if (pTaggantObj->root)
    {
        /* Compare taggant version */
        if (pTaggant->Header.Version == TAGGANT_VERSION2 && pTaggant->Header.CMSLength > 0)
        {			
            cmsbio = BIO_new(BIO_s_mem());
            if (cmsbio)
            {
                BIO_write(cmsbio, pTaggant->CMSBuffer, pTaggant->CMSBufferSize);
                pTaggantObj->CMS = d2i_CMS_bio(cmsbio, NULL);
                if (pTaggantObj->CMS)
                {
                    /* Check the CMS size, convert CMS to base64 and compare the length from the header for textual taggant */
                    if (((pTaggant->tagganttype == TAGGANT_PEFILE || pTaggant->tagganttype == TAGGANT_BINFILE) && check_binary_cms(pTaggantObj->CMS, pTaggant->Header.CMSLength)) || ((pTaggant->tagganttype == TAGGANT_JSFILE || pTaggant->tagganttype == TAGGANT_TXTFILE) && check_textual_cms(pTaggantObj->CMS, pTaggant->CMSBufferSize, pTaggant->Header.CMSLength)))
                    {
                        signedbio = BIO_new(BIO_s_mem());
                        if (signedbio)
                        {
                            /* Create a store with trusted certificates */
                            trusted_store = X509_STORE_new();
                            if (trusted_store)
                            {
                                /* Add root certificate to the trusted store */
                                if (X509_STORE_add_cert(trusted_store, pTaggantObj->root))
                                {
                                    vpm = X509_VERIFY_PARAM_new();
                                    if (vpm)
                                    {
                                        /* We have to set the purpose to "any" to be used for signing certificate
                                        CMS_Verify expects that signer certificate has the purpose "smimeencrypt"
                                        but it does not.
                                        */
                                        X509_VERIFY_PARAM_set_purpose(vpm, X509_PURPOSE_ANY);
                                        X509_STORE_set1_param(trusted_store, vpm);
                                        /* Set the custom cb function to suppress certificate time errors */
                                        X509_STORE_set_verify_cb(trusted_store, verify_cms_cb);
                                        if (CMS_verify(pTaggantObj->CMS, NULL, trusted_store, NULL, signedbio, CMS_BINARY))
                                        {
                                            /* Make sure there are 2 certificate in CMS */
                                            cms_certs = CMS_get1_certs(pTaggantObj->CMS);
                                            if (cms_certs)
                                            {
                                                if (sk_X509_num(cms_certs) == CERTIFICATES_IN_TAGGANT_CHAIN)
                                                {
                                                    /* Set the spv and user certificates, check first certificate against second one */
                                                    pTaggantObj->spv = X509_dup(sk_X509_value(cms_certs, 0));
                                                    pTaggantObj->user = X509_dup(sk_X509_value(cms_certs, 1));
                                                    pkey = X509_get_pubkey(pTaggantObj->spv);
                                                    if (pkey)
                                                    {
                                                        if (!X509_verify(pTaggantObj->user, pkey))
                                                        {
                                                            tmpcer = pTaggantObj->user;
                                                            pTaggantObj->user = pTaggantObj->spv;
                                                            pTaggantObj->spv = tmpcer;
                                                        }
                                                        EVP_PKEY_free(pkey);
                                                    }
                                                    /* CMS is OK, next try to read a timestamp */
                                                    if ((res = taggant2_read_taggantblob2(signedbio, &pTaggantObj->tagBlob)) == TNOERR)
                                                    {
                                                        /* get size of the signed data */
                                                        biolength = BIO_read(signedbio, NULL, maxlen);
                                                        /* check if the timestamp response exists in the taggant */
                                                        if ((biolength - (int)pTaggantObj->tagBlob.Header.Length) > 0)
                                                        {
                                                            /* seek the pointer of the bio to tsresponse */
                                                            if (BIO_read(signedbio, NULL, pTaggantObj->tagBlob.Header.Length) == pTaggantObj->tagBlob.Header.Length)
                                                            {
                                                                /* load TS response, better to use d2i_TS_RESP instead of d2i_TS_RESP_bio */
                                                                tsbio = BIO_new(BIO_s_mem());
                                                                if (tsbio)
                                                                {
                                                                    while ((inlen = BIO_read(signedbio, inbuf, 512)) > 0)
                                                                    {
                                                                        BIO_write(tsbio, inbuf, inlen);
                                                                    }
                                                                    pTaggantObj->TSResponse = d2i_TS_RESP_bio(tsbio, NULL);
                                                                    BIO_free(tsbio);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                sk_X509_pop_free(cms_certs, X509_free);
                                            }
                                        }
                                        X509_VERIFY_PARAM_free(vpm);
                                    }
                                }
                                X509_STORE_free(trusted_store);
                            }
                            BIO_free(signedbio);
                        }
                        else
                        {
                            res = TMEMORY;
                        }
                    }
                }
                BIO_free(cmsbio);
            }
            else
            {
                res = TMEMORY;
            }
        }
    }
    else
    {
        res = TBADKEY;
    }

    if (res != TNOERR)
    {
        taggant2_free_taggantobj_content(pTaggantObj);
    }
    return res;
}

UNSIGNED32 taggant2_compare_default_hash(PHASHBLOB_DEFAULT pHash1, PHASHBLOB_DEFAULT pHash2)
{
    UNSIGNED32 res = TMISMATCH;

    /* Check if hashblob of default hashes matches */
    if (pHash1->Header.Version == pHash2->Header.Version &&
        pHash1->Header.Version == HASHBLOB_VERSION2 &&
        pHash1->Header.Type == pHash2->Header.Type &&
        pHash1->Header.Type == TAGGANT_HASBLOB_DEFAULT &&
        (memcmp(&pHash1->Header.Hash, &pHash2->Header.Hash, sizeof(pHash1->Header.Hash)) == 0)
        )
    {
        res = TNOERR;
    }
    return res;
}

UNSIGNED32 taggant2_compare_extended_hash(PHASHBLOB_EXTENDED pHash1, PHASHBLOB_EXTENDED pHash2)
{
    UNSIGNED32 res = TMISMATCH;

    /* Check if extended hash matches */
    if (pHash1->Header.Version == pHash2->Header.Version &&
        pHash1->Header.Version == HASHBLOB_VERSION2 &&
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

UNSIGNED32 taggant2_validate_default_hashes_pe(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd)
{
    PE_ALL_HEADERS peh;
    UNSIGNED32 res = TMEMORY;
    HASHBLOB_FULLFILE tmphb;
    UNSIGNED32 ds_offset, ds_size;
    UNSIGNED64 fileend = uFileEnd;
    EVP_MD_CTX evp;
    int valid_ds = 1;
    int valid_file = 0;

    if (winpe_is_correct_pe_file(pCtx, hFile, &peh))
    {
        if (pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd == 0)
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
            }
            else
            {
                ds_offset = (UNSIGNED32)peh.oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                ds_size = (UNSIGNED32)peh.oh.pe32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            }
            if (ds_offset != 0 && ds_size != 0)
            {
                if ((ds_offset + ds_size) != fileend)
                {
                    valid_ds = 0;
                }
                else
                {
                    fileend -= ds_size;
                }
            }
            valid_file = valid_ds;
        }
        else
        {
            fileend = pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd;
            valid_file = 1;
        }

        if (valid_file && (!uFileEnd || (uFileEnd && fileend <= uFileEnd)) && fileend >= uObjectEnd)
        {
            if (fileend >= uObjectEnd)
            {
                /* Allocate a copy of taggant blob, without hashmap and extrablob buffers */
                tmphb = pTaggantObj->tagBlob.Hash.FullFile;
                /* Compute hash */
                EVP_MD_CTX_init(&evp);
                EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
                /* Compute default hash */
                if ((res = taggant2_compute_default_hash_pe(&evp, pCtx, &tmphb.DefaultHash, hFile, &peh, uObjectEnd)) == TNOERR)
                {
                    if ((res = taggant2_compare_default_hash(&pTaggantObj->tagBlob.Hash.FullFile.DefaultHash, &tmphb.DefaultHash)) == TNOERR)
                    {
                        /* Compute extended hash */
                        if ((res = taggant2_compute_extended_hash_pe(&evp, pCtx, &tmphb.ExtendedHash, hFile, uObjectEnd, fileend)) == TNOERR)
                        {
                            res = taggant2_compare_extended_hash(&pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash, &tmphb.ExtendedHash);
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

UNSIGNED32 taggant2_validate_default_hashes_bin(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uFileEnd)
{
    UNSIGNED32 res = TMEMORY;
    HASHBLOB_FULLFILE tmphb;
    UNSIGNED64 fileend = uFileEnd;
    EVP_MD_CTX evp;

    if (pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd == 0)
    {
        /* if the fileend value is not specified, take the file size */
        if (!fileend)
        {
            fileend = get_file_size(pCtx, hFile);
        }
    }
    else
    {
        fileend = pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd;
    }

    if (!uFileEnd || (uFileEnd && fileend <= uFileEnd))
    {
        /* Allocate a copy of taggant blob, without hashmap and extrablob buffers */
        tmphb = pTaggantObj->tagBlob.Hash.FullFile;
        /* Compute hash */
        EVP_MD_CTX_init(&evp);
        EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
        /* Compute default hash */
        if ((res = taggant2_compute_default_hash_raw(&evp, pCtx, &tmphb.DefaultHash, hFile, fileend)) == TNOERR)
        {
            if ((res = taggant2_compare_default_hash(&pTaggantObj->tagBlob.Hash.FullFile.DefaultHash, &tmphb.DefaultHash)) == TNOERR)
            {
                /* Compute extended hash */
                if ((res = taggant2_compute_extended_hash_raw(&tmphb.ExtendedHash, uFileEnd)) == TNOERR)
                {
                    res = taggant2_compare_extended_hash(&pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash, &tmphb.ExtendedHash);
                }
            }
        }
        /* Clean hash context */
        EVP_MD_CTX_cleanup(&evp);
    }
    else
    {
        res = TERROR;
    }
    return res;
}

UNSIGNED32 taggant2_validate_default_hashes_js(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uFileEnd)
{
    UNSIGNED32 res = TMEMORY;
    HASHBLOB_FULLFILE tmphb;
    UNSIGNED64 fileend = uFileEnd, dsoffset;
    EVP_MD_CTX evp;

    if (pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd == 0)
    {
        /* if the fileend value is not specified, take the file size */
        if (!fileend)
        {
            fileend = get_file_size(pCtx, hFile);
        }
        /* Check if the file contains digital signature */
        if (js_get_ds_offset(pCtx, hFile, &dsoffset))
        {
            fileend = dsoffset;
        }
    }
    else
    {
        fileend = pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd;
    }

    if (!uFileEnd || (uFileEnd && fileend <= uFileEnd))
    {
        /* Allocate a copy of taggant blob, without hashmap and extrablob buffers */
        tmphb = pTaggantObj->tagBlob.Hash.FullFile;
        /* Compute hash */
        EVP_MD_CTX_init(&evp);
        EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
        /* Compute default hash */
        if ((res = taggant2_compute_default_hash_raw(&evp, pCtx, &tmphb.DefaultHash, hFile, fileend)) == TNOERR)
        {
            if ((res = taggant2_compare_default_hash(&pTaggantObj->tagBlob.Hash.FullFile.DefaultHash, &tmphb.DefaultHash)) == TNOERR)
            {
                /* Compute extended hash */
                if ((res = taggant2_compute_extended_hash_raw(&tmphb.ExtendedHash, uFileEnd)) == TNOERR)
                {
                    res = taggant2_compare_extended_hash(&pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash, &tmphb.ExtendedHash);
                }
            }
        }
        /* Clean hash context */
        EVP_MD_CTX_cleanup(&evp);
    } else
    {
        res = TERROR;
    }
    return res;
}

UNSIGNED32 taggant2_validate_default_hashes_txt(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile, UNSIGNED64 uFileEnd)
{
    UNSIGNED32 res = TMEMORY;
    HASHBLOB_FULLFILE tmphb;
    UNSIGNED64 fileend = uFileEnd;
    EVP_MD_CTX evp;

    if (pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd == 0)
    {
        /* if the fileend value is not specified, take the file size */
        if (!fileend)
        {
            fileend = get_file_size(pCtx, hFile);
        }
    }
    else
    {
        fileend = pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd;
    }

    if (!uFileEnd || (uFileEnd && fileend <= uFileEnd))
    {
        /* Allocate a copy of taggant blob, without hashmap and extrablob buffers */
        tmphb = pTaggantObj->tagBlob.Hash.FullFile;
        /* Compute hash */
        EVP_MD_CTX_init(&evp);
        EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
        /* Compute default hash */
        if ((res = taggant2_compute_default_hash_raw(&evp, pCtx, &tmphb.DefaultHash, hFile, fileend)) == TNOERR)
        {
            if ((res = taggant2_compare_default_hash(&pTaggantObj->tagBlob.Hash.FullFile.DefaultHash, &tmphb.DefaultHash)) == TNOERR)
            {
                /* Compute extended hash */
                if ((res = taggant2_compute_extended_hash_raw(&tmphb.ExtendedHash, uFileEnd)) == TNOERR)
                {
                    res = taggant2_compare_extended_hash(&pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash, &tmphb.ExtendedHash);
                }
            }
        }
        /* Clean hash context */
        EVP_MD_CTX_cleanup(&evp);
    }
    else
    {
        res = TERROR;
    }
    return res;
}

UNSIGNED32 taggant2_compare_hash_map(PHASHBLOB_HASHMAP pHm1, PHASHBLOB_HASHMAP pHm2)
{
    UNSIGNED32 res = TMISMATCH;

    if (pHm1->Header.Version == HASHBLOB_VERSION2 &&
        pHm1->Header.Type == TAGGANT_HASBLOB_HASHMAP &&
        pHm1->Entries == pHm2->Entries &&
        (memcmp(&pHm1->Header, &pHm2->Header, sizeof(HASHBLOB_HEADER)) == 0))
    {
        res = TNOERR;
    }
    return res;
}

UNSIGNED32 taggant2_validate_hashmap(PTAGGANTCONTEXT pCtx, PTAGGANTOBJ2 pTaggantObj, PFILEOBJECT hFile)
{
    UNSIGNED32 res = TNOERR;
    HASHBLOB_HASHMAP tmphm;
    int i;

    if ((pTaggantObj->tagBlob.Hash.Hashmap.DoublesOffset + (pTaggantObj->tagBlob.Hash.Hashmap.Entries * sizeof(HASHBLOB_HASHMAP_DOUBLE))) > pTaggantObj->tagBlob.Header.Length)
    {
        return TMEMORY;
    }

    /* Make sure the regions in hashmap are ordered correctly (from lowest offset to highest) */
    for (i = 1; i < pTaggantObj->tagBlob.Hash.Hashmap.Entries; i++)
    {
        if (pTaggantObj->tagBlob.pHashMapDoubles[i - 1].AbsoluteOffset >= pTaggantObj->tagBlob.pHashMapDoubles[i].AbsoluteOffset)
        {
            res = TERROR;
            break;
        }
    }
    if (res == TNOERR)
    {
        /* Check if hashmap contains regions with zero size */
        for (i = 0; i < pTaggantObj->tagBlob.Hash.Hashmap.Entries; i++)
        {
            if (pTaggantObj->tagBlob.pHashMapDoubles[i].Length == 0)
            {
                res = TERROR;
                break;
            }
        }
    }
    if (res == TNOERR)
    {
        /* Compute hash map */
        tmphm = pTaggantObj->tagBlob.Hash.Hashmap;
        if ((res = taggant2_compute_hash_map(pCtx, hFile, &tmphm, pTaggantObj->tagBlob.pHashMapDoubles)) == TNOERR)
        {
            res = taggant2_compare_hash_map(&pTaggantObj->tagBlob.Hash.Hashmap, &tmphm);
        }
    }
    return res;
}

UNSIGNED32 taggant2_get_timestamp(PTAGGANTOBJ2 pTaggantObj, UNSIGNED64 *pTime, PVOID pTSRootCert)
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
    int maxlen = MAX_INTEGER, len;
    X509 *cert = NULL;
    X509_STORE *store;
    TS_TST_INFO* tstInfo = NULL;
    const ASN1_GENERALIZEDTIME* asn1Time = NULL;

    if (pTaggantObj->TSResponse == NULL)
    {
        return TNOTIME;
    }

    /* Calculate the hash of the taggant blob structure */	
    EVP_MD_CTX_init (&evp);
    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
    /* save taggant blob to bio and then to buffer */
    tmpbio = BIO_new(BIO_s_mem());	
    if (tmpbio)
    {
        if (taggant2_write_taggantblob2(tmpbio, &pTaggantObj->tagBlob))
        {
            len = BIO_read(tmpbio, NULL, maxlen);
            ptmp = memory_alloc(len);
            if (ptmp)
            {
                BIO_read(tmpbio, ptmp, len);
                EVP_DigestUpdate(&evp, ptmp, len);
                res = TNOERR;
                memory_free(ptmp);				
            }
            else
            {
                res = TMEMORY;
            }
        }
        BIO_free(tmpbio);
    }
    else
    {
        res = TMEMORY;
    }
    EVP_DigestFinal_ex(&evp, (unsigned char *)&hash, NULL);
    EVP_MD_CTX_cleanup (&evp);

    /* Load all provided certificates */
    if (res == TNOERR)
    {
        tmpbio = BIO_new(BIO_s_mem());
        if (tmpbio)
        {
            BIO_write(tmpbio, pTSRootCert, (int)strlen((const char*)pTSRootCert));
            if ((store = X509_STORE_new()))
            {
                while ((cert = PEM_read_bio_X509(tmpbio, NULL, 0, NULL)))
                {
                    res = X509_STORE_add_cert(store, cert) ? res : TERROR;
                    X509_free(cert);
                    if (res != TNOERR)
                    {
                        X509_STORE_free(store);
                        break;
                    }
                }
                if (res == TNOERR)
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

UNSIGNED32 taggant2_get_info(PTAGGANTOBJ2 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 *pSize, PINFO pInfo)
{
    UNSIGNED32 res = TERRORKEY;
    int biolength = 0;
    BIO *tmpbio = NULL;
    int maxlen = MAX_INTEGER;

    if (pTaggantObj->CMS == NULL)
    {
        return TNOTAGGANTS;
    }
    switch (eKey)
    {
    case ESPVCERT:
        res = TERROR;
        if (pTaggantObj->spv)
        {
            tmpbio = BIO_new(BIO_s_mem());
            if (tmpbio)
            {
                if (i2d_X509_bio(tmpbio, pTaggantObj->spv))
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
                        }
                        else
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
        }
        break;
    case EUSERCERT:
        res = TERROR;
        if (pTaggantObj->user)
        {
            tmpbio = BIO_new(BIO_s_mem());
            if (tmpbio)
            {
                if (i2d_X509_bio(tmpbio, pTaggantObj->user))
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
                        }
                        else
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
        }
        break;
    case EFILEEND:
        /* get the PhysicalEnd value from the taggant */
        if (*pSize >= sizeof(pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd) && pInfo != NULL)
        {
            memcpy(pInfo, &pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd, sizeof(pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd));
            res = TNOERR;
        } else
        {
            res = TINSUFFICIENTBUFFER;
        }
        *pSize = sizeof(pTaggantObj->tagBlob.Hash.FullFile.ExtendedHash.PhysicalEnd);
        break;
    case EPACKERINFO:
        /* get the packer information from the taggant */
        if (*pSize >= sizeof(PACKERINFO) && pInfo != NULL)
        {
            memcpy(pInfo, &pTaggantObj->tagBlob.Header.PackerInfo, sizeof(PACKERINFO));
            res = TNOERR;
        } else
        {
            res = TINSUFFICIENTBUFFER;
        }
        *pSize = sizeof(PACKERINFO);
        break;
    default:
        res = taggant2_get_extrainfo(&pTaggantObj->tagBlob.Extrablob, eKey, pSize, pInfo);
        break;
    }
    return res;
}

#endif

#ifdef SPV_LIBRARY

UNSIGNED32 taggant2_put_timestamp(PTAGGANTOBJ2 pTaggantObj, const char* pTSUrl, UNSIGNED32 uTimeout)
{
    UNSIGNED32 res = TNONET;
    char hash[HASH_SHA256_DIGEST_SIZE];
    EVP_MD_CTX evp;
    TS_RESP* tsResponse = NULL;
    char* ptmp = NULL;
    BIO *tbio;
    int maxlen = MAX_INTEGER, biolen;

    if (pTaggantObj->TSResponse != NULL)
    {
        TS_RESP_free(pTaggantObj->TSResponse);
        pTaggantObj->TSResponse = NULL;
    }
    /* Calculate the hash of the taggant blob structure */
    EVP_MD_CTX_init (&evp);
    EVP_DigestInit_ex(&evp, EVP_sha256(), NULL);
    /* Dump taggant blob */
    tbio = BIO_new(BIO_s_mem());
    if (tbio)
    {		
        pTaggantObj->tagBlob.Header.Length = taggant2_taggantblob2_size(&pTaggantObj->tagBlob);
        if (taggant2_write_taggantblob2(tbio, &pTaggantObj->tagBlob))
        {
            biolen = BIO_read(tbio, NULL, maxlen);
            ptmp = memory_alloc(biolen);
            if (ptmp)
            {
                BIO_read(tbio, ptmp, biolen);
                /* hash the taggant blob 2 */
                EVP_DigestUpdate(&evp, ptmp, biolen);
                res = TNOERR;
                memory_free(ptmp);
            }
            else
            {
                res = TMEMORY;
            }
        }
        BIO_free(tbio);
    }
    else
    {
        res = TMEMORY;
    }
    if (res == TNOERR)
    {
        EVP_DigestFinal_ex(&evp, (unsigned char *)&hash, NULL);
        EVP_MD_CTX_cleanup(&evp);
        if ((res = get_timestamp_response(pTSUrl, (char*)&hash, sizeof(hash), uTimeout, &tsResponse)) == TNOERR)
        {
            pTaggantObj->TSResponse = tsResponse;
        }
    }
    return res;
}

UNSIGNED32 taggant2_add_hash_region(PTAGGANTOBJ2 pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength)
{
    PHASHBLOB_HASHMAP_DOUBLE hmd;
    HASHBLOB_HASHMAP_DOUBLE t;
    int i, j;
    UNSIGNED16 count;
    UNSIGNED64 a, b, c, d;
    char *tmpbuf;

    /* Check if the number of existing regions does not exceed allowed */
    if (pTaggantObj->tagBlob.Hash.Hashmap.Entries >= HASHMAP_MAXIMUM_ENTRIES)
    {
        return TENTRIESEXCEED;
    }

    /* Realloc hashmap doubles to contain sufficient buffer for additional region */
    tmpbuf = memory_realloc(pTaggantObj->tagBlob.pHashMapDoubles, pTaggantObj->tagBlob.Header.Length + sizeof(HASHBLOB_HASHMAP_DOUBLE));	
    if (!tmpbuf)
    {
        return TMEMORY;
    }
    pTaggantObj->tagBlob.pHashMapDoubles = (PHASHBLOB_HASHMAP_DOUBLE)tmpbuf;
    
    hmd = (PHASHBLOB_HASHMAP_DOUBLE)pTaggantObj->tagBlob.pHashMapDoubles;
    hmd[pTaggantObj->tagBlob.Hash.Hashmap.Entries].AbsoluteOffset = uOffset;
    hmd[pTaggantObj->tagBlob.Hash.Hashmap.Entries].Length = uLength;
    /* bubble sort hashmap array */
    bubblesort_hashmap(hmd, pTaggantObj->tagBlob.Hash.Hashmap.Entries);
    pTaggantObj->tagBlob.Hash.Hashmap.Entries++;
    /* increase size of taggant blob */
    pTaggantObj->tagBlob.Header.Length += sizeof(HASHBLOB_HASHMAP_DOUBLE);

    /* searching for overlapped regions */
    count = 0;
    for (i = 0; i < pTaggantObj->tagBlob.Hash.Hashmap.Entries - 1; i++)
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
        for (i = pTaggantObj->tagBlob.Hash.Hashmap.Entries - 1; i >= 0; i--)
        {
            for (j = 0; j <= pTaggantObj->tagBlob.Hash.Hashmap.Entries - 2; j++)
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
        pTaggantObj->tagBlob.Hash.Hashmap.Entries = pTaggantObj->tagBlob.Hash.Hashmap.Entries - count;
        /* sort regions array */
        bubblesort_hashmap(hmd, pTaggantObj->tagBlob.Hash.Hashmap.Entries - 1);
        /* realloc hashmap doubles */
        tmpbuf = memory_realloc(pTaggantObj->tagBlob.pHashMapDoubles, pTaggantObj->tagBlob.Header.Length);	
        if (!tmpbuf)
        {
            return TMEMORY;
        }
        pTaggantObj->tagBlob.pHashMapDoubles = (PHASHBLOB_HASHMAP_DOUBLE)tmpbuf;
    }
    return TNOERR;
}

UNSIGNED32 taggant2_put_info(PTAGGANTOBJ2 pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 uSize, PINFO pInfo)
{
    UNSIGNED32 res = TERRORKEY;

    switch (eKey)
    {
    case EPACKERINFO:
        /* set the packer information to the taggant */
        if (uSize >= sizeof(PACKERINFO) && pInfo != NULL)
        {
            memcpy(&pTaggantObj->tagBlob.Header.PackerInfo, pInfo, sizeof(PACKERINFO));
            res = TNOERR;
        } else
        {
            res = TINSUFFICIENTBUFFER;
        }
        break;
    default:
        res = taggant2_put_extrainfo(&pTaggantObj->tagBlob.Extrablob, eKey, uSize, pInfo);
        break;
    }	
    return res;
}

#endif

void taggant2_free_taggantobj_content(PTAGGANTOBJ2 pTaggantObj)
{
    /* Free extrablob */				
    if (pTaggantObj->tagBlob.Extrablob.Data)
    {
        memory_free(pTaggantObj->tagBlob.Extrablob.Data);
        pTaggantObj->tagBlob.Extrablob.Data = NULL;
    }
    pTaggantObj->tagBlob.Extrablob.Length = 0;
    /* Free hashmap */				
    if (pTaggantObj->tagBlob.pHashMapDoubles)
    {
        memory_free(pTaggantObj->tagBlob.pHashMapDoubles);
        pTaggantObj->tagBlob.pHashMapDoubles = NULL;
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
    /* Free user certificate*/
    if (pTaggantObj->user)
    {
        X509_free(pTaggantObj->user);
        pTaggantObj->user = NULL;
    }
    /* Free spv certificate*/
    if (pTaggantObj->spv)
    {
        X509_free(pTaggantObj->spv);
        pTaggantObj->spv = NULL;
    }
    /* Free root certificate*/
    if (pTaggantObj->root)
    {
        X509_free(pTaggantObj->root);
        pTaggantObj->root = NULL;
    }
}