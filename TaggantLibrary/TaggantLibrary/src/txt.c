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
#include "endianness.h"
#include "taggant_types.h"
#include "callbacks.h"
#include "miscellaneous.h"

UNSIGNED32 txt_taggant_header2_size(void)
{
    return sizeof(UNSIGNED16) * 2 /* Version */ + sizeof(UNSIGNED32) * 2 /* CMSLength */ + sizeof(UNSIGNED32) * 2 /* TaggantLength */ + sizeof(UNSIGNED32) /* MarkerBegin */;
}

UNSIGNED32 txt_read_taggant_header2(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, TAGGANT_HEADER2* pTagHeader, UNSIGNED32 *uSize)
{
    UNSIGNED32 res = TFILEACCESSDENIED, size = txt_taggant_header2_size();
    /* offset is pointing to the end of the taggant header */
    /* seek to the beginning of the taggant header */
    memset(pTagHeader, 0, sizeof(TAGGANT_HEADER2));
    if (file_seek(pCtx, fp, offset - size, SEEK_SET))
    {
        /* read Version */		
        if (file_read_textual_UNSIGNED16(pCtx, fp, &pTagHeader->Version))
        {
            /* read CMSLength */
            if (file_read_textual_UNSIGNED32(pCtx, fp, &pTagHeader->CMSLength))
            {
                /* read TaggantLength */
                if (file_read_textual_UNSIGNED32(pCtx, fp, &pTagHeader->TaggantLength))
                {
                    if (file_read_UNSIGNED32(pCtx, fp, &pTagHeader->MarkerBegin))
                    {
                        *uSize = size;
                        res = TNOERR;
                    }
                }
            }
        }
    }
    return res;
}

UNSIGNED32 txt_bio_base64_decode(BIO *inbio, BIO *outbio)
{
    BIO *bio64, *tbio;
    char inbuf[512];
    int inlen;
    UNSIGNED32 res = 0;

    bio64 = BIO_new(BIO_f_base64());
    if (bio64)
    {
        BIO_set_flags(bio64, BIO_FLAGS_BASE64_NO_NL);
        tbio = BIO_push(bio64, inbio);
        while ((inlen = BIO_read(tbio, inbuf, 512)) > 0) 
        {
            BIO_write(outbio, inbuf, inlen);
            res += inlen;
        }
        BIO_free(bio64);
    }
    return res;
}

UNSIGNED32 txt_read_taggant_cms(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, UNSIGNED32 size, PVOID* pCms, UNSIGNED32 *uSize)
{
    char *buf;
    BIO *biomem, *biomemout;
    int osize;
    UNSIGNED32 res = TFILEACCESSDENIED;

    if (file_seek(pCtx, fp, offset - size, SEEK_SET))
    {
        buf = memory_alloc(size);
        if (buf)
        {
            if (file_read_buffer(pCtx, fp, buf, size))
            {
                biomem = BIO_new(BIO_s_mem());
                if (biomem)
                {										
                    BIO_write(biomem, buf, size); 
                    biomemout = BIO_new(BIO_s_mem());
                    if (biomemout)
                    {		
                        osize = txt_bio_base64_decode(biomem, biomemout);
                        if (osize)
                        {
                            *pCms = memory_alloc(osize);
                            if (*pCms)
                            {
                                BIO_read(biomemout, *pCms, osize);
                                *uSize = osize;
                                res = TNOERR;
                            }
                            else
                            {
                                res = TMEMORY;
                            }
                        }
                        BIO_free(biomemout);
                    }
                    else
                    {
                        res = TMEMORY;
                    }
                    BIO_free(biomem);
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
            memory_free(buf);
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

UNSIGNED32 txt_read_taggant_footer2(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, TAGGANT_FOOTER2* pTagFooter, UNSIGNED32 *uSize)
{
    UNSIGNED32 res = TFILEACCESSDENIED;
    /* offset is pointing to the end of the taggant footer */
    /* seek to the beginning of the taggant footer */
    memset(pTagFooter, 0, sizeof(TAGGANT_FOOTER2));
    /* Read end marker */
    if (file_seek(pCtx, fp, offset - sizeof(UNSIGNED32), SEEK_SET))
    {
        if (file_read_UNSIGNED32(pCtx, fp, &pTagFooter->MarkerEnd))
        {
            /* Return the size of taggant_footer2 structure */
            *uSize = sizeof(UNSIGNED32) /* size of end marker */;
            res = TNOERR;
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
    return res;
}

int txt_write_UNSIGNED16(BIO *outBio, UNSIGNED16 value)
{
    char buf[5];
    if (sprintf((char*)&buf, "%.4x", value) == sizeof(buf) - 1)
    {
        BIO_write(outBio, &buf, sizeof(buf) - 1);
        return 1;
    }
    return 0;
}

int txt_write_UNSIGNED32(BIO *outBio, UNSIGNED32 value)
{
    char buf[9];
    if (sprintf((char*)&buf, "%.8x", value) == sizeof(buf) - 1)
    {
        BIO_write(outBio, &buf, sizeof(buf) - 1);
        return 1;
    }
    return 0;
}

int txt_write_taggant_header2(PTAGGANT_HEADER2 pTagHeader, BIO *outBio)
{
    UNSIGNED32 val;

    if (txt_write_UNSIGNED16(outBio, pTagHeader->Version))
    {
        if (txt_write_UNSIGNED32(outBio, pTagHeader->CMSLength))
        {
            if (txt_write_UNSIGNED32(outBio, pTagHeader->TaggantLength))
            {
                val = pTagHeader->MarkerBegin;
                if (IS_BIG_ENDIAN)
                {
                    UNSIGNED32_to_little_endian(val, (char*)&val);
                }
                BIO_write(outBio, (char*)&val, sizeof(val));
                return 1;
            }
        }
    }
    return 0;
}

UNSIGNED32 txt_bio_base64_encode(BIO *inbio, BIO *outbio)
{
    BIO *bio64, *tbio;
    char inbuf[512], *buf;
    int inlen, size;
    int maxlen = MAX_INTEGER;
    UNSIGNED32 res = 0;

    bio64 = BIO_new(BIO_f_base64());
    if (bio64)
    {
        BIO_set_flags(bio64, BIO_FLAGS_BASE64_NO_NL);
        tbio = BIO_push(bio64, inbio);
        size = BIO_read(inbio, NULL, maxlen);
        buf = memory_alloc(size);
        if (buf)
        {
            BIO_read(inbio, buf, size);
            BIO_write(tbio, buf, size);
            BIO_flush(tbio);
            while ((inlen = BIO_read(inbio, inbuf, 512)) > 0) 
            {
                BIO_write(outbio, inbuf, inlen);
                res += inlen;
            }
            memory_free(buf);
        }
        BIO_free(bio64);
    }
    return res;
}

int txt_write_buffer(BIO *outBio, char *buffer, UNSIGNED16 length)
{
    int i, res = 1;
    char buf[3];

    for (i = 0; i < length; i++)
    {
        if (sprintf((char*)&buf, "%.2x", *buffer) == sizeof(buf) - 1)
        {
            BIO_write(outBio, &buf, sizeof(buf) - 1);
        } else 
        {
            res = 0;
            break;
        }
        buffer++;
    }
    return 0;
}

int txt_write_taggant_footer2(PTAGGANT_FOOTER2 pTagFooter, BIO *outBio, UNSIGNED32 *size)
{
    UNSIGNED32 val = pTagFooter->MarkerEnd;
    /* write end marker */
    if (IS_BIG_ENDIAN)
    {
        UNSIGNED32_to_little_endian(val, (char*)&val);
    }
    BIO_write(outBio, (char*)&val, sizeof(val));
    /* return the size of written data */
    *size = sizeof(val);
    return 1;
}