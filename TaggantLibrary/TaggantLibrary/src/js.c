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
#include "types.h"
#include "taggant.h"
#include "endianness.h"
#include "taggant_types.h"
#include "callbacks.h"
#include "miscellaneous.h"

int js_get_ds_offset(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 *offset)
{

    char* buf;
    int res = 0, err, i, j, found, toread;
    UNSIGNED64 pos = get_file_size(pCtx, fp);

    if (pos > 0)
    {
        /* allocate buffer for file content*/
        buf = memory_alloc(HASH_READ_BLOCK);
        if (buf)
        {
            /* find the end of the file excluding \r and \n */
            err = 0;
            while (pos > 0)
            {
                toread = pos > HASH_READ_BLOCK ? HASH_READ_BLOCK : (int)pos;
                if (file_seek(pCtx, fp, pos - toread, SEEK_SET))
                {
                    if (file_read_buffer(pCtx, fp, buf, toread))
                    {
                        found = 0;
                        for (i = toread - 1; i > 0; i--)
                        {
                            if (buf[i] == '\r' || buf[i] == '\n')
                            {
                                pos--;
                            }
                            else
                            {
                                found = 1;
                                break;
                            }
                        }
                        if (found)
                        {
                            break;
                        }
                    }
                    else
                    {
                        err = 1;
                        break;
                    }
                }
                else
                {
                    err = 1;
                    break;
                }
            }
            /* search for end ds marker */
            if (!err)
            {
                toread = (int)strlen(JS_DS_END);
                if (pos >= toread)
                {                    
                    if (file_seek(pCtx, fp, pos - toread, SEEK_SET))
                    {
                        if (file_read_buffer(pCtx, fp, buf, toread))
                        {
                            if (_strnicmp(buf, JS_DS_END, toread) == 0)
                            {
                                pos -= toread;
                            }
                            else
                            {
                                err = 1;
                            }
                        }
                        else
                        {
                            err = 1;
                        }
                    }
                    else
                    {
                        err = 1;
                    }

                }
            }
            /* search for begin ds marker */
            if (!err)
            {
                while (pos >= strlen(JS_DS_BEGIN))
                {
                    toread = pos > HASH_READ_BLOCK ? HASH_READ_BLOCK : (int)pos;
                    if (file_seek(pCtx, fp, pos - toread, SEEK_SET))
                    {
                        if (file_read_buffer(pCtx, fp, buf, toread))
                        {                            
                            i = toread;                            
                            while (i != 0)
                            {                                
                                j = (int)strlen(JS_DS_BEGIN);
                                found = 1;
                                while (j != 0)
                                {
                                    i--;
                                    j--;
                                    if ((buf[i] | 32) != (JS_DS_BEGIN[j] | 32))
                                    {
                                        found = 0;
                                        break;
                                    }                                    
                                }                 
                                if (found)
                                {
                                    *offset = pos - toread + i;
                                    res = 1;
                                    break;
                                }
                            }
                            if (res)
                            {
                                break;
                            }
                            pos -= toread;
                            if (pos != 0)
                            {
                                pos += strlen(JS_DS_BEGIN) - 1;
                            }
                        }
                        else
                        {
                            err = 1;
                            break;
                        }
                    }
                    else
                    {
                        err = 1;
                        break;
                    }
                    if (res != 0)
                    {
                        break;
                    }
                }
            }
            memory_free(buf);
        }
        else
        {
            err = 1;
        }
    }
    return res;
}