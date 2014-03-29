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


#include <stdio.h>
#include <stdlib.h>
#include "taggantlib.h"
#include "endianness.h"

long round_up(long alignment, long size)
{
	return (size + alignment - 1) &- alignment;
}

long round_down(long alignment, long size)
{
	return size &- alignment;
}

long get_min(long v1, long v2)
{
	return (v1 < v2) ? v1 : v2;
}

long get_max(long v1, long v2)
{
	return (v1 > v2) ? v1 : v2;
}

UNSIGNED64 get_file_size (PTAGGANTCONTEXT pCtx, PFILEOBJECT fp)
{
	UNSIGNED64 size;
	UNSIGNED64 pos = pCtx->FileTellCallBack(fp);
	pCtx->FileSeekCallBack(fp, 0, SEEK_END);
	size = pCtx->FileTellCallBack(fp);
	pCtx->FileSeekCallBack(fp, pos, SEEK_SET);
	return size;
}

int file_seek(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 offset, int type)
{
	return pCtx->FileSeekCallBack(fp, offset, type) == 0 ? 1 : 0;
}

int file_read_buffer(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, void* buffer, size_t length)
{
	return (pCtx->FileReadCallBack(fp, buffer, length) == length) ? 1 : 0;
}

int file_read_UNSIGNED16(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED16 *value)
{
	if (pCtx->FileReadCallBack(fp, value, sizeof(UNSIGNED16)) == sizeof(UNSIGNED16))
	{
		if (IS_BIG_ENDIAN)
		{
			*value = UNSIGNED16_to_big_endian((char*)value);
		}
		return 1;
	}
	return 0;
}

int file_read_UNSIGNED32(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED32 *value)
{
	if (pCtx->FileReadCallBack(fp, value, sizeof(UNSIGNED32)) == sizeof(UNSIGNED32))
	{
		if (IS_BIG_ENDIAN)
		{
			*value = UNSIGNED32_to_big_endian((char*)value);
		}
		return 1;
	}
	return 0;
}

int file_read_UNSIGNED64(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, UNSIGNED64 *value)
{
	if (pCtx->FileReadCallBack(fp, value, sizeof(UNSIGNED64)) == sizeof(UNSIGNED64))
	{
		if (IS_BIG_ENDIAN)
		{
			*value = UNSIGNED64_to_big_endian((char*)value);
		}
		return 1;
	}
	return 0;
}
