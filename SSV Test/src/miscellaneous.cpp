/*
 * miscellaneous.c
 *
 *  Created on: Dec 19, 2011
 *      Author: Enigma
 */

#include <stdio.h>
#include <stdlib.h>
#include "taggant_types.h"

long round_up(long alignment, long size)
{
	return (size % alignment != 0 && size != 0) ? size + alignment - size % alignment : size;
}

long round_down(long alignment, long size)
{
	return (size % alignment != 0 && size != 0) ? size - size % alignment : size;
}

long get_min(long v1, long v2)
{
	return (v1 < v2) ? v1 : v2;
}

long get_file_size (PTAGGANTCONTEXT pCtx, PFILEOBJECT fp)
{
	long size;
	long pos = pCtx->FileTellCallBack(fp);
	pCtx->FileSeekCallBack(fp, 0, SEEK_END);
	size = pCtx->FileTellCallBack(fp);
	pCtx->FileSeekCallBack(fp, pos, SEEK_SET);
	return size;
}

