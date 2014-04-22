/*
 * miscellaneous.h
 *
 *  Created on: Dec 19, 2011
 *      Author: Enigma
 */

#ifndef MISCELLANEOUS_H_
#define MISCELLANEOUS_H_

#include "taggant_types.h"

long round_up(long alignment, long size);
long round_down(long alignment, long size);
long get_min(long v1, long v2);
long get_file_size (PTAGGANTCONTEXT pCtx, PFILEOBJECT fp);

#endif /* MISCELLANEOUS_H_ */
