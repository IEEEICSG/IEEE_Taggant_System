/*
 * fileio.h
 *
 *  Created on: Nov 7, 2011
 *      Author: Vladimir Sukhov
 */

#ifndef FILEIO_H_
#define FILEIO_H_

#include <iostream>
#include <fstream>
#include <istream>
#include "taggant_types.h"

using namespace std;

__DECLARATION size_t fileio_fread(ifstream* fin, void* buffer, size_t size);
__DECLARATION int fileio_fseek(ifstream* fin, UNSIGNED64 offset, int type);
__DECLARATION UNSIGNED64 fileio_ftell(ifstream* fin);
UNSIGNED64 fileio_fsize (ifstream* fin);

#endif /* FILEIO_H_ */
