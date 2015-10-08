/*
 * winpe.h
 *
 *  Created on: Oct 16, 2011
 *      Author: Enigma
 */

#ifndef WINPE_H_
#define WINPE_H_

#include <iostream>
#include <fstream>
#include <istream>
#include <string>
#include <string.h>

#include "winpe_types.h"

using namespace std;

#define TAGGANT_ADDRESS_JMP 0x08EB
#define TAGGANT_ADDRESS_JMP_SIZE 2

typedef struct _PE_ALL_HEADERS {
	IMAGE_DOS_HEADER dh;
	DWORD signature;
	IMAGE_FILE_HEADER fh;
	union {
		IMAGE_OPTIONAL_HEADER32 pe32;
		IMAGE_OPTIONAL_HEADER64 pe64;
	} oh;
} PE_ALL_HEADERS,*PPE_ALL_HEADERS;

// checks file header if the file is correct PE file
// returns TRUE is PE file is valid
int winpe_is_correct_pe_file(ifstream* fp, PE_ALL_HEADERS* peh);

// returns a physical file offset of file entry point
// PE file has to be valid
// function returns -1 if entry point is not found
long winpe_entry_point_physical_offset(ifstream* fp, PE_ALL_HEADERS* peh);

int winpe_is_pe64(PE_ALL_HEADERS* peh);

int winpe_va_to_rwa(ifstream* fp, PE_ALL_HEADERS* peh, unsigned long va);

int winpe_object_size(ifstream* fp, PE_ALL_HEADERS* peh);

#endif /* WINPE_H_ */
