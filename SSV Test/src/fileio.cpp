/*
 * fileio.cpp
 *
 *  Created on: Nov 7, 2011
 *      Author: Vladimir Sukhov
 */

#include <iostream>
#include <fstream>
#include <istream>
#include "taggant_types.h"

using namespace std;

__DECLARATION size_t fileio_fread(ifstream* fin, void* buffer, size_t size)
{
	fin->read((char*)buffer, size);
	return fin->gcount();
}

__DECLARATION int fileio_fseek(ifstream* fin, UNSIGNED64 offset, int type)
{
	switch (type)
	{
	case SEEK_SET:
		fin->seekg(offset, ios::beg);
		break;
	case SEEK_CUR:
		fin->seekg(offset, ios::cur);
		break;
	case SEEK_END:
		fin->seekg(offset, ios::end);
		break;
	default:
		return 0;
	}
	return ((fin->rdstate() & fin->failbit) || (fin->rdstate() & fin->badbit) || (fin->rdstate() & fin->eofbit)) ? 1 : 0;
}

__DECLARATION UNSIGNED64 fileio_ftell(ifstream* fin)
{
	return fin->tellg();
}

UNSIGNED64 fileio_fsize (ifstream* fin)
{
	UNSIGNED64 pos = fileio_ftell(fin);
	fileio_fseek(fin, 0L, SEEK_END);
	UNSIGNED64 size = fileio_ftell(fin);
	fileio_fseek(fin, pos, SEEK_SET);
	return size;
}


