//============================================================================
// Name        : ssv.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <fstream>
#include <istream>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include "fileio.h"
#include "winpe.h"
#include "taggantlib.h"
#include "taggant_types.h"
#include "miscellaneous.h"

using namespace std;

void print_tag_info(PTAGGANTOBJ tag_obj, ENUMTAGINFO eKey)
{
	long unsigned int tag_info_size = 0;
	// Get the length of the eKey taggant information
	if (TaggantGetInfo(tag_obj, eKey, &tag_info_size, NULL) == TMEMORY)
	{
		// Allocate enough buffer
		char* taginfo = new char[tag_info_size];
		// Get the eKey taggant information
		if (TaggantGetInfo(tag_obj, eKey, &tag_info_size, taginfo) == TNOERR)
		{
			// Print taggant information
			if (tag_info_size > 0)
			{
				for (int i = 0; i <= (int)tag_info_size / 16; i++)
				{
					int k = tag_info_size - i * 16;
					if (k > 0)
					{
						k = (k < 16) ? k : 16;
						cout << "     ";
						for (int j = 0; j < k; j++)
						{
							printf("%02x ", (BYTE)taginfo[i * 16 + j]);
						}
						cout << "\n";
					}
				}
			}
		}
		// Free buffer
		delete[] taginfo;
	}
	//
	return;
}

void seekdir(PTAGGANTCONTEXT pCtx, char* cacert, char* tscert, string path)
{
	// Try to open the directory
	DIR* dir = opendir(path.c_str());
	if (dir != 0)
	{
		struct dirent *d;
		while( (d = readdir(dir)) != 0)
		{
			if(strcmp(d->d_name,".") != 0 && strcmp(d->d_name,"..") != 0)
			{
			    string p = path + "/" + d->d_name;
			    // Try to open the file
			    ifstream fin(p.c_str(), ios::binary);
			    if (fin.is_open())
			    {
			    	cout << "" + p + "\n";
			    	PE_ALL_HEADERS peh;
			    	// Make sure the file is correct PE file
			    	if (winpe_is_correct_pe_file(&fin, &peh))
			    	{
			    		cout << " - correct PE file\n";
			    		PTAGGANT taggant;
						// Get the taggant from the file
						if (TaggantGetTaggant(pCtx, (void*)&fin, TAGGANT_PEFILE, &taggant) == TNOERR)
						{
							cout << " - taggant is found\n";
							// Initialize taggant object before it will be validated
							PTAGGANTOBJ tag_obj = TaggantObjectNew(taggant);
							if (tag_obj)
							{
								cout << " - taggant object created\n";
								// Validate the taggant
								if (TaggantValidateSignature(tag_obj, (PTAGGANT)taggant, (PVOID)cacert) == TNOERR)
								{

									cout << " - taggant is correct\n";
									// Check if the TS exists
									unsigned long long timest = 0;
									if (TaggantGetTimestamp(tag_obj, &timest, (PVOID)tscert) == TNOERR)
									{
										cout << " - taggant timestamp " << asctime(gmtime((time_t*)&timest));
									} else
									{
										cout << " - taggant does not contain timestamp\n";
									}

									// print packer information
									PPACKERINFO packer_info = TaggantPackerInfo(tag_obj);
									cout << " - file protected by packer with " << packer_info->PackerId << " id, version " << packer_info->VersionMajor << "."<< packer_info->VersionMinor << "." << packer_info->VersionBuild << "\n";

									// Get file hash type
									int res = TNOERR;
									// Do a quick file check using hash map (in case it exists)
									PHASHBLOB_HASHMAP_DOUBLE dbl = NULL;
									int dbl_count = TaggantGetHashMapDoubles(tag_obj, &dbl);
									if (dbl_count)
									{
										cout << " - hashmap covers following regions:\n";
										for (int i = 0; i < dbl_count; i++)
										{
											cout << i << ". from " << dbl[i].AbsoluteOffset << " to " << (dbl[i].AbsoluteOffset + dbl[i].Length) << "\n";
										}
										// Compute hashmap of the current file
										res = TaggantValidateHashMap(pCtx, tag_obj, (void*)&fin);
										// Check if file hash is valid
										if (res == TNOERR)
										{
											cout << " - hashmap is valid\n";
										} else
										{
											cout << " - hashmap is INVALID\n";
										}
									}

									// If hashmap does not exist, or if it exists and valid we do a full file hash check
									if (res == TNOERR)
									{
										UNSIGNED64 file_end = 0;
										UNSIGNED32 size = sizeof(UNSIGNED64);
										// Get file end value from the taggant
										TaggantGetInfo(tag_obj, EFILEEND, &size, (char*)&file_end);
										if (!file_end)
										{
											file_end = fileio_fsize(&fin);
										}
										//
										int object_end = winpe_object_size(&fin, &peh);
										// Compute default hashes of the current file
										res = TaggantValidateDefaultHashes(pCtx, tag_obj, (void*)&fin, object_end, file_end);
										// Check if file hash is valid
										if (res == TNOERR)
										{
											cout << " - full file hash is valid\n";
											cout << " - full file hash covers first " << file_end << " bytes\n";
										} else
										{
											cout << " - full file hash is INVALID\n";
										}
									}

									// Check if file hash is valid
									if (res == TNOERR)
									{
										// Extract all information from the taggant
										// SPV certificate
										cout << " - SPV Certificate\n";
										print_tag_info(tag_obj, ESPVCERT);
										// End User certificate
										cout << " - User Certificate\n";
										print_tag_info(tag_obj, EUSERCERT);
									}


								} else {
									cout << " - taggant is invalid\n";
								}
								TaggantObjectFree(tag_obj);
							}
							TaggantFreeTaggant(taggant);
						} else {
							cout << " - taggant is not found\n";
						}
					}
			    	fin.close();
			    }
			    // Scan new directory recursively
			    seekdir(pCtx, cacert, tscert, p);
			}
		}
		closedir(dir);
	}
	return;
}

#define MAX_PATH_LENGTH 0x8000

int main(int argc, char *argv[], char *envp[])
{
	cout << "Taggant Test Application\n\n";
	const char* usage = "Usage: test.exe ca_root_certificate_file ca_ts_certificate_file [optional] directory_to_scan\n\n";
	// Check if number of arguments is not less than 2
	if (argc < 3)
	{
		cout << "Invalid Arguments, no CA and/or TS root certificates!\n\n" << usage;
		return 1;
	}

	// Check if second arguments points to the CA root certificate file
	ifstream fca(argv[1], ios::binary);
    if (!fca.is_open())
    {
		cout << "CA certificate file does not exist\n\n" << usage;
		return 1;
    }
    fca.close();

	// Check if third arguments points to the TS root certificate file
	ifstream fts(argv[2], ios::binary);
    if (!fts.is_open())
    {
		cout << "TS certificate file does not exist\n\n" << usage;
		return 1;
    }
    fts.close();

    // Check if the 4th argument exists and if it is a directory
    // Otherwise, scan current directory
    char* cwd = NULL;
    if (argc >= 4)
    {
    	DIR* dir = opendir(argv[3]);
    	if (dir != 0)
    	{
    		cwd = argv[3];
    		closedir(dir);
    	}
    }
    char* tmp = NULL;
    if (cwd == NULL)
    {
    	tmp = new char [MAX_PATH_LENGTH];
    	memset(tmp, 0, MAX_PATH_LENGTH);
    	if (getcwd(tmp, MAX_PATH_LENGTH))
    	{
    		cwd = tmp;
    	}
    }
    int err = 0;
	if (cwd != NULL)
	{
		// Initialize taggant library
		TAGGANTFUNCTIONS funcs;
		memset(&funcs, 0, sizeof(TAGGANTFUNCTIONS));
		UNSIGNED64 uVersion;
		// Set structure size
		funcs.size = sizeof(TAGGANTFUNCTIONS);
		TaggantInitializeLibrary(&funcs, &uVersion);
		cout << "Taggant Library version " << uVersion << "\n\n";

		// Create taggant context
		PTAGGANTCONTEXT pCtx = TaggantContextNew();
		// Vendor should check version flow here!
		pCtx->FileReadCallBack = (size_t (__DECLARATION *)(void*, void*, size_t))fileio_fread;
		pCtx->FileSeekCallBack = (int (__DECLARATION *)(void*, UNSIGNED64, int))fileio_fseek;
		pCtx->FileTellCallBack = (UNSIGNED64 (__DECLARATION *)(void*))fileio_ftell;

		// Load CA certificate to the memory
		ifstream fca(argv[1], ios::binary);
		fca.seekg(0, ios::end);
		long fsize = fca.tellg();
		char* cacert = new char[fsize];
		fca.seekg(0, ios::beg);
		fca.read(cacert, fsize);
		fca.clear();

		// Load TS certificate to the memory
		ifstream fts(argv[2], ios::binary);
		fts.seekg(0, ios::end);
		long ftssize = fts.tellg();
		char* tscert = new char[ftssize];
		fts.seekg(0, ios::beg);
		fts.read(tscert, ftssize);
		fts.clear();

		if (TaggantCheckCertificate(cacert) == TNOERR)
		{
			if (TaggantCheckCertificate(tscert) == TNOERR)
			{
				// scan the directory and search files with the taggant
				seekdir(pCtx, cacert, tscert, string(cwd));
			} else
			{
				cout << "TS certificate is invalid\n\n" << usage;
				err = 1;
			}
		} else
		{
			cout << "CA certificate is invalid\n\n" << usage;
			err = 1;
		}

		delete[] cacert;

		TaggantContextFree(pCtx);
		TaggantFinalizeLibrary();
	}
	if (tmp != NULL)
	{
		delete[] tmp;
	}
	return err;
}
