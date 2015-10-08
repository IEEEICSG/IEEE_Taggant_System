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

#include <iostream>
#include <fstream>
#include <istream>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_MSC_VER) && (_MSC_VER > 1300)

#include <direct.h>
#include <windows.h>
#include <strsafe.h>

#else

#include <unistd.h>
#include <dirent.h>

#endif

#include <time.h>
#include "fileio.h"
#include "winpe.h"
#include "taggantlib.h"
#include "taggant_types.h"
#include "miscellaneous.h"

using namespace std;

void print_tag_info(__in PTAGGANTOBJ tag_obj, ENUMTAGINFO eKey);
void check_file(PTAGGANTCONTEXT pCtx, char* cacert, char* tscert, string fileName);
int dir_exists(const char* dirName);
void seek_dir(PTAGGANTCONTEXT pCtx, char* cacert, char* tscert, string path);

#define MAX_PATH_LENGTH 4096

int main(int argc, char *argv[])
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
		if (dir_exists(argv[3]))
		{
    		cwd = argv[3];
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
		UNSIGNED64 uVersion = TAGGANT_LIBRARY_VERSION2;
		// Set structure size
		funcs.size = sizeof(TAGGANTFUNCTIONS);
		TaggantInitializeLibrary(&funcs, &uVersion);

    	cout << "Taggant Library version " << uVersion << "\n";
    	// Make sure the taggant library supports version 2
    	if (uVersion < TAGGANT_LIBRARY_VERSION2)
    	{
    		cout << "Current taggant library does not support version 2\n\n";
    		err = 1;
    	}
    	if (!err)
		{
			// Create taggant context
			PTAGGANTCONTEXT pCtx;
			UNSIGNED32 ctxres = TaggantContextNewEx(&pCtx);
			if (ctxres == TNOERR)
			{
				// Vendor should check version flow here!
				pCtx->FileReadCallBack = (size_t (__DECLARATION *)(void*, void*, size_t))fileio_fread;
				pCtx->FileSeekCallBack = (int (__DECLARATION *)(void*, UNSIGNED64, int))fileio_fseek;
				pCtx->FileTellCallBack = (UNSIGNED64 (__DECLARATION *)(void*))fileio_ftell;
			
				// Load CA certificate to the memory
				ifstream fca(argv[1], ios::binary);
				fca.seekg(0, ios::end);
				long fsize = fca.tellg();
				char* cacert = new char[fsize + 1];
                cacert[fsize] = '\0';
				fca.seekg(0, ios::beg);
				fca.read(cacert, fsize);
				fca.clear();
			
				// Load TS certificate to the memory
				ifstream fts(argv[2], ios::binary);
				fts.seekg(0, ios::end);
				long ftssize = fts.tellg();
				char* tscert = new char[ftssize + 1];
                tscert[ftssize] = '\0';
				fts.seekg(0, ios::beg);
				fts.read(tscert, ftssize);
				fts.clear();
			
				if (TaggantCheckCertificate(cacert) == TNOERR)
				{
					if (TaggantCheckCertificate(tscert) == TNOERR)
					{
						// scan the directory and search files with the taggant
						seek_dir(pCtx, cacert, tscert, string(cwd));
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
				delete[] tscert;
			
				TaggantContextFree(pCtx);
			} else
			{
				cout << "TaggantContextNewEx failed with result: " << ctxres << "\n\n";
				err = 1;
			}
			TaggantFinalizeLibrary();
		}
	}
	if (tmp != NULL)
	{
		delete[] tmp;
	}
	return err;
}

void print_tag_info(PTAGGANTOBJ tag_obj, ENUMTAGINFO eKey)
{	
	unsigned int tag_info_size = 0;
	// Get the length of the eKey taggant information
	if (TaggantGetInfo(tag_obj, eKey, &tag_info_size, NULL) == TINSUFFICIENTBUFFER)
	{
		// Allocate enough buffer
		char* taginfo = new char[tag_info_size];
		// Get the eKey taggant information
		if ( TaggantGetInfo(tag_obj, eKey, &tag_info_size, taginfo) == TNOERR)
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
							printf("%02x ", (unsigned char)taginfo[i * 16 + j]);
						}
						cout << "\n";
					}
				}
			}
			else
			{
				cout << "     no data" << endl;
			}
		}
		// Free buffer
		delete[] taginfo;
	}
	//
	return;
}

#if defined(_MSC_VER) && (_MSC_VER > 1300)

int dir_exists(const char* dirName)
{
	DWORD attr = GetFileAttributes(dirName);
	if (attr == INVALID_FILE_ATTRIBUTES)
	{
		return 0;  
	}
	if (attr & FILE_ATTRIBUTE_DIRECTORY)
	{
		// this is a directory!
		return 1;  
	}
	return 0;   
}

void seek_dir(PTAGGANTCONTEXT pCtx, char* cacert, char* tscert, string path)
{
	WIN32_FIND_DATA ffd;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	size_t length_of_arg;
	TCHAR szDir[MAX_PATH];
	StringCchLength(path.c_str(), MAX_PATH, &length_of_arg);

	// Prepare string for use with FindFile functions.  First, copy the
	// string to a buffer, then append '\*' to the directory name.

	StringCchCopy(szDir, MAX_PATH, path.c_str());
	StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

	hFind = FindFirstFile(szDir, &ffd);

	if (hFind != INVALID_HANDLE_VALUE) 
	{
		do
		{			
			string fileName = path + "/" + ffd.cFileName;
			
			if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				check_file(pCtx, cacert, tscert, fileName);
			}
			else
			{
				if(strcmp(ffd.cFileName,".") != 0 && strcmp(ffd.cFileName,"..") != 0) 
				{
					// Scan new directory recursively
					seek_dir(pCtx, cacert, tscert, fileName); 
				}
			}
		}
		while (FindNextFile(hFind, &ffd) != 0);	
        FindClose(hFind);
	} 
}

#else

int dir_exists(const char* dirName)
{
	DIR* dir = opendir(dirName);
	if (dir != 0)
	{
		closedir(dir);
		return 1;
	} 
	return 0;
}

void seek_dir(PTAGGANTCONTEXT pCtx, char* cacert, char* tscert, string path)
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
			    string fileName = path + "/" + d->d_name;

				check_file(pCtx, cacert, tscert, fileName);

				// Scan new directory recursively
			    seekdir(pCtx, cacert, tscert, p);
			}
		}
	}
}

#endif

void process_taggant(PTAGGANTCONTEXT pCtx, ifstream *pfin, PPE_ALL_HEADERS ppeh, PTAGGANT pTaggant, char* cacert, char* tscert)
{
    cout << " - taggant is found\n";
    // Initialize taggant object before it will be validated
    PTAGGANTOBJ	tag_obj;
    UNSIGNED32 objres = TaggantObjectNewEx(pTaggant, 0, TAGGANT_PEFILE, &tag_obj);
    if (objres == TNOERR)
    {
        cout << " - taggant object created\n";
        // Validate the taggant
        UNSIGNED32 res = TNOERR;
        if ((res = TaggantValidateSignature(tag_obj, pTaggant, (PVOID)cacert)) == TNOERR)
        {

            cout << " - taggant is correct\n";

            // Check if the TS exists
            unsigned long long timest = 0;
            if ((res = TaggantGetTimestamp(tag_obj, &timest, (PVOID)tscert)) == TNOERR)
            {
                cout << " - taggant timestamp " << asctime(gmtime((time_t*)&timest));
            }
            else
            {
                cout << " - taggant does not contain timestamp, or it is invalid, error code " << res << "\n";
            }

            // print packer information
            PACKERINFO pinfo;
            UNSIGNED32 psize = sizeof(PACKERINFO);
            if ((res = TaggantGetInfo(tag_obj, EPACKERINFO, &psize, (char*)&pinfo)) == TNOERR)
            {
                cout << " - file protected by packer with " << pinfo.PackerId << " id, version " << pinfo.VersionMajor << "." << pinfo.VersionMinor << "." << pinfo.VersionBuild << "\n";
            }
            else
            {
                cout << " - cannot get packer info, error code " << res << "\n";
            }

            // print contributors info					
            UNSIGNED32 csize;
            if ((res = TaggantGetInfo(tag_obj, ECONTRIBUTORLIST, &csize, NULL)) == TINSUFFICIENTBUFFER)
            {
                cout << " - found contributors information of " << csize << " bytes length\n";
                char *cinfo = new char[csize];
                if (TaggantGetInfo(tag_obj, ECONTRIBUTORLIST, &csize, cinfo) == TNOERR)
                {
                    cout << " - contributors information: " << cinfo << "\n";
                }
                delete[] cinfo;
            }
            else
            {
                cout << " - cannot get contributor info or it is empty, error code " << res << "\n";
            }

            // get the ignore hash map value
            UNSIGNED8 ignorehmh = 0;
            UNSIGNED32 ihmhsize = sizeof(UNSIGNED8);
            if ((res = TaggantGetInfo(tag_obj, EIGNOREHMH, &ihmhsize, (char*)&ignorehmh)) == TNOERR)
            {
                if (ignorehmh)
                {
                    cout << " - ignore hash map value is set for the taggant\n";
                }
            }
            else
            {
                cout << " - cannot get ignore hash map value, error code " << res << "\n";
            }

            // get the previous tag value
            UNSIGNED8 tagprev = 0;
            UNSIGNED32 tprevsize = sizeof(UNSIGNED8);
            if ((res = TaggantGetInfo(tag_obj, ETAGPREV, &tprevsize, (char*)&tagprev)) == TNOERR)
            {
                if (tagprev)
                {
                    cout << " - previous tag value is set for the taggant\n";
                }
            }
            else
            {
                cout << " - cannot get previous tag value, error code " << res << "\n";
            }

            res = TNOERR;
            if (!ignorehmh)
            {
                // Get file hash type
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
                    res = TaggantValidateHashMap(pCtx, tag_obj, (void*)pfin);
                    // Check if file hash is valid
                    if (res == TNOERR)
                    {
                        cout << " - hashmap is valid\n";
                    }
                    else
                    {
                        cout << " - hashmap is INVALID\n";
                    }
                }
            }

            // If hashmap does not exist, or if it exists and valid we do a full file hash check
            if (res == TNOERR)
            {
                // Check full file hash only if there is no previous tag
                if (!tagprev)
                {
                    UNSIGNED64 file_end = 0;
                    UNSIGNED32 size = sizeof(UNSIGNED64);
                    // Get file end value from the taggant, used for taggant v1 only
                    TaggantGetInfo(tag_obj, EFILEEND, &size, (char*)&file_end);
                    if (!file_end)
                    {
                        file_end = fileio_fsize(pfin);
                    }
                    int object_end = winpe_object_size(pfin, ppeh);

                    // Compute default hashes of the current file
                    res = TaggantValidateDefaultHashes(pCtx, tag_obj, (void*)pfin, object_end, file_end);
                    // Check if file hash is valid
                    if (res == TNOERR)
                    {
                        cout << " - full file hash is valid\n";
                    }
                    else
                    {
                        cout << " - full file hash is INVALID\n";
                    }
                }
                else
                {
                    cout << " - skip check of full file hash as there is another taggant in the file\n";
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

        }
        else
        {
            cout << " - taggant is invalid, error code: " << res << "\n";
        }
        TaggantObjectFree(tag_obj);
    }
    else
    {
        cout << " - could not create taggant object, error code: " << objres << "\n";
    }
}

void check_file(PTAGGANTCONTEXT pCtx, char* cacert, char* tscert, string fileName)
{
	// Try to open the file
	ifstream fin(fileName.c_str(), ios::binary);
	if (fin.is_open())
	{
		cout << "" + fileName + "\n";

		PE_ALL_HEADERS peh;

        void *taggant = NULL;
        UNSIGNED32 res = TNOTAGGANTS;
        TAGGANTCONTAINER filetype = TAGGANT_PEFILE;
		// Make sure the file is correct PE file
        if (winpe_is_correct_pe_file(&fin, &peh))
        {
            cout << " - check against PE file\n";
            filetype = TAGGANT_PEFILE;
            res = TaggantGetTaggant(pCtx, (void*)&fin, filetype, &taggant);
        }
        else
        {
            cout << " - check against JS file\n";
            filetype = TAGGANT_JSFILE;
            res = TaggantGetTaggant(pCtx, (void*)&fin, filetype, &taggant);
            if (res != TNOERR)
            {
                TaggantFreeTaggant(taggant);
                taggant = NULL;
                cout << " - check against TXT file\n";
                filetype = TAGGANT_TXTFILE;
                res = TaggantGetTaggant(pCtx, (void*)&fin, filetype, &taggant);
                if (res != TNOERR)
                {
                    TaggantFreeTaggant(taggant);
                    taggant = NULL;
                    cout << " - check against BIN file\n";
                    filetype = TAGGANT_BINFILE;
                    res = TaggantGetTaggant(pCtx, (void*)&fin, filetype, &taggant);
                }
            }
        }
        if (res == TNOERR)
        {
            process_taggant(pCtx, &fin, &peh, taggant, cacert, tscert);
            // Enumerate taggants
            while ((res = TaggantGetTaggant(pCtx, (void*)&fin, filetype, &taggant)) == TNOERR)
            {
                process_taggant(pCtx, &fin, &peh, taggant, cacert, tscert);
            }
        }
        else
            if (res == TNOTAGGANTS)
            {
                cout << " - taggant is not found\n";
            }
            else
            {
                cout << " - TaggantGetTaggant failed, error code: " << res << "\n";
            }
		TaggantFreeTaggant(taggant);
		fin.close();
	}
}

