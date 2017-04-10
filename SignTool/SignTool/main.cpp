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

#include <windows.h>
#include <string.h>
#include <time.h>
#include "fileio.h"
#include "taggant_types.h"
#include "taggantlib.h"
#include "winpe.h"

using namespace std;

#define SIGNTOOL_VERSION 0x010000

#define SSV_LIB_NAME "libssv.dll"
#define SPV_LIB_NAME "libspv.dll"

#ifdef _MSC_VER 
#define strcasecmp _stricmp
#endif

static UNSIGNED32(STDCALL *pSSVTaggantInitializeLibrary) (__in_opt TAGGANTFUNCTIONS *pFuncs, __out UNSIGNED64 *puVersion);
static void(STDCALL *pSSVTaggantFinalizeLibrary) ();
static PTAGGANTOBJ(STDCALL *pSSVTaggantObjectNew) (__in_opt PTAGGANT pTaggant);
static UNSIGNED32(STDCALL *pSSVTaggantObjectNewEx) (__in_opt PTAGGANT pTaggant, UNSIGNED64 uVersion, TAGGANTCONTAINER eTaggantType, __out PTAGGANTOBJ *pTaggantObj);
static void(STDCALL *pSSVTaggantObjectFree) (__deref PTAGGANTOBJ pTaggantObj);
static PTAGGANTCONTEXT(STDCALL *pSSVTaggantContextNew) ();
static UNSIGNED32(STDCALL *pSSVTaggantContextNewEx) (__out PTAGGANTCONTEXT *pCtx);
static void(STDCALL *pSSVTaggantContextFree) (__deref PTAGGANTCONTEXT pTaggantCtx);
/* Deprecated function, use TaggantGetInfo/TaggantPutInfo with EPACKERINFO parameter instead */
static DEPRECATED PPACKERINFO(STDCALL *pSSVTaggantPackerInfo) (__in PTAGGANTOBJ pTaggantObj);
static UNSIGNED16(STDCALL *pSSVTaggantGetHashMapDoubles) (__in PTAGGANTOBJ pTaggantObj, __out PHASHBLOB_HASHMAP_DOUBLE *pDoubles);
static UNSIGNED32(STDCALL *pSSVTaggantValidateDefaultHashes) (__in PTAGGANTCONTEXT pCtx, __in PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd);
static UNSIGNED32(STDCALL *pSSVTaggantValidateHashMap) (__in PTAGGANTCONTEXT pCtx, __in PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile);
static UNSIGNED32(STDCALL *pSSVTaggantGetTaggant) (__in PTAGGANTCONTEXT pCtx, __in PFILEOBJECT hFile, TAGGANTCONTAINER eContainer, __inout PTAGGANT *pTaggant);
static void(STDCALL *pSSVTaggantFreeTaggant) (__deref PTAGGANT pTaggant);
static UNSIGNED32(STDCALL *pSSVTaggantValidateSignature) (__in PTAGGANTOBJ pTaggantObj, __in PTAGGANT pTaggant, __in PVOID pRootCert);
static UNSIGNED32(STDCALL *pSSVTaggantGetInfo) (__in PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, __inout UNSIGNED32 *pSize, __out_bcount_full_opt(*pSize) PINFO pInfo);
static UNSIGNED32(STDCALL *pSSVTaggantGetTimestamp) (__in PTAGGANTOBJ pTaggantObj, __out UNSIGNED64 *pTime, __in PVOID pTSRootCert);
static UNSIGNED32(STDCALL *pSSVTaggantCheckCertificate) (__in PVOID pCert);

static UNSIGNED32(STDCALL *pSPVTaggantInitializeLibrary) (__in_opt TAGGANTFUNCTIONS *pFuncs, __out UNSIGNED64 *puVersion);
static void(STDCALL *pSPVTaggantFinalizeLibrary) ();
static PTAGGANTOBJ(STDCALL *pSPVTaggantObjectNew) (__in_opt PTAGGANT pTaggant);
static UNSIGNED32(STDCALL *pSPVTaggantObjectNewEx) (__in_opt PTAGGANT pTaggant, UNSIGNED64 uVersion, TAGGANTCONTAINER eTaggantType, __out PTAGGANTOBJ *pTaggantObj);
static void(STDCALL *pSPVTaggantObjectFree) (__deref PTAGGANTOBJ pTaggantObj);
static PTAGGANTCONTEXT(STDCALL *pSPVTaggantContextNew) ();
static UNSIGNED32(STDCALL *pSPVTaggantContextNewEx) (__out PTAGGANTCONTEXT *pCtx);
static void(STDCALL *pSPVTaggantContextFree) (__deref PTAGGANTCONTEXT pTaggantCtx);
/* Deprecated function, use TaggantGetInfo/TaggantPutInfo with EPACKERINFO parameter instead */
static DEPRECATED PPACKERINFO(STDCALL *pSPVTaggantPackerInfo) (__in PTAGGANTOBJ pTaggantObj);
static UNSIGNED32(STDCALL *pSPVTaggantPutInfo) (__inout PTAGGANTOBJ pTaggantObj, ENUMTAGINFO eKey, UNSIGNED32 pSize, __in_bcount(Size) PINFO pInfo);
static UNSIGNED32(STDCALL *pSPVTaggantComputeHashes) (__in PTAGGANTCONTEXT pCtx, __inout PTAGGANTOBJ pTaggantObj, __in PFILEOBJECT hFile, UNSIGNED64 uObjectEnd, UNSIGNED64 uFileEnd, UNSIGNED32 uTaggantSize);
static UNSIGNED32(STDCALL *pSPVTaggantGetLicenseExpirationDate) (__in const PVOID pLicense, __out UNSIGNED64 *pTime);
static UNSIGNED32(STDCALL *pSPVTaggantAddHashRegion) (__inout PTAGGANTOBJ pTaggantObj, UNSIGNED64 uOffset, UNSIGNED64 uLength);
static UNSIGNED32(STDCALL *pSPVTaggantPrepare) (__inout PTAGGANTOBJ pTaggantObj, __in const PVOID pLicense, __out_bcount_part(*uTaggantReservedSize, *uTaggantReservedSize) PVOID pTaggantOut, __inout UNSIGNED32 *uTaggantReservedSize);
static UNSIGNED32(STDCALL *pSPVTaggantPutTimestamp) (__inout PTAGGANTOBJ pTaggantObj, __in const char* pTSUrl, UNSIGNED32 uTimeout);

int init_functions()
{
    HMODULE libssv = LoadLibrary(SSV_LIB_NAME);
    if (libssv == NULL)
    {
        cout << "Error: Cannot load SSV library!\n\n";
        return 0;
    }

    if (
        (pSSVTaggantInitializeLibrary = (UNSIGNED32(STDCALL *) (TAGGANTFUNCTIONS*, UNSIGNED64*)) GetProcAddress(libssv, "TaggantInitializeLibrary")) == NULL ||
        (pSSVTaggantFinalizeLibrary = (void(STDCALL *) ()) GetProcAddress(libssv, "TaggantFinalizeLibrary")) == NULL ||
        (pSSVTaggantObjectNew = (PTAGGANTOBJ(STDCALL *) (PTAGGANT)) GetProcAddress(libssv, "TaggantObjectNew")) == NULL ||
        (pSSVTaggantObjectNewEx = (UNSIGNED32(STDCALL *) (PTAGGANT, UNSIGNED64, TAGGANTCONTAINER, PTAGGANTOBJ*)) GetProcAddress(libssv, "TaggantObjectNewEx")) == NULL ||
        (pSSVTaggantObjectFree = (void(STDCALL *) (PTAGGANTOBJ)) GetProcAddress(libssv, "TaggantObjectFree")) == NULL ||
        (pSSVTaggantContextNew = (PTAGGANTCONTEXT(STDCALL *) ()) GetProcAddress(libssv, "TaggantContextNew")) == NULL ||
        (pSSVTaggantContextNewEx = (UNSIGNED32(STDCALL *) (PTAGGANTCONTEXT*)) GetProcAddress(libssv, "TaggantContextNewEx")) == NULL ||
        (pSSVTaggantContextFree = (void(STDCALL *) (PTAGGANTCONTEXT)) GetProcAddress(libssv, "TaggantContextFree")) == NULL ||
        (pSSVTaggantPackerInfo = (PPACKERINFO(STDCALL *) (PTAGGANTOBJ)) GetProcAddress(libssv, "TaggantPackerInfo")) == NULL ||

        (pSSVTaggantGetHashMapDoubles = (UNSIGNED16(STDCALL *) (PTAGGANTOBJ, PHASHBLOB_HASHMAP_DOUBLE *)) GetProcAddress(libssv, "TaggantGetHashMapDoubles")) == NULL ||
        (pSSVTaggantValidateDefaultHashes = (UNSIGNED32(STDCALL *) (PTAGGANTCONTEXT, PTAGGANTOBJ, PFILEOBJECT, UNSIGNED64, UNSIGNED64)) GetProcAddress(libssv, "TaggantValidateDefaultHashes")) == NULL ||
        (pSSVTaggantValidateHashMap = (UNSIGNED32(STDCALL *) (PTAGGANTCONTEXT, PTAGGANTOBJ, PFILEOBJECT)) GetProcAddress(libssv, "TaggantValidateHashMap")) == NULL ||
        (pSSVTaggantGetTaggant = (UNSIGNED32(STDCALL *) (PTAGGANTCONTEXT, PFILEOBJECT, TAGGANTCONTAINER, PTAGGANT*)) GetProcAddress(libssv, "TaggantGetTaggant")) == NULL ||
        (pSSVTaggantFreeTaggant = (void(STDCALL *) (PTAGGANT)) GetProcAddress(libssv, "TaggantFreeTaggant")) == NULL ||
        (pSSVTaggantValidateSignature = (UNSIGNED32(STDCALL *) (PTAGGANTOBJ, PTAGGANT, PVOID)) GetProcAddress(libssv, "TaggantValidateSignature")) == NULL ||
        (pSSVTaggantGetInfo = (UNSIGNED32(STDCALL *) (PTAGGANTOBJ, ENUMTAGINFO, UNSIGNED32*, PINFO)) GetProcAddress(libssv, "TaggantGetInfo")) == NULL ||
        (pSSVTaggantGetTimestamp = (UNSIGNED32(STDCALL *) (PTAGGANTOBJ, UNSIGNED64*, PVOID)) GetProcAddress(libssv, "TaggantGetTimestamp")) == NULL ||
        (pSSVTaggantCheckCertificate = (UNSIGNED32(STDCALL *) (PVOID)) GetProcAddress(libssv, "TaggantCheckCertificate")) == NULL
        ) 
    {
        cout << "Error: Cannot initialize functions of SSV library!\n\n";
        return 0;
    }

    HMODULE libspv = LoadLibrary(SPV_LIB_NAME);
    if (libspv == NULL)
    {
        cout << "Error: Cannot load SPV library!\n\n";
        return 0;
    }

    if (
        (pSPVTaggantInitializeLibrary = (UNSIGNED32(STDCALL *) (TAGGANTFUNCTIONS*, UNSIGNED64*)) GetProcAddress(libspv, "TaggantInitializeLibrary")) == NULL ||
        (pSPVTaggantFinalizeLibrary = (void(STDCALL *) ()) GetProcAddress(libspv, "TaggantFinalizeLibrary")) == NULL ||
        (pSPVTaggantObjectNew = (PTAGGANTOBJ(STDCALL *) (PTAGGANT)) GetProcAddress(libspv, "TaggantObjectNew")) == NULL ||
        (pSPVTaggantObjectNewEx = (UNSIGNED32(STDCALL *) (PTAGGANT, UNSIGNED64, TAGGANTCONTAINER, PTAGGANTOBJ*)) GetProcAddress(libspv, "TaggantObjectNewEx")) == NULL ||
        (pSPVTaggantObjectFree = (void(STDCALL *) (PTAGGANTOBJ)) GetProcAddress(libspv, "TaggantObjectFree")) == NULL ||
        (pSPVTaggantContextNew = (PTAGGANTCONTEXT(STDCALL *) ()) GetProcAddress(libspv, "TaggantContextNew")) == NULL ||
        (pSPVTaggantContextNewEx = (UNSIGNED32(STDCALL *) (PTAGGANTCONTEXT*)) GetProcAddress(libspv, "TaggantContextNewEx")) == NULL ||
        (pSPVTaggantContextFree = (void(STDCALL *) (PTAGGANTCONTEXT)) GetProcAddress(libspv, "TaggantContextFree")) == NULL ||
        (pSPVTaggantPackerInfo = (PPACKERINFO(STDCALL *) (PTAGGANTOBJ)) GetProcAddress(libspv, "TaggantPackerInfo")) == NULL ||

        (pSPVTaggantPutInfo = (UNSIGNED32(STDCALL *) (PTAGGANTOBJ, ENUMTAGINFO, UNSIGNED32, PINFO)) GetProcAddress(libspv, "TaggantPutInfo")) == NULL ||
        (pSPVTaggantComputeHashes = (UNSIGNED32(STDCALL *) (PTAGGANTCONTEXT, PTAGGANTOBJ, PFILEOBJECT, UNSIGNED64, UNSIGNED64, UNSIGNED32)) GetProcAddress(libspv, "TaggantComputeHashes")) == NULL ||
        (pSPVTaggantGetLicenseExpirationDate = (UNSIGNED32(STDCALL *) (const PVOID, UNSIGNED64*)) GetProcAddress(libspv, "TaggantGetLicenseExpirationDate")) == NULL ||
        (pSPVTaggantAddHashRegion = (UNSIGNED32(STDCALL *) (PTAGGANTOBJ, UNSIGNED64, UNSIGNED64)) GetProcAddress(libspv, "TaggantAddHashRegion")) == NULL ||
        (pSPVTaggantPrepare = (UNSIGNED32(STDCALL *) (PTAGGANTOBJ, const PVOID, PVOID, UNSIGNED32*)) GetProcAddress(libspv, "TaggantPrepare")) == NULL ||
        (pSPVTaggantPutTimestamp = (UNSIGNED32(STDCALL *) (PTAGGANTOBJ, const char*, UNSIGNED32)) GetProcAddress(libspv, "TaggantPutTimestamp")) == NULL
        )
    {
        cout << "Error: Cannot initialize functions of SPV library!\n\n";
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[], char *envp[])
{
    int silent = 0;
    int filearg = 1;

	if ((argc > 1) && !stricmp(argv[1], "-silent"))
    {
        silent = 1;
        filearg = 2;
    }

    if (!silent) cout << "SignTool Application (adds Taggant v2 to files)\n\n";
    const char* usage = "Usage: signtool.exe [-silent] <file_to_sign> <license.pem> [optional] -t:<type> -csa -r:<root.crt> -s:<timestamp server url>\n\n-t:<type> - type of the file to sign (pe/js/txt/bin)\n-csa - enables CSA Mode\n-r:<root.crt> - root certificate for CSA Mode\n-s:<timestamp server url> - url to the timestamp server (default: http://taggant-tsa.ieee.org/)\n\n";

	// Check if number of arguments is not less than 2
	if (argc < 2)
	{
		cout << "Error: Invalid Arguments, no file_to_sign and/or license.pem is specified!\n\n" << usage;
		return 1;
	}    

    if (!init_functions())
    {
        return 1;
    }

	// Get the type of the file to sign (pe/js)
	TAGGANTCONTAINER filetype = TAGGANT_PEFILE;
    int csamode = 0;
    char *rootfile = NULL;
    char *root = NULL;
    char *tsurl = NULL;
	if (argc >= 3)
	{
        for (int i = 3; i < argc; i++)
        {
            if (stricmp(argv[i], "-csa") == 0)
            {
                csamode = 1;
            } else if (strnicmp(argv[i], "-r:", 3) == 0)
            {
                int len = strlen(argv[i]) - 3 + 1;
                rootfile = new char[len];
                memset(rootfile, 0, len);
                strcpy(rootfile, argv[i] + 3);
            }
            else if (strnicmp(argv[i], "-t:", 3) == 0)
            {
                char type[4];
                memset(&type, 0, sizeof(type));
                strncpy((char*)&type, argv[i] + 3, strlen(argv[i]) > 6 ? 3 : strlen(argv[i]) - 3);
                // Determine the type
                if (stricmp((char*)&type, "js") == 0)
                {
                    filetype = TAGGANT_JSFILE;
                } else if (stricmp((char*)&type, "txt") == 0)
                {
                    filetype = TAGGANT_TXTFILE;
                } else if (stricmp((char*)&type, "bin") == 0)
                {
                    filetype = TAGGANT_BINFILE;
                }
            }
            else if (strnicmp(argv[i], "-s:", 3) == 0)
            {
                int len = strlen(argv[i]) - 3 + 1;
                tsurl = new char[len];
                memset(tsurl, 0, len);
                strcpy(tsurl, argv[i] + 3);
            }
        }
	}

    int err = 0;
    UNSIGNED32 ffhres = TNOTIMPLEMENTED;
    UNSIGNED32 hmhres = TNOERR;

    // If CSA mode is used, load and check root and tsroot certificates
    if (csamode)
    {
        // Initialize SSV taggant library
        TAGGANTFUNCTIONS funcs;
        memset(&funcs, 0, sizeof(TAGGANTFUNCTIONS));
        UNSIGNED64 uVersion;
        // Set structure size
        funcs.size = sizeof(TAGGANTFUNCTIONS);
        pSSVTaggantInitializeLibrary(&funcs, &uVersion);

        if (!silent) cout << "SSV Taggant Library version " << uVersion << "\n";

        if (uVersion < TAGGANT_LIBRARY_VERSION2)
        {
            if (!silent) cout << "Current SSV taggant library does not support version 2\n\n";
            err = 1;
        }

        if (!err)
        {
            ifstream tmps(rootfile, ios::binary);
            if (tmps.is_open())
            {
                tmps.seekg(0, ios::end);
                long tmpsize = tmps.tellg();
                root = new char[tmpsize];
                tmps.seekg(0, ios::beg);
                tmps.read(root, tmpsize);
                tmps.close();

                // Check certificate
                if (pSSVTaggantCheckCertificate(root) != TNOERR)
                {
                    if (!silent) cout << "Error: root certificate is invalid\n\n" << usage;
                    err = 1;
                }
            }
            else
            {
                if (!silent) cout << "Error: root certificate file does not exist\n\n" << usage;
                err = 1;
            }

            // Check the previous taggant before adding a new one
            if (!err)
            {                
                UNSIGNED32 res = TNOERR;
                // Create taggant context
                PTAGGANTCONTEXT pCtx;
                if ((res = pSSVTaggantContextNewEx(&pCtx)) == TNOERR)
                {
                    // Vendor should check version flow here!
                    pCtx->FileReadCallBack = (size_t(__DECLARATION *)(void*, void*, size_t))fileio_fread;
                    pCtx->FileSeekCallBack = (int (__DECLARATION *)(void*, UNSIGNED64, int))fileio_fseek;
                    pCtx->FileTellCallBack = (UNSIGNED64(__DECLARATION *)(void*))fileio_ftell;
                                        
                    // Try to open the file
                    ifstream fin(argv[filearg], ios::binary);
                    if (fin.is_open())
                    {
                        void *taggant = NULL;                        
                        // Get the taggant from the file
                        if ((res = pSSVTaggantGetTaggant(pCtx, (void*)&fin, filetype, &taggant)) == TNOERR)
                        {
                            // Initialize taggant object before it will be validated
                            PTAGGANTOBJ	tag_obj;
                            if ((res = pSSVTaggantObjectNewEx(taggant, 0, TAGGANT_PEFILE, &tag_obj)) == TNOERR)
                            {
                                // Validate the taggant
                                if ((res = pSSVTaggantValidateSignature(tag_obj, taggant, (PVOID)root)) == TNOERR)
                                {
                                    // get the ignore hash map value
                                    UNSIGNED8 ignorehmh = 0;
                                    UNSIGNED32 ihmhsize = sizeof(UNSIGNED8);
                                    res = pSSVTaggantGetInfo(tag_obj, EIGNOREHMH, &ihmhsize, (char*)&ignorehmh);
                                    if (res == TNOERR || res == TNOTFOUND || res == TERRORKEY)
                                    {
                                        res = TNOERR;
                                        if (!ignorehmh)
                                        {
                                            // Get file hash type
                                            // Do a quick file check using hash map (in case it exists)
                                            PHASHBLOB_HASHMAP_DOUBLE dbl = NULL;
                                            int dbl_count = pSSVTaggantGetHashMapDoubles(tag_obj, &dbl);
                                            if (dbl_count)
                                            {
                                                // Compute hashmap of the current file, remember result for later
                                                hmhres = pSSVTaggantValidateHashMap(pCtx, tag_obj, (void*)&fin);
                                            }
                                        }

                                        // get the previous tag value
                                        UNSIGNED8 tagprev = 0;
                                        UNSIGNED32 tprevsize = sizeof(UNSIGNED8);
                                        res = pSSVTaggantGetInfo(tag_obj, ETAGPREV, &tprevsize, (char*)&tagprev);
                                        if (res == TNOERR || res == TNOTFOUND || res == TERRORKEY)
                                        {
                                            res = TNOERR;
                                            // Check full file hash only if there is no previous tag
                                            if (!tagprev)
                                            {
                                                UNSIGNED64 file_end = 0;
                                                UNSIGNED32 size = sizeof(UNSIGNED64);
                                                // Get file end value from the taggant, used for taggant v1 only
                                                if (pSSVTaggantGetInfo(tag_obj, EFILEEND, &size, (char*)&file_end) == TNOERR)
                                                {
                                                    if (!file_end)
                                                    {
                                                        file_end = fileio_fsize(&fin);
                                                    }
                                                    int object_end = 0;
                                                    if (filetype == TAGGANT_PEFILE)
                                                    {
                                                        PE_ALL_HEADERS peh;
                                                        if (winpe_is_correct_pe_file(&fin, &peh))
                                                        {
                                                            object_end = winpe_object_size(&fin, &peh);
                                                        }
                                                    }
                                                    // Compute default hashes of the current file
                                                    ffhres = pSSVTaggantValidateDefaultHashes(pCtx, tag_obj, (void*)&fin, object_end, file_end);

                                                    if (ffhres != TNOERR)
                                                    {
                                                        res = ffhres;
                                                    }
                                                }
                                            }
                                            else if (hmhres != TNOERR)
                                            {
                                                res = hmhres;
                                            }
                                        }
                                    }
                                }
                                pSSVTaggantObjectFree(tag_obj);
                            }
                        }
                        pSSVTaggantFreeTaggant(taggant);
                        fin.close();
                    }
                    else
                    {
                        if (!silent) cout << "Error: Cannot open file to validate for CSA mode\n\n";
                        err = 1;
                    }
                    pSSVTaggantContextFree(pCtx);
                }
                if (res != TNOTAGGANTS && res != TNOERR)
                {
                    if (!silent) cout << "Error: Validation of the file for CSA mode failed with error " << res <<" \n\n";
                    err = res;
                }
            }
        }
        pSSVTaggantFinalizeLibrary();
    }

    delete[] rootfile;
    delete[] root;

    if (!err)
    {
        // Check if the first argument refers to existing file
        ifstream ffs(argv[filearg], ios::binary);
        if (ffs.is_open())
        {
            // Initialize taggant library
            TAGGANTFUNCTIONS funcs;
            memset(&funcs, 0, sizeof(TAGGANTFUNCTIONS));
            UNSIGNED64 uVersion;
            // Set structure size
            funcs.size = sizeof(TAGGANTFUNCTIONS);

            //spv_namespace::Tagga
            pSPVTaggantInitializeLibrary(&funcs, &uVersion);
            if (!silent) cout << "SPV Taggant Library version " << uVersion << "\n";
            // Make sure the taggant library supports version 2
            if (uVersion < TAGGANT_LIBRARY_VERSION2)
            {
                if (!silent) cout << "Error: Current taggant library does not support version 2\n\n";
                err = 1;
            }

            if (!err)
            {
                // Check if the license.pem file exist
                char* lic;
                ifstream flc(argv[filearg + 1], ios::binary);
                if (!flc.is_open())
                {
                    if (!silent) cout << "Error: license.pem does not exist\n\n" << usage;
                    err = 1;
                }
                else
                {
                    // Read license from file
                    flc.seekg(0, ios::end);
                    long fsize = flc.tellg();
                    lic = new char[fsize];
                    flc.seekg(0, ios::beg);
                    flc.read(lic, fsize);

                    // Make sure the license is valid
                    UNSIGNED64 ltime;
                    if (pSPVTaggantGetLicenseExpirationDate(lic, &ltime) == TNOERR)
                    {
                        if (!silent) cout << "License file is valid, expiration date is " << asctime(gmtime((time_t*)&ltime));

                        // Create taggant context
                        PTAGGANTCONTEXT pCtx;
                        UNSIGNED32 ctxres = pSPVTaggantContextNewEx(&pCtx);
                        if (ctxres == TNOERR)
                        {
                            // Vendor should check version flow here!
                            pCtx->FileReadCallBack = (size_t(__DECLARATION *)(void*, void*, size_t))fileio_fread;
                            pCtx->FileSeekCallBack = (int (__DECLARATION *)(void*, UNSIGNED64, int))fileio_fseek;
                            pCtx->FileTellCallBack = (UNSIGNED64(__DECLARATION *)(void*))fileio_ftell;

                            PTAGGANTOBJ tagobj;
                            UNSIGNED32 objres = pSPVTaggantObjectNewEx(NULL, TAGGANT_LIBRARY_VERSION2, filetype, &tagobj);
                            if (objres == TNOERR)
                            {
                                UNSIGNED32 hashres = pSPVTaggantComputeHashes(pCtx, tagobj, &ffs, 0, 0, 0);
                                if (hashres == TNOERR)
                                {
                                    if (!silent) cout << "File hashes computed successfully\n";

                                    // set packer information
                                    PACKERINFO packer_info;
                                    memset(&packer_info, 0, sizeof(PACKERINFO));
                                    packer_info.PackerId = 1;
                                    packer_info.VersionMajor = SIGNTOOL_VERSION >> 16 & 0xFF;
                                    packer_info.VersionMinor = SIGNTOOL_VERSION >> 8 & 0xFF;
                                    packer_info.VersionBuild = SIGNTOOL_VERSION & 0xFF;

                                    UNSIGNED32 packerres = pSPVTaggantPutInfo(tagobj, EPACKERINFO, sizeof(PACKERINFO), (char*)&packer_info);
                                    if (packerres == TNOERR)
                                    {
                                        UNSIGNED32 ihmhres = TNOERR;
                                        if ((ffhres == TNOERR) && (hmhres != TNOERR))
                                        {
                                            UNSIGNED8 ignorehmh = 1;
                                            ihmhres = pSPVTaggantPutInfo(tagobj, EIGNOREHMH, sizeof(UNSIGNED8), (char*)&ignorehmh);
                                        }
                                        if (ihmhres == TNOERR)
                                        {
                                            // Set contributor list information
                                            char *clist = "CONTRIBUTORS LIST HERE";
                                            UNSIGNED32 clistres = pSPVTaggantPutInfo(tagobj, ECONTRIBUTORLIST, strlen(clist) + 1, clist);
                                            if (clistres == TNOERR)
                                            {
                                                // try to put timestamp
                                                if (!silent) cout << "Put timestamp\n";
                                                UNSIGNED32 timestampres = pSPVTaggantPutTimestamp(tagobj, tsurl ? tsurl : "http://taggant-tsa.ieee.org/", 50);
                                                if (!silent)
                                                {
                                                    switch (timestampres)
                                                    {
                                                        case TNOERR:
                                                        {
                                                            cout << "Timestamp successfully placed\n";
                                                            break;
                                                        }
                                                        case TNONET:
                                                        {
                                                            cout << "Warning: Can't put timestamp, no connection to the internet\n";
                                                            break;
                                                        }
                                                        case TTIMEOUT:
                                                        {
                                                            cout << "Warning: Can't put timestamp, the timestamp authority server response time has expired\n";
                                                            break;
                                                        }
                                                        default:
                                                        {
                                                            cout << "Warning: Can't put timestamp, error: " << timestampres << "\n";
                                                            break;
                                                        }
                                                    }
                                                    cout << "Prepare the taggant\n";
                                                }
                                                // allocate the approximate buffer for CMS
                                                UNSIGNED32 taggantsize = 0x10000;
                                                char* taggant = new char[taggantsize];
                                                UNSIGNED32 prepareres = pSPVTaggantPrepare(tagobj, (PVOID)lic, taggant, &taggantsize);
                                                // if the allocated buffer is not sufficient then allocate bigger buffer
                                                if (prepareres == TINSUFFICIENTBUFFER)
                                                {
                                                    delete[] taggant;
                                                    taggantsize = taggantsize * 2;
                                                    taggant = new char[taggantsize];
                                                    prepareres = pSPVTaggantPrepare(tagobj, (PVOID)lic, taggant, &taggantsize);
                                                }
                                                if (prepareres == TNOERR)
                                                {
                                                    if (!silent) cout << "Taggant successfully created\n";
                                                    // append the file with the taggant
                                                    ofstream ofs(argv[filearg], ios::binary | ios::app | ios::out);
                                                    if (ofs.is_open())
                                                    {
                                                        ofs.write(taggant, taggantsize);
                                                        if (!silent) cout << "Taggant is written to file\n";
                                                    }
                                                    ofs.close();
                                                }
                                                else
                                                {
                                                    if (!silent) cout << "Error: TaggantPrepare failed with result: " << prepareres << "\n\n";
                                                }
                                                delete[] taggant;
                                            }
                                            else
                                            {
                                                if (!silent) cout << "Error: TaggantSetInfo failed to set contributor list information with result: " << clistres << "\n\n";
                                                err = 1;
                                            }
                                        }
                                        else
                                        {
                                            if (!silent) cout << "Error: TaggantSetInfo failed to set EIGNOREHMH with result: " << ihmhres << "\n\n";
                                            err = 1;
                                        }
                                    }
                                    else
                                    {
                                        if (!silent) cout << "Error: TaggantSetInfo failed to set packer information with result: " << packerres << "\n\n";
                                        err = 1;
                                    }
                                }
                                else
                                {
                                    if (!silent) cout << "Error: TaggantComputeHashes failed with result: " << hashres << "\n\n";
                                    err = 1;
                                }
                                pSPVTaggantObjectFree(tagobj);
                            }
                            else
                            {
                                if (!silent) cout << "Error: TaggantObjectNewEx failed with result: " << objres << "\n\n";
                                err = 1;
                            }
                            pSPVTaggantContextFree(pCtx);
                        }
                        else
                        {
                            if (!silent) cout << "Error: TaggantContextNewEx failed with result: " << ctxres << "\n\n";
                            err = 1;
                        }
                    }
                    else
                    {
                        if (!silent) cout << "Error: License file is not valid\n\n";
                        err = 1;
                    }
                }
                flc.close();
                delete[] lic;
            }
            pSPVTaggantFinalizeLibrary();
        }
        else
        {
            if (!silent) cout << "Error: file_to_sign does not exist\n\n" << usage;
            err = 1;
        }
        ffs.close();
    }
    delete[] tsurl;
	return err;
}
