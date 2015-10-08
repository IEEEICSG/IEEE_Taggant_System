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
#include "fileio.h"
#include "winpe.h"
#include "winpe_types.h"
#include "miscellaneous.h"

using namespace std;

int winpe_raw_section_offset(PE_ALL_HEADERS* peh, TAG_IMAGE_SECTION_HEADER* sec)
{
	long section_alignment;
	//
	section_alignment = (winpe_is_pe64(peh)) ? peh->oh.pe64.SectionAlignment : peh->oh.pe32.SectionAlignment;
	if (section_alignment >= 0x1000)
	{
		return round_down(0x200, sec->PointerToRawData);
	}
	return sec->PointerToRawData;
}

int winpe_section_size(PE_ALL_HEADERS* peh, TAG_IMAGE_SECTION_HEADER* sec)
{
	long section_alignment;
	long file_alignment;
	//
	section_alignment = (winpe_is_pe64(peh)) ? peh->oh.pe64.SectionAlignment : peh->oh.pe32.SectionAlignment;
	file_alignment = (winpe_is_pe64(peh)) ? peh->oh.pe64.FileAlignment : peh->oh.pe32.FileAlignment;
	return (sec->Misc.VirtualSize ? get_min(round_up(section_alignment, sec->Misc.VirtualSize), round_up(file_alignment, sec->SizeOfRawData)) : round_up(file_alignment, sec->SizeOfRawData));
}

int winpe_is_pe64(PE_ALL_HEADERS* peh)
{
	if (peh->fh.Machine == IMAGE_FILE_MACHINE_I386)
	{
		return 0;
	}
	return 1;
}

int winpe_object_size(ifstream* fp, PE_ALL_HEADERS* peh)
{
	UNSIGNED64 filelength;
	int res = -1;

	// check is number of sections greater zero
	if (peh->fh.NumberOfSections > 0)
	{
		long filepos = peh->dh.e_lfanew + sizeof(DWORD) + sizeof(TAG_IMAGE_FILE_HEADER) + peh->fh.SizeOfOptionalHeader;
		// shift file pointer to the sections array
		if (fileio_fseek(fp, filepos, SEEK_SET) == 0)
		{
			int i;
			TAG_IMAGE_SECTION_HEADER fs;
			for (i = 0; i < peh->fh.NumberOfSections; i++)
			{
				// read section from the file
				if (fileio_fread(fp, &fs, sizeof(TAG_IMAGE_SECTION_HEADER)) == sizeof(TAG_IMAGE_SECTION_HEADER))
				{
					if (winpe_raw_section_offset(peh, &fs) != 0)
					{
						res = winpe_raw_section_offset(peh, &fs) + winpe_section_size(peh, &fs);
					}
					filepos += sizeof(TAG_IMAGE_SECTION_HEADER);
					if (fileio_fseek(fp, filepos, SEEK_SET) != 0)
					{
						res = -1;
						break;
					}
				} else
				{
					res = -1;
					break;
				}
			}
		}
	}
	filelength = fileio_fsize(fp);
	return get_min(res, (int)filelength);
}

int winpe_va_to_rwa(ifstream* fp, PE_ALL_HEADERS* peh, unsigned long va)
{
	if (peh->fh.NumberOfSections == 0)
	{
		return va;
	}
	if (winpe_is_pe64(peh))
	{
		if (va < peh->oh.pe32.SizeOfHeaders)
		{
			return va;
		}
	} else
	{
		if (va < peh->oh.pe64.SizeOfHeaders)
		{
			return va;
		}
	}
	// check is number of sections greater zero
	if (peh->fh.NumberOfSections > 0)
	{
		long filepos = peh->dh.e_lfanew + sizeof(DWORD) + sizeof(TAG_IMAGE_FILE_HEADER) + peh->fh.SizeOfOptionalHeader;
		// shift file pointer to the sections array
		if (fileio_fseek(fp, filepos, SEEK_SET) == 0)
		{
			// reading all sections and find rwa address
			int i;
			TAG_IMAGE_SECTION_HEADER fs;
			for (i = 0; i < peh->fh.NumberOfSections; i++)
			{
				// read section from the file
				if (fileio_fread(fp, &fs, sizeof(TAG_IMAGE_SECTION_HEADER)) == sizeof(TAG_IMAGE_SECTION_HEADER))
				{
					//
					if (va < fs.VirtualAddress)
					{
						break;
					} else
						if (winpe_raw_section_offset(peh, &fs) != 0)
						{
							if (va >= fs.VirtualAddress && va < (fs.VirtualAddress + winpe_section_size(peh, &fs)))
							{
								return va - fs.VirtualAddress + winpe_raw_section_offset(peh, &fs);
							}
						}
					filepos += sizeof(TAG_IMAGE_SECTION_HEADER);
					if (fileio_fseek(fp, filepos, SEEK_SET) != 0)
					{
						break;
					}
				} else
				{
					break;
				}
			}
		}
	}
	return -1;
}

long winpe_entry_point_physical_offset(ifstream* fp, PE_ALL_HEADERS* peh)
{

	if (winpe_is_pe64(peh))
	{
		if (peh->oh.pe64.AddressOfEntryPoint != 0)
		{
			return winpe_va_to_rwa(fp, peh, peh->oh.pe64.AddressOfEntryPoint);
		}
	} else
	{
		if (peh->oh.pe32.AddressOfEntryPoint != 0)
		{
			return winpe_va_to_rwa(fp, peh, peh->oh.pe32.AddressOfEntryPoint);
		}
	}
	return -1;
}

int winpe_is_correct_pe_file(ifstream* fp, PE_ALL_HEADERS* peh)
{
	// remember the size of the file
	UNSIGNED64 filesize = fileio_fsize(fp);
	// make sure filesize is greater than size of DOS header
	if (filesize >= sizeof(TAG_IMAGE_DOS_HEADER))
	{
		// seek file to the file beginning
		if (fileio_fseek(fp, 0L, SEEK_SET) == 0)
		{
			// make sure dos header is read fully
			if (fileio_fread(fp, &peh->dh, sizeof(TAG_IMAGE_DOS_HEADER)) == sizeof(TAG_IMAGE_DOS_HEADER))
			{
				// check dos header e_magic
				if (peh->dh.e_magic == IMAGE_DOS_SIGNATURE)
				{
					if (filesize >= peh->dh.e_lfanew)
					{
						// seek file to the dh.e_magic from beginning
						if (fileio_fseek(fp, peh->dh.e_lfanew, SEEK_SET) == 0)
						{
							// read file signature
							if (fileio_fread(fp, &peh->signature, sizeof(DWORD)) == sizeof(DWORD))
							{
								if (peh->signature == IMAGE_NT_SIGNATURE)
								{
									// read file header
									if (fileio_fread(fp, &peh->fh, sizeof(TAG_IMAGE_FILE_HEADER)) == sizeof(TAG_IMAGE_FILE_HEADER))
									{
										// As MSDN says, only these types of files can be run in Windows
										switch (peh->fh.Machine)
										{
											case IMAGE_FILE_MACHINE_I386:
											{
												// PE32 file, read optional header
												memset(&peh->oh.pe32, 0, sizeof(TAG_IMAGE_OPTIONAL_HEADER32));
												if (fileio_fread(fp, &peh->oh.pe32, sizeof(TAG_IMAGE_OPTIONAL_HEADER32)) == sizeof(TAG_IMAGE_OPTIONAL_HEADER32))
												{
													if (peh->oh.pe32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
													{
														return 1;
													}
												}
												break;
											}
											case IMAGE_FILE_MACHINE_AMD64:
											{
												memset(&peh->oh.pe64, 0, sizeof(TAG_IMAGE_OPTIONAL_HEADER64));
												if (fileio_fread(fp, &peh->oh.pe64, sizeof(TAG_IMAGE_OPTIONAL_HEADER64)) == sizeof(TAG_IMAGE_OPTIONAL_HEADER64))
												{
													if (peh->oh.pe64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
													{
														return 1;
													}
												}
												break;
											}
											default:
											{
												break;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}
