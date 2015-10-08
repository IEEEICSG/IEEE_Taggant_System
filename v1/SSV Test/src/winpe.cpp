/*
 * winpe.c
 *
 *  Created on: Oct 16, 2011
 *      Author: Enigma
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

int winpe_raw_section_offset(PE_ALL_HEADERS* peh, IMAGE_SECTION_HEADER* sec)
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

int winpe_section_size(PE_ALL_HEADERS* peh, IMAGE_SECTION_HEADER* sec)
{
	long section_alignment;
	long file_alignment;
	//
	section_alignment = (winpe_is_pe64(peh)) ? peh->oh.pe64.SectionAlignment : peh->oh.pe32.SectionAlignment;
	file_alignment = (winpe_is_pe64(peh)) ? peh->oh.pe64.FileAlignment : peh->oh.pe32.FileAlignment;
    return (sec->Misc.VirtualSize ? min(round_up(section_alignment, sec->Misc.VirtualSize), round_up(file_alignment, sec->SizeOfRawData)) : round_up(file_alignment, sec->SizeOfRawData));
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
		long filepos = peh->dh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + peh->fh.SizeOfOptionalHeader;
		// shift file pointer to the sections array
		if (fileio_fseek(fp, filepos, SEEK_SET) == 0)
		{
			int i;
			IMAGE_SECTION_HEADER fs;
			for (i = 0; i < peh->fh.NumberOfSections; i++)
			{
				// read section from the file
				if (fileio_fread(fp, &fs, sizeof(IMAGE_SECTION_HEADER)) == sizeof(IMAGE_SECTION_HEADER))
				{
					if (winpe_raw_section_offset(peh, &fs) != 0)
					{
						res = winpe_raw_section_offset(peh, &fs) + winpe_section_size(peh, &fs);
					}
					filepos += sizeof(IMAGE_SECTION_HEADER);
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
	return min(res, (int) filelength);
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
		long filepos = peh->dh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + peh->fh.SizeOfOptionalHeader;
		// shift file pointer to the sections array
		if (fileio_fseek(fp, filepos, SEEK_SET) == 0)
		{
			// reading all sections and find rwa address
			int i;
			IMAGE_SECTION_HEADER fs;
			for (i = 0; i < peh->fh.NumberOfSections; i++)
			{
				// read section from the file
				if (fileio_fread(fp, &fs, sizeof(IMAGE_SECTION_HEADER)) == sizeof(IMAGE_SECTION_HEADER))
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
					filepos += sizeof(IMAGE_SECTION_HEADER);
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
	if (filesize >= sizeof(IMAGE_DOS_HEADER))
	{
		// seek file to the file beginning
		if (fileio_fseek(fp, 0L, SEEK_SET) == 0)
		{
			// make sure dos header is read fully
			if (fileio_fread(fp, &peh->dh, sizeof(IMAGE_DOS_HEADER)) == sizeof(IMAGE_DOS_HEADER))
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
									if (fileio_fread(fp, &peh->fh, sizeof(IMAGE_FILE_HEADER)) == sizeof(IMAGE_FILE_HEADER))
									{
										// As MSDN says, only these types of files can be run in Windows
										switch (peh->fh.Machine)
										{
											case IMAGE_FILE_MACHINE_I386:
											{
												// PE32 file, read optional header
												memset(&peh->oh.pe32, 0, sizeof(IMAGE_OPTIONAL_HEADER32));
												if (fileio_fread(fp, &peh->oh.pe32, sizeof(IMAGE_OPTIONAL_HEADER32)) == sizeof(IMAGE_OPTIONAL_HEADER32))
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
												memset(&peh->oh.pe64, 0, sizeof(IMAGE_OPTIONAL_HEADER64));
												if (fileio_fread(fp, &peh->oh.pe64, sizeof(IMAGE_OPTIONAL_HEADER64)) == sizeof(IMAGE_OPTIONAL_HEADER64))
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
