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

#include "global.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "callbacks.h"
#include "winpe.h"
#include "miscellaneous.h"
#include "endianness.h"

int winpe_read_optional_header64(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, TAG_IMAGE_OPTIONAL_HEADER64 *oheader)
{
    UNSIGNED32 dirsize, ohsize;
    int i;

    /* PE32+ file, read optional header */
    memset(oheader, 0, sizeof(TAG_IMAGE_OPTIONAL_HEADER64));
    /* Read optional header without directories */
    ohsize = sizeof(TAG_IMAGE_OPTIONAL_HEADER64) - IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(TAG_IMAGE_DATA_DIRECTORY);
    if (pCtx->FileReadCallBack(fp, oheader, ohsize) == ohsize)
    {
        if (IS_BIG_ENDIAN)
        {
            oheader->Magic = UNSIGNED16_to_big_endian((char*)&oheader->Magic);
            oheader->AddressOfEntryPoint = UNSIGNED32_to_big_endian((char*)&oheader->AddressOfEntryPoint);
            oheader->SectionAlignment = UNSIGNED32_to_big_endian((char*)&oheader->SectionAlignment);
            oheader->FileAlignment = UNSIGNED32_to_big_endian((char*)&oheader->FileAlignment);
            oheader->SizeOfHeaders = UNSIGNED32_to_big_endian((char*)&oheader->SizeOfHeaders);
            oheader->NumberOfRvaAndSizes = UNSIGNED32_to_big_endian((char*)&oheader->NumberOfRvaAndSizes);
        }
        if (oheader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            /* Read directories */
            if (oheader->NumberOfRvaAndSizes > 0)
            {
                dirsize = get_min(oheader->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES) * sizeof(TAG_IMAGE_DATA_DIRECTORY);
                if (pCtx->FileReadCallBack(fp, &oheader->DataDirectory, dirsize) == dirsize)
                {
                    if (IS_BIG_ENDIAN)
                    {
                        for (i = 0; i < (int)get_min(oheader->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++)
                        {
                            oheader->DataDirectory[i].VirtualAddress = UNSIGNED32_to_big_endian((char*)&oheader->DataDirectory[i].VirtualAddress);
                            oheader->DataDirectory[i].Size = UNSIGNED32_to_big_endian((char*)&oheader->DataDirectory[i].Size);
                        }
                    }
                    return 1;
                }
            }
            else
            {
                return 1;
            }
        }
    }
    return 0;
}

int winpe_read_optional_header32(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, TAG_IMAGE_OPTIONAL_HEADER32 *oheader)
{
    UNSIGNED32 dirsize, ohsize;
    int i;

    /* PE32 file, read optional header */
    memset(oheader, 0, sizeof(TAG_IMAGE_OPTIONAL_HEADER32));
    /* Read optional header without directories */
    ohsize = sizeof(TAG_IMAGE_OPTIONAL_HEADER32) - IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(TAG_IMAGE_DATA_DIRECTORY);
    if (pCtx->FileReadCallBack(fp, oheader, ohsize) == ohsize)
    {
        if (IS_BIG_ENDIAN)
        {
            oheader->Magic = UNSIGNED16_to_big_endian((char*)&oheader->Magic);
            oheader->AddressOfEntryPoint = UNSIGNED32_to_big_endian((char*)&oheader->AddressOfEntryPoint);
            oheader->SectionAlignment = UNSIGNED32_to_big_endian((char*)&oheader->SectionAlignment);
            oheader->FileAlignment = UNSIGNED32_to_big_endian((char*)&oheader->FileAlignment);
            oheader->SizeOfHeaders = UNSIGNED32_to_big_endian((char*)&oheader->SizeOfHeaders);
            oheader->NumberOfRvaAndSizes = UNSIGNED32_to_big_endian((char*)&oheader->NumberOfRvaAndSizes);
        }
        if (oheader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            /* Read directories */
            if (oheader->NumberOfRvaAndSizes > 0)
            {
                dirsize = get_min(oheader->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES) * sizeof(TAG_IMAGE_DATA_DIRECTORY);
                if (pCtx->FileReadCallBack(fp, &oheader->DataDirectory, dirsize) == dirsize)
                {
                    if (IS_BIG_ENDIAN)
                    {
                        for (i = 0; i < (int)get_min(oheader->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++)
                        {
                            oheader->DataDirectory[i].VirtualAddress = UNSIGNED32_to_big_endian((char*)&oheader->DataDirectory[i].VirtualAddress);
                            oheader->DataDirectory[i].Size = UNSIGNED32_to_big_endian((char*)&oheader->DataDirectory[i].Size);
                        }
                    }
                    return 1;
                }
            }
            else
            {
                return 1;
            }
        }
    }
    return 0;
}

int winpe_read_file_header(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, TAG_IMAGE_FILE_HEADER *fheader)
{
    if (pCtx->FileReadCallBack(fp, fheader, sizeof(TAG_IMAGE_FILE_HEADER)) == sizeof(TAG_IMAGE_FILE_HEADER))
    {
        if (IS_BIG_ENDIAN)
        {
            fheader->Machine = UNSIGNED16_to_big_endian((char*)&fheader->Machine);
            fheader->NumberOfSections = UNSIGNED16_to_big_endian((char*)&fheader->NumberOfSections);
            fheader->SizeOfOptionalHeader = UNSIGNED16_to_big_endian((char*)&fheader->SizeOfOptionalHeader);
        }
        return 1;
    }
    return 0;
}

int winpe_read_dos_header(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, TAG_IMAGE_DOS_HEADER *dheader)
{
    if (pCtx->FileReadCallBack(fp, dheader, sizeof(TAG_IMAGE_DOS_HEADER)) == sizeof(TAG_IMAGE_DOS_HEADER))
    {
        if (IS_BIG_ENDIAN)
        {
            dheader->e_magic = UNSIGNED16_to_big_endian((char*)&dheader->e_magic);
            dheader->e_lfanew = (SIGNED32)UNSIGNED32_to_big_endian((char*)&dheader->e_lfanew);
        }
        return 1;
    }
    return 0;
}

int winpe_read_section_header(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, TAG_IMAGE_SECTION_HEADER *section)
{
    if (pCtx->FileReadCallBack(fp, section, sizeof(TAG_IMAGE_SECTION_HEADER)) == sizeof(TAG_IMAGE_SECTION_HEADER))
    {
        if (IS_BIG_ENDIAN)
        {
            section->Misc.VirtualSize = UNSIGNED32_to_big_endian((char*)&section->Misc.VirtualSize);
            section->VirtualAddress = UNSIGNED32_to_big_endian((char*)&section->VirtualAddress);
            section->SizeOfRawData = UNSIGNED32_to_big_endian((char*)&section->SizeOfRawData);
            section->PointerToRawData = UNSIGNED32_to_big_endian((char*)&section->PointerToRawData);
        }
        return 1;
    }
    return 0;
}

UNSIGNED32 winpe_header_size(PE_ALL_HEADERS* peh)
{
    UNSIGNED32 ohdefsize, ohsize;

    ohdefsize = winpe_is_pe64(peh) ? sizeof(TAG_IMAGE_OPTIONAL_HEADER64) : sizeof(TAG_IMAGE_OPTIONAL_HEADER32);
    ohsize = get_max(peh->fh.SizeOfOptionalHeader, ohdefsize);
    return peh->dh.e_lfanew + sizeof(peh->signature) + sizeof(peh->fh) + ohsize + peh->fh.NumberOfSections * sizeof(TAG_IMAGE_SECTION_HEADER);
}

int winpe_taggant_physical_offset(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, UNSIGNED64 ep_physical_offset, UNSIGNED64 *tag_offset)
{
    UNSIGNED16 jmpcode = 0;
    UNSIGNED64 offset = 0;

    /* read 2 bytes from file entry point */
    if (file_seek(pCtx, fp, ep_physical_offset, SEEK_SET))
    {
        if (file_read_UNSIGNED16(pCtx, fp, &jmpcode))
        {
            if (jmpcode == TAGGANT_ADDRESS_JMP)
            {
                if (file_seek(pCtx, fp, ep_physical_offset + sizeof(UNSIGNED16), SEEK_SET))
                {
                    if (file_read_UNSIGNED64(pCtx, fp, &offset))
                    {
                        /* Check if the taggant offset points to the area after headers */
                        if (offset >= winpe_header_size(peh))
                        {
                            *tag_offset = offset;
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

UNSIGNED32 winpe_raw_section_size(PE_ALL_HEADERS* peh, TAG_IMAGE_SECTION_HEADER* sec)
{
    long file_alignment = winpe_is_pe64(peh) ? peh->oh.pe64.FileAlignment : peh->oh.pe32.FileAlignment;
    /* Note, sec->Misc.VirtualSize is being rounded up to the multiple page size value
       for i386 and AMD64 we assume it is 0x1000 */
    return (sec->Misc.VirtualSize ? get_min(round_up(0x1000, sec->Misc.VirtualSize), round_up(file_alignment, sec->SizeOfRawData)) : round_up(file_alignment, sec->SizeOfRawData));
}

UNSIGNED32 winpe_raw_section_offset(PE_ALL_HEADERS* peh, TAG_IMAGE_SECTION_HEADER* sec)
{
    long section_alignment;

    section_alignment = winpe_is_pe64(peh) ? peh->oh.pe64.SectionAlignment : peh->oh.pe32.SectionAlignment;
    if (section_alignment >= 0x1000)
    {
        return round_down(0x200, sec->PointerToRawData);
    }
    return sec->PointerToRawData;
}

int winpe_va_to_rwa(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, UNSIGNED32 va, UNSIGNED64 *offset)
{
    long filepos;
    int i;
    TAG_IMAGE_SECTION_HEADER fs;

    if (peh->fh.NumberOfSections == 0)
    {
        *offset = (UNSIGNED64)va;
        return 1;
    } else
    {
        filepos = peh->dh.e_lfanew + sizeof(UNSIGNED32) + sizeof(TAG_IMAGE_FILE_HEADER) + peh->fh.SizeOfOptionalHeader;
        /* shift file pointer to the sections array */
        if (file_seek(pCtx, fp, filepos, SEEK_SET))
        {
            /* reading all sections and find rwa address */
            for (i = 0; i < peh->fh.NumberOfSections; i++)
            {
                /* read section from the file */
                if (winpe_read_section_header(pCtx, fp, &fs))
                {
                    if (va < fs.VirtualAddress)
                    {
                        /* If va is less than virtual address of the first section, then
                           we assume the va is located in file header, and so va = rwa */
                        if (i == 0)
                        {
                            *offset = (UNSIGNED64)va;
                            return 1;
                        }
                        break;
                    } else
                        if (fs.PointerToRawData != 0)
                        {
                            if (va >= fs.VirtualAddress && va < (fs.VirtualAddress + winpe_raw_section_size(peh, &fs)))
                            {
                                *offset = (UNSIGNED64)va - (UNSIGNED64)fs.VirtualAddress + (UNSIGNED64)winpe_raw_section_offset(peh, &fs);
                                return 1;
                            }
                        }
                    filepos += sizeof(TAG_IMAGE_SECTION_HEADER);
                    if (!file_seek(pCtx, fp, filepos, SEEK_SET))
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
    return 0;
}

int winpe_is_pe64(PE_ALL_HEADERS* peh)
{
    return (peh->fh.Machine == IMAGE_FILE_MACHINE_AMD64) ? 1 : 0;
}

int winpe_entry_point_physical_offset(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh, UNSIGNED64 *ep_offset)
{

    if (winpe_is_pe64(peh))
    {
        if (peh->oh.pe64.AddressOfEntryPoint != 0)
        {
            return winpe_va_to_rwa(pCtx, fp, peh, peh->oh.pe64.AddressOfEntryPoint, ep_offset);
        }
    } else
    {
        if (peh->oh.pe32.AddressOfEntryPoint != 0)
        {
            return winpe_va_to_rwa(pCtx, fp, peh, peh->oh.pe32.AddressOfEntryPoint, ep_offset);
        }
    }
    return 0;
}

int winpe_is_correct_pe_file(PTAGGANTCONTEXT pCtx, PFILEOBJECT fp, PE_ALL_HEADERS* peh)
{
    /* remember the size of the file */
    UNSIGNED64 filesize = get_file_size(pCtx, fp);

    /* make sure filesize is greater than size of DOS header */
    if (filesize >= sizeof(TAG_IMAGE_DOS_HEADER))
    {
        /* seek file to the file beginning */
        if (file_seek(pCtx, fp, 0L, SEEK_SET))
        {
            /* make sure dos header is read fully */
            if (winpe_read_dos_header(pCtx, fp, &peh->dh))
            {
                /* check dos header e_magic */
                if (peh->dh.e_magic == IMAGE_DOS_SIGNATURE)
                {
                    if (filesize >= peh->dh.e_lfanew)
                    {
                        /* seek file to the dh.e_magic from beginning */
                        if (file_seek(pCtx, fp, peh->dh.e_lfanew, SEEK_SET))
                        {
                            /* read file signature */
                            if (file_read_UNSIGNED32(pCtx, fp, &peh->signature))
                            {
                                if (peh->signature == IMAGE_NT_SIGNATURE)
                                {
                                    /* read file header */
                                    if (winpe_read_file_header(pCtx, fp, &peh->fh))
                                    {
                                        /* As MSDN says, only these types of files can be run in Windows */
                                        if (peh->fh.Machine == IMAGE_FILE_MACHINE_I386)
                                        {
                                            return winpe_read_optional_header32(pCtx, fp, &peh->oh.pe32);
                                        } else
                                        if (peh->fh.Machine == IMAGE_FILE_MACHINE_AMD64)
                                        {
                                            return winpe_read_optional_header64(pCtx, fp, &peh->oh.pe64);
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
