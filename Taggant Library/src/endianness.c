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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "taggant_types.h"
#include "types.h"

void UNSIGNED64_to_little_endian(UNSIGNED64 value, char* buffer)
{
	int i;

	for (i = 0; i < 8; i++)
	{
		buffer[i] = (char)value;
		value = value >> 8;
	}
}

void UNSIGNED32_to_little_endian(UNSIGNED32 value, char* buffer)
{
	int i;

	for (i = 0; i < 4; i++)
	{
		buffer[i] = (char)value;
		value = value >> 8;
	}
}

void UNSIGNED16_to_little_endian(UNSIGNED16 value, char* buffer)
{
	int i;

	for (i = 0; i < 2; i++)
	{
		buffer[i] = (char)value;
		value = value >> 8;
	}
}

void PACKERINFO_to_little_endian(PPACKERINFO in_packer_info, PPACKERINFO out_packer_info)
{
	UNSIGNED32_to_little_endian(in_packer_info->PackerId, (char*)&out_packer_info->PackerId);
	UNSIGNED16_to_little_endian(in_packer_info->VersionMajor, (char*)&out_packer_info->VersionMajor);
	UNSIGNED16_to_little_endian(in_packer_info->VersionMinor, (char*)&out_packer_info->VersionMinor);
	UNSIGNED16_to_little_endian(in_packer_info->VersionBuild, (char*)&out_packer_info->VersionBuild);
	UNSIGNED16_to_little_endian(in_packer_info->Reserved, (char*)&out_packer_info->Reserved);
}

void TAGGANTBLOB_HEADER_little_endian(PTAGGANTBLOB_HEADER in_tag_blob_header, PTAGGANTBLOB_HEADER out_tag_blob_header)
{
	UNSIGNED16_to_little_endian(in_tag_blob_header->Length, (char*)&out_tag_blob_header->Length);
	UNSIGNED16_to_little_endian(in_tag_blob_header->Version, (char*)&out_tag_blob_header->Version);
	PACKERINFO_to_little_endian(&in_tag_blob_header->PackerInfo, &out_tag_blob_header->PackerInfo);
}

void HASHBLOB_HEADER_to_little_endian(PHASHBLOB_HEADER in_hash_blob_header, PHASHBLOB_HEADER out_hash_blob_header)
{
	UNSIGNED16_to_little_endian(in_hash_blob_header->Length, (char*)&out_hash_blob_header->Length);
	UNSIGNED16_to_little_endian(in_hash_blob_header->Type, (char*)&out_hash_blob_header->Type);
	UNSIGNED16_to_little_endian(in_hash_blob_header->Version, (char*)&out_hash_blob_header->Version);
	memcpy(&out_hash_blob_header->Hash, &in_hash_blob_header->Hash, sizeof(in_hash_blob_header->Hash));
}

void HASHBLOB_DEFAULT_to_little_endian(PHASHBLOB_DEFAULT in_hash_blob_default, PHASHBLOB_DEFAULT out_hash_blob_default)
{
	HASHBLOB_HEADER_to_little_endian(&in_hash_blob_default->Header, &out_hash_blob_default->Header);
}

void HASHBLOB_EXTENDED_to_little_endian(PHASHBLOB_EXTENDED in_hash_blob_extended, PHASHBLOB_EXTENDED out_hash_blob_extended)
{
	HASHBLOB_HEADER_to_little_endian(&in_hash_blob_extended->Header, &out_hash_blob_extended->Header);
	UNSIGNED64_to_little_endian(in_hash_blob_extended->PhysicalEnd, (char*)&out_hash_blob_extended->PhysicalEnd);
}

void HASHBLOB_FULLFILE_to_little_endian(PHASHBLOB_FULLFILE in_hash_blob_full_file, PHASHBLOB_FULLFILE out_hash_blob_full_file)
{

	HASHBLOB_DEFAULT_to_little_endian(&in_hash_blob_full_file->DefaultHash, &out_hash_blob_full_file->DefaultHash);
	HASHBLOB_EXTENDED_to_little_endian(&in_hash_blob_full_file->ExtendedHash, &out_hash_blob_full_file->ExtendedHash);
}

void HASHBLOB_HASHMAP_DOUBLE_to_little_endian(PHASHBLOB_HASHMAP_DOUBLE in_hash_blob_hash_map_double, PHASHBLOB_HASHMAP_DOUBLE out_hash_blob_hash_map_double)
{
	UNSIGNED64_to_little_endian(in_hash_blob_hash_map_double->AbsoluteOffset, (char*)&out_hash_blob_hash_map_double->AbsoluteOffset);
	UNSIGNED64_to_little_endian(in_hash_blob_hash_map_double->Length, (char*)&out_hash_blob_hash_map_double->Length);
}

void HASHBLOB_HASHMAP_to_little_endian(PHASHBLOB_HASHMAP in_hash_blob_hash_map, PHASHBLOB_HASHMAP out_hash_blob_hash_map)
{
	HASHBLOB_HEADER_to_little_endian(&in_hash_blob_hash_map->Header, &out_hash_blob_hash_map->Header);
	UNSIGNED16_to_little_endian(in_hash_blob_hash_map->Entries, (char*)&out_hash_blob_hash_map->Entries);
	UNSIGNED16_to_little_endian(in_hash_blob_hash_map->DoublesOffset, (char*)&out_hash_blob_hash_map->DoublesOffset);
}
void HASHBLOB_to_little_endian(PHASHBLOB in_hash_blob, PHASHBLOB out_hash_blob)
{
	HASHBLOB_FULLFILE_to_little_endian(&in_hash_blob->FullFile, &out_hash_blob->FullFile);
	HASHBLOB_HASHMAP_to_little_endian(&in_hash_blob->Hashmap, &out_hash_blob->Hashmap);
}

void EXTRABLOB_to_little_endian(PEXTRABLOB in_extra_blob, PEXTRABLOB out_extra_blob)
{
	UNSIGNED16_to_little_endian(in_extra_blob->Length, (char*)&out_extra_blob->Length);
}

void TAGGANTBLOB_to_little_endian(PTAGGANTBLOB in_tag_blob, PTAGGANTBLOB out_tag_blob)
{
	int i;
	PHASHBLOB_HASHMAP_DOUBLE hmd;
	/* Convert doubles */
	hmd = (PHASHBLOB_HASHMAP_DOUBLE)((char*)in_tag_blob + in_tag_blob->Hash.Hashmap.DoublesOffset);
	for (i = 0; i < in_tag_blob->Hash.Hashmap.Entries; i++)
	{
		HASHBLOB_HASHMAP_DOUBLE_to_little_endian(&hmd[i], &hmd[i]);
	}
	/* Walk through whole structure and convert numbers */
	TAGGANTBLOB_HEADER_little_endian(&in_tag_blob->Header, &out_tag_blob->Header);
	HASHBLOB_to_little_endian(&in_tag_blob->Hash, &out_tag_blob->Hash);
	EXTRABLOB_to_little_endian(&in_tag_blob->Extrablob, &out_tag_blob->Extrablob);
}

void TAGGANT_HEADER_to_little_endian(PTAGGANT_HEADER in_tag_header, PTAGGANT_HEADER out_tag_header)
{
	UNSIGNED32_to_little_endian(in_tag_header->MarkerBegin, (char*)&out_tag_header->MarkerBegin);
	UNSIGNED32_to_little_endian(in_tag_header->TaggantLength, (char*)&out_tag_header->TaggantLength);
	UNSIGNED32_to_little_endian(in_tag_header->CMSLength, (char*)&out_tag_header->CMSLength);
	UNSIGNED16_to_little_endian(in_tag_header->Version, (char*)&out_tag_header->Version);
}

void TAGGANT_FOOTER_to_little_endian(PTAGGANT_FOOTER in_tag_footer, PTAGGANT_FOOTER out_tag_footer)
{
	EXTRABLOB_to_little_endian(&in_tag_footer->Extrablob, &out_tag_footer->Extrablob);
	UNSIGNED32_to_little_endian(in_tag_footer->MarkerEnd, (char*)&out_tag_footer->MarkerEnd);
}

void TAGGANT_to_little_endian(PVOID in_tag, PVOID out_tag)
{
	UNSIGNED32 cmslength = ((PTAGGANT_HEADER)in_tag)->CMSLength;
	/* Convert taggant header */
	TAGGANT_HEADER_to_little_endian((PTAGGANT_HEADER)in_tag, (PTAGGANT_HEADER)out_tag);
	in_tag = (char*)in_tag + sizeof(TAGGANT_HEADER);
	out_tag = (char*)out_tag + sizeof(TAGGANT_HEADER);
	/* Copy CMS */
	memcpy(out_tag, in_tag, cmslength);
	in_tag = (char*)in_tag + cmslength;
	out_tag = (char*)out_tag + cmslength;
	/* Convert taggant footer */
	TAGGANT_FOOTER_to_little_endian((PTAGGANT_FOOTER)in_tag, (PTAGGANT_FOOTER)out_tag);
}

UNSIGNED64 UNSIGNED64_to_big_endian(char* buffer)
{
	int i;
	UNSIGNED64 res = buffer[7];

	for (i = 6; i >= 0; i--)
	{
		res = res << 8;
		res += buffer[i];
	}
	return res;
}

UNSIGNED32 UNSIGNED32_to_big_endian(char* buffer)
{
	return ((UNSIGNED32)buffer[3] << 0x18) + ((UNSIGNED32)buffer[2] << 0x10) + ((UNSIGNED32)buffer[1] << 8) + buffer[0];
}

UNSIGNED16 UNSIGNED16_to_big_endian(char* buffer)
{
	return ((UNSIGNED16)buffer[1] << 8) + buffer[0];
}

void PACKERINFO_to_big_endian(PPACKERINFO in_packer_info, PPACKERINFO out_packer_info)
{
	out_packer_info->PackerId = UNSIGNED32_to_big_endian((char*)&in_packer_info->PackerId);
	out_packer_info->VersionMajor = UNSIGNED16_to_big_endian((char*)&in_packer_info->VersionMajor);
	out_packer_info->VersionMinor = UNSIGNED16_to_big_endian((char*)&in_packer_info->VersionMinor);
	out_packer_info->VersionBuild = UNSIGNED16_to_big_endian((char*)&in_packer_info->VersionBuild);
	out_packer_info->Reserved = UNSIGNED16_to_big_endian((char*)&in_packer_info->Reserved);
}

void TAGGANTBLOB_HEADER_big_endian(PTAGGANTBLOB_HEADER in_tag_blob_header, PTAGGANTBLOB_HEADER out_tag_blob_header)
{
	out_tag_blob_header->Length = UNSIGNED16_to_big_endian((char*)&in_tag_blob_header->Length);
	out_tag_blob_header->Version = UNSIGNED16_to_big_endian((char*)&in_tag_blob_header->Version);
	PACKERINFO_to_big_endian(&in_tag_blob_header->PackerInfo, &out_tag_blob_header->PackerInfo);
}

void HASHBLOB_HEADER_to_big_endian(PHASHBLOB_HEADER in_hash_blob_header, PHASHBLOB_HEADER out_hash_blob_header)
{
	out_hash_blob_header->Length = UNSIGNED16_to_big_endian((char*)&in_hash_blob_header->Length);
	out_hash_blob_header->Type = UNSIGNED16_to_big_endian((char*)&in_hash_blob_header->Type);
	out_hash_blob_header->Version = UNSIGNED16_to_big_endian((char*)&in_hash_blob_header->Version);
	memcpy(&out_hash_blob_header->Hash, &in_hash_blob_header->Hash, sizeof(in_hash_blob_header->Hash));
}

void HASHBLOB_DEFAULT_to_big_endian(PHASHBLOB_DEFAULT in_hash_blob_default, PHASHBLOB_DEFAULT out_hash_blob_default)
{
	HASHBLOB_HEADER_to_big_endian(&in_hash_blob_default->Header, &out_hash_blob_default->Header);
}

void HASHBLOB_EXTENDED_to_big_endian(PHASHBLOB_EXTENDED in_hash_blob_extended, PHASHBLOB_EXTENDED out_hash_blob_extended)
{
	HASHBLOB_HEADER_to_big_endian(&in_hash_blob_extended->Header, &out_hash_blob_extended->Header);
	out_hash_blob_extended->PhysicalEnd = UNSIGNED64_to_big_endian((char*)&in_hash_blob_extended->PhysicalEnd);
}

void HASHBLOB_FULLFILE_to_big_endian(PHASHBLOB_FULLFILE in_hash_blob_full_file, PHASHBLOB_FULLFILE out_hash_blob_full_file)
{

	HASHBLOB_DEFAULT_to_big_endian(&in_hash_blob_full_file->DefaultHash, &out_hash_blob_full_file->DefaultHash);
	HASHBLOB_EXTENDED_to_big_endian(&in_hash_blob_full_file->ExtendedHash, &out_hash_blob_full_file->ExtendedHash);
}

void HASHBLOB_HASHMAP_DOUBLE_to_big_endian(PHASHBLOB_HASHMAP_DOUBLE in_hash_blob_hash_map_double, PHASHBLOB_HASHMAP_DOUBLE out_hash_blob_hash_map_double)
{
	out_hash_blob_hash_map_double->AbsoluteOffset = UNSIGNED64_to_big_endian((char*)&in_hash_blob_hash_map_double->AbsoluteOffset);
	out_hash_blob_hash_map_double->Length = UNSIGNED64_to_big_endian((char*)&in_hash_blob_hash_map_double->Length);
}

void HASHBLOB_HASHMAP_to_big_endian(PHASHBLOB_HASHMAP in_hash_blob_hash_map, PHASHBLOB_HASHMAP out_hash_blob_hash_map)
{
	HASHBLOB_HEADER_to_big_endian(&in_hash_blob_hash_map->Header, &out_hash_blob_hash_map->Header);
	out_hash_blob_hash_map->Entries = UNSIGNED16_to_big_endian((char*)&in_hash_blob_hash_map->Entries);
	out_hash_blob_hash_map->DoublesOffset = UNSIGNED16_to_big_endian((char*)&in_hash_blob_hash_map->DoublesOffset);
}

void HASHBLOB_to_big_endian(PHASHBLOB in_hash_blob, PHASHBLOB out_hash_blob)
{
	HASHBLOB_FULLFILE_to_big_endian(&in_hash_blob->FullFile, &out_hash_blob->FullFile);
	HASHBLOB_HASHMAP_to_big_endian(&in_hash_blob->Hashmap, &out_hash_blob->Hashmap);
}

void EXTRABLOB_to_big_endian(PEXTRABLOB in_extra_blob, PEXTRABLOB out_extra_blob)
{
	out_extra_blob->Length = UNSIGNED16_to_big_endian((char*)&in_extra_blob->Length);
}

void TAGGANTBLOB_to_big_endian(PTAGGANTBLOB in_tag_blob, PTAGGANTBLOB out_tag_blob)
{
	int i;
	PHASHBLOB_HASHMAP_DOUBLE hmd;
	/* Walk through whole structure and convert numbers */
	TAGGANTBLOB_HEADER_big_endian(&in_tag_blob->Header, &out_tag_blob->Header);
	HASHBLOB_to_big_endian(&in_tag_blob->Hash, &out_tag_blob->Hash);
	EXTRABLOB_to_big_endian(&in_tag_blob->Extrablob, &out_tag_blob->Extrablob);
	/* Convert doubles */
	hmd = (PHASHBLOB_HASHMAP_DOUBLE)((char*)out_tag_blob + out_tag_blob->Hash.Hashmap.DoublesOffset);
	for (i = 0; i < out_tag_blob->Hash.Hashmap.Entries; i++)
	{
		HASHBLOB_HASHMAP_DOUBLE_to_big_endian(&hmd[i], &hmd[i]);
	}
}

void TAGGANT_HEADER_to_big_endian(PTAGGANT_HEADER in_tag_header, PTAGGANT_HEADER out_tag_header)
{
	out_tag_header->MarkerBegin = UNSIGNED32_to_big_endian((char*)&in_tag_header->MarkerBegin);
	out_tag_header->TaggantLength = UNSIGNED32_to_big_endian((char*)&in_tag_header->TaggantLength);
	out_tag_header->CMSLength = UNSIGNED32_to_big_endian((char*)&in_tag_header->CMSLength);
	out_tag_header->Version = UNSIGNED16_to_big_endian((char*)&in_tag_header->Version);
}

void TAGGANT_FOOTER_to_big_endian(PTAGGANT_FOOTER in_tag_footer, PTAGGANT_FOOTER out_tag_footer)
{
	EXTRABLOB_to_big_endian(&in_tag_footer->Extrablob, &out_tag_footer->Extrablob);
	out_tag_footer->MarkerEnd = UNSIGNED32_to_big_endian((char*)&in_tag_footer->MarkerEnd);
}

void TAGGANT_to_big_endian(PVOID in_tag, PVOID out_tag)
{
	UNSIGNED32 cmslength = 0;
	/* Convert taggant header */
	TAGGANT_HEADER_to_big_endian((PTAGGANT_HEADER)in_tag, (PTAGGANT_HEADER)out_tag);
	cmslength = ((PTAGGANT_HEADER)out_tag)->CMSLength;
	in_tag = (char*)in_tag + sizeof(TAGGANT_HEADER);
	out_tag = (char*)out_tag + sizeof(TAGGANT_HEADER);
	/* Copy CMS */
	memcpy(out_tag, in_tag, cmslength);
	in_tag = (char*)in_tag + cmslength;
	out_tag = (char*)out_tag + cmslength;
	/* Convert taggant footer */
	TAGGANT_FOOTER_to_big_endian((PTAGGANT_FOOTER)in_tag, (PTAGGANT_FOOTER)out_tag);
}