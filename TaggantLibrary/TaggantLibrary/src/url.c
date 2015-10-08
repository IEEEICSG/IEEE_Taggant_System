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
#include "url.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "callbacks.h"

int is_char(int c)
{
    return (!isalpha(c) && '+' != c && '-' != c && '.' != c) ? 0 : 1;
}

Url* parse_url(const char* urlStr)
{
    Url* url;
    const char* tempStr;
    const char* currentStr;
    char* port;
    int i, length;

    url = (Url*)memory_alloc(sizeof(Url));
    if (url == NULL)
    {
        return NULL;
    }
    url->Scheme = NULL;
    url->Host = NULL;
    url->Port = 80;

    currentStr = urlStr;

    /* Scheme */
    tempStr = strchr(currentStr, ':');
    if (tempStr == NULL)
    {
        goto error;
    }

    length = (int)(tempStr - currentStr);
    for ( i = 0; i < length; i++ )
    {
        if (!is_char(currentStr[i]) )
        {
            goto error;
        }
    }

    url->Scheme = (char*)memory_alloc(length + 1);
    if (url->Scheme == NULL)
    {
        goto error;
    }
    strncpy(url->Scheme, currentStr, length);
    url->Scheme[length] = '\0';
    for (i = 0; i < length; i++ )
    {
        url->Scheme[i] = (char)tolower(url->Scheme[i]);
    }

    /* Skip ':' */
    tempStr++;
    currentStr = tempStr;

    /* Check "//" */
    if (*currentStr != '/' || *(currentStr + 1) != '/')
    {
        goto error;
    }
    currentStr += 2;

    /* Host */
    tempStr = currentStr;
    while (*tempStr != '\0')
    {
        if ((*tempStr == ':') || (*tempStr == '/'))
        {
            break;
        }
        tempStr++;
    }
    length = (int)(tempStr - currentStr);
    if (length <= 0)
    {
        goto error;
    }
    url->Host = (char*)memory_alloc(length + 1);

    if (url->Host == NULL)
    {
        goto error;
    }
    strncpy(url->Host, currentStr, length);
    url->Host[length] = '\0';
    currentStr = tempStr;

    /* Port */
    if (*currentStr == ':' )
    {
        currentStr++;
        tempStr = currentStr;
        while ((*tempStr != '\0') && (*tempStr != '/'))
        {
            tempStr++;
        }
        length = (int)(tempStr - currentStr);
        if (length <= 0)
        {
            goto error;
        }

        port = (char*)memory_alloc(length + 1);
        if (port == NULL)
        {
            goto error;
        }
        strncpy(port, currentStr, length);
        port[length] = '\0';

        url->Port = atoi(port);
        if (url->Port <= 0)
        {
            url->Port = 80;
        }
        memory_free(port);
    }

    return url;

    error:
        free_url(url);
        return NULL;
}


void free_url(Url* url)
{
    /* Free url memory */
    if (url == NULL)
    {
        return;
    }
    if (url->Scheme != NULL)
    {
        memory_free(url->Scheme);
    }
    if (url->Host != NULL)
    {
        memory_free(url->Host);
    }
    memory_free(url);
}
