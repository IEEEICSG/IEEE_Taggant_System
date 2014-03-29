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


#ifdef SPV_LIBRARY

#include <stdio.h>
#include <string.h>

#ifdef WIN32
	#include <winsock2.h>
#else
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <sys/types.h>
	#include <stdlib.h>
	#include <stdbool.h>
	#include <unistd.h>
#endif

#ifdef WIN32
#	define SOCKET_DESCRIPTOR SOCKET
#else
#	define SOCKET_DESCRIPTOR int
#	ifndef INVALID_SOCKET
#		define INVALID_SOCKET (-1)
#	endif
#endif

#include "http.h"
#include "callbacks.h"
#include "miscellaneous.h"

const char *HTTP_Header_Location = "Location: ";

int safe_send(SOCKET_DESCRIPTOR socketDescriptor, const void *buffer, int length, int flag);
void close_socket(SOCKET_DESCRIPTOR socketDescriptor);

int http_read(const char *hostName, const void *requestString, int requestLength, int port, int readTimeOut,
		int contentOnly, void **resultBuffer, int *resultBufferLength)
{
	int responseStatusCode = 0;
	SOCKET_DESCRIPTOR socketDescriptor;
    struct hostent *host;
    struct sockaddr_in serverAddr;

	char *buffer = NULL;
	int bytes_read = 0;
	int count = 0;
	int readCount = 0;
	int res;

	char *r_start, *r_end;

#ifdef WIN32
	WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	if (socketDescriptor == INVALID_SOCKET)
	{
#ifdef WIN32
		WSACleanup();
#endif
		return HTTP_SOCKET_ERROR;
	}

	host = (struct hostent *) gethostbyname(hostName);

    if (host == NULL)
    {
		res = HTTP_NOLIVEINTERNET_ERROR;
		goto exit_sopened;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = (short)host->h_addrtype;
	serverAddr.sin_port = htons((unsigned short)port);
    serverAddr.sin_addr.s_addr = *(unsigned long*)host->h_addr;

    if (connect(socketDescriptor, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
		res = HTTP_CONNECT_ERROR;
		goto exit_sopened;
    }

    /* Send request */

    if (safe_send(socketDescriptor, requestString, requestLength, 0) != requestLength)
    {
		res = HTTP_SEND_ERROR;
		goto exit_sopened;
	}

	buffer = (char*)memory_alloc(0);
	count = 0;
	for(;;)
	{
		fd_set rfds;
		struct timeval tv;
		int selectResult;

		tv.tv_sec = readTimeOut;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		FD_SET(socketDescriptor, &rfds);

		selectResult = select((int)socketDescriptor + 1, &rfds, NULL, NULL, &tv);
		if ((selectResult == 0) || (selectResult == -1))
		{
			res = HTTP_READTIMEOUT_ERROR;
			goto exit_sopened;
		}

		count++;
		buffer = (char*)memory_realloc((void*)buffer, HTTP_READ_BUFFER_SIZE * count);

		if (!buffer)
		{
			res = HTTP_RECEIVE_ERROR;
			goto exit_sopened;
		}

#ifdef WIN32
		readCount = recv(socketDescriptor, buffer + bytes_read, HTTP_READ_BUFFER_SIZE, 0);
#else
		readCount = read(socketDescriptor, buffer + bytes_read, HTTP_READ_BUFFER_SIZE);
#endif

		if (readCount == 0)
		{
			buffer[bytes_read] = '\0';
			break;
		}
		if (readCount < 0)
		{
			res = HTTP_RECEIVE_ERROR;
			goto exit_sopened;
		}
		bytes_read += readCount;

	}

	close_socket(socketDescriptor);

	if (buffer)
	{
		if (sscanf(buffer, "%*s %d",  &responseStatusCode) != 1)
		{
			res = HTTP_RECEIVE_ERROR;
			goto exit_buffree;
		}
	}

	switch (responseStatusCode)
	{
		case 200:
		{
			/* Status is OK */
			break;
		}
		case 301:
		{
			/* Permanent redirection, extract new location */
			if (buffer)
			{
				r_start = strstr(buffer, HTTP_Header_Location);
				if (r_start)
				{
					r_start += strlen(HTTP_Header_Location);
					r_end = strstr(r_start, "\r\n");
					if (r_end && r_end > r_start)
					{
						*resultBufferLength = r_end - r_start;
						*resultBuffer = memory_alloc(*resultBufferLength + 1);
						if (!*resultBuffer)
						{
							res = HTTP_RECEIVE_ERROR;
							goto exit_buffree;
						}
						memcpy(*resultBuffer, r_start, *resultBufferLength);
						/* Put null terminating character */
						((char*)*resultBuffer)[*resultBufferLength] = '\0';
						*resultBufferLength += 1;
						res = HTTP_REDIRECTION;
						goto exit_buffree;
					}
				}
			}
			break;
		}
		default:
		{
			/* No HTTP return code */
			res = HTTP_RESPONSESTATUS_ERROR;
			goto exit_buffree;
		}
	}

	if (contentOnly == 0)
	{
		*resultBuffer = buffer;
		*resultBufferLength = bytes_read;
	}
	else
	{
		int headerLength;
		char* temp = strstr(buffer, "\r\n\r\n");
		headerLength = (int)(temp - buffer + 4);
		res = HTTP_CONTENT_ERROR;

		if (!temp) goto exit_buffree;

		*resultBuffer = memory_alloc(bytes_read - headerLength);

		if (!*resultBuffer) goto exit_buffree;

		*resultBuffer = memcpy(*resultBuffer, temp + 4, bytes_read - headerLength);
		*resultBufferLength = bytes_read - headerLength;

		res = HTTP_NOERROR;
		goto exit_buffree;
	}

	res = HTTP_NOERROR;
	goto exit;

exit_sopened:
	close_socket(socketDescriptor);
exit_buffree:
	if (buffer)
	{
		memory_free(buffer);
	}
exit:
	return res;
}

int safe_send(SOCKET_DESCRIPTOR socketDescriptor, const void *buffer, int length, int flag)
{
	int sentCount = 0;
    char *point = (char*)buffer;
    while(sentCount < length)
    {
    	int tempResult;
#ifdef WIN32
    	tempResult = send(socketDescriptor, (const char*)point, length - sentCount, flag);
        if(tempResult == SOCKET_ERROR || tempResult == 0)
        {
        	return -1;
        }
#else
        tempResult = write(socketDescriptor, (const void*)point, length - sentCount);
        if(tempResult <= 0)
        {
        	return -1;
        }
#endif

        point += tempResult;
        sentCount += tempResult;
    }
    return sentCount;
}

void close_socket(SOCKET_DESCRIPTOR socketDescriptor)
{
#ifdef WIN32
	closesocket(socketDescriptor);
	WSACleanup();
#else
	close(socketDescriptor);
#endif
}

#endif
