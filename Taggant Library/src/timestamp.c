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

/*
 * Portions of this software include software developed by the OpenSSL Project for
 * use in the OpenSSL Toolkit (http://www.openssl.org/), and those portions
 * are governed by the OpenSSL Toolkit License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ts.h>
#include "http.h"
#include "callbacks.h"
#include "url.h"
#include "types.h"
#include "timestamp.h"
#include "timestamp_nonce.h"
#include "ossl_ts_rsp_verify.h"

#define	NONCE_LENGTH		64

TS_REQ* get_timestamp_request(char* hash, int hash_size, ASN1_INTEGER *nonce_asn1)
{
	int ret = 0;
	TS_REQ *ts_req = NULL;
	TS_MSG_IMPRINT *msg_imprint = NULL;
	X509_ALGOR *algo = NULL;
	unsigned char *data = NULL;
	ASN1_OBJECT *policy_obj = NULL;
	const EVP_MD* md = NULL;

	/* Setting default message digest. */
	if ((md = EVP_get_digestbyname("sha256")) == NULL)
	{
		goto err;
	}

	/* Creating request object. */
	if ((ts_req = TS_REQ_new()) == NULL)
	{
		goto err;
	}

	/* Setting version. */
	if (!TS_REQ_set_version(ts_req, 1)) goto err;

	/* Creating and adding MSG_IMPRINT object. */
	if ((msg_imprint = TS_MSG_IMPRINT_new()) == NULL)
	{
		goto err;
	}

	/* Adding algorithm. */
	if ((algo = X509_ALGOR_new()) == NULL)
	{
		goto err;
	}
	if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(md))) == NULL)
	{
		goto err;
	}
	if ((algo->parameter = ASN1_TYPE_new()) == NULL)
	{
		goto err;
	}
	algo->parameter->type = V_ASN1_NULL;
	if (!TS_MSG_IMPRINT_set_algo(msg_imprint, algo)) goto err;

	/* Adding message digest. */
	if (!TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)hash, hash_size)) goto err;

	if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint)) goto err;

	/* Setting policy if requested. */
	if ((policy_obj = OBJ_txt2obj("1.1.3", 0)) == NULL)
	{
		goto err;
	}
	if (policy_obj && !TS_REQ_set_policy_id(ts_req, policy_obj)) goto err;

	/* Setting nonce if requested. */
	if (nonce_asn1 && !TS_REQ_set_nonce(ts_req, nonce_asn1)) goto err;

	/* Setting certificate request flag if requested. */
	if (!TS_REQ_set_cert_req(ts_req, 1)) goto err;

	ret = 1;
 err:
	if (!ret)
	{
		TS_REQ_free(ts_req);
		ts_req = NULL;
	}
	TS_MSG_IMPRINT_free(msg_imprint);
	X509_ALGOR_free(algo);
	OPENSSL_free(data);
	ASN1_OBJECT_free(policy_obj);
	return ts_req;
}

#ifdef SPV_LIBRARY

UNSIGNED32 get_timestamp_response(const char* urlStr, char* hash, UNSIGNED32 hash_size, UNSIGNED32 httpTimeOut, TS_RESP** tsResponse)
{
	UNSIGNED32 result = TINTERNALERROR;
	BIO* responseBio = NULL;
	Url* url = NULL;
	TS_REQ* tsRequest = NULL;
	BIO* requestBio = NULL;
	int requestHeaderLength;
	int requestLength;
	int requestContentLength;
	char requestHeader[2048 + 256];
	char* request = NULL;
	void* contentBuffer = NULL;
	void* resultBuffer = NULL;
	int resultLength;
	TS_MSG_IMPRINT* msgImprint = NULL;
	ASN1_OCTET_STRING* hashedMessage = NULL;
	int hashedMessageLength;
	int httpResult;
	char *urlBuffer = NULL;
	int redirection = 0;

	/* Check if TS url is specified */
	if (!urlStr)
	{
		goto end;
	}

	/* Get Request for timestamp */
	tsRequest = get_timestamp_request(hash, hash_size, create_nonce(NONCE_LENGTH));
	msgImprint = TS_REQ_get_msg_imprint(tsRequest);
	hashedMessage = TS_MSG_IMPRINT_get_msg(msgImprint);
	hashedMessageLength = ASN1_STRING_length((ASN1_STRING*)hashedMessage);
	if ((int)hash_size != hashedMessageLength)
	{
		goto end;
	}

	requestBio = BIO_new(BIO_s_mem());
	if (requestBio == NULL)
	{
		goto end;
	}

	if (!i2d_TS_REQ_bio(requestBio, tsRequest))
	{
		goto end;
	}

	contentBuffer = memory_alloc(BIO_number_written(requestBio));
	if (contentBuffer == NULL)
	{
		goto end;
	}

    requestContentLength = BIO_read(requestBio, contentBuffer, BIO_number_written(requestBio));

    /* Allocate memory buffer for timestamp server url */
    urlBuffer = memory_alloc(strlen(urlStr) + 1);
    if (!urlBuffer)
    {
    	goto end;
    }
    /* Copy TS url to allocated buffer */
    strcpy(urlBuffer, urlStr);

http_redirect:

	/* Parse and check URL */
	url = parse_url(urlBuffer);
	if (url == NULL)
	{
		goto end;
	}
	if (strcmp(url->Scheme, "http") != 0)
	{
		goto end;
	}

    requestHeaderLength = sprintf(requestHeader, "POST %s HTTP/1.0\r\nHOST: %s\r\nPragma: no-cache\r\nContent-Type: application/timestamp-query\r\nAccept: application/timestamp-reply\r\nContent-Length: %d\r\n\r\n",
    		urlBuffer, url->Host, requestContentLength);

	requestLength = requestHeaderLength + requestContentLength;

	request = (char*)memory_alloc(requestLength);
	if (request == NULL)
	{
		goto end;
	}

	memcpy(request, requestHeader, requestHeaderLength);
	memcpy(request + requestHeaderLength, contentBuffer, requestContentLength);

	httpResult = http_read(url->Host, request, requestLength, url->Port, httpTimeOut, 1, &resultBuffer, &resultLength);
	if (httpResult == HTTP_REDIRECTION && (resultBuffer) && !redirection)
	{
		free_url(url);
		url = NULL;
		memory_free(request);
		request = NULL;
		/* Allocated buffer for redirected url */
	    urlBuffer = memory_realloc(urlBuffer, resultLength);
	    if (!urlBuffer)
	    {
	    	goto end;
	    }
	    memcpy(urlBuffer, resultBuffer, resultLength);
	    memory_free(resultBuffer);
	    redirection++;
		goto http_redirect;
	} else
	if ((httpResult == HTTP_NOERROR) && (resultBuffer))
	{
		responseBio = BIO_new(BIO_s_mem());
		if (responseBio == NULL)
		{
			goto end;
		}
		BIO_write(responseBio, resultBuffer, resultLength);

		*tsResponse = d2i_TS_RESP_bio(responseBio, NULL);
		if (*tsResponse == NULL)
		{
			goto end;
		}

		result = TNOERR;
	}
	else
	{
		switch (httpResult)
		{
			case HTTP_NOLIVEINTERNET_ERROR:
				result = TNONET;
				break;
			case HTTP_TIMEOUT_ERROR:
				result = TTIMEOUT;
				break;
			case HTTP_RESPONSESTATUS_ERROR:
				result = TSERVERERROR;
				break;
			default:
				result = TINTERNALERROR;
				break;
		}
	}

end:
	free_url(url);
	if (tsRequest != NULL)
	{
		TS_REQ_free(tsRequest);
	}
	if (requestBio != NULL)
	{
		BIO_free_all(requestBio);
	}
	if (responseBio != NULL)
	{
		BIO_free_all(responseBio);
	}
	if (request != NULL)
	{
		memory_free(request);
	}
	if (contentBuffer != NULL)
	{
		memory_free(contentBuffer);
	}
	if (resultBuffer != NULL)
	{
		memory_free(resultBuffer);
	}
	if (urlBuffer != NULL)
	{
		memory_free(urlBuffer);
	}

	return result;
}

#endif

int check_time_stamp(TS_RESP* tsResponse, X509* caCert, char* hash, UNSIGNED32 hash_size)
{
	int result = 0;
	TS_REQ* tsRequest = NULL;
	TS_VERIFY_CTX* ctx = NULL;
	TS_MSG_IMPRINT* msgImprint = NULL;
	ASN1_OCTET_STRING* hashedMessage = NULL;
	int hashedMessageLength;

	tsRequest = get_timestamp_request(hash, hash_size, tsResponse->tst_info->nonce);

	msgImprint = TS_REQ_get_msg_imprint(tsRequest);
	hashedMessage = TS_MSG_IMPRINT_get_msg(msgImprint);
	hashedMessageLength = ASN1_STRING_length((ASN1_STRING*)hashedMessage);
	if (hashedMessageLength != (int)hash_size)
	{
		goto end;
	}

	if (!(ctx = TS_REQ_to_TS_VERIFY_CTX(tsRequest, NULL)))
	{
		goto end;
	}

	ctx->flags |= TS_VFY_SIGNATURE;

	ctx->store =  X509_STORE_new();
	X509_STORE_add_cert(ctx->store, caCert);

	if (ossl_TS_RESP_verify_response(ctx, tsResponse))
	{
		result = 1;
	}
end:
	if (tsRequest != NULL)
	{
		TS_REQ_free(tsRequest);
	}

	if (ctx != NULL)
	{
		TS_VERIFY_CTX_free(ctx);
	}
	return result;
}

UNSIGNED64 time_as_unsigned64(int year, int month, int day, int hour, int minute, int second)
{
	UNSIGNED64 days = ((year - 1970) * (365 + 365 + 366 + 365) + 1) / 4 + day - 1;
	switch (month)
	{
		case 2: days += 31; break;
		case 3: days += 31 + 28; break;
		case 4: days += 31 + 28 + 31; break;
		case 5: days += 31 + 28 + 31 + 30; break;
		case 6: days += 31 + 28 + 31 + 30 + 31; break;
		case 7: days += 31 + 28 + 31 + 30 + 31 + 30; break;
		case 8: days += 31 + 28 + 31 + 30 + 31 + 30 + 31; break;
		case 9: days += 31 + 28 + 31 + 30 + 31 + 30 + 31 + 31; break;
		case 10: days += 31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30; break;
		case 11: days += 31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31; break;
		case 12: days += 31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30; break;
	}
	if ((month >= 3) && (((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0)))
	{
		days++;
	}
	return (days * 24 * 3600) + (hour * 3600) + (minute * 60) + second;
}

