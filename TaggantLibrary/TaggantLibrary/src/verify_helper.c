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

#include "global.h"
#include <string.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/ts.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>


/* This function is copied from openssl x509_vfy.c. It checks certificates chain.
   We customized this function and eliminated check of certificates date */

int verify_certificates_chain(X509_STORE_CTX *ctx)
{
    int ok=0,n;
    X509 *xs,*xi;
    EVP_PKEY *pkey=NULL;
    int (*cb)(int xok,X509_STORE_CTX *xctx);

    cb=ctx->verify_cb;

    n=sk_X509_num(ctx->chain);
    ctx->error_depth=n-1;
    n--;
    xi=sk_X509_value(ctx->chain,n);

    if (ctx->check_issued(ctx, xi, xi))
        xs=xi;
    else
    {
        if (n <= 0)
        {
            ctx->error=X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
            ctx->current_cert=xi;
            ok=cb(0,ctx);
            goto end;
        }
        else
        {
            n--;
            ctx->error_depth=n;
            xs=sk_X509_value(ctx->chain,n);
        }
    }

/*	ctx->error=0;  not needed */
    while (n >= 0)
    {
        ctx->error_depth=n;

        /* Skip signature check for self signed certificates unless
         * explicitly asked for. It doesn't add any security and
         * just wastes time.
         */
        if (!xs->valid && (xs != xi || (ctx->param->flags & X509_V_FLAG_CHECK_SS_SIGNATURE)))
        {
            if ((pkey=X509_get_pubkey(xi)) == NULL)
            {
                ctx->error=X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
                ctx->current_cert=xi;
                ok=(*cb)(0,ctx);
                if (!ok) goto end;
            }
            else if (X509_verify(xs,pkey) <= 0)
            {
                ctx->error=X509_V_ERR_CERT_SIGNATURE_FAILURE;
                ctx->current_cert=xs;
                ok=(*cb)(0,ctx);
                if (!ok)
                {
                    EVP_PKEY_free(pkey);
                    goto end;
                }
            }
            EVP_PKEY_free(pkey);
            pkey=NULL;
        }

        xs->valid = 1;

        /* Do not check the time
        ok = check_cert_time(ctx, xs);
        if (!ok)
            goto end;
        */

        /* The last error (if any) is still in the error value */
        ctx->current_issuer=xi;
        ctx->current_cert=xs;
        ok=(*cb)(1,ctx);
        if (!ok) goto end;

        n--;
        if (n >= 0)
        {
            xi=xs;
            xs=sk_X509_value(ctx->chain,n);
        }
    }
    ok=1;
end:
    return ok;
}

