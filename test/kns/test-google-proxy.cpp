/*===========================================================================
*
*                            PUBLIC DOMAIN NOTICE
*               National Center for Biotechnology Information
*
*  This software/database is a "United States Government Work" under the
*  terms of the United States Copyright Act.  It was written as part of
*  the author's official duties as a United States Government employee and
*  thus cannot be copyrighted.  This software/database is freely available
*  to the public for use. The National Library of Medicine and the U.S.
*  Government have not placed any restriction on its use or reproduction.
*
*  Although all reasonable efforts have been taken to ensure the accuracy
*  and reliability of the software and data, the NLM and the U.S.
*  Government do not and cannot warrant the performance or results that
*  may be obtained by using this software or data. The NLM and the U.S.
*  Government disclaim all warranties, express or implied, including
*  warranties of performance, merchantability or fitness for any particular
*  purpose.
*
*  Please cite the author in any work or product based on this material.
*
* ===========================================================================
*
*/

#include <kfs/file.h> /* KFileRelease */
#include <kfg/kfg-priv.h> /* KConfigMakeEmpty */

#include <klib/debug.h> /* KDbgSetString */

#include <kns/endpoint.h> /* KNSManagerInitDNSEndpoint */
#include <kns/http.h> /* KNSManagerMakeHttpFile */
#include <kns/manager.h> /* KNSManagerRelease */
#include <kns/tls.h> /* KNSManagerSetAllowAllCerts */

#include <ktst/unit_test.hpp> // TEST_SUITE

#include <../../libs/kns/mgr-priv.h> /* KNSManager */

TEST_SUITE ( GoogleProxyTestSuite )

static KConfig * KFG = NULL;

static const char * http_proxy = NULL;

TEST_CASE ( GoogleProxyTest ) {
    KNSManager * mgr = NULL;
    REQUIRE_RC ( KNSManagerMake ( & mgr ) );

    const KFile * file = NULL;

    /* we fail to vaidate googleapis' certificate */
    REQUIRE_RC_FAIL ( KNSManagerMakeHttpFile ( mgr, & file, NULL, 0x01010000,
       "https://storage.googleapis.com/yan-blastdb/2018-09-12-08-33-02/fuse.xml"
      ) );

    REQUIRE_RC ( KNSManagerSetAllowAllCerts ( mgr, true ) );

    /* skip certificate vaildation; direct (no proxy) connection*/
#if GOOGLE_FILE_EXISTS
    REQUIRE_RC ( KNSManagerMakeHttpFile ( mgr, & file, NULL, 0x01010000,
       "https://storage.googleapis.com/yan-blastdb/2018-09-12-08-33-02/fuse.xml"
      ) );
#endif

    REQUIRE_RC ( KFileRelease ( file ) );
    file = NULL;

    REQUIRE_RC ( KConfigWriteString ( KFG, "/tls/allow-all-certs", "true" ) );
    REQUIRE_RC ( KConfigWriteString ( KFG, "/http/proxy/only", "true" ) );
    REQUIRE_RC ( KConfigWriteString ( KFG, "/http/proxy/path", "bad.host" ) );

    mgr -> notSingleton = true;
    REQUIRE_RC ( KNSManagerRelease ( mgr ) );
    REQUIRE_RC ( KNSManagerMake ( & mgr ) );

    /* fail to use bad proxy */
    REQUIRE_RC_FAIL ( KNSManagerMakeHttpFile ( mgr, & file, NULL, 0x01010000,
       "https://storage.googleapis.com/yan-blastdb/2018-09-12-08-33-02/fuse.xml"
      ) );

    http_proxy = getenv("http_proxy");
    if (http_proxy == NULL)
        http_proxy = "webproxy:3128";

    REQUIRE_RC ( KConfigWriteString ( KFG, "/http/proxy/path", http_proxy) );

    String dns;
    StringInitCString( & dns, "webproxy" );

    KEndPoint ep;
    memset(&ep, 0, sizeof ep);
    if (KNSManagerInitDNSEndpoint(mgr, &ep, &dns, 3128) != 0)
        http_proxy = NULL;

    mgr -> notSingleton = true;
    REQUIRE_RC ( KNSManagerRelease ( mgr ) );
    REQUIRE_RC ( KNSManagerMake ( & mgr ) );

    /* standard connection via proxy:
       format HTTP request in KClientHttpRequestFormatMsgBegin using
       absoluteURI form of Request-URI */
    if (http_proxy != NULL)
        REQUIRE_RC ( KNSManagerMakeHttpFile ( mgr, & file, NULL, 0x01010000,
            "http://www.baidu.com/" ) );
    else
        REQUIRE_RC_FAIL(KNSManagerMakeHttpFile(mgr, &file, NULL, 0x01010000,
            "http://www.baidu.com/"));

    char buffer [ 256 ] = "";
    size_t num_read = 0;
    /* reuse the same absoluteURI form stored in KFile */
    if (http_proxy != NULL)
        REQUIRE_RC ( KFileRead ( file, 0, buffer, sizeof buffer, & num_read ) );
    else
        REQUIRE_RC_FAIL(KFileRead(file, 0, buffer, sizeof buffer, &num_read));

    REQUIRE_RC ( KFileRelease ( file ) );
    file = NULL;

    /* special connection via proxy:
       format HTTP request in KClientHttpRequestFormatMsgBegin using
       origin-form (absolute-path) of Request-URI 
       ( https://tools.ietf.org/html/rfc7230#section-5.3.1 ) */
#if GOOGLE_FILE_EXISTS
    REQUIRE_RC ( KNSManagerMakeHttpFile ( mgr, & file, NULL, 0x01010000,
       "https://storage.googleapis.com/yan-blastdb/2018-09-12-08-33-02/fuse.xml"
      ) );

    /* reuse the same origin-form stored in KFile */
    REQUIRE_RC ( KFileRead ( file, 0, buffer, sizeof buffer, & num_read ) );
#endif

    REQUIRE_RC ( KFileRelease ( file ) );
    file = NULL;

    REQUIRE_RC ( KNSManagerRelease ( mgr ) );
}

TEST_CASE ( KClientHttpRequestPOSTTest ) {
   /* Here proxy is used from configuration created in the previous test case */

    KNSManager * mgr = NULL;
    REQUIRE_RC ( KNSManagerMake ( & mgr ) );

    KHttpRequest * req = NULL;
    if (http_proxy != NULL)
        REQUIRE_RC ( KNSManagerMakeClientRequest ( mgr, & req, 0x01000000,
            NULL, "https://www.ncbi.nlm.nih.gov/Traces/names/names.fcgi" ) ); 
    else
        REQUIRE_RC_FAIL(KNSManagerMakeClientRequest(mgr, &req, 0x01000000,
            NULL, "https://www.ncbi.nlm.nih.gov/Traces/names/names.fcgi"));

    if (http_proxy != NULL) {
        REQUIRE_RC(KHttpRequestAddPostParam(req, "acc=AAAB01"));
        REQUIRE_RC(KHttpRequestAddPostParam(req, "accept-proto=https"));
        REQUIRE_RC(KHttpRequestAddPostParam(req, "version=1.2"));
    }
    else
        REQUIRE_RC_FAIL(KHttpRequestAddPostParam(req, "acc=AAAB01"));

    KHttpResult * rslt = NULL;
    /* POST: format HTTP request in KClientHttpRequestFormatMsgBegin using
       absoluteURI form of Request-URI
       ( https://tools.ietf.org/html/rfc2616#section-5.1.2 ) */
    if (http_proxy != NULL)
        REQUIRE_RC ( KHttpRequestPOST ( req, & rslt ) );
    else
        REQUIRE_RC_FAIL(KHttpRequestPOST(req, &rslt));

    REQUIRE_RC ( KHttpResultRelease ( rslt ) );

    REQUIRE_RC ( KHttpRequestRelease ( req ) );

    REQUIRE_RC ( KNSManagerRelease ( mgr ) );
}

extern "C" {
    ver_t CC KAppVersion ( void ) { return 0; }

    rc_t CC KMain ( int argc, char * argv [] ) { if (
0 ) assert ( ! KDbgSetString ( "KNS-DNS"   ) );   if (
1 ) assert ( ! KDbgSetString ( "KNS-HTTP"  ) );   if (
0 ) assert ( ! KDbgSetString ( "KNS-PROXY" ) );

        rc_t rc = KConfigMakeEmpty ( & KFG );

        if ( rc == 0 )
            rc = GoogleProxyTestSuite(argc, argv);

        rc_t r = KConfigRelease ( KFG );
        if ( r != 0 && rc == 0 )
            rc = r;

        return rc;
    }
}
