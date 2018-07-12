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
* ==============================================================================
*
*/
#include <kns/extern.h>

#include <kns/manager.h>
#include <kns/http.h>
#include <kns/adapt.h>
#include <kns/endpoint.h>
#include <kns/socket.h>
#include <kns/stream.h>
#include <kns/impl.h>
#include <kfs/file.h>
#include <kfs/directory.h>

#ifdef ERR
#undef ERR
#endif

#include <klib/text.h>
#include <klib/container.h>
#include <klib/out.h>
#include <klib/log.h>
#include <klib/refcount.h>
#include <klib/rc.h>
#include <klib/printf.h>
#include <klib/vector.h>
#include <kproc/timeout.h>

#include <os-native.h>
#include <strtol.h>
#include <va_copy.h>

#include "mgr-priv.h"
#include "stream-priv.h"

#include <sysalloc.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "http-priv.h"

#include "../vfs/path-priv.h" /* VPathMakeFmt */

/*--------------------------------------------------------------------------
 * URLBlock
 *  RFC 3986
 *
 * TBD - replace with VPath
 */

static void _String_Fini ( String * self ) {
    assert ( self );
    free ( ( void * ) self -> addr );
    memset ( self, 0, sizeof * self );
}

void URLBlockFini ( URLBlock *self )
{
    assert ( self );

    /* don't free host - it was not allocated here */

    _String_Fini ( & self -> scheme );
    _String_Fini ( & self -> path  );
    _String_Fini ( & self -> path  );
    _String_Fini ( & self -> query  );

    memset ( self, 0, sizeof * self );
}

static rc_t _String_Set ( const String * self, String * out ) {
    assert ( self && out );

    if ( self -> size == 0 )
        memset ( out, 0, sizeof * out );
    else {
        out -> addr = string_dup ( self -> addr, self -> size );
        if ( out -> addr == NULL )
            return RC( rcNS, rcUrl, rcPacking, rcMemory, rcExhausted );

        out -> len  = self -> len;
        out -> size = self -> size;
    }

    return 0;
}

rc_t URLBlockCopy ( const URLBlock * self, URLBlock * copy )
{
    rc_t rc = 0;

    assert ( self && copy );

    memset ( copy, 0, sizeof * copy );

    if ( rc == 0 )
        rc = _String_Set ( & self -> scheme, & copy -> scheme );
    if ( rc == 0 )
        rc = _String_Set ( & self -> path  , & copy -> path );
    if ( rc == 0 )
        rc = _String_Set ( & self -> query , & copy -> query );

    /* keep the original pointer because of its use in KSubBuffer */
    copy -> host = self -> host;

    copy -> port = self -> port;
    copy -> tls  = self -> tls;

    if ( rc != 0 )
        URLBlockFini ( copy );

    return rc;
}

typedef enum
{
    st_NONE,
    st_HTTP,
    st_HTTPS,
    st_S3
} SchemeType;

/* Init
 *  accept standard, full http URL:
 *    <scheme>://<host>[:<port>]/<path>[?<query>][#<fragment>]
 *
 *  scheme can be missing, i.e.:
 *    //<host>[:<port>]/<path>[?<query>][#<fragment>]
 *
 *  we can also accept missing path[query][fragment], i.e.:
 *    <scheme>://<host>[:<port>]
 *    //<host>[:<port>]
 *
 *  finally, we can accept path without host, i.e.:
 *    /<path>[?<query>][#<fragment>]
 *
 *  patterns to reject:
 *    <scheme>:/<path>...    # scheme followed by anything other than '//'
 *    <path>...              # no leading '/'
 */
rc_t URLBlockInit ( URLBlock * self, const char * url, size_t url_size )
{
    VPath * path = NULL;
    rc_t rc = VPathMakeFmt ( & path, "%.*s", ( uint32_t ) url_size, url );
    if ( rc != 0 )
        return rc;
    else {
        SchemeType scheme_type = st_NONE;

        String str;

        assert ( self );
        memset ( self, 0, sizeof * self );

        rc = VPathGetScheme ( path, & str );
        if ( rc == 0 ) {
            String http;
            CONST_STRING ( & http, "http" );

            rc = _String_Set ( & str, & self -> scheme );

            if ( StringCaseEqual ( & str, & http ) )
                scheme_type = st_HTTP;
            else {
                String https;
                CONST_STRING ( & https, "https" );
                if ( StringCaseEqual ( & str, & https ) ) {
                    scheme_type = st_HTTPS;
                    self -> tls = true;
                }
                else {
                    String s3;
                    CONST_STRING ( & s3, "s3" );
                    if ( StringCaseEqual ( & str, & s3 ) )
                        scheme_type = st_S3;
                }
            }
        }

        if ( rc == 0 )
            rc = VPathGetHost ( path, & str );
        if ( rc == 0 && str . size > 0 ) {
            size_t i = 0;
            assert ( str . addr );
            for ( i = 0; url_size - i >= str . size; ++ i ) {
                if ( url [ i ] != str .addr [ 0 ] )
                    continue;
                if ( string_cmp ( str . addr, str . size,
                                    url + i, str . size, str . size ) == 0 )
                {
                /* keep the original pointer because of its use in KSubBuffer */
                    self -> host . addr = url + i;
                    self -> host . size = str . size;
                    self -> host . len  = str . len;
                    break;
                }
            }
            if ( self -> host . size == 0 )
                rc = RC ( rcNS, rcUrl, rcParsing, rcName, rcNotFound );
        }

        if ( rc == 0 )
            rc = VPathGetPath ( path, & str );
        if ( rc == 0 )
            rc = _String_Set ( & str, & self -> path );

        if ( rc == 0 )
            rc = VPathGetQuery ( path, & str );
        if ( rc == 0 )
            rc = _String_Set ( & str, & self -> query );

        if ( rc == 0 ) {
            self -> port = VPathGetPortNum ( path );
            if ( self -> port == 0 )
                switch ( scheme_type ) {
                    case st_HTTP :
                    case st_S3   : self -> port =  80; break;
                    case st_HTTPS: self -> port = 443; break;
                    default      :                     break;
                }
        }

        {
            rc_t r = VPathRelease ( path );
            if ( rc == 0 && r != 0 )
                rc = r;
        }
    }

    return rc;
}

void URLBlockInitHost ( URLBlock * self,
                        const String * host, uint32_t port, bool tls )
{
    assert ( self && host );

    memset ( self, 0, sizeof * self );

    if ( tls )
        CONST_STRING ( & self -> scheme,"https");
    else
        CONST_STRING ( & self -> scheme,"https");

    self -> host = * host;
    self -> port = port;
    self -> tls  = tls;
}

/*--------------------------------------------------------------------------
 * KHttpHeader
 *  node structure to place http header lines into a BSTree
 */

void CC KHttpHeaderWhack ( BSTNode *n, void *ignore )
{
    KHttpHeader * self = ( KHttpHeader* ) n;
    KDataBufferWhack ( & self -> value_storage );
    free ( self );
}

int64_t CC KHttpHeaderSort ( const BSTNode *na, const BSTNode *nb )
{
    const KHttpHeader *a = ( const KHttpHeader* ) na;
    const KHttpHeader *b = ( const KHttpHeader* ) nb;

    return StringCaseCompare ( & a -> name, & b -> name );
}

int64_t CC KHttpHeaderCmp ( const void *item, const BSTNode *n )
{
    const String *a = item;
    const KHttpHeader *b = ( const KHttpHeader * ) n;

    return StringCaseCompare ( a, & b -> name );
}
