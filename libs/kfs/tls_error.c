/*==============================================================================
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
* =========================================================================== */

#include <ext/mbedtls/net_sockets.h> /* MBEDTLS_ERR_NET_RECV_FAILED */
#include <klib/rc.h> /* RC */
#include "tls_error.h" /* TlsError */

struct TlsError {
    bool delayErrReporting;
    int ret; /* return code of mbedtl */
    int rd_rc; /* read error returned from ciphertext stream */
    bool handshake; /* error from handhake of read */
};

rc_t TlsErrorRelease(TlsError * self) {
    if (self != NULL) {
        memset(self, 0, sizeof *self);
        free(self);
    }

    return 0;
}
    
rc_t TlsErrorMake(TlsError ** self) {
    if (self != NULL) {
        TlsError *p = NULL;

        p = calloc(1, sizeof *p);
        if (p == NULL)
            return RC(rcFS, rcStorage, rcAllocating, rcMemory, rcExhausted);

        *self = p;
    }

    return 0;
}

rc_t TlsErrorSetDelayReporting(TlsError *self, bool delay) {
    if (self != NULL)
        self->delayErrReporting = delay;

    return 0;
}

bool TlsErrorGetDelayReporting(TlsError * self) {
    if (self != NULL) {
        if (self->handshake && self->ret != 0
            && self->ret != MBEDTLS_ERR_NET_RECV_FAILED)
        {
            return false;
        }
        return self->delayErrReporting;
    }

    return false;
}

rc_t TlsErrorSet(TlsError * self, int ret, rc_t rd_rc, bool handshake) {
    if (self != NULL) {
        self->ret = ret;
        self->rd_rc = rd_rc;
        self->handshake = handshake;
        if (ret != 0 && handshake) {
            int i = 0;
        }
    }

    return 0;
}

rc_t TlsErrorGet(TlsError * self, int * ret, rc_t * rd_rc, bool * handshake) {
    int iDummy = 0;
    rc_t rDummy = 0;
    bool bDummy = false;

    if (self == NULL)
        return RC(rcFS, rcStorage, rcAccessing, rcSelf, rcNull);

    if (ret == NULL)
        ret = &iDummy;
    if (rd_rc == NULL)
        rd_rc = &rDummy;
    if (handshake == NULL)
        handshake = &bDummy;

    *ret = self->ret;
    *rd_rc = self->rd_rc;
    *handshake = self->handshake;

    return 0;
}

rc_t TlsErrorCopy(const TlsError * from, TlsError * to) {
    if (from != NULL && to != NULL) {
        to->ret = from->ret;
        to->rd_rc = from->rd_rc;
        to->handshake = from->handshake;
        if (to->ret != 0 && to->handshake) {
            int i = 0;
        }
    }

    return 0;
}
