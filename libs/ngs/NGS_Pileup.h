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

#ifndef _h_ngs_pileup_
#define _h_ngs_pileup_

typedef struct NGS_Pileup NGS_Pileup;
#ifndef NGS_PILEUP
#define NGS_PILEUP NGS_Pileup
#endif

#ifndef _h_ngs_refcount_
#define NGS_REFCOUNT NGS_PILEUP
#include "NGS_Refcount.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------------------------------------------
 * forwards
 */
struct NGS_String;
struct NGS_PileupEvent;

/*--------------------------------------------------------------------------
 * NGS_Pileup
 */
 

/* ToRefcount
 *  inline cast that preserves const
 */
#define NGS_PileupToRefcount( self ) \
    ( & ( self ) -> dad )

/* Release
 *  release reference
 */
#define NGS_PileupRelease( self, ctx ) \
    NGS_RefcountRelease ( NGS_PileupToRefcount ( self ), ctx )

/* Duplicate
 *  duplicate reference
 */
#define NGS_PileupDuplicate( self, ctx ) \
    ( ( NGS_Pileup* ) NGS_RefcountDuplicate ( NGS_PileupToRefcount ( self ), ctx ) )

struct NGS_String* NGS_PileupGetReferenceSpec ( const NGS_Pileup* self, ctx_t ctx );

int64_t NGS_PileupGetReferencePosition ( const NGS_Pileup* self, ctx_t ctx );

struct NGS_PileupEvent* NGS_PileupGetPileupEvents ( const NGS_Pileup* self, ctx_t ctx );

unsigned int NGS_PileupGetPileupDepth ( const NGS_Pileup* self, ctx_t ctx );
 
bool NGS_PileupIteratorNext ( NGS_Pileup* self, ctx_t ctx );


/*--------------------------------------------------------------------------
 * implementation details
 */
struct NGS_Pileup
{
    NGS_Refcount dad;
};

typedef struct NGS_Pileup_vt NGS_Pileup_vt;
struct NGS_Pileup_vt
{
    NGS_Refcount_vt dad;

    /* Pileup interface */
    struct NGS_String *         ( * get_reference_spec )        ( const NGS_PILEUP * self, ctx_t ctx );
    int64_t                     ( * get_reference_position )    ( const NGS_PILEUP * self, ctx_t ctx );
    struct NGS_PileupEvent *    ( * get_pileup_events )         ( const NGS_PILEUP * self, ctx_t ctx );
    unsigned int                ( * get_pileup_depth )          ( const NGS_PILEUP * self, ctx_t ctx );

    /* PileupIterator interface */
    bool ( * next ) ( NGS_PILEUP * self, ctx_t ctx );
};

/* Init
*/
void NGS_PileupInit ( ctx_t ctx, struct NGS_Pileup * self, NGS_Pileup_vt * vt, const char *clsname, const char *instname );

/* NullPileup
 * will error out on any call
 */
struct NGS_Pileup * NGS_PileupMakeNull ( ctx_t ctx, const struct NGS_String * spec );

#ifdef __cplusplus
}
#endif

#endif /* _h_ngs_pileup_ */
