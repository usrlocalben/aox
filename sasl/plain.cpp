// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

/*! \class Plain plain.h
    Implements plain-text authentication (RFC 2595 section 6)

    SASL permits a distinction between the authentication ID (which
    credentials are checked) and the authorization ID (which is logged
    in). This class firmly insists that the two be the same.

    Note that there is also a different, incompatible plain-text
    mechanism offered by some servers and supported by some clients
    "AUTH=LOGIN", implemented by SaslLogin.
*/

#include "plain.h"

#include "estringlist.h"


/*! Creates a plain-text SASL authentication object on behalf of \a c */

Plain::Plain( EventHandler *c )
    : SaslMechanism( c, SaslMechanism::Plain )
{
    setState( AwaitingInitialResponse );
}


void Plain::parseResponse( const EString & response )
{
    EString authorizeId;
    EString authenticateId;
    EString secret;

    bool ok = parse( authorizeId, authenticateId, secret, response );
    if ( !ok || authenticateId != authorizeId ) {
        setState( Failed );

        if ( !ok )
            log( "PLAIN: Parse error for (?)", Log::Error );
        else
            log( "PLAIN: Client supplied two identities: " +
                 authenticateId.quoted() + ", " +
                 authorizeId.quoted(), Log::Error );
        return;
    }

    setState( Authenticating );
    setLogin( authenticateId );
    setSecret( secret );
    execute();
}


/*! Parses an AUTH=PLAIN \a response to extract the \a authenticateId,
    \a authorizeId, and \a pw.
*/

bool Plain::parse( EString & authorizeId, EString & authenticateId,
                   EString & pw, const EString & response )
{
    EStringList * l = EStringList::split( 0, response );
    if ( !l || l->count() != 3 )
        return false;

    EStringList::Iterator i( l );
    authorizeId = *i;
    ++i;
    authenticateId = *i;
    ++i;
    pw = *i;

    if ( authenticateId.isEmpty() || pw.isEmpty() )
        return false;

    if ( authorizeId.isEmpty() )
        authorizeId = authenticateId;

    return true;
}
