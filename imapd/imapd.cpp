#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "logclient.h"
#include "occlient.h"
#include "database.h"
#include "mailbox.h"
#include "listener.h"
#include "imap.h"
#include "loop.h"
#include "tls.h"

#include <stdlib.h>


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".imapdrc" );

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    TLS::setup();
    OCClient::setup();
    Database::setup();
    Mailbox::setup();

    log( Test::report() );

    Listener< IMAP >::create( "IMAP", "", 2052 );

    Configuration::global()->report();
    l.commit();

    if ( Log::disastersYet() )
        exit( 1 );

    Loop::start();
}
