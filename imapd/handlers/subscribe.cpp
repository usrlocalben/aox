/*! \class Subscribe subscribe.h
    Adds a mailbox to the subscription list (RFC 3501, �6.3.6)
*/

#include "subscribe.h"

#include "imap.h"


/*! \reimp */

void Subscribe::parse()
{
    space();
    m = astring();
    end();
}


/*! \reimp */

void Subscribe::execute()
{
    error( No, "unimplemented command" );
    setState( Finished );
}
