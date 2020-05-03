// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "smtp.h"

#include "smtpmailrcpt.h"
#include "smtpcommand.h"
#include "transaction.h"
#include "eventloop.h"
#include "address.h"
#include "mailbox.h"
#include "buffer.h"
#include "query.h"
#include "scope.h"
#include "sieve.h"
#include "date.h"
#include "user.h"

// getpid()
#include <sys/types.h>
#include <unistd.h>


class SMTPData
    : public Garbage
{
public:
    SMTPData():
        executing( false ), executeAgain( false ),
        inputState( SMTP::Command ),
        dialect( SMTP::Smtp ),
        sieve( 0 ), user( 0 ), permittedAddresses( 0 ),
        recipients( new List<SmtpRcptTo> ), now( 0 ) {}

    bool executing;
    bool executeAgain;
    SMTP::InputState inputState;
    SMTP::Dialect dialect;
    Sieve * sieve;
    List<SmtpCommand> commands;
    EString heloName;
    User * user;
    List<Address> * permittedAddresses;
    List<SmtpRcptTo> * recipients;
    EString body;
    Date * now;
    EString id;

    class AddressFinder
        : public EventHandler
    {
    public:
        AddressFinder( List<Address> * addresses ) : q( 0 ), a( addresses ) {}
        void execute();
        Query * q;
    private:
        List<Address> * a;
    };
};


/*! \class SMTP smtp.h
    The SMTP class implements a basic SMTP server.

    This is not a classic MTA. It implements all that's needed to
    deliver to local users, and for local users to submit messages to
    others. Nothing more.

    This class implements SMTP as specified by RFC 2821, with the
    extensions specified by RFC 1651 (EHLO), RFC 1652 (8BITMIME), RFC
    2487 (STARTTLS), RFC 2554 (AUTH), RFC 3030 (BINARYMIME and
    CHUNKING) and RFC 4468 (BURL).
*/

/*! \class LMTP smtp.h
    This subclass of SMTP implements LMTP (RFC 2033).
*/

/*! \class SMTPSubmit smtp.h
    This subclass of SMTP implements SMTP submission (RFC 4409).
*/

/*!  Constructs an (E)SMTP server for socket \a s, speaking \a dialect. */

SMTP::SMTP( int s, Dialect dialect )
    : SaslConnection( s, Connection::SmtpServer ), d( new SMTPData )
{
    Scope x( log() );
    d->dialect = dialect;
    switch( dialect ) {
    case Smtp:
        enqueue( "220 ESMTP " );
        break;
    case Lmtp:
        enqueue( "220 LMTP " );
        break;
    case Submit:
        enqueue( "220 SMTP Submission " );
        break;
    }
    enqueue( Configuration::hostname() );
    enqueue( "\r\n" );
    setTimeoutAfter( 1800 );
    EventLoop::global()->addConnection( this );
}


/*! Constructs an LMTP server of socket \a s. */

LMTP::LMTP( int s )
    : SMTP( s, SMTP::Lmtp )
{
}


/*!  Constructs a SMTP/submit server (see RFC 4409) for socket \a s. */

SMTPSubmit::SMTPSubmit( int s )
    : SMTP( s, SMTP::Submit )
{
}


void SMTP::react( Event e )
{
    switch ( e ) {
    case Read:
        setTimeoutAfter( 1800 );
        parse();
        break;

    case Timeout:
        log( "Idle timeout" );
        enqueue( "421 Tempus fugit\r\n" );
        Connection::setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
        break;

    case Shutdown:
        enqueue( "421 Server shutdown\r\n" );
        break;
    }
    execute();
}


/*! Parses the SMTP/LMTP input stream.
*/

void SMTP::parse()
{
    Buffer * r = readBuffer();

    if ( !checkProxyHeader() )
        return;

    bool progress = true;
    while ( progress && Connection::state() == Connected ) {
        uint n = r->size();
        if ( inputState() == Command )
            parseCommand();
        else
            d->commands.last()->execute();
        if ( r->size() >= n )
            progress = false;
    }
}


/*! Reads a single SMTP/LMTP/Submit command from the client and
    creates an execution object for it.

    Line length is limited to 4096 (for SMTP commands, not for message
    bodies): RFC 2821 section 4.5.3 says 512 is acceptable and various
    SMTP extensions may increase it. RFC 2822 declares that line
    lengths should be limited to 998 characters.
*/

void SMTP::parseCommand()
{
    Buffer * r = readBuffer();
    EString * line = r->removeLine( 4096 );
    if ( !line && r->size() > 4096 ) {
        log( "Connection closed due to overlong line", Log::Error );
        enqueue( "500 Line too long (legal maximum is 998 bytes)\r\n" );
        Connection::setState( Closing );
        return;
    }
    if ( !line )
        return;

    d->commands.append( SmtpCommand::create( this, *line ) );
}


/*! Runs all outstanding commands. When the oldest command is done,
    execute() removes it from the list and sends its responses to the
    client.
*/

void SMTP::execute()
{
    // make sure we don't call execute() recursively.
    if ( d->executing ) {
        d->executeAgain = true;
        return;
    }
    d->executing = true;
    d->executeAgain = true;

    // run each command, and do the whole loop again if execute() is
    // called recursively meanwhile.
    while ( d->executeAgain ) {
        d->executeAgain = false;
        List<SmtpCommand>::Iterator i( d->commands );
        while ( i ) {
            SmtpCommand * c = i;
            ++i;
            if ( !c->done() )
                c->notify();
        }

        // see if any old commands may be retired
        i = d->commands.first();
        while ( i && i->done() ) {
            d->executeAgain = true;
            i->emitResponses();
            d->commands.take( i );
        }
    }

    // allow execute() to be called again
    d->executing = false;
}


/*! Returns the dialect used, ie. SMTP, LMTP or SMTP/Submit. */

SMTP::Dialect SMTP::dialect() const
{
    return d->dialect;
}


/*! Records that the client claims to be called \a name. \a name isn't
    used for anything, just logged and recorded in any received fields
    generated.
*/

void SMTP::setHeloName( const EString & name )
{
    d->heloName = name;
}


/*! Returns the recorded HELO name, as recorded by setHeloName(). The
    initial value is an empty string.
*/

EString SMTP::heloName() const
{
    return d->heloName;
}


/*! Resets most transaction variables, so a new mail from/rcpt to/data
    cycle can begin. Leaves the heloName() untouched, since some
    clients do not resend helo/ehlo/lhlo.
*/

void SMTP::reset()
{
    if ( d->sieve ||
         ( d->recipients && !d->recipients->isEmpty() ) ||
         !d->body.isEmpty() )
        log( "State reset" );
    d->sieve = 0;
    d->recipients = new List<SmtpRcptTo>;
    d->body.truncate();
    d->id.truncate();
    d->now = 0;
}


/*! Returns a pointer to the Sieve that manages local delivery for
    this SMTP server.

*/

class Sieve * SMTP::sieve() const
{
    if ( !d->sieve ) {
        Scope x( log() );
        d->sieve = new Sieve;
    }
    return d->sieve;
}


/*! Returns a pointer to the authenticated user, or a null pointer if
    the connection is unauthenticated.
*/

class User * SMTP::user() const
{
    return d->user;
}


/*! Sets this server's authenticated user to \a user. */

void SMTP::authenticated( User * user )
{
    d->user = user;
    if ( !user )
        return;

    log( "Authenticated as " + user->login().ascii() );

    d->permittedAddresses = new List<Address>;
    d->permittedAddresses->append( d->user->address() );

    SMTPData::AddressFinder * af
        = new SMTPData::AddressFinder( d->permittedAddresses );
    af->q = new Query( "select distinct a.localpart::text, a.domain::text "
                       "from addresses a "
                       "join aliases al on (a.id=al.address) "
                       "join mailboxes mb on (al.mailbox=mb.id) "
                       "where mb.owner=$1 or mb.id in"
                       "(select mailbox from permissions "
                       "where rights ilike '%p%' "
                       "and (identifier='anyone' or identifier=$2))",
                       af );
    af->q->bind( 1, d->user->id() );
    af->q->bind( 2, d->user->login() );
    af->q->execute();
}


void SMTPData::AddressFinder::execute()
{
    Row * r = q->nextRow();
    while ( r ) {
        a->append( new Address( UString(),
                                r->getUString( "localpart" ),
                                r->getUString( "domain" ) ) );
        r = q->nextRow();
    }
}


/*! Returns a pointer to the list of addresses the currently
    authenticated User is permitted to use, or a null pointer if the
    list is not yet known.
*/

List<Address> * SMTP::permittedAddresses()
{
    return d->permittedAddresses;
}


/*! Returns the current input state, which is Command initially. */

SMTP::InputState SMTP::inputState() const
{
    return d->inputState;
}


/*! Notifies this SMTP server that its input state is now \a s. If the
    state is anything other than Command, the SMTP server calls the
    last SmtpCommand every time there's more input. Eventually, the
    SmtpCommand has to call setInputState( Command ) again.

*/

void SMTP::setInputState( InputState s )
{
    d->inputState = s;
}


/*! Notifies this SMTP server that \a r is a valid rcpt to
    command. SMTP records that so the LMTP SmtpData command can use
    the list later.
*/

void SMTP::addRecipient( SmtpRcptTo * r )
{
    log( "Recipient: " + r->address()->lpdomain() );
    d->recipients->append( r );
}


/*! Returns a list of all valid SmtpRcptTo commands. This is never a
    null pointer, but may be an empty list.
*/

List<SmtpRcptTo> * SMTP::rcptTo() const
{
    return d->recipients;
}


/*! Records \a b for later recall. reset() clears this. */

void SMTP::setBody( const EString & b )
{
    d->body = b;
}


/*! Returns what setBody() set. Used for SmtpBdat instances to
    coordinate the body.
*/

EString SMTP::body() const
{
    return d->body;
}


/*! Returns true if \a c is the oldest command in the SMTP server's
    queue of outstanding commands, and false if the queue is empty or
    there is a command older than \a c in the queue.
*/

bool SMTP::isFirstCommand( SmtpCommand * c ) const
{
    if ( c == d->commands.firstElement() )
        return true;
    return false;
}


class SMTPSData
    : public Garbage
{
public:
    SMTPSData() : helper( 0 ) {}
    EString banner;
    class SmtpsHelper * helper;
};

class SmtpsHelper: public EventHandler
{
public:
    SmtpsHelper( SMTPS * connection ) : c( connection ) {}
    void execute() { c->finish(); }

private:
    SMTPS * c;
};

/*! \class SMTPS smtp.h

    The SMTPS class implements the old wrapper trick still commonly
    used on port 465. As befits a hack, it is a bit of a hack, and
    depends on the ability to empty its writeBuffer().
*/

/*! Constructs an SMTPS server on file descriptor \a s, and starts to
    negotiate TLS immediately.
*/

SMTPS::SMTPS( int s )
    : SMTPSubmit( s ), d( new SMTPSData )
{
    EString * tmp = writeBuffer()->removeLine();
    if ( tmp )
        d->banner = *tmp;
    startTls();
    enqueue( d->banner + "\r\n" );
}


/*! Handles completion of TLS negotiation and sends the banner. */

void SMTPS::finish()
{
}


/*! Uses \a id as transaction id for this message. Reset by rset. Used
    for debugging.
*/

void SMTP::setTransactionId( const EString & id )
{
    d->id = id;
}


/*! Return an ESMTP id, either based on an internal algorithm or on
    something the client specified using an Archiveopteryx-specific
    extension.

    This function returns the same ID even if called several times.
    Rset resets it.
*/

EString SMTP::transactionId()
{
    if ( !d->id.isEmpty() )
        return d->id;

    Scope x( log() );
    d->id = fn( transactionTime()->unixTime() );
    d->id.append( '-' );
    d->id.appendNumber( getpid() );
    d->id.append( '-' );
    d->id.append( log()->id() );
    log( "Assigned transaction ID " + d->id );
    return d->id;
}


/*! Records the current time, \a now. The rest of the SMTP transaction
    will be considered to happen at the specified time. Used for
    debugging, when we want mail to be injected at known times.
*/

void SMTP::setTransactionTime( class Date * now )
{
    d->now = now;
}


/*! Returns the current time and date, except that if you call it
    more than once for the same object, it returns the same value.
*/

class Date * SMTP::transactionTime() const
{
    if ( d->now )
        return d->now;

    d->now = new Date;
    d->now->setCurrentTime();
    return d->now;
}


void SMTP::sendChallenge( const EString &s )
{
    enqueue( "334 "+ s +"\r\n" );
}
