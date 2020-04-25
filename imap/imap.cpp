// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "imap.h"

#include "log.h"
#include "list.h"
#include "timer.h"
#include "query.h"
#include "scope.h"
#include "buffer.h"
#include "estring.h"
#include "mailbox.h"
#include "selector.h"
#include "eventloop.h"
#include "transaction.h"
#include "imapsession.h"
#include "configuration.h"
#include "handlers/capability.h"
#include "mailboxgroup.h"
#include "imapparser.h"
#include "database.h"
#include "eventmap.h"
#include "command.h"
#include "cache.h"
#include "date.h"
#include "user.h"

#include "time.h"

#include <sys/socket.h>  // AF_INET
#include <string.h> // memcmp
#include <arpa/inet.h> // ntohl

static bool endsWithLiteral( const EString *, uint *, bool * );


class IMAPData
    : public Garbage
{
public:
    IMAPData()
        : maybeProxy( true ),
          state( IMAP::NotAuthenticated ), reader( 0 ),
          prefersAbsoluteMailboxes( false ),
          runningCommands( false ), runCommandsAgain( false ),
          readingLiteral( false ),
          literalSize( 0 ), mailbox( 0 ),
          bytesArrived( 0 ),
          eventMap( new EventMap ),
          lastBadTime( 0 ),
          nextOkTime( 0 )
    {
        uint i = 0;
        while ( i < IMAP::NumClientCapabilities )
            clientCapabilities[i++] = false;
        i = 0;
        while ( i < IMAP::NumClientBugs )
            clientBugs[i++] = false;
        EventFilterSpec * normal = new EventFilterSpec;
        normal->setNotificationWanted( EventFilterSpec::FlagChange, true );
        normal->setNotificationWanted( EventFilterSpec::NewMessage, true );
        normal->setNotificationWanted( EventFilterSpec::Expunge, true );
        eventMap->add( normal );
    }

    bool maybeProxy;
    IMAP::State state;

    Command * reader;

    EString str;

    bool prefersAbsoluteMailboxes;
    bool runningCommands;
    bool runCommandsAgain;
    bool readingLiteral;
    uint literalSize;

    List<Command> commands;
    List<ImapResponse> responses;

    Mailbox *mailbox;

    uint bytesArrived;

    bool clientCapabilities[IMAP::NumClientCapabilities];
    bool clientBugs[IMAP::NumClientBugs];

    List<MailboxGroup> possibleGroups;

    EventMap * eventMap;

    uint lastBadTime;

    class BadBouncer
        : public EventHandler
    {
    public:
        BadBouncer( IMAP * owner ) : i( owner ) {}

        void execute() { i->unblockCommands(); }

        IMAP * i;
    };

    class NatDefeater
        : public EventHandler
    {
    public:
        NatDefeater( IMAP * owner ) : i( owner ) {}

        void execute() { i->defeatNat(); }

        IMAP * i;
    };

    uint nextOkTime;
};


/*! \class IMAP imap.h
    This class implements the IMAP server as seen by clients.

    This class is responsible for interacting with IMAP clients, and for
    overseeing the operation of individual command handlers. It looks at
    client input to decide which Command to defer the real work to, and
    ensures that the handler is called at the appropriate times.

    Each IMAP object has a state() (RFC 3501 section 3), and may possess
    other state information, such as the user() logged in or a
    session(). The Idle state (RFC 2177) is also kept here.

    The IMAP class parses incoming commands as soon as possible and
    may keep several commands executing at a time, if the client
    issues that. It depends on Command::group() to decide whether each
    parsed Command can be executed concurrently with the already
    running Command objects.
*/

/*! This setup function expects to be called from ::main().

    It reads and validates any relevant configuration variables, and
    logs a disaster if it encounters an error.
*/

void IMAP::setup()
{
}


/*! Creates an IMAP server on file descriptor \a s, and sends an
    initial OK[CAPABILITY...] response to the client.
*/

IMAP::IMAP( int s )
    : SaslConnection( s, Connection::ImapServer ), d( new IMAPData )
{
    if ( s < 0 )
        return;

    EString banner = "* OK [CAPABILITY " +
                    Capability::capabilities( this ) + "] " +
                    Configuration::hostname() +
                    " Archiveopteryx IMAP Server";
    if ( !Configuration::toggle( Configuration::Security ) )
        banner.append( " (security checking disabled)" );
    banner.append( "\r\n" );
    enqueue( banner );
    setTimeoutAfter( 120 );
    EventLoop::global()->addConnection( this );
}


/*! Handles the incoming event \a e as appropriate for its type. */

void IMAP::react( Event e )
{
    d->bytesArrived += readBuffer()->size();
    switch ( e ) {
    case Read:
        parse();
        if ( d->bytesArrived > 32768 && state() == NotAuthenticated ) {
            log( ">32k received before login" );
            enqueue( "* BYE overlong login sequence\r\n" );
            Connection::setState( Closing );
            if ( d->reader ) {
                Scope s( d->reader->log() );
                d->reader->read();
            }
        }
        break;

    case Timeout:
        if ( state() != Logout ) {
            log( "Idle timeout" );
            enqueue( "* BYE Tempus fugit\r\n" );
        }
        Connection::setState( Closing );
        if ( d->reader ) {
            Scope s( d->reader->log() );
            d->reader->read();
        }
        setSession( 0 );
        break;

    case Connect:
        break;

    case Error:
    case Close:
        if ( session() ) {
            log( "Unexpected close by client" );
            setSession( 0 );
        }
        if ( !d->commands.isEmpty() ) {
            List<Command>::Iterator i( d->commands );
            while ( i ) {
                Command * c = i;
                ++i;
                if ( c->state() == Command::Unparsed ||
                     c->state() == Command::Blocked ||
                     c->state() == Command::Executing )
                    c->error( Command::No,
                              "Unexpected close by client" );
            }
        }
        break;

    case Shutdown:
        enqueue( "* BYE server shutdown\r\n" );
        if ( session() && d->commands.isEmpty() )
            setSession( 0 );
        break;
    }

    runCommands();

    d->bytesArrived -= readBuffer()->size();

    if ( timeout() == 0 ||
         ( e == Read && state() != NotAuthenticated ) ) {
        switch ( state() ) {
        case NotAuthenticated:
            setTimeoutAfter( 120 );
            break;
        case Authenticated:
        case Selected:
            if ( idle() )
                setTimeoutAfter( 3600 ); // one hour while IDLE
            else
                setTimeoutAfter( 1860 ); // a half-hour without
            break;
        case Logout:
            break;
        }

    }
}


/*! Reads input from the client, and feeds it to the appropriate Command
    handlers.
*/
const char v2sig[13] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

struct Hdr {
    uint8_t sig[12];
    uint8_t ver_cmd;
    uint8_t fam;
    uint16_t len;
    union {
        struct {  /* for TCP/UDP over IPv4, len = 12 */
            uint32_t src_addr;
            uint32_t dst_addr;
            uint16_t src_port;
            uint16_t dst_port;
        } ip4;
        struct {  /* for TCP/UDP over IPv6, len = 36 */
            uint8_t  src_addr[16];
            uint8_t  dst_addr[16];
            uint16_t src_port;
            uint16_t dst_port;
        } ip6;
        struct {  /* for AF_UNIX sockets, len = 216 */
            uint8_t src_addr[108];
            uint8_t dst_addr[108];
        } unx;
    } addr;
};

static int min(int a, int b) {
    if (a < b) {
        return a;
    }
    return b;
}

bool IMAP::maybeParseProxyLeader()
{
    Buffer * r = readBuffer();
    Hdr msg;

    if ( !d->maybeProxy )
        return true;

    if ( r->size() < 16 )
        return false;  // still waiting...

    const int n = min( sizeof(Hdr), r->size() );
    for ( int i=0; i<n; ++i )
        reinterpret_cast<char*>(&msg)[i] = (*r)[i];

    if ( memcmp( &msg, v2sig, 12 ) != 0 ) {
        // signature does not match
        d->maybeProxy = false;
        return true;
    }

    if ( ( msg.ver_cmd & 0xf0 ) != 0x20 ) {
        // version nibble is not 2
        log( "PROXY binary signature present, but version != 2", Log::Error );
        d->maybeProxy = false;
        return true;
    }

    int size = 16 + ntohs( msg.len );
    if ( n < size ) {
        // still waiting...
        return false;
    }

    // we received a valid PROXY blob, so we will continue
    // even if it is a type that we can't support
    r->remove(size);
    d->maybeProxy = false;

    sockaddr_storage peer;
    sockaddr_storage self;

    switch ( msg.ver_cmd & 0xf ) {
    case 0x01: // PROXY command
        switch ( msg.fam ) {
        case 0x11: // TCPv4
            ((struct sockaddr_in *)&peer)->sin_family = AF_INET;
            ((struct sockaddr_in *)&peer)->sin_addr.s_addr = msg.addr.ip4.src_addr;
            ((struct sockaddr_in *)&peer)->sin_port = msg.addr.ip4.src_port;
            ((struct sockaddr_in *)&self)->sin_family = AF_INET;
            ((struct sockaddr_in *)&self)->sin_addr.s_addr = msg.addr.ip4.dst_addr;
            ((struct sockaddr_in *)&self)->sin_port = msg.addr.ip4.dst_port;
            setRealPeer( (sockaddr*)&peer );
            setRealSelf( (sockaddr*)&self );
            break;
        case 0x21: // TCPv6
            ((struct sockaddr_in6 *)&peer)->sin6_family = AF_INET6;
            memcpy(&((struct sockaddr_in6 *)&peer)->sin6_addr, msg.addr.ip6.src_addr, 16);
            ((struct sockaddr_in6 *)&peer)->sin6_port = msg.addr.ip6.src_port;
            ((struct sockaddr_in6 *)&self)->sin6_family = AF_INET6;
            memcpy(&((struct sockaddr_in6 *)&self)->sin6_addr, msg.addr.ip6.dst_addr, 16);
            ((struct sockaddr_in6 *)&self)->sin6_port = msg.addr.ip6.dst_port;
            setRealPeer( (sockaddr*)&peer );
            setRealSelf( (sockaddr*)&self );
            break;
        default:
            // unsupported protocol, keep local address
            log( "PROXY using unsupported protocol " + fn(msg.fam) + ", ignoring", Log::Error );
            break;
        }
        break;
    case 0x00: // LOCAL command
        // keep local connection address for LOCAL
        break;
    default:
        log( "PROXY unknown command " + fn(msg.ver_cmd & 0xf) + ", ignoring", Log::Error );
        break;
    }
    return true;
}


void IMAP::parse()
{
    Scope s;
    Buffer * r = readBuffer();

    bool cont = maybeParseProxyLeader();
    if ( !cont ) {
        return;
    }

    while ( true ) {
        // We read a line of client input, possibly including literals,
        // and create a Command to deal with it.
        if ( !d->readingLiteral && !d->reader ) {
            bool plus = false;
            EString * s;
            uint n;

            // Do we have a complete line yet?
            s = r->removeLine();
            if ( !s )
                return;

            d->str.append( *s );

            if ( endsWithLiteral( s, &n, &plus ) ) {
                d->str.append( "\r\n" );
                if ( n <= ImapParser::literalSizeLimit() ) {
                    d->readingLiteral = true;
                    d->literalSize = n;
                    if ( !plus )
                        enqueue( "+ reading literal\r\n" );
                }
            }

            // Have we finished reading the entire command?
            if ( !d->readingLiteral ) {
                addCommand();
                d->str.truncate();
            }
        }
        else if ( d->readingLiteral ) {
            // Have we finished reading a complete literal?
            if ( r->size() < d->literalSize )
                return;

            d->str.append( r->string( d->literalSize ) );
            r->remove( d->literalSize );
            d->readingLiteral = false;
        }
        else if ( d->reader ) {
            // If a Command has reserve()d input, we just feed it.
            Scope s( d->reader->log() );
            d->reader->read();
            if ( d->reader )
                return;
        }
    }
}


/*! This function parses enough of the command line to create a Command,
    and then uses it to parse the rest of the input.
*/

void IMAP::addCommand()
{
    // I love this feature
    if ( d->str == "quit" )
        d->str = "arnt logout";

    ImapParser * p = new ImapParser( d->str );

    EString tag = p->tag();
    if ( !p->ok() ) {
        enqueue( "* BAD " + p->error() + "\r\n" );
        recordSyntaxError();
        log( p->error(), Log::Info );
        return;
    }

    p->require( " " );

    EString name = p->command();
    if ( !p->ok() ) {
        enqueue( "* BAD " + p->error() + "\r\n" );
        recordSyntaxError();
        log( p->error(), Log::Error );
        return;
    }

    if ( EventLoop::global()->inShutdown() && name != "logout" ) {
        uint n = 0;
        List< Command >::Iterator i( d->commands );
        while ( i ) {
            if ( i->state() == Command::Executing )
                n++;
            ++i;
        }

        if ( !n ) {
            enqueue( "* BYE Server or process shutdown\r\n" );
            Connection::setState( Closing );
        }

        enqueue( tag + " NO May not be started during server shutdown\r\n" );
        return;
    }

    Command * cmd = Command::create( this, tag, name, p );

    if ( !cmd ) {
        if ( Command::create( this, tag, tag, p ) )
            enqueue( "* OK  Hint: An IMAP command is prefixed by a tag. "
                     "The command is the\r\n"
                     "* OK  second word on the line, after the tag. In "
                     "your command, " + name.quoted() + "\r\n"
                     "* OK  is the command and " + tag.quoted() +
                     " is the tag.\r\n" );
        recordSyntaxError();
        enqueue( tag + " BAD No such command: " + name + "\r\n" );
        log( "Unknown command. Line: " + p->firstLine().quoted(),
             Log::Error );
        return;
    }

    d->commands.append( cmd );
    d->nextOkTime = time( 0 ) + 117;

    Scope x( cmd->log() );
    if ( name.lower() != "login" && name.lower() != "authenticate" )
        ::log( "First line: " + p->firstLine(), Log::Debug );
}


/*! Returns the current state of this IMAP session, which is one of
    NotAuthenticated, Authenticated, Selected and Logout.
*/

IMAP::State IMAP::state() const
{
    return d->state;
}


/*! Sets this IMAP connection to be in state \a s. The initial value
    is NotAuthenticated.
*/

void IMAP::setState( State s )
{
    if ( s == d->state )
        return;
    d->state = s;
    EString name;
    switch ( s ) {
    case NotAuthenticated:
        name = "not authenticated";
        break;
    case Authenticated:
        name = "authenticated";
        break;
    case Selected:
        name = "selected";
        break;
    case Logout:
        name = "logout";
        break;
    };
    log( "Changed to " + name + " state", Log::Debug );
}


/*! Returns true if the server has no particular work to do to server
    the peer(), and false if it's currently working on behalf of peer().

    If there are no commands, a connection is idle(). If the command
    currently being executed is Idle, the connection is also idle.
*/

bool IMAP::idle() const
{
    List<Command>::Iterator i( d->commands );
    while ( i ) {
        Command * c = i;
        ++i;
        switch ( c->state() ) {
        case Command::Unparsed:
            return false;
            break;
        case Command::Blocked:
            return false;
            break;
        case Command::Executing:
            if ( c->name() != "idle" )
                return false;
            break;
        case Command::Finished:
            return false;
            break;
        case Command::Retired:
            break;
        }
    }

    return true;
}


/*! Notifies the IMAP object that \a user was successfully
    authenticated by way of \a mechanism. This changes the state() of
    the IMAP object to Authenticated.
*/

void IMAP::setUser( User * user, const EString & mechanism )
{
    log( "Authenticated as " + user->login().ascii() + " using " +
         mechanism, Log::Significant );
    SaslConnection::setUser( user, mechanism );
    setState( Authenticated );

    bool possiblyOutlook = true;
    List< Command >::Iterator i( d->commands );
    while ( i && possiblyOutlook ) {
        EString tag = i->tag();
        ++i;
        if ( tag.length() != 4 || tag.contains( '.' ) )
            possiblyOutlook = false;
    }
    if ( possiblyOutlook )
        setClientBug( Nat );
    setTimeoutAfter( 1860 );
}


/*! Reserves input from the connection for \a command.

    When more input is available, Command::read() is
    called. Command::finish() releases control.
*/

void IMAP::reserve( Command * command )
{
    d->reader = command;
}


/*! Causes any blocked commands to be executed if possible.
*/

void IMAP::unblockCommands()
{
    if ( d->state != NotAuthenticated )
        while ( d->commands.firstElement() &&
                d->commands.firstElement()->state() == Command::Retired )
            d->commands.shift();
    if ( d->runningCommands )
        d->runCommandsAgain = true;
    else
        runCommands();
}


/*! Calls Command::execute() on all currently operating commands, and
    if possible calls Command::emitResponses() and retires those which
    can be retired.
*/

void IMAP::runCommands()
{
    d->runningCommands = true;
    d->runCommandsAgain = true;

    while ( d->runCommandsAgain ) {
        d->runCommandsAgain = false;
        log( "IMAP::runCommands, " + fn( d->commands.count() ) + " commands",
             Log::Debug );

        // run all currently executing commands once
        uint n = 0;
        List< Command >::Iterator i( d->commands );
        while ( i ) {
            Command * c = i;
            ++i;
            Scope s( c->log() );
            if ( c->state() == Command::Executing ) {
                if ( c->ok() )
                    c->execute();
                else
                    c->finish();
                n++;
            }
        }

        // emit responses for zero or more finished commands and
        // retire them.
        n = 0;
        i = d->commands.first();
        while ( i && i->state() == Command::Finished ) {
            Command * c = i;
            ++i;
            if ( d->reader == c )
                d->reader = 0;
            c->emitResponses();
            n++;
        }

        // slow down the command rate if the client is sending
        // errors. specificaly, if we've sent a NO/BAD, then we don't
        // start any new commands for n seconds, where n is the number
        // of NO/BADs we've sent, bounded at 16.

        int delayNeeded = (int)syntaxErrors();
        if ( delayNeeded > 16 )
            delayNeeded = 16;
        delayNeeded = (int)d->lastBadTime + delayNeeded - (int)::time(0);
        if ( delayNeeded < 0 )
            delayNeeded = 0;
        if ( user() && !user()->inbox() && delayNeeded < 4 )
            delayNeeded = 4;
        if ( delayNeeded > 0 && !d->commands.isEmpty() ) {
            log( "Delaying next IMAP command for " + fn( delayNeeded ) +
                 " seconds (because of " + fn( syntaxErrors() ) +
                 " syntax errors)" );
            (void)new Timer( new IMAPData::BadBouncer( this ), delayNeeded );
            d->runningCommands = false;
            return;
        }

        // we may be able to start new commands.
        i = d->commands.first();
        Command * first = i;
        if ( first && first->state() != Command::Retired ) {
            Scope x( first->log() );
            ++i;
            if ( first->state() == Command::Unparsed )
                first->parse();
            if ( !first->ok() )
                first->setState( Command::Finished );
            else if ( first->state() == Command::Unparsed ||
                      first->state() == Command::Blocked )
                first->setState( Command::Executing );
            if ( first->state() != Command::Executing )
                first = 0;
        }

        // if we have a leading command, we can parse and execute
        // followers in the same group.
        if ( first && first->group() ) {
            while ( first && i && first->state() == i->state() ) {
                Command * c = i;
                Scope x( c->log() );
                ++i;
                if ( c->state() == Command::Unparsed )
                    c->parse();
                if ( !c->ok() )
                    c->setState( Command::Finished );
                else if ( c->state() == Command::Unparsed ||
                          c->state() == Command::Blocked )
                    c->setState( Command::Executing );
                if ( c->group() != first->group() &&
                     c->state() == Command::Executing ) {
                    first = 0;
                    c->setState( Command::Blocked );
                }
            }
        }
    }

    d->runningCommands = false;

    List< Command >::Iterator i( d->commands );
    while ( i ) {
        if ( i->state() == Command::Retired )
            d->commands.take( i );
        else
            ++i;
    }
    if ( d->commands.isEmpty() ) {
        if ( EventLoop::global()->inShutdown() &&
             Connection::state() == Connected )
            Connection::setState( Closing );
        else
            restartNatDefeater();
    }
}


/*! Executes \a c once, provided it's in the right state, and emits its
    responses.
*/

void IMAP::run( Command * c )
{
    if ( c->state() != Command::Executing )
        return;

    Scope s( c->log() );

    if ( c->ok() )
        c->execute();
    else
        c->finish();
}


/*  This static helper function returns true if \a s ends with an IMAP
    literal specification. If so, it sets \a *n to the number of bytes
    in the literal, and \a *plus to true if the number had a trailing
    '+' (for LITERAL+). Returns false if it couldn't find a literal.
*/

static bool endsWithLiteral( const EString *s, uint *n, bool *plus )
{
    if ( !s->endsWith( "}" ) )
        return false;

    uint i = s->length() - 2;
    if ( (*s)[i] == '+' ) {
        *plus = true;
        i--;
    }

    uint j = i;
    while ( i > 0 && (*s)[i] >= '0' && (*s)[i] <= '9' )
        i--;

    if ( (*s)[i] != '{' )
        return false;

    bool ok;
    *n = s->mid( i+1, j-i ).number( &ok );

    return ok;
}


/*! Switches to Selected state and operates on the mailbox session \a
    s. If the object already had a session, ends the previous session.
*/

void IMAP::setSession( Session * s )
{
    if ( !s && !session() )
        return;

    if ( session() ) {
        (void)new ImapResponse( this, "OK [CLOSED] I, missa est" );
    }
    Connection::setSession( s );
    if ( s ) {
        setState( Selected );
        log( "Starting session on mailbox " + s->mailbox()->name().ascii() );
    }
    else {
        setState( Authenticated );
    }
}


/*! \class IMAPS imap.h

    The IMAPS class implements the old wrapper trick still commonly
    used on port 993. As befits a hack, it is a bit of a hack, and
    depends on the ability to empty its writeBuffer().
*/

/*! Constructs an IMAPS server on file descriptor \a s, and starts to
    negotiate TLS immediately.
*/

IMAPS::IMAPS( int s )
    : IMAP( s )
{
    EString * tmp = writeBuffer()->removeLine();
    startTls();
    enqueue( *tmp + "\r\n" );
}


/*! Returns true if the client has shown that it supports a given \a
    capability, and false if this is still unknown.
*/

bool IMAP::clientSupports( ClientCapability capability ) const
{
    return d->clientCapabilities[capability];
}


/*! Records that the client supports \a capability. The initial value
    is valse for all capabilities, and there is no way to disable a
    capability once enabled.
*/

void IMAP::setClientSupports( ClientCapability capability )
{
    d->clientCapabilities[capability] = true;
    if ( capability == QResync )
        d->clientCapabilities[Condstore] = true;
}


/*! Returns true if the server thinks the client may have \a bug, and
    false otherwise.
*/

bool IMAP::clientHasBug( ClientBug bug ) const
{
    return d->clientBugs[bug];
}


static const char * clientBugMessages[IMAP::NumClientBugs] = {
   "Mishandling of unsolicited responses",
   "NAT"
};

/*! Records that the client is presumed to suffer from \a bug. */

void IMAP::setClientBug( ClientBug bug )
{
    if ( d->clientBugs[bug] )
        return;
    d->clientBugs[bug] = true;
    log( EString("Activating client workaround: ") + clientBugMessages[bug] );
}


/*! Returns a list of all Command objects currently known by this IMAP
    server. First received command first. Commands in all states may
    be in the list, except Retired.

*/

List<Command> * IMAP::commands() const
{
    while ( d->commands.firstElement() &&
            d->commands.firstElement()->state() == Command::Retired )
        d->commands.shift();
    return &d->commands;
}


void IMAP::sendChallenge( const EString &s )
{
    enqueue( "+ "+ s +"\r\n" );
}


/*! Records that the IMAP client likes to see its mailbox names in
    absolute form (ie. /users/kiki/lists/mja instead of lists/mja)
    if \a b is true, and that it prefers relative names otherwise.
    The initial value is false.
*/

void IMAP::setPrefersAbsoluteMailboxes( bool b )
{
    d->prefersAbsoluteMailboxes = b;
}


/*! Returns whatever setPrefersAbsoluteMailboxes() set. */

bool IMAP::prefersAbsoluteMailboxes() const
{
    return d->prefersAbsoluteMailboxes;
}


/*! Records that \a response needs to be sent at the earliest possible
    date. When is the earliest possible date? Well, it depends on \a
    response, on the commands active and so on.
*/

void IMAP::respond( class ImapResponse * response )
{
    d->responses.append( response );
}


/*! Emits those responses which can be emitted at this time. */

void IMAP::emitResponses()
{
    if ( clientHasBug( NoUnsolicitedResponses ) && commands()->isEmpty() )
        return;

    // first, see if expunges are permitted
    bool can = false;
    bool cannot = false;
    List<Command>::Iterator c( commands() );

    while ( c && !cannot ) {
        // expunges are permitted in idle mode
        if ( c->state() == Command::Executing && c->name() == "idle" )
            can = true;
        // we cannot send an expunge while a command is being
        // executed (not without NOTIFY at least...)
        else if ( c->state() == Command::Executing )
            cannot = true;
        // group 2 contains commands during which we may not send
        // expunge, group 3 contains all commands that change
        // flags.
        else if ( c->group() == 2 || c->group() == 3 )
            cannot = true;
        // if there are MSNs in the pipeline we cannot send
        // expunge. the copy rule is due to RFC 2180 section
        // 4.4.1/2
        else if ( c->usesMsn() && c->name() != "copy" )
            cannot = true;
        // if another command is finished, we can.
        else if ( c->state() == Command::Finished && !c->tag().isEmpty() )
            can = true;
        ++c;
    }
    if ( cannot )
        can = false;

    bool any = false;

    Buffer * w = writeBuffer();
    List<ImapResponse>::Iterator r( d->responses );
    uint n = 0;
    while ( r ) {
        if ( !r->meaningful() ) {
            r->setSent();
        }
        else if ( !r->sent() && ( can || !r->changesMsn() ) ) {
            EString t = r->text();
            if ( !t.isEmpty() ) {
                w->append( "* ", 2 );
                w->append( t );
                w->append( "\r\n", 2 );
                n++;
            }
            r->setSent();
            any = true;
        }
        if ( r->sent() )
            d->responses.take( r );
        else
            ++r;
    }

    if ( !any )
        return;

    c = commands()->first();
    while ( c ) {
        c->checkUntaggedResponses();
        ++c;
    }
}


/*! Records that \a m is a (possibly) active mailbox group. */

void IMAP::addMailboxGroup( MailboxGroup * m )
{
    d->possibleGroups.append( m );
}


/*! Records that \a m is no longer active. MailboxGroup calls this,
    noone else needs to.
*/

void IMAP::removeMailboxGroup( MailboxGroup * m )
{
    d->possibleGroups.remove( m );
}


/*! Returns the MailboxGroup most likely to be the one the client is
    working on, assuming that the client performs an operation on \a
    m.

    Returns a null pointer if the client doesn't seem to be working on
    any easily defined group, or if it is working on one, but
    MailboxGroup::hits() returns a value less than \a l.
*/

MailboxGroup * IMAP::mostLikelyGroup( Mailbox * m, uint l )
{
    List<MailboxGroup>::Iterator i( d->possibleGroups );
    MailboxGroup * best = 0;
    uint bestCount = 0;
    while ( i ) {
        MailboxGroup * g = i;
        ++i;
        if ( g->contains( m ) && g->hits() >= l ) {
            uint count = g->count();
            if ( !best || bestCount < count ) {
                best = g;
                bestCount = count;
            }
        }
    }
    return best;
}


/*! Returns a pointer to the event map currently in force. This is
    never a null pointer; IMAP sets up a suitable map when it starts.
*/

class EventMap * IMAP::eventMap() const
{
    return d->eventMap;
}


/*! Records that IMAP should base its notification decisions on \a map
    henceforth. \a map must not be null.

*/

void IMAP::setEventMap( class EventMap * map )
{
    if ( map )
        d->eventMap = map;
}


/*! Reimplemented in order to record the time, so we can rate-limit
    bad IMAP commands in runCommands();
*/

void IMAP::recordSyntaxError()
{
    SaslConnection::recordSyntaxError();
    d->lastBadTime = time( 0 );
}


/*! Restarts the timing logic we use to send little OK response in
    order to defeat too-quick NAT timeouts.
*/

void IMAP::restartNatDefeater()
{
    if ( !clientHasBug( Nat ) )
        return;

    if ( state() == NotAuthenticated || state() == Logout )
        return;

    uint now = time( 0 );
    uint next = now + 4;
    // if we've already set up a suitable timer, just quit
    if ( d->nextOkTime >= next && d->nextOkTime < now + 6 )
        return;
    // otherwise, set one up
    d->nextOkTime = next;
    (void)new Timer( new IMAPData::NatDefeater( this ), 6 );
}


/*! Called regularly to ensure that we send an untagged OK every
    minute or so, in order to ensure a steady stream of packets. Some
    NAT gateways will kill the connection after as little as two
    minutes if no traffic is seen.
*/

void IMAP::defeatNat()
{
    if ( !idle() )
        return;
    if ( Connection::state() != Connection::Connected )
        return;
    if ( state() == NotAuthenticated || state() == Logout )
        return;

    uint now = time( 0 );
    if ( now < d->nextOkTime )
        return;

    d->nextOkTime = now + 117;
    (void)new Timer( new IMAPData::NatDefeater( this ), d->nextOkTime - now );
    Date x;
    x.setUnixTime( now );
    enqueue( "* OK (NAT keepalive: " + x.isoTime() + ")\r\n" );
}
