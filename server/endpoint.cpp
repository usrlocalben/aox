// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "endpoint.h"

#include "estring.h"
#include "file.h"
#include "resolver.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <stdlib.h>  // getenv
#include <unistd.h>  // getpid

const int kSystemdBeginFD = 3;

class EndpointData
    : public Garbage
{
public:
    EndpointData()
        : valid( false ), proto( Endpoint::IPv4 ), fd( -1 ), ip4a( 0 ), port( 0 )
    {}

    bool valid;
    Endpoint::Protocol proto;
    EString ua;
    int fd;
    ushort ip6a[8];
    uint ip4a;
    uint port;
};


static uint ip4a( const EString &, bool * );
static void ip6a( const EString &, ushort [], bool * );


/*! \class Endpoint endpoint.h
    Endpoint parses and stores a Unix/IPv4/IPv6 address.

    It can parse an IPv4/6 string representation, or a fully-qualified
    Unix path; and it stores a binary representation of those. If the
    Endpoint is valid(), its protocol(), address() and port() are all
    accessible.

    The OS equivalent of an Endpoint, sockaddr, is available through
    sockaddr() and sockaddrSize().

    Finally, it can generate a correct string() representation.

    There is no DNS or /etc/hosts support.
*/

/*! Creates an empty Endpoint object. */

Endpoint::Endpoint()
    : d( new EndpointData )
{}


/*! Constructs a copy of \a other. */

Endpoint::Endpoint( const Endpoint & other )
    : Garbage(), d( new EndpointData )
{
    *this = other;
}


/*! Constructs an Endpoint representing \a port on \a address. If the
    \a address is a Unix path, the \a port is ignored.
*/

Endpoint::Endpoint( const EString &address, uint port )
    : d( new EndpointData )
{
    if ( address[0] == '/' ) {
        d->valid = true;
        d->proto = Unix;
        d->ua = address;
    }

    else if ( address.startsWith( "fd/" ) ) {
        EStringList * parts = EStringList::split( '/', address );
        EString& value = *parts->lastElement();

        bool good;
        d->fd = value.number( &good );
        if ( !good ) {
            log( "bad fd endpoint value \"" + value + "\"", Log::Disaster );
            return;
        }
        d->proto = IPv4;
        d->ip4a = 0;
        d->valid = true;
    }

    else if ( address.startsWith( "systemd/" ) ) {
        bool good;
        const char * tmp = getenv( "LISTEN_PID" );
        if ( !tmp ) {
            log( "systemd endpoint configured, but LISTEN_PID not in environment", Log::Disaster );
            return;
        }
        EString listenPIDText( tmp );
        int listenPID = listenPIDText.number( &good );
        if ( !good ) {
            log( "unexpected systemd LISTEN_PID value " + listenPIDText, Log::Disaster );
            return;
        }
        if ( listenPID != getpid() ) {
            log( "systemd LISTEN_PID value does not match mine!", Log::Disaster );
            return;
        }
        tmp = getenv( "LISTEN_FDS" );
        if ( !tmp ) {
            log( "systemd endpoint configured, but LISTEN_FDS not in environment", Log::Disaster );
            return;
        }
        EString fdCntText( tmp );
        int fdCnt = fdCntText.number( &good );
        if ( !good ) {
            log( "unexpected systemd LISTEN_FDS value " + fdCntText, Log::Disaster );
            return;
        }
        const int fdEnd = kSystemdBeginFD + fdCnt;

        EStringList * parts = EStringList::split( '/', address );
        EStringList::Iterator it( parts );
        uint domain = 0;
        int index = -1;
        while ( it ) {
            EStringList * kv = EStringList::split( '.', *it );
            EString& key = *kv->firstElement();
            EString& value = *kv->lastElement();
            if ( key == "domain" ) {
                if ( value == "INET" ) {
                    domain = AF_INET;
                }
                else if ( value == "UNIX" ) {
                    domain = AF_UNIX;
                }
                else if ( value == "INET6" ) {
                    domain = AF_INET6;
                }
                else {
                    log( "unknown systemd endpoint domain " + value, Log::Disaster );
                    return;
                }
            }
            else if ( key == "index" ) {
                bool good;
                index = value.number( &good );
                if ( !good ) {
                    log( "invalid systemd endpoint index " + value, Log::Disaster );
                    return;
                }
            }
            else {
                log( "unexpected systemd endpoitn argument " + key, Log::Disaster );
                return;
            }
        }
        if ( domain == 0 ) {
            log( "systemd endpoint missing domain argument", Log::Disaster );
            return;
        }
        if ( index == -1 ) {
            log( "systemd endpoint missing index argument", Log::Disaster );
            return;
        }

        d->fd = kSystemdBeginFD + index;
        if ( d->fd >= fdEnd ) {
            log( "systemd endpoint index out of bounds", Log::Disaster );
            return;
        }

        if ( domain == AF_UNIX ) {
            d->proto = Unix;
            d->ua = "<unknown>";
        }
        else if ( domain == AF_INET ) {
            d->proto = IPv4;
            d->ip4a = 0;
        }
        else if ( domain == AF_INET6 ) {
            d->proto = IPv6;
            for (int i=0; i<8; ++i)
                d->ip6a[i] = 0;
        }
        else {
            log( "should never reach here", Log::Disaster );
            return;
        }
        d->valid = true;
    }
    else {
        uint i = 0;
        while ( i < address.length() &&
                ( address[i] != ':' && address[i] != '.' ) )
            i++;

        if ( address[i] == '.' ) {
            d->valid = true;
            d->proto = IPv4;
            d->ip4a  = ip4a( address, &d->valid );
        }
        else {
            d->valid = true;
            d->proto = IPv6;
            ip6a( address, d->ip6a, &d->valid );
        }

        d->port = port;
        if ( d->port == 0 || d->port > 65535 )
            d->valid = false;
    }
}


/*! Constructs an Endpoint corresponding to the sockaddr \a sa. */

Endpoint::Endpoint( const struct sockaddr *sa, uint len )
    : d( new EndpointData )
{
    if ( !sa )
        return;

    switch ( sa->sa_family ) {
    case AF_UNIX:
        {
            struct sockaddr_un *un = (struct sockaddr_un *)sa;
            d->valid = true;
            d->proto = Unix;
            if ( len == sizeof(sa_family_t) ) {
                d->ua = "(unnamed)";
            } else {
                d->ua = File::root().mid( 0, File::root().length()-1 ) +
                    un->sun_path;
            }
        }
        break;

    case AF_INET:
        {
            struct sockaddr_in *in = (struct sockaddr_in *)sa;
            d->valid = true;
            d->proto = IPv4;
            d->port  = ntohs( in->sin_port );
            d->ip4a  = ntohl( in->sin_addr.s_addr );
        }
        break;

    case AF_INET6:
        {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
            d->valid = true;
            d->proto = IPv6;
            d->port  = ntohs( in6->sin6_port );
            memmove( d->ip6a, in6->sin6_addr.s6_addr, 16 );
            int i = 0;
            while ( i < 8 ) {
                d->ip6a[i] = ntohs( d->ip6a[i] );
                i++;
            }
        }
        break;
    }
}


/*! Constructs an Endpoint using configuration data. \a address and \a
    port are fetched using Configuration.

    This constructor logs errors if anything goes wrong.
*/

Endpoint::Endpoint( Configuration::Text address,
                    Configuration::Scalar port )
    : d( new EndpointData )
{
    EString a( Configuration::text( address ) );
    if ( a[0] == '/' || a.startsWith("systemd/") || a.startsWith("fd/") ) {
        Endpoint tmp( a, 0 );
        *this = tmp;
        if ( Configuration::present( port ) )
            log( EString( Configuration::name( port ) ) +
                 " meaningless since " +
                 Configuration::name( address ) +
                 " is a unix-domain or inherited socket",
                 Log::Error );
    }
    else {
        const EStringList & r = Resolver::resolve( a );
        if ( r.isEmpty() ) {
            log( "Could not resolve "
                  + EString( Configuration::name( address ) )
                  + " = " + a, Log::Error );
        }
        else {
            // what a hack...
            Endpoint tmp( *r.first(), Configuration::scalar( port ) );
            *this = tmp;
        }
    }
}


/*! Returns true if this endpoint represents something sensible, and
    false if there was an error during parsing or similar. */

bool Endpoint::valid() const
{
    return d->valid;
}


/*! Returns the protocol to be used for this Endpoint. */

Endpoint::Protocol Endpoint::protocol() const
{
    return d->proto;
}


/*! Returns a string representation of this Endpoint's address. The
    return value is both human-readable and uniquely parsable. For
    example, the Endpoint constructor can parse the result of
    address().

    If the Endpoint isn't valid(), address() returns an empty string.
*/

EString Endpoint::address() const
{
    EString result;

    if ( !d->valid )
        return "";

    if ( d->fd >= 0 ) {
        return "inherited:" + fn( d->fd );
    }

    switch ( d->proto ) {
    case Unix:
        result = d->ua;
        break;

    case IPv4:
        result = fn( (d->ip4a >> 24) & 0xff ) + "." +
                 fn( (d->ip4a >> 16) & 0xff ) + "." +
                 fn( (d->ip4a >>  8) & 0xff ) + "." +
                 fn(  d->ip4a        & 0xff );
        break;

    case IPv6:
        if ( d->ip6a[0] == 0 &&
             d->ip6a[1] == 0 &&
             d->ip6a[2] == 0 &&
             d->ip6a[3] == 0 &&
             d->ip6a[4] == 0 &&
             d->ip6a[5] == 0xffff ) {
            result = fn( (d->ip6a[6] >> 8) & 0xff ) + "." +
                     fn( (d->ip6a[6]     ) & 0xff ) + "." +
                     fn( (d->ip6a[7] >> 8) & 0xff ) + "." +
                     fn( (d->ip6a[7]     ) & 0xff );
        }
        else {
            // First, find the longest series of zeroes.
            uint i = 0;
            uint z = 0;
            uint l = 0;
            while ( i < 8 ) {
                if ( d->ip6a[i] == 0 ) {
                    uint e = 0;
                    while ( i + e < 8 && d->ip6a[i+e] == 0 )
                        e++;
                    if ( e > l ) {
                        z = i;
                        l = e;
                    }
                    i += e;
                }
                else {
                    i++;
                }
            }

            // Next, pile them on.
            i = 0;
            bool sep = false;
            while ( i < 8 ) {
                if ( l > 0 && i == z ) {
                    result.append( "::" );
                    i += l;
                    sep = false;
                }
                else {
                    if ( sep )
                        result.append( ":" );
                    result.appendNumber( d->ip6a[i++], 16 );
                    sep = true;
                }
            }
        }
        break;
    }

    return result;
}


/*! And what port? */

uint Endpoint::port() const
{
    if ( !d->valid )
        return 0;
    return d->port;
}


/*! inherited? */

bool Endpoint::inherited() const
{
    return d->fd >= 0;
}


/*! inherited fd? */
int Endpoint::fd() const
{
    // XXX assert(d->fd >= 0);
    return d->fd;
}


/*! This strange function exists only so that we can construct a valid
    sockaddr that has the port set to zero, so that we can pass it to
    bind(2) and ask it to fill in a random port for us. The calling
    convention is inconvenient, but makes it easy to locate callers.
*/

void Endpoint::zeroPort()
{
    d->port = 0;
}


static union {
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
    struct sockaddr_un un;
} sa;


/*! Returns a pointer to a static sockaddr structure filled in with
    this Endpoint's information. Subsequent calls to sockaddr() will
    overwrite the result.

    If the Endpoint is not valid, this function returns a null pointer.
*/

struct sockaddr * Endpoint::sockaddr() const
{
    if ( !d->valid )
        return 0;

    memset( &sa, 0, sockaddrSize() );

    switch ( d->proto ) {
    case Unix:
        {
            EString n = File::chrooted( d->ua );
            sa.un.sun_family = AF_UNIX;
            // Does anyone have sun_len any more?
            // sa.un.sun_len = n.length();
            memmove( sa.un.sun_path, n.data(), n.length() );
        }
        break;

    case IPv4:
        sa.in.sin_family = AF_INET;
        sa.in.sin_port = htons( d->port );
        sa.in.sin_addr.s_addr = htonl( d->ip4a );
        break;

    case IPv6:
        {
            sa.in6.sin6_family = AF_INET6;
            sa.in6.sin6_port = htons( d->port );
            ushort a[8];
            int i = 0;
            while ( i < 8 ) {
                a[i] = ntohs( d->ip6a[i] );
                i++;
            }
            memmove( sa.in6.sin6_addr.s6_addr, a, 16 );
        }
        break;
    }

    return (struct sockaddr *)&sa;
}


/*! Returns the size of the struct to which sockaddr() returns a
    pointer.
*/

uint Endpoint::sockaddrSize() const
{
    if ( !d->valid )
        return 0;

    uint n = 0;
    switch ( d->proto ) {
    case IPv4:
        n = sizeof( struct sockaddr_in );
        break;
    case IPv6:
        n = sizeof( struct sockaddr_in6 );
        break;
    case Unix:
        n = sizeof( struct sockaddr_un );
        break;
    }
    return n;
}


/*! Returns the string representation of an endpoint. Note that this
    cannot be parsed - it's strictly for human consumption.

    The returned value does not contain slash, backslash or parens.
*/

EString Endpoint::string() const
{
    if ( !d->valid )
        return "";

    EString s;
    switch ( d->proto ) {
    case Unix:
        s = address();
        break;

    case IPv4:
    case IPv6:
        s = address() + ":" + fn( d->port );
        break;
    }

    return s;
}


/*! Makes this Endpoint into a copy of \a other and returns a
    reference to this Endpoint.
*/

Endpoint & Endpoint::operator=( const Endpoint & other )
{
    d->valid = other.d->valid;
    d->proto = other.d->proto;

    switch ( d->proto ) {
    case Unix:
        d->ua = other.d->ua;
        break;

    case IPv4:
        d->ip4a = other.d->ip4a;
        d->port = other.d->port;
        break;

    case IPv6:
        {
            uint i = 0;
            while ( i < 8 ) {
                d->ip6a[i] = other.d->ip6a[i];
                i++;
            }
            d->port = other.d->port;
        }
        break;
    }

    return *this;
}


static uint ip4a( const EString &address, bool * good )
{
    uint i = 0;
    uint b = 0;
    uint r = 0;
    while ( *good && i < address.length() ) {
        uint j = i;
        while ( address[j] >= '0' && address[j] <= '9' )
            j++;
        if ( j < address.length() && address[j] != '.' )
            *good = false;
        uint byte = 0;
        if ( *good )
            byte = address.mid( i, j-i ).number( good );
        if ( byte > 255 )
            *good = false;
        r = (r << 8) + byte;
        i = j+1;
        b++;
    }
    if ( b != 4 )
        *good = false; // bug: a string with UINT_MAX+1+4 dots... ;)
    return r;
}


static void ip6a( const EString &address, unsigned short int r[], bool * good )
{
    uint i = 0;
    uint b = 0;
    uint c = 8;
    while ( *good && i < address.length() ) {
        uint j = i;
        while ( ( address[j] >= '0' && address[j] <= '9' ) ||
                ( address[j] >= 'A' && address[j] <= 'F' ) ||
                ( address[j] >= 'a' && address[j] <= 'f' ) )
            j++;
        if ( j < address.length() && address[j] != ':' && address[j] != '.' )
            *good = false;
        if ( address[j] == '.' ) {
            uint a = ip4a( address.mid( i ), good );
            if ( b < 7 ) {
                r[b++] = a >> 16;
                r[b++] = a & 0xffff;
            }
            else {
                *good = false;
            }
            i = address.length();
        }
        else {
            uint word = 0; // correct value for i==0, address=="::"
            if ( j == i && c < 8 )
                *good = false;
            if ( *good && j > i )
                word = address.mid( i, j-i ).number( good, 16 );
            if ( word > 65535 )
                *good = false;
            r[b++] = word;
            i = j+1;
            if ( *good && address[j+1] == ':' && c == 8 ) {
                c = b;
                i++;
            }
        }
    }
    if ( c < 8 ) {
        if ( b >= 8 ) {
            *good = false;
        }
        else {
            i = 8;
            while ( b > c )
                r[--i] = r[--b];
            while ( i > c )
                r[--i] = 0;
            b = 8;
        }
    }
    if ( b != 8 )
        *good = false;
}


