// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "fetch.h"

#include "messagecache.h"
#include "imapsession.h"
#include "transaction.h"
#include "annotation.h"
#include "messageset.h"
#include "stringlist.h"
#include "mimefields.h"
#include "imapparser.h"
#include "bodypart.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "ustring.h"
#include "section.h"
#include "listext.h"
#include "fetcher.h"
#include "iso8859.h"
#include "codec.h"
#include "query.h"
#include "scope.h"
#include "store.h"
#include "timer.h"
#include "imap.h"
#include "flag.h"
#include "date.h"
#include "user.h"
#include "dict.h"
#include "utf.h"



static const char * legalAnnotationAttributes[] = {
    "value",
    "value.priv",
    "value.shared",
    "size",
    "size.priv",
    "size.shared",
    0
};


class FetchData
    : public Garbage
{
public:
    FetchData()
        : state( 0 ), peek( true ),
          changedSince( 0 ), those( 0 ),
          t( 0 ),
          store( 0 ),
          timer( 0 ), responseRate( 0 ),
          uid( false ),
          flags( false ), envelope( false ),
          body( false ), bodystructure( false ),
          internaldate( false ), rfc822size( false ),
          annotation( false ), modseq( false ),
          needsHeader( false ), needsAddresses( false ),
          needsBody( false ), needsPartNumbers( false )
    {}

    int state;
    bool peek;
    MessageSet set;
    MessageSet expunged;
    List<Message> requested;
    List<Message> available;
    int64 changedSince;
    Query * those;
    Transaction * t;
    Store * store;

    class ResponseTrickler
        : public EventHandler
    {
    public:
        ResponseTrickler( Fetch * fetch )
            : EventHandler(), f( fetch ) { setLog( Scope::current()->log() ); }
        void execute() { f->trickle(); }

        Fetch * f;
    };
    Timer * timer;
    uint responseRate;

    // we want to ask for...
    bool uid;
    bool flags;
    bool envelope;
    bool body;
    bool bodystructure;
    bool internaldate;
    bool rfc822size;
    bool annotation;
    bool modseq;
    List<Section> sections;

    // and the sections imply that we...
    bool needsHeader;
    bool needsAddresses;
    bool needsBody;
    bool needsPartNumbers;

    StringList entries;
    StringList attribs;

};


/*! \class Fetch fetch.h

    Returns message data (RFC 3501, section 6.4.5, extended by RFC
    4551 and RFC 5257).

    Our parser used to be slightly more permissive than the RFC. This
    is a bug (is it? why?), and many of the problems have been
    corrected (but not tested).
*/


/*! Creates a new handler for FETCH if \a u is false, or for UID FETCH
    if \a u is true.
*/

Fetch::Fetch( bool u )
    : Command(), d( new FetchData )
{
    d->uid = u;
    if ( u )
        setGroup( 1 );
    else
        setGroup( 2 );
}


/*! Constructs a handler for the implicit fetch which is executed by
    ImapSession for flag updates, etc. If \a f is true the updates
    will include FLAGS sections and if \a a is true, ANNOTATION. The
    handler starts fetching those messagges in \a set that have a
    modseq greater than \a limit. The responses are sent via \a i.
*/

Fetch::Fetch( bool f, bool a, const MessageSet & set, int64 limit, IMAP * i )
    : Command( i ), d( new FetchData )
{
    setLog( new Log( Log::IMAP ) );
    Scope x( log() );
    d->uid = true;
    d->flags = f;
    d->annotation = a;
    d->set = set;
    d->changedSince = limit;
    d->modseq = i->clientSupports( IMAP::Condstore );

    d->peek = true;

    List<Command>::Iterator c( i->commands() );
    while ( c && c->state() == Command::Retired )
        ++c;
    while ( c && c->tag().isEmpty() )
        ++c;
    if ( c && ( c->state() == Command::Finished ||
                c->state() == Command::Executing ) ) {
        log( "Inserting flag update for modseq>" + fn( limit ) +
             " and UIDs " + set.set() + " before " +
             c->tag() + " " + c->name() );
        i->commands()->insert( c, this );
        if ( c->group() == 1 || c->group() == 2 )
            setGroup( c->group() );
    }
    else {
        log( "Appending flag update for modseq>" + fn( limit ) +
             " and UIDs " + set.set() );
        i->commands()->append( this );
    }

    setAllowedState( IMAP::Selected );
    setState( Executing );
}


// fetch           = "FETCH" SP set SP ("ALL" / "FULL" / "FAST" / fetch-att /
//                   "(" fetch-att *(SP fetch-att) ")")
// fetch-att       = "ENVELOPE" / "FLAGS" / "INTERNALDATE" /
//                   "RFC822" [".HEADER" / ".SIZE" / ".TEXT"] /
//                   "BODY" ["STRUCTURE"] / "UID" /
//                   "BODY" [".PEEK"] section ["<" number "." nz-number ">"]
//                 / "MODSEQ" ; 4551
// section         = "[" [section-spec] "]"
// section-spec    = section-msgtext / (section-part ["." section-text])
// section-msgtext = "HEADER" / "HEADER.FIELDS" [".NOT"] SP header-list /
//                   "TEXT"
// section-part    = nz-number *("." nz-number)
// section-text    = section-msgtext / "MIME"
// header-list     = "(" header-fld-name *(SP header-fld-name) ")"
// header-fld-name = astring


void Fetch::parse()
{
    space();
    d->set = set( !d->uid );
    space();
    if ( nextChar() == '(' ) {
        // "(" fetch-att *(SP fetch-att) ")")
        step();
        parseAttribute( false );
        while( nextChar() == ' ' ) {
            step();
            parseAttribute( false );
        }
        require( ")" );
    }
    else {
        // single fetch-att, or the macros
        parseAttribute( true );
    }
    if ( present( " (" ) ) {
        // RFC 4466 fetch-modifiers
        parseFetchModifier();
        while ( present( " " ) )
            parseFetchModifier();
        require( ")" );
    }
    end();
    if ( d->envelope ) {
        d->needsHeader = true;
        d->needsAddresses = true;
    }
    if ( d->body || d->bodystructure ) {
        // message/rfc822 body[structure] includes envelope in some
        // cases, so we need both here too.
        d->needsHeader = true;
        d->needsAddresses = true;
        // and we even need some data about the bodies
        d->needsPartNumbers = true;
    }
    if ( !ok() )
        return;
    StringList l;
    l.append( new String( "Fetch " + fn( d->set.count() ) + " messages: " ) );
    if ( d->needsAddresses )
        l.append( "address" );
    if ( d->needsHeader )
        l.append( "header" );
    if ( d->needsBody )
        l.append( "body" );
    if ( d->flags )
        l.append( "flags" );
    if ( d->rfc822size || d->internaldate || d->modseq )
        l.append( "trivia" );
    if ( d->needsPartNumbers )
        l.append( "bytes/lines" );
    if ( d->annotation )
        l.append( "annotations" );
    log( l.join( " " ) );
}


/*! This helper is responsible for parsing a single attribute from the
    fetch arguments. If \a alsoMacro is true, this function parses a
    macro as well as a single attribute.
*/

void Fetch::parseAttribute( bool alsoMacro )
{
    String keyword = dotLetters( 3, 13 ).lower(); // UID/ALL, RFC822.HEADER
    if ( alsoMacro && keyword == "all" ) {
        // equivalent to: (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)
        d->flags = true;
        d->envelope = true;
        d->internaldate = true;
        d->rfc822size = true;
    }
    else if ( alsoMacro && keyword == "full" ) {
        // equivalent to: (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)
        d->flags = true;
        d->envelope = true;
        d->body = true;
        d->internaldate = true;
        d->rfc822size = true;
    }
    else if ( alsoMacro && keyword == "fast" ) {
        // equivalent to: (FLAGS INTERNALDATE RFC822.SIZE)
        d->flags = true;
        d->internaldate = true;
        d->rfc822size = true;
    }
    else if ( keyword == "envelope" ) {
        d->envelope = true;
    }
    else if ( keyword == "flags" ) {
        d->flags = true;
    }
    else if ( keyword == "internaldate" ) {
        d->internaldate = true;
    }
    else if ( keyword == "rfc822" ) {
        d->peek = false;
        d->needsAddresses = true;
        d->needsHeader = true;
        d->needsBody = true;
        Section * s = new Section;
        s->id = keyword;
        d->sections.append( s );
    }
    else if ( keyword == "rfc822.header" ) {
        d->needsAddresses = true;
        d->needsHeader = true;
        Section * s = new Section;
        s->id = keyword;
        d->sections.append( s );
    }
    else if ( keyword == "rfc822.size" ) {
        d->rfc822size = true;
    }
    else if ( keyword == "annotation" ) {
        d->annotation = true;
        require( " " );
        parseAnnotation();
    }
    else if ( keyword == "rfc822.text" ) {
        d->peek = false;
        d->needsHeader = true;
        d->needsBody = true;
        Section * s = new Section;
        s->id = keyword;
        d->sections.append( s );
    }
    else if ( keyword == "body.peek" && nextChar() == '[' ) {
        step();
        parseBody( false );
    }
    else if ( keyword == "body" ) {
        if ( nextChar() == '[' ) {
            d->peek = false;
            step();
            parseBody( false );
        }
        else {
            d->body = true;
            // poor man's bodystructure
        }
    }
    else if ( keyword == "bodystructure" ) {
        d->bodystructure = true;
        // like body, but with bells and whistles
    }
    else if ( keyword == "uid" ) {
        d->uid = true;
    }
    else if ( keyword == "binary.peek" && nextChar() == '[' ) {
        step();
        parseBody( true );
    }
    else if ( keyword == "binary" && nextChar() == '[' ) {
        d->peek = false;
        step();
        parseBody( true );
    }
    else if ( keyword == "binary.size" && nextChar() == '[' ) {
        step();
        parseBody( true );
        Section * s = d->sections.last();
        s->id = "size";
        if ( s->partial )
            error( Bad, "Fetching partial BINARY.SIZE is not meaningful" );
        if ( s->part.isEmpty() )
            d->rfc822size = true;
    }
    else if ( keyword == "modseq" ) {
        d->modseq = true;
    }
    else {
        error( Bad, "expected fetch attribute, saw word " + keyword );
    }
}


/*! This utility function fetches at least \a min, at most \a max
    characters, all of which must be a letter, a digit or a dot.
    Consecutive dots ARE allowed.
*/

String Fetch::dotLetters( uint min, uint max )
{
    String r( parser()->dotLetters( min, max ) );
    if ( !parser()->ok() )
        error( Bad, parser()->error() );
    return r;
}


/*! Uses the ImapParser \a ip to parse a section-text production, and
    returns a pointer to a suitably constructed Section object. Upon
    return, the ImapParser's cursor is advanced to point past the end
    of the section-text. \a ip must not be 0; and the return value of
    this function is also guaranteed to be non-zero.

    If \a binary is false (the default), then the BINARY extensions of
    RFC 3516 are summarily ignored.

    If there were any parsing errors, Section::error will be non-empty.
*/

Section * Fetch::parseSection( ImapParser * ip, bool binary )
{
    Section * s = new Section;
    s->binary = binary;

    // section-spec    = section-msgtext / (section-part ["." section-text])
    // section-msgtext = "HEADER" /
    //                   "HEADER.FIELDS" [".NOT"] SP header-list /
    //                   "TEXT"
    // section-part    = nz-number *("." nz-number)
    // section-text    = section-msgtext / "MIME"

    // Parse a section-part.
    bool dot = false;
    if ( ip->nextChar() >= '0' && ip->nextChar() <= '9' ) {
        String part;
        part.append( fn( ip->nzNumber() ) );
        while ( ip->nextChar() == '.' ) {
            ip->step();
            if ( ip->nextChar() >= '0' && ip->nextChar() <= '9' ) {
                part.append( "." );
                part.append( fn( ip->nzNumber() ) );
            }
            else {
                dot = true;
                break;
            }
        }
        s->part = part;
    }

    // Parse any section-text.
    String item = ip->dotLetters( 0, 17 ).lower();
    if ( binary && !item.isEmpty() ) {
        s->error = "BINARY with section-text is not legal, saw " + item;
    }
    else if ( item.isEmpty() || item == "text" ) {
        s->needsBody = true;
        // and because we might need headers and addresses of subparts:
        s->needsHeader = true;
        s->needsAddresses = true;
    }
    else if ( item == "header" ) {
        s->needsHeader = true;
        s->needsAddresses = true;
    }
    else if ( item == "header.fields" ||
              item == "header.fields.not" )
    {
        ip->require( " (" );
        s->fields.append( new String( ip->astring().headerCased() ) );
        while ( ip->nextChar() == ' ' ) {
            ip->require( " " );
            s->fields.append( new String( ip->astring().headerCased() ) );
        }
        ip->require( ")" );
        if ( item == "header.fields.not" ) {
            // if we need to hand out "all other" fields...
            s->needsAddresses = true;
            s->needsHeader = true;
        }
        StringList::Iterator i( s->fields );
        while ( i && ( !s->needsAddresses || !s->needsHeader ) ) {
            uint t = HeaderField::fieldType( *i );
            if ( t > 0 && t <= HeaderField::LastAddressField )
                s->needsAddresses = true;
            else
                s->needsHeader = true;
            ++i;
        }
    }
    else if ( item == "mime" ) {
        if ( s->part.isEmpty() )
            s->error = "MIME requires a section-part.";
        s->needsHeader = true;
    }
    else if ( dot ) {
        s->error =
            "Expected text, header, header.fields etc, not " + item +
            ip->following();
    }

    s->id = item;
    return s;
}


/*! Parses a bodypart description - the bit following "body[" in an
    attribute. The cursor must be after '[' on entry, and is left
    after the trailing ']'.

    If \a binary is true, the parsed section will be sent using the
    BINARY extension (RFC 3516). If not, it'll be sent using a normal
    BODY.
*/

void Fetch::parseBody( bool binary )
{
    Section * s = parseSection( parser(), binary );
    if ( !s->error.isEmpty() ) {
        error( Bad, s->error );
        return;
    }

    require( "]" );

    // Parse any range specification.
    if ( nextChar() == '<' ) {
        s->partial = true;
        step();
        s->offset = number();
        require( "." );
        s->length = nzNumber();
        require( ">" );
    }

    d->sections.append( s );
    if ( s->needsAddresses )
        d->needsAddresses = true;
    if ( s->needsHeader )
        d->needsHeader = true;
    if ( s->needsBody )
        d->needsBody = true;
}


void record( StringList & l, Dict<void> & d, const String & a )
{
    if ( !d.contains( a.lower() ) )
        l.append( new String( a ) );
    d.insert( a.lower(), (void *)1 );
}


/*! Parses the entries and attributes from an ANNOTATION fetch-att.
    Expects the cursor to be on the first parenthesis, and advances
    it to past the last one.
*/

void Fetch::parseAnnotation()
{
    bool atEnd;
    bool paren;

    // Simplified ABNF from draft-ietf-imapext-annotate-15:
    //
    //  fetch-att =/ "ANNOTATION" SP "(" entries SP attribs ")"
    //  entries   = list-mailbox /
    //              "(" list-mailbox *(SP list-mailbox) ")"
    //  attribs   = astring /
    //              "(" astring *(SP astring) ")"

    require( "(" );

    paren = false;
    if ( nextChar() == '(' ) {
        step();
        paren = true;
    }

    atEnd = false;
    while ( !atEnd ) {
        d->entries.append( new String( parser()->listMailbox() ) );
        if ( !parser()->ok() )
            error( Bad, parser()->error() );

        if ( paren ) {
            if ( nextChar() == ')' ) {
                step();
                atEnd = true;
            }
            else {
                space();
            }
        }
        else {
            atEnd = true;
        }
    }

    require( " " );

    paren = false;
    if ( nextChar() == '(' ) {
        step();
        paren = true;
    }

    Dict<void> attribs;

    atEnd = false;
    while ( !atEnd ) {
        String a( astring() );

        // XXX: This check (and the legalAnnotationAttributes table) is
        // duplicated in Search::parseKey(). But where should a common
        // attribute-checking function live?
        uint i = 0;
        while ( ::legalAnnotationAttributes[i] &&
                a != ::legalAnnotationAttributes[i] )
            i++;
        if ( !::legalAnnotationAttributes[i] )
            error( Bad, "Unknown annotation attribute: " + a );

        if ( a.endsWith( ".priv" ) || a.endsWith( ".shared" ) ) {
            record( d->attribs, attribs, a );
        }
        else {
            record( d->attribs, attribs, a + ".priv" );
            record( d->attribs, attribs, a + ".shared" );
        }

        if ( paren ) {
            if ( nextChar() == ')' ) {
                step();
                atEnd = true;
            }
            else {
                space();
            }
        }
        else {
            atEnd = true;
        }
    }

    require( ")" );
}


void Fetch::execute()
{
    if ( state() != Executing )
        return;

    ImapSession * s = session();

    if ( !d->peek && s->readOnly() )
        d->peek = true;

    if ( d->state == 0 ) {
        if ( d->changedSince ) {
            if ( !d->those ) {
                d->t = new Transaction( this );
                d->those = new Query( "select uid from mailbox_messages "
                                      "where mailbox=$1 and modseq>$2 "
                                      "and uid=any($3) for update",
                                      this );
                d->those->bind( 1, s->mailbox()->id() );
                d->those->bind( 2, d->changedSince );
                d->those->bind( 3, d->set );
                d->t->enqueue( d->those );
                d->t->execute();
            }
            if ( !d->those->done() )
                return;
            d->set.clear();
            Row * r;
            while ( (r=d->those->nextRow()) != 0 )
                d->set.add( r->getInt( "uid" ) );
        }
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( group() == 2 ) // then RFC 2180 section 4.1.2 applies
            d->expunged = s->expunged().intersection( d->set );
        shrink( &d->set );
        d->state = 2;
        if ( d->set.isEmpty() )
            d->state = 5;
    }

    if ( d->state == 2 ) {
        if ( d->peek ) {
            d->state = 3;
        }
        else {
            if ( !d->store ) {
                List<Command>::Iterator c = imap()->commands()->find( this );
                if ( c ) {
                    d->store = new Store( imap(), d->set, d->flags );
                    d->store->setState( Executing );
                    imap()->commands()->insert( c, d->store );
                    d->store->execute();
                }
            }
            if ( d->store && d->store->state() == Executing )
                return;
            d->state = 3;
        }
    }

    if ( d->state == 3 ) {
        d->state = 4;
        sendFetchQueries();
    }

    if ( d->state < 4 )
        return;

    pickup();

    if ( !d->requested.isEmpty() )
        return;

    if ( d->t )
        d->t->commit();

    while ( !d->available.isEmpty() ) {
        Message * m = d->available.shift();
        uint u = m->uid( s->mailbox() );
        respond( makeFetchResponse( m, u, s->msn( u ) ) );
    }
    d->available.clear();

    if ( !d->expunged.isEmpty() ) {
        s->recordExpungedFetch( d->expunged );
        error( No, "UID(s) " + d->expunged.set() + " has/have been expunged" );
    }
    finish();
}


/*! Issues queries to resolve any questions this FETCH needs to answer.
*/

void Fetch::sendFetchQueries()
{
    Mailbox * mb = session()->mailbox();

    List<Message> * l = new List<Message>;

    bool haveAddresses = true;
    bool haveHeader = true;
    bool haveBody = true;
    bool havePartNumbers = true;
    bool haveTrivia = true;
    bool haveFlags = true;
    bool haveAnnotations = true;

    while ( !d->set.isEmpty() ) {
        uint uid = d->set.value( 1 );
        d->set.remove( uid );
        Message * m = MessageCache::find( mb, uid );
        if ( !m ) {
            m = new Message;
        }
        else if ( m->modSeq( mb ) + 1 < mb->nextModSeq() ) {
            m->setFlagsFetched( mb, false );
            m->setAnnotationsFetched( mb, false );
            m->setModSeq( mb, 0 );
        }
        if ( !m->hasAddresses() )
            haveAddresses = false;
        if ( !m->hasHeaders() )
            haveHeader = false;
        if ( !m->hasBytesAndLines() )
            havePartNumbers = false;
        if ( !m->hasBodies() )
            haveBody = false;
        if ( !m->hasTrivia() )
            haveTrivia = false;
        if ( !m->hasFlags( mb ) )
            haveFlags = false;
        if ( !m->hasAnnotations( mb ) )
            haveAnnotations = false;
        m->setUid( mb, uid );
        d->requested.append( m );
        l->append( m );
    }

    Fetcher * f = new Fetcher( mb, l, this );
    if ( d->needsAddresses && !haveAddresses )
        f->fetch( Fetcher::Addresses );
    if ( d->needsHeader && !haveHeader )
        f->fetch( Fetcher::OtherHeader );
    if ( d->needsBody && !haveBody )
        f->fetch( Fetcher::Body );
    if ( d->needsPartNumbers && !havePartNumbers )
        f->fetch( Fetcher::PartNumbers );
    if ( d->flags && !haveFlags )
        f->fetch( Fetcher::Flags );
    if ( ( d->rfc822size || d->internaldate || d->modseq ) &&
         !haveTrivia )
        f->fetch( Fetcher::Trivia );
    if ( d->annotation && !haveAnnotations )
        f->fetch( Fetcher::Annotations );
    f->setSession( imap()->session() );
    if ( d->t )
        f->setTransaction( d->t );
    f->execute();

    FetchData::ResponseTrickler * t = new FetchData::ResponseTrickler( this );
    d->timer = new Timer( t, 1 );
    d->timer->setRepeating( true );
}


/*! This function returns the text of that portion of the Message \a m
    that is described by the Section \a s. It is publicly available so
    that Append may use it for CATENATE.
*/

String Fetch::sectionData( Section * s, Message * m )
{
    String item, data;

    if ( s->id == "rfc822" ) {
        item = s->id.upper();
        data = m->rfc822();
    }

    else if ( s->id == "mime" ||
              s->id == "rfc822.header" ||
              s->id.startsWith( "header" ) ) {
        bool rfc822 = s->id == "rfc822.header";
        bool fields = s->id.startsWith( "header.fields" );
        bool exclude = s->id.endsWith( ".not" );

        data.reserve( 80 * s->fields.count() ); // suboptimal for .not, but...

        Header * hdr = m->header();
        if ( !s->part.isEmpty() ) {
            Bodypart * bp = m->bodypart( s->part, false );
            if ( bp && bp->header() )
                hdr = bp->header();
            else
                hdr = 0;
        }

        List< HeaderField >::Iterator it;
        if ( hdr )
            it = hdr->fields()->first();
        while ( it ) {
            bool include = false;
            if ( !fields ) {
                include = true;
            }
            else {
                bool listed = s->fields.find( it->name() );
                if ( exclude )
                    include = !listed;
                else
                    include = listed;
            }
            if ( include ) {
                String n = it->name().headerCased();
                data.append( n );
                data.append( ": " );
                data.append( it->rfc822() );
                data.append( "\r\n" );
            }
            ++it;
        }

        item = s->id.upper();
        if ( !rfc822 ) {
            if ( !s->part.isEmpty() )
                item = s->part + "." + item;
            item = "BODY[" + item;
            if ( fields )
                item.append( " (" + s->fields.join( " " ) + ")" );
            item.append( "]" );
        }
        data.append( "\r\n" );
    }

    else if ( s->id == "rfc822.text" ) {
        item = s->id.upper();
        data = m->body();
    }

    else if ( s->id == "text" ) {
        if ( s->part.isEmpty() ) {
            item = "TEXT";
            data = m->body();
        }
        else {
            item = s->part + ".TEXT";
            Bodypart *bp = m->bodypart( s->part, false );
            if ( bp && bp->message() )
                data = bp->message()->body();
        }
        item = "BODY[" + item + "]";
    }

    else if ( ( s->id.isEmpty() || s->id == "size" ) &&
              s->part.isEmpty() )
    {
        if ( s->id == "size" ) {
            item = "BINARY.SIZE[]";
            data = fn( m->rfc822Size() );
        }
        else {
            item = "BODY[]";
            data = m->rfc822();
        }
    }

    else if ( s->id.isEmpty() || s->id == "size" ) {
        item = "BODY";
        Bodypart * bp = m->bodypart( s->part, false );
        if ( !bp ) {
            // nonexistent part number
            if ( s->binary )
                item = "BINARY";
            // should we report an error?  the fetch responses will be
            // sent anyway.
            // error( No, "No such bodypart: " + s->part );
        }
        else if ( bp->message() ) {
            // message/rfc822 part
            data = bp->message()->rfc822();
        }
        else if ( bp->children()->isEmpty() ) {
            // leaf part
            data = bp->data();

            ContentType * ct = bp->contentType();
            if ( !ct || ct->type() == "text" ) {
                UString text;

                if ( data.isEmpty() ) {
                    text = bp->text();
                }
                else {
                    Codec * c = new Utf8Codec;
                    text = c->toUnicode( data );
                }

                Codec * c = 0;
                if ( ct )
                    c = Codec::byName( ct->parameter( "charset" ) );
                if ( !c && ct && ct->subtype() == "html" )
                    c = new Iso88591Codec;
                if ( !c )
                    c = new Utf8Codec;
                data = c->fromUnicode( text );
            }
            if ( !s->binary )
                data = data.encode( bp->contentTransferEncoding(), 70 );
        }
        else {
            // nonleaf part. probably wrong - this might use the wrong
            // content-transfer-encoding.
            data = bp->asText();
        }

        if ( s->binary )
            item = "BINARY";

        if ( s->id == "size" ) {
            item = "BINARY.SIZE";
            data = fn( data.length() );
        }

        item = item + "[" + s->part + "]";
    }

    if ( s->partial ) {
        item.append( "<" + fn( s->offset ) + ">" );
        data = data.mid( s->offset, s->length );
    }

    s->item = item;
    return data;
}


/* This function returns the response data for an element in
   d->sections, to be included in the FETCH response by
   fetchResponses() below.
*/

static String sectionResponse( Section * s, Message * m )
{
    String data( Fetch::sectionData( s, m ) );
    if ( !s->item.startsWith( "BINARY.SIZE" ) )
        data = Command::imapQuoted( data, Command::NString );
    String r;
    r.reserve( data.length() + s->item.length() + 1 );
    r.append( s->item );
    r.append( " " );
    r.append( data );
    return r;
}


/*! Emits a single FETCH response for the message \a m, which is
    trusted to have UID \a uid and MSN \a msn.

    The message must have all necessary content.
*/

String Fetch::makeFetchResponse( Message * m, uint uid, uint msn )
{
    StringList l;
    if ( d->uid )
        l.append( "UID " + fn( uid ) );
    if ( d->rfc822size )
        l.append( "RFC822.SIZE " + fn( m->rfc822Size() ) );
    if ( d->flags )
        l.append( "FLAGS (" + flagList( m, uid, imap()->session() ) + ")" );
    if ( d->internaldate )
        l.append( "INTERNALDATE " + internalDate( m ) );
    if ( d->envelope )
        l.append( "ENVELOPE " + envelope( m ) );
    if ( d->body )
        l.append( "BODY " + bodyStructure( m, false ) );
    if ( d->bodystructure )
        l.append( "BODYSTRUCTURE " + bodyStructure( m, true ) );
    if ( d->annotation )
        l.append( "ANNOTATION " + annotation( m, imap()->user(),
                                              session()->mailbox(),
                                              d->entries, d->attribs ) );
    if ( d->modseq )
        l.append( "MODSEQ (" +
                  fn( m->modSeq( session()->mailbox() ) ) + ")" );

    List< Section >::Iterator it( d->sections );
    while ( it ) {
        l.append( sectionResponse( it, m ) );
        ++it;
    }

    String r;
    String payload = l.join( " " );
    r.reserve( payload.length() + 30 );
    r.append( fn( msn ) );
    r.append( " FETCH (" );
    r.append( payload );
    r.append( ")" );
    return r;
}


/*! Returns a string containing all the flags that are set for message
    \a m, which has UID \a uid and is interpreted within \a session.
*/

String Fetch::flagList( Message * m, uint uid, Session * session )
{
    StringList r;

    if ( session && session->isRecent( uid ) )
        r.append( "\\recent" );

    StringList * f = m->flags( session->mailbox() );
    if ( f && !f->isEmpty() ) {
        StringList::Iterator it( f );
        while ( it ) {
            r.append( *it );
            ++it;
        }
    }

    return r.join( " " );
}


/*! Returns the internaldate of \a m in IMAP format. */

String Fetch::internalDate( Message * m )
{
    Date date;
    date.setUnixTime( m->internalDate( session()->mailbox() ) );
    return "\"" + date.imap() + "\"";
}


static String hf( Header * f, HeaderField::Type t )
{
    List<Address> * a = f->addresses( t );
    if ( !a || a->isEmpty() )
        return "NIL ";
    String r;
    r.reserve( 50 );
    r.append( "(" );
    List<Address>::Iterator it( a );
    while ( it ) {
        r.append( "(" );
        if ( it->type() == Address::EmptyGroup ) {
            r.append( "NIL NIL " );
            r.append( Command::imapQuoted( it->name(), Command::NString ) );
            r.append( " NIL)(NIL NIL NIL NIL" );
        } else if ( it->type() == Address::Local ||
                    it->type() == Address::Normal ) {
            UString u = it->uname();
            String eu;
            if ( u.isAscii() )
                eu = u.simplified().utf8();
            else
                eu = HeaderField::encodePhrase( u );
            r.append( Command::imapQuoted( eu, Command::NString ) );
            r.append( " NIL " );
            r.append( Command::imapQuoted( it->localpart(),
                                           Command::NString ) );
            r.append( " " );
            if ( it->domain().isEmpty() )
                r.append( "\" \"" ); // RFC 3501, page 77 near bottom
            else
                r.append( Command::imapQuoted( it->domain(),
                                               Command::NString ) );
        }
        r.append( ")" );
        ++it;
    }
    r.append( ") " );
    return r;
}


/*! Returns the IMAP envelope for \a m. */

String Fetch::envelope( Message * m )
{
    Header * h = m->header();

    // envelope = "(" env-date SP env-subject SP env-from SP
    //                env-sender SP env-reply-to SP env-to SP env-cc SP
    //                env-bcc SP env-in-reply-to SP env-message-id ")"

    String r;
    r.reserve( 300 );
    r.append( "(" );

    Date * date = h->date();
    if ( date )
        r.append( imapQuoted( date->rfc822(), NString ) );
    else
        r.append( "NIL" );
    r.append( " " );

    r.append( imapQuoted( h->subject(), NString ) + " " );
    r.append( hf( h, HeaderField::From ) );
    r.append( hf( h, HeaderField::Sender ) );
    r.append( hf( h, HeaderField::ReplyTo ) );
    r.append( hf( h, HeaderField::To ) );
    r.append( hf( h, HeaderField::Cc ) );
    r.append( hf( h, HeaderField::Bcc ) );
    r.append( imapQuoted( h->inReplyTo(), NString ) + " " );
    r.append( imapQuoted( h->messageId(), NString ) );

    r.append( ")" );
    return r;
}


static String parameterString( MimeField *mf )
{
    StringList *p = 0;

    if ( mf )
        p = mf->parameters();
    if ( !mf || !p || p->isEmpty() )
        return "NIL";

    StringList l;
    StringList::Iterator it( p );
    while ( it ) {
        l.append( Command::imapQuoted( *it ) );
        l.append( Command::imapQuoted( mf->parameter( *it ) ) );
        ++it;
    }

    String r = l.join( " " );
    r.prepend( "(" );
    r.append( ")" );
    return r;
}


static String dispositionString( ContentDisposition *cd )
{
    if ( !cd )
        return "NIL";

    String s;
    switch ( cd->disposition() ) {
    case ContentDisposition::Inline:
        s = "inline";
        break;
    case ContentDisposition::Attachment:
        s = "attachment";
        break;
    }

    return "(\"" + s + "\" " + parameterString( cd ) + ")";
}


static String languageString( ContentLanguage *cl )
{
    if ( !cl )
        return "NIL";

    StringList m;
    const StringList *l = cl->languages();
    StringList::Iterator it( l );
    while ( it ) {
        m.append( Command::imapQuoted( *it ) );
        ++it;
    }

    if ( l->count() == 1 )
        return *m.first();
    String r = m.join( " " );
    r.prepend( "(" );
    r.append( ")" );
    return r;
}


/*! Returns either the IMAP BODY or BODYSTRUCTURE production for \a
    m. If \a extended is true, BODYSTRUCTURE is returned. If it's
    false, BODY.
*/

String Fetch::bodyStructure( Multipart * m, bool extended )
{
    String r;

    Header * hdr = m->header();
    ContentType * ct = hdr->contentType();

    if ( ct && ct->type() == "multipart" ) {
        StringList children;
        List< Bodypart >::Iterator it( m->children() );
        while ( it ) {
            children.append( bodyStructure( it, extended ) );
            ++it;
        }

        r = children.join( "" );
        r.prepend( "(" );
        r.append( " " );
        r.append( imapQuoted( ct->subtype() ));

        if ( extended ) {
            r.append( " " );
            r.append( parameterString( ct ) );
            r.append( " " );
            r.append( dispositionString( hdr->contentDisposition() ) );
            r.append( " " );
            r.append( languageString( hdr->contentLanguage() ) );
            r.append( " " );
            r.append( imapQuoted( hdr->contentLocation(), NString ) );
        }

        r.append( ")" );
    }
    else {
        r = singlePartStructure( (Bodypart*)m, extended );
    }

    return r;
}


/*! Returns the structure of the single-part bodypart \a mp.

    If \a extended is true, extended BODYSTRUCTURE attributes are
    included.
*/

String Fetch::singlePartStructure( Multipart * mp, bool extended )
{
    StringList l;

    if ( !mp )
        return "";

    ContentType * ct = mp->header()->contentType();

    if ( ct ) {
        l.append( imapQuoted( ct->type() ) );
        l.append( imapQuoted( ct->subtype() ) );
    }
    else {
        // XXX: What happens to the default if this is a /digest?
        l.append( "\"text\"" );
        l.append( "\"plain\"" );
    }

    l.append( parameterString( ct ) );
    l.append( imapQuoted( mp->header()->messageId( HeaderField::ContentId ),
                          NString ) );
    l.append( imapQuoted( mp->header()->contentDescription(), NString ) );

    if ( mp->header()->contentTransferEncoding() ) {
        switch( mp->header()->contentTransferEncoding()->encoding() ) {
        case String::Binary:
            l.append( "\"8BIT\"" ); // hm. is this entirely sound?
            break;
        case String::Uuencode:
            l.append( "\"x-uuencode\"" ); // should never happen
            break;
        case String::Base64:
            l.append( "\"BASE64\"" );
            break;
        case String::QP:
            l.append( "\"QUOTED-PRINTABLE\"" );
            break;
        }
    }
    else {
        l.append( "\"7BIT\"" );
    }

    Bodypart * bp = 0;
    if ( mp->isBodypart() )
        bp = (Bodypart*)mp;
    else if ( mp->isMessage() )
        bp = ((Message*)mp)->children()->first();

    if ( bp ) {
        l.append( fn( bp->numEncodedBytes() ) );
        if ( ct && ct->type() == "message" && ct->subtype() == "rfc822" ) {
            // body-type-msg   = media-message SP body-fields SP envelope
            //                   SP body SP body-fld-lines
            l.append( envelope( bp->message() ) );
            l.append( bodyStructure( bp->message(), extended ) );
            l.append( fn( bp->numEncodedLines() ) );
        }
        else if ( !ct || ct->type() == "text" ) {
            // body-type-text  = media-text SP body-fields SP body-fld-lines
            l.append( fn( bp->numEncodedLines() ) );
        }
    }

    if ( extended ) {
        String md5;
        HeaderField *f = mp->header()->field( HeaderField::ContentMd5 );
        if ( f )
            md5 = f->rfc822();

        l.append( imapQuoted( md5, NString ) );
        l.append( dispositionString( mp->header()->contentDisposition() ) );
        l.append( languageString( mp->header()->contentLanguage() ) );
        l.append( imapQuoted( mp->header()->contentLocation(), NString ) );
    }

    String r = l.join( " " );
    r.prepend( "(" );
    r.append( ")" );
    return r;
}


/*! Returns the IMAP ANNOTATION production for \a m, from the point of
    view of \a u (0 for no user, only public annotations) and \a mb. \a
    entrySpecs is a list of the entries to be matched, each of which
    can contain the * and % wildcards. \a attributes is a list of
    attributes to be returned (each including the .priv or .shared
    suffix).
*/

String Fetch::annotation( Multipart * m, User * u, Mailbox * mb,
                          const StringList & entrySpecs,
                          const StringList & attributes )
{
    if ( !m->isMessage() )
        return "";

    typedef Dict< String > AttributeDict;
    Dict< AttributeDict > entries;

    StringList entryNames;

    uint user = 0;
    if ( u )
        user = u->id();
    List<Annotation>::Iterator i( ((Message*)m)->annotations( mb ) );
    while ( i ) {
        Annotation * a = i;
        ++i;

        String entry( a->entryName() );
        bool entryWanted = false;
        StringList::Iterator e( entrySpecs );
        while ( e ) {
            AsciiCodec c;
            if ( Mailbox::match( c.toUnicode( *e ), 0,
                                 c.toUnicode( entry ), 0 ) == 2 ) {
                if ( !entries.find( entry ) )
                    entryNames.append( new String( entry ) );
                entryWanted = true;
                break;
            }
            ++e;
        }

        if ( ( a->ownerId() == 0 || a->ownerId() == user ) &&
             entryWanted )
        {
            AttributeDict * atts = entries.find( entry );
            if ( !atts ) {
                atts = new AttributeDict;
                entries.insert( entry, atts );
            }

            const char * suffix = ".shared";
            if ( a->ownerId() )
                suffix = ".priv";

            String * v = new String( a->value() );
            String * s = new String( fn( v->length() ) );

            atts->insert( String( "value" ) + suffix, v );
            atts->insert( String( "size" ) + suffix, s );
        }
    }

    String r( "(" );
    StringList::Iterator e( entryNames );
    while ( e ) {
        String entry( *e );

        String tmp;
        StringList::Iterator a( attributes );
        while ( a ) {
            String attrib( *a );

            String * value = 0;
            AttributeDict * atts = entries.find( entry );
            if ( atts )
                value = atts->find( attrib );

            tmp.append( attrib );
            tmp.append( " " );
            if ( value )
                tmp.append( imapQuoted( *value ) );
            else if ( attrib.startsWith( "size." ) )
                tmp.append( "\"0\"" );
            else
                tmp.append( "NIL" );
            ++a;
            if ( a )
                tmp.append( " " );
        }

        r.append( entry );
        if ( !tmp.isEmpty() ) {
            r.append( " (" );
            r.append( tmp );
            r.append( ")" );
        }

        ++e;
        if ( e )
            r.append( " " );
    }
    r.append( ")" );
    return r;
}


/*! Parses a single RFC 4466 fetch-modifier. At the moment only RFC
    4551 is supported.
*/

void Fetch::parseFetchModifier()
{
    String name = atom().lower();
    if ( name == "changedsince" ) {
        space();
        d->changedSince = number();
        d->modseq = true;
    }
    else {
        error( Bad, "Unknown fetch modifier: " + name );
    }
}


/*! Sends one or a few responses to the client per second, then calls
    execute(). Execute will adjust the response rate so that we
    generally keep impatient IMAP clients happy and never seem to
    actually slow down (we may speed up).
*/

void Fetch::trickle()
{
    if ( state() == Finished || state() == Retired ) {
        delete d->timer;
        d->timer = 0;
        return;
    }

    pickup();
    uint r = d->available.count() / 90;
    if ( r > d->responseRate ) {
        log( "Increasing response rate to " + fn( r ), Log::Debug );
        d->responseRate = r;
    }
    else if ( r < 2 && d->responseRate > 1 ) {
        log( "Resetting response rate to 1", Log::Debug );
        d->responseRate = 1;
    }

    Session * s = session();
    r = 0;
    while ( r < d->responseRate && !d->available.isEmpty() ) {
        Message * m = d->available.shift();
        uint u = m->uid( s->mailbox() );
        respond( makeFetchResponse( m, u, s->msn( u ) ) );
        r++;
    }
    emitUntaggedResponses();
}


/*! Retrieves completed messages and builds fetch responses for use by
    execute() and/or trickle().
*/

void Fetch::pickup()
{
    ImapSession * s = imap()->session();
    if ( !s )
        return;
    Mailbox * mb = s->mailbox();
    if ( !mb )
        return;

    uint done = 0;
    bool ok = true;
    Message * m = 0;
    while ( ok && !d->requested.isEmpty() ) {
        m = d->requested.first();
        uint msn = s->msn( m->uid( mb ) );
        if ( d->needsAddresses && !m->hasAddresses() )
            ok = false;
        if ( d->needsHeader && !m->hasHeaders() )
            ok = false;
        if ( d->needsPartNumbers && !m->hasBytesAndLines() )
            ok = false;
        if ( d->needsBody && !m->hasBodies() )
            ok = false;
        if ( d->flags && !m->hasFlags( mb ) )
            ok = false;
        if ( ( d->rfc822size || d->internaldate || d->modseq ) &&
             !m->hasTrivia() )
            ok = false;
        if ( d->annotation && !m->hasAnnotations( mb ) )
            ok = false;
        if ( !m->uid( mb ) )
            ok = false;
        if ( !msn )
            ok = false;
        if ( ok ) {
            d->available.append( m );
            done++;
            d->requested.shift();
        }
    }
    if ( !done )
        return;

    if ( m && !d->requested.isEmpty() )
        log( "Processed " + fn( done ) + " messages, "
             "next message has UID " + fn( m->uid( mb ) ),
             Log::Debug );
    else
        log( "Processed " + fn( done ) + " messages",
             Log::Debug );

}
