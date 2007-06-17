// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "deliveryagent.h"

#include "log.h"
#include "scope.h"
#include "query.h"
#include "transaction.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"
#include "smtpclient.h"
#include "dsn.h"
#include "address.h"
#include "recipient.h"
#include "injector.h"
#include "spoolmanager.h"


static SmtpClient * client;


class DeliveryAgentData
    : public Garbage
{
public:
    DeliveryAgentData()
        : log( 0 ), mailbox( 0 ), uid( 0 ), owner( 0 ),
          t( 0 ), qm( 0 ), qs( 0 ), qr( 0 ), deliveryRow( 0 ),
          message( 0 ), dsn( 0 ), injector( 0 ), update( 0 ),
          senders( 0 ), sent( 0 )
    {}

    Log * log;
    Mailbox * mailbox;
    uint uid;
    EventHandler * owner;
    Transaction * t;
    Query * qm;
    Query * qs;
    Query * qr;
    Row * deliveryRow;
    Message * message;
    DSN * dsn;
    Injector * injector;
    Query * update;
    uint senders;
    uint sent;
};


/*! \class DeliveryAgent deliveryagent.h
    Responsible for attempting to deliver a queued message and updating
    the corresponding row in the deliveries table.
*/

/*! Creates a new DeliveryAgent object to deliver the message in
    \a mailbox with \a uid. The \a owner will be notified upon
    completion.
*/

DeliveryAgent::DeliveryAgent( Mailbox * mailbox, uint uid,
                              EventHandler * owner )
    : d( new DeliveryAgentData )
{
    d->log = new Log( Log::SMTP );
    Scope x( d->log );
    log( "Starting delivery attempt for " +
         mailbox->name() + ":" + fn( uid ) );
    d->mailbox = mailbox;
    d->uid = uid;
    d->owner = owner;
}


void DeliveryAgent::execute()
{
    Scope x( d->log );

    // Fetch and lock all pending deliveries for (mailbox,uid).

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->qm =
            new Query(
                "select id, sender, "
                "current_timestamp > expires_at as expired, "
                "(tried_at is null or tried_at+interval '1 hour'"
                " < current_timestamp) as can_retry "
                "from deliveries where mailbox=$1 "
                "and uid=$2 for update", this
            );
        d->qm->bind( 1, d->mailbox->id() );
        d->qm->bind( 2, d->uid );
        d->t->enqueue( d->qm );
        d->t->execute();
    }

    // Count each delivery, and either try to deliver it right away, or
    // leave it until enough time has passed to try it again.

    while ( d->deliveryRow || d->qm->hasResults() ) {

        // If we're not processing a delivery already, we'll look for
        // the next one that we can attempt immediately.

        if ( !d->deliveryRow ) {
            do {
                d->deliveryRow = d->qm->nextRow();
                d->senders++;
                if ( d->deliveryRow->getBoolean( "can_retry" ) == true )
                    break;
                d->deliveryRow = 0;
            }
            while ( d->qm->hasResults() );

            // If there isn't one, we're done.
            if ( !d->deliveryRow )
                break;
        }

        // We'll need a functioning SmtpClient.

        if ( !client || !client->usable() ) {
            Endpoint e( Configuration::text( Configuration::SmartHostAddress ),
                        Configuration::scalar( Configuration::SmartHostPort ) );
            client = new SmtpClient( e, this );
        }

        // Fetch the sender address, the relevant delivery_recipients
        // entries, and the message itself. (We assume that we won't
        // be called if there's nothing to do, i.e. we've previously
        // been called for this message and have claimed to complete
        // the delivery.)

        if ( !d->message ) {
            List<Message> messages;
            d->message = new Message;
            d->message->setUid( d->uid );
            messages.append( d->message );

            Fetcher * f;
            f = new MessageHeaderFetcher( d->mailbox, &messages, this );
            f->execute();

            f = new MessageAddressFetcher( d->mailbox, &messages, this );
            f->execute();

            f = new MessageBodyFetcher( d->mailbox, &messages, this );
            f->execute();

            // We fetch the sender address separately because we don't
            // (and should not) have UPDATE privileges on addresses, so
            // we can't join to addresses in the first query above.
            d->qs =
                new Query( "select localpart,domain from addresses "
                           "where id=$1", this );
            d->qs->bind( 1, d->deliveryRow->getInt( "sender" ) );
            d->t->enqueue( d->qs );

            // XXX: We go just a little too far to fetch last_attempt in
            // RFC822 format here.
            d->qr =
                new Query(
                    "select recipient,localpart,domain,action,status,"
                    "to_char(last_attempt,'Dy, DD Mon YYYY HH24:MI:SS ')||"
                    "to_char((extract(timezone from last_attempt)/60) + "
                    "40*((extract(timezone from last_attempt)/60)"
                    "::integer/60), 'SG0000') as last_attempt "
                    "from delivery_recipients join addresses "
                    "on (recipient=addresses.id) "
                    "where delivery=$1", this
                );
            d->qr->bind( 1, d->deliveryRow->getInt( "id" ) );
            d->t->enqueue( d->qr );
            d->t->execute();
        }

        if ( !d->qs->done() || !d->qr->done() )
            return;

        if ( !( d->message->hasHeaders() &&
                d->message->hasAddresses() &&
                d->message->hasBodies() ) )
            return;

        if ( !client->ready() )
            return;

        // Now we're ready to process the delivery. We create a DSN, set
        // the message, sender, and the recipients, then decide whether
        // to send the message.

        if ( !d->dsn ) {
            d->dsn = new DSN;
            d->dsn->setMessage( d->message );

            Row * r = d->qs->nextRow();
            Address * a =
                new Address( "", r->getString( "localpart" ),
                             r->getString( "domain" ) );
            d->dsn->setSender( a );

            while ( d->qr->hasResults() ) {
                r = d->qr->nextRow();

                Address * a =
                    new Address( "", r->getString( "localpart" ),
                                 r->getString( "domain" ) );
                a->setId( r->getInt( "recipient" ) );

                Date date;
                date.setRfc822( r->getString( "last_attempt" ) );

                Recipient * recipient = new Recipient;
                recipient->setLastAttempt( date );
                recipient->setFinalRecipient( a );
                recipient->setAction( (Recipient::Action)r->getInt( "action" ),
                                      r->getString( "status" ) );
                d->dsn->addRecipient( recipient );

                if ( recipient->action() == Recipient::Unknown )
                    log( "Attempting delivery to " +
                         a->localpart() + "@" + a->domain() + "@" );
            }

            // XXX: Check that there's really something to do; if not,
            // we should bypass the rest of the loop below and move on
            // to the next row. (How?)
            if ( d->dsn->deliveriesPending() ) {
            }

            bool expired = false;
            if ( !d->deliveryRow->isNull( "expired" ) )
                expired = d->deliveryRow->getBoolean( "expired" );
            if ( expired ) {
                // XXX: Set expiry here.
            }

            client->send( d->dsn, this );
        }

        if ( d->dsn->deliveriesPending() )
            return;

        // At this point, the SmtpClient has updated the action and
        // status for each recipient. Now we decide whether or not
        // to spool a bounce message.

        if ( !d->injector ) {
            Mailbox * m = Mailbox::find( "/archiveopteryx/spool" );

            if ( d->dsn->allOk() ) {
                d->sent++;
            }
            else if ( m && d->dsn->sender()->type() == Address::Normal ) {
                List<Address> * addresses = new List<Address>;

                addresses->append( d->dsn->sender() );
                d->injector = new Injector( d->dsn->result(), this );
                d->injector->setDeliveryAddresses( addresses );
                d->injector->setSender( new Address( "", "", "" ) );
                d->injector->setMailbox( m );
                d->injector->execute();
            }
        }

        if ( d->injector && !d->injector->done() )
            return;

        if ( !d->update ) {
            uint delivery = d->deliveryRow->getInt( "id" );

            d->update =
                new Query( "update deliveries "
                           "set tried_at=current_timestamp "
                           "where id=$1", this );
            d->update->bind( 1, delivery );
            d->t->enqueue( d->update );

            uint handled = 0;
            uint unhandled = 0;
            List<Recipient>::Iterator it( d->dsn->recipients() );
            while ( it ) {
                Recipient * r = it;
                ++it;
                if ( r->action() == Recipient::Unknown ) {
                    unhandled++;
                }
                else {
                    Query * q =
                        new Query( "update delivery_recipients "
                                   "set action=$1, status=$2, "
                                   "last_attempt=current_timestamp "
                                   "where delivery=$3 and recipient=$4",
                                   this );
                    q->bind( 1, (int)r->action() );
                    q->bind( 2, r->status() );
                    q->bind( 3, delivery );
                    q->bind( 4, r->finalRecipient()->id() );
                    d->t->enqueue( q );
                    handled++;
                }
            }

            // XXX: Should increment d->sent here if appropriate.

            log( "Recipients handled: " + fn( handled ) +
                 ", still queued: " + fn( unhandled ) );

            d->t->execute();
        }
    }

    // XXX: This may call commit multiple times; find a better
    // condition. (New flag?)
    if ( d->qm->done() && !d->t->done() )
        d->t->commit();

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        // XXX: We might end up resending copies of some messages that
        // we couldn't update during this transaction. I can't think of
        // any way around that. I could split up the code above so that
        // each (sender,mailbox,uid) gets its own transaction, but there
        // will always be some risk, and the common case is for a single
        // matching row (so it didn't seem worth doing).
        log( "Delivery attempt failed due to database error: " +
             d->t->error(), Log::Error );
        log( "Shutting down spool manager.", Log::Error );
        SpoolManager::shutdown();
    }

    // We're done() now. What we did can be guaged by delivered().

    d->owner->execute();
}


/*! Returns true if this DeliveryAgent has finished processing
    deliveries for the message submitted to it.
*/

bool DeliveryAgent::done() const
{
    return d->t->done();
}


/*! Returns true if the message was delivered (or the delivery was
    permanently abandoned), and the spooled message may be deleted.
*/

bool DeliveryAgent::delivered() const
{
    return d->senders == d->sent;
}
