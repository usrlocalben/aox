// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FETCH_H
#define FETCH_H

#include "command.h"


class Header;
class Section;
class Message;
class Bodypart;
class Multipart;


class Fetch
    : public Command
{
public:
    Fetch( bool = false );

    void parse();
    void execute();

    static Section * parseSection( const String & );
    static String sectionData( Section *, Message * );

private:
    void parseAttribute( bool );
    void parseFetchModifier();
    void parseBody( bool );
    void parseAnnotation();
    void sendFetchQueries();
    String dotLetters( uint, uint );
    String flagList( Message *, uint );
    String internalDate( Message * );
    String envelope( Message * );
    String bodyStructure( Multipart *, bool );
    String annotation( Multipart * );
    String singlePartStructure( Multipart *, bool );
    String fetchResponse( Message *, uint, uint );

private:
    class FetchData * d;
};


#endif
