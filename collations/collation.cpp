// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "collation.h"

#include "octet.h"
#include "ascii-casemap.h"
#include "ascii-numeric.h"

#include "estringlist.h"


/*! \class Collation collation.h
    This abstract base class represents an RFC 4790 Collation.

    "A collation is a named function which takes two arbitrary length
    strings as input and can be used to perform one or more of three
    basic comparison operations: equality test, substring match, and
    ordering test."
*/

/*! Creates a new Collation. */

Collation::Collation()
{
}


/*! Boilerplate virtual destructor. */


Collation::~Collation()
{
}


/*! \fn virtual bool Collation::valid( const UString & s ) const = 0;
    Returns true if \a s is valid input to this Collation, and false
    otherwise.
*/

/*! \fn virtual bool Collation::equals( const UString & a, const UString & b ) const = 0;
    Returns true if \a a and \a b are equal according to this Collation,
    and false otherwise.
*/

/*! \fn virtual bool Collation::contains( const UString & a, const UString & b ) const = 0;
    Returns true if \a a contains \a b, i.e. if \a b is a substring of
    \a a, and false otherwise.
*/

/*! \fn virtual int Collation::compare( const UString & a, const UString & b ) const = 0;
    Returns 0 if \a a and \a b are equal; and -1 if \a a is smaller, or
    1 if \a a is greater, than \a b.
*/

/*! Returns a pointer to a newly-created Collation object corresponding
    to \a s, or 0 if no such collation is recognised.
*/

Collation * Collation::create( const UString & s )
{
    if ( s == "i;octet" )
        return new Octet;
    else if ( s == "i;ascii-casemap" )
        return new AsciiCasemap;
    else if ( s == "i;ascii-numeric" )
        return new AsciiNumeric;
    return 0;
}


/*! Returns a list of all collations implementated. The list is
    allocated for the purpose and may be changed by the caller.  The
    names are sorted alphabetically.
*/

EStringList * Collation::supported()
{
    EStringList * l = new EStringList;
    // alphabetically:
    l->append( "i;ascii-casemap" );
    l->append( "i;ascii-numeric" );
    l->append( "i;octet" );
    return l;
}
