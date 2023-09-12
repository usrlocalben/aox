// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LOGCLIENT_H
#define LOGCLIENT_H

#include "logger.h"

class EString;
class Endpoint;

const int LT_LOGD = 0;
const int LT_SYSLOG = 1;
const int LT_STDERR = 2;

class LogClient
    : public Logger
{
public:
    static void setup( const EString & );

    void send( const EString &, Log::Severity, const EString & );

    EString name() const;

private:
    class LogClientData * d;
    LogClient();
    int logType;
};


#endif
