#ifndef CAPABILITY_H
#define CAPABILITY_H

#include "command.h"


class Capability
    : public Command
{
public:
    void execute();
    static const char * capabilities();
};


#endif
