#ifndef STORE_H
#define STORE_H

#include "command.h"
#include "string.h"
#include "list.h"
#include "set.h"


class Store
    : public Command
{
public:
    void parse();
    void execute();

private:
    Set s;
    enum { Add, Replace, Remove } op;
    bool silent;
    List< String > flags;
};

#endif
