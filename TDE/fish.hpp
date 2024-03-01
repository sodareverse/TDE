#ifndef FISH_HPP_
#define FISH_HPP_

#include "wild.hpp"
#include "fish_context.hpp"
#include "fish_handler.hpp"

class Fish : public Wild<FishHandler>
{
public:
    Fish() {}

    bool isSignature(InstructionContainer& vmEntrance);
    
private:
    bool parseInitialHandler(InstructionContainer& instructions);
    bool updateArgumentData();

private:
    FishContext context;
};

#endif
