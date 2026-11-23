#ifndef CHATCORE_HPP
#define CHATCORE_HPP

#include <vector>
#include <string>

#include "net.hpp"


struct OutgoingFrame
{
    MsgType type;
    std::vector<unsigned char> body;
};

enum class UiEventKind
{
    MESSAGE,    // message from contact
    CONNECTED,  // a secure session was set up
    NOTICE,     // neutral information;; no warning; unknown sender goes here
    WARNING,    // something went wrong or looks suspicious
};

struct UiEvent
{
    UiEventKind kind;
    std::string name;
    std::string text;
    std::string fingerprint;
};

struct Effects
{
    std::vector<OutgoingFrame> frames;
    std::vector<UiEvent> events;
    bool fatal = false;
};


#endif