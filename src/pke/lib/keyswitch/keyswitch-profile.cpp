#include "keyswitch/keyswitch-profile.h"
namespace ksprofile {

static thread_local Phases g;
void Reset(){ g = Phases{}; }
void AddModUp(double ms){ g.modup_ms += ms; g.modup_calls++; }
void AddInner(double ms){ g.inner_ms += ms; g.inner_calls++; }
void AddModDown(double ms){ g.moddown_ms += ms; g.moddown_calls++; }
Phases Snapshot(){ return g; }

} 
