#pragma once
#include <cstdint>
namespace ksprofile {
struct Phases { double modup_ms=0, inner_ms=0, moddown_ms=0; uint64_t modup_calls=0, inner_calls=0, moddown_calls=0; };
void Reset();
void AddModUp(double ms);
void AddInner(double ms);
void AddModDown(double ms);
Phases Snapshot();
} 
