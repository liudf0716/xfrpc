#ifndef _SESSION_H_
#define _SESSION_H_

#include "uthash.h"
#include "common.h"

uint32_t *init_sid_index();
uint32_t get_current_sid_index();
uint32_t new_sid();

#endif //_SESSION_H_
