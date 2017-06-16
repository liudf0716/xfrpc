#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "uthash.h"
#include "session.h"
#include "version.h"

uint32_t *sid_index = NULL;

// need free
uint32_t *init_sid_index()
{
	if (NULL == sid_index) {
		sid_index = (uint32_t *)calloc(1, sizeof(uint32_t));
		if (NULL == sid_index)
			return sid_index;

#ifdef CLIENT_V
		*sid_index = 1;
#elif SERVER
		*sid_index = 0;
#endif
	}

	*sid_index += 2;	//xfrp client session id start from 3
	return sid_index;
}

uint32_t get_current_sid_index()
{
	if (NULL == sid_index) {
		return *init_sid_index();
	}

	return *sid_index;
}

uint32_t new_sid()
{
	if (NULL == sid_index) {
		init_sid_index();
		return get_current_sid_index();
	}

	*sid_index += 2;
	return *sid_index;
}