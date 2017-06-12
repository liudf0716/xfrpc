#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "uthash.h"

uint32_t *sid_index = NULL;

uint32_t *init_sid_index()
{
	if (NULL == sid_index) {
		sid_index = (uint32_t *)calloc(1, sizeof(uint32_t));
		assert(sid_index);

		*sid_index = 1;
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