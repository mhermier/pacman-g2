/*
 *  list.c
 *
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 *  USA.
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
/* pacman-g2 */
#include "list.h"
#include "util.h"

pmlist_t *_pacman_list_new()
{
	pmlist_t *list = _pacman_malloc(sizeof(pmlist_t));

	if(list == NULL) {
		return(NULL);
	}
	list->data = NULL;
	list->prev = NULL;
	list->next = NULL;
	list->last = list;
	return(list);
}

void _pacman_list_free(pmlist_t *list, _pacman_fn_free fn)
{
	pmlist_t *ptr, *it = list;

	while(it) {
		ptr = it->next;
		if(fn) {
			fn(it->data);
		}
		free(it);
		it = ptr;
	}
}

pmlist_t *_pacman_list_add(pmlist_t *list, void *data)
{
	pmlist_t *ptr, *lp;

	ptr = list;
	if(ptr == NULL) {
		ptr = _pacman_list_new();
		if(ptr == NULL) {
			return(NULL);
		}
	}

	lp = _pacman_list_last(ptr);
	if(lp == ptr && lp->data == NULL) {
		/* nada */
	} else {
		lp->next = _pacman_list_new();
		if(lp->next == NULL) {
			return(NULL);
		}
		lp->next->prev = lp;
		lp->last = NULL;
		lp = lp->next;
	}

	lp->data = data;
	ptr->last = lp;

	return(ptr);
}

/* Add items to a list in sorted order. Use the given comparison function to
 * determine order.
 */
pmlist_t *_pacman_list_add_sorted(pmlist_t *list, void *data, _pacman_fn_cmp fn)
{
	pmlist_t *add;
	pmlist_t *prev = NULL;
	pmlist_t *iter = list;

	add = _pacman_list_new();
	add->data = data;

	/* Find insertion point. */
	while(iter) {
		if(fn(add->data, iter->data) <= 0) break;
		prev = iter;
		iter = iter->next;
	}

	/*  Insert node before insertion point. */
	add->prev = prev;
	add->next = iter;

	if(iter != NULL) {
		iter->prev = add;   /*  Not at end.  */
	} else {
		if (list != NULL) {
			list->last = add;   /* Added new to end, so update the link to last. */
		}
	}

	if(prev != NULL) {
		prev->next = add;       /*  In middle.  */
	} else {
		if(list == NULL) {
			add->last = add;
		} else {
			add->last = list->last;
			list->last = NULL;
		}
		list = add;           /*  Start or empty, new list head.  */
	}

	return(list);
}

/* Remove an item in a list. Use the given comparison function to find the
 * item.
 * If the item is found, 'data' is pointing to the removed element.
 * Otherwise, it is set to NULL.
 * Return the new list (without the removed element).
 */
pmlist_t *_pacman_list_remove(pmlist_t *haystack, void *needle, _pacman_fn_cmp fn, void **data)
{
	pmlist_t *i = haystack;

	if(data) {
		*data = NULL;
	}

	while(i) {
		if(i->data == NULL) {
			continue;
		}
		if(fn(needle, i->data) == 0) {
			break;
		}
		i = i->next;
	}

	if(i) {
		/* we found a matching item */
		if(i->next) {
			i->next->prev = i->prev;
		}
		if(i->prev) {
			i->prev->next = i->next;
		}
		if(i == haystack) {
			/* The item found is the first in the chain */
			if(haystack->next) {
				haystack->next->last = haystack->last;
			}
			haystack = haystack->next;
		} else if(i == haystack->last) {
			/* The item found is the last in the chain */
			haystack->last = i->prev;
		}

		if(data) {
			*data = i->data;
		}
		i->data = NULL;
		free(i);
	}

	return(haystack);
}

size_t _pacman_list_count(const pmlist_t *list)
{
	size_t count = 0;

	for(const pmlist_t *lp = list; lp; lp = lp->next, count++);

	return count;
}

bool _pacman_list_is_in(void *needle, const pmlist_t *haystack)
{
	for(const pmlist_t *lp = haystack; lp; lp = lp->next) {
		if(lp->data == needle) {
			return true;
		}
	}
	return false;
}

/* Test for existence of a string in a pmlist_t
 */
bool _pacman_list_is_strin(const char *needle, const pmlist_t *haystack)
{
	for(const pmlist_t *lp = haystack; lp; lp = lp->next) {
		if(lp->data && !strcmp(lp->data, needle)) {
			return true;
		}
	}
	return false;
}

pmlist_t *_pacman_list_last(pmlist_t *list)
{
	if(list == NULL) {
		return(NULL);
	}

	assert(list->last != NULL);

	return(list->last);
}

/* Filter out any duplicate strings in a list.
 *
 * Not the most efficient way, but simple to implement -- we assemble
 * a new list, using is_in() to check for dupes at each iteration.
 *
 */
pmlist_t *_pacman_list_remove_dupes(pmlist_t *list)
{
	pmlist_t *i, *newlist = NULL;

	for(i = list; i; i = i->next) {
		if(!_pacman_list_is_strin(i->data, newlist)) {
			newlist = _pacman_list_add(newlist, strdup(i->data));
		}
	}
	return newlist;
}

/* Reverse the order of a list
 *
 * The caller is responsible for freeing the old list
 */
pmlist_t *_pacman_list_reverse(pmlist_t *list)
{
	/* simple but functional -- we just build a new list, starting
	 * with the old list's tail
	 */
	pmlist_t *newlist = NULL;
	pmlist_t *lp;

	for(lp = list->last; lp; lp = lp->prev) {
		newlist = _pacman_list_add(newlist, lp->data);
	}

	return(newlist);
}

pmlist_t *_pacman_list_strdup(pmlist_t *list)
{
	pmlist_t *newlist = NULL;
	pmlist_t *lp;

	for(lp = list; lp; lp = lp->next) {
		newlist = _pacman_list_add(newlist, strdup(lp->data));
	}

	return(newlist);
}

/* vim: set ts=2 sw=2 noet: */
