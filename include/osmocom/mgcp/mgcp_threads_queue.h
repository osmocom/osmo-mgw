/*
 * (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Eric Wild
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

struct spsc {
	atomic_uint readptr;
	atomic_uint writeptr;

	int efd_r, efd_w; /* eventfds used to block/notify readers/writers */

	int count;
	int size_per_buf;

	void *buf; /* buffer size count*size_per_buf */
	uintptr_t data[0]; /* count sized array of pointers to size_per_buf chunks in buf array*/
};

struct qchan {
	struct spsc *a;
	struct spsc *b;
};

bool spsc_push(struct spsc *q, void *elem);
bool spsc_pop(struct spsc *q, void *elem);
ssize_t spsc_prep_pop(struct spsc *q);
int spsc_get_a_rdfd(struct qchan *q);

struct qchan spsc_chan_init(void *talloc_ctx, unsigned int count, unsigned int size_per_buf);
struct qchan spsc_chan_init_ex(void *talloc_ctx, unsigned int count, unsigned int size_per_buf, bool blockr_a,
			       bool blockw_a, bool blockr_b, bool blockw_b);
void spsc_chan_close(struct qchan *q);
