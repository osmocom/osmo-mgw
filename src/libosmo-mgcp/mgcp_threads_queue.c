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

#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>
#include <talloc.h>

#include <osmocom/mgcp/mgcp_threads_queue.h>

/*
classic lamport circular lockfree spsc queue:
every "side" only writes its own ptr, but may read the other sides ptr

notify reader using eventfd as soon as element is added, reader then reads until
read fails
-> reader pops in a loop until FALSE and might get spurious events because it
read before it was notified, which is fine
-> writing pushes *the same data* in a loop until TRUE, blocks

shutting this down requires
1) to stop reading and pushing
2) ONE side to take care of the eventfds
*/

static struct spsc *spsc_init(void *talloc_ctx, unsigned int count, unsigned int size_per_buf, bool blockr, bool blockw)
{
	struct spsc *q = talloc_zero_size(talloc_ctx, sizeof(struct spsc) + sizeof(uintptr_t) * count);
	atomic_init(&q->readptr, 0);
	atomic_init(&q->writeptr, 0);
	q->efd_r = eventfd(0, blockr ? 0 : EFD_NONBLOCK);
	q->efd_w = eventfd(1, blockw ? 0 : EFD_NONBLOCK);
	q->count = count;
	q->size_per_buf = size_per_buf;
	q->buf = talloc_zero_size(q, size_per_buf * count);

	for (int i = 0; i < count; i++)
		q->data[i] = (uintptr_t)q->buf + i * size_per_buf;
	return q;
}

static void spsc_deinit(struct spsc *q)
{
	talloc_free(q->buf);
	close(q->efd_r);
	close(q->efd_w);
	talloc_free(q);
}

static ssize_t spsc_check_r(struct spsc *q)
{
	uint64_t efdr;
	return read(q->efd_r, &efdr, sizeof(uint64_t));
}
static ssize_t spsc_check_w(struct spsc *q)
{
	uint64_t efdr;
	return read(q->efd_w, &efdr, sizeof(uint64_t));
}
static void spsc_notify_r(struct spsc *q)
{
	uint64_t efdu = 1;
	write(q->efd_r, &efdu, sizeof(uint64_t));
}
static void spsc_notify_w(struct spsc *q)
{
	uint64_t efdu = 1;
	write(q->efd_w, &efdu, sizeof(uint64_t));
}

/*! Adds element to the queue by copying the data.
 *  \param[in] q queue.
 *  \param[in] elem input buffer, must match the originally configured queue buffer size!.
 *  \returns true if queue was not full and element was successfully pushed */
bool spsc_push(struct spsc *q, void *elem)
{
	size_t cur_wp, cur_rp;
	cur_wp = atomic_load_explicit(&q->writeptr, memory_order_relaxed);
	cur_rp = atomic_load_explicit(&q->readptr, memory_order_acquire);
	if ((cur_wp + 1) % q->count == cur_rp) {
		spsc_check_w(q); /* blocks, ensures next (!) call succeeds */
		return false;
	}
	memcpy((void *)q->data[cur_wp], elem, q->size_per_buf);
	atomic_store_explicit(&q->writeptr, (cur_wp + 1) % q->count, memory_order_release);
	spsc_notify_r(q); /* fine after release */
	return true;
}

/*! Reads the read-fd of the queue, which, depending on settings passed on queue creation, blocks.
 * This function can be used to deliberately wait for a non-empty queue on the read side.
 *  \param[in] q queue.
 *  \returns result of reading the fd. */
ssize_t spsc_prep_pop(struct spsc *q)
{
	return spsc_check_r(q);
}

/*! Removes element from the queue by copying the data.
 *  \param[in] q queue.
 *  \param[in] elem output buffer, must match the originally configured queue buffer size!.
 *  \returns true if queue was not empty and element was successfully removed */
bool spsc_pop(struct spsc *q, void *elem)
{
	size_t cur_wp, cur_rp;
	cur_wp = atomic_load_explicit(&q->writeptr, memory_order_acquire);
	cur_rp = atomic_load_explicit(&q->readptr, memory_order_relaxed);

	if (cur_wp == cur_rp) /* blocks via prep_pop */
		return false;
	memcpy(elem, (void *)q->data[cur_rp], q->size_per_buf);
	atomic_store_explicit(&q->readptr, (cur_rp + 1) % q->count, memory_order_release);
	spsc_notify_w(q);
	return true;
}

/*! Creates a bidirectional queue channel that consists of two queues, one in each direction,
 *  commonly referred to as a and b side.
 *  \param[in] talloc_ctx allocation context.
 *  \param[in] count number of buffers per queue.
 *  \param[in] size_per_buf size of buffers per queue.
 *  \param[in] blockr_a should reading the a-side read fd block?.
 *  \param[in] blockw_a should reading the a-side write fd block?.
 *  \param[in] blockr_b should reading the b-side read fd block?.
 *  \param[in] blockw_b should reading the b-side write fd block?.
  *  \returns queue channel */
struct qchan spsc_chan_init_ex(void *talloc_ctx, unsigned int count, unsigned int size_per_buf, bool blockr_a,
			       bool blockw_a, bool blockr_b, bool blockw_b)
{
	struct qchan q;
	q.a = spsc_init(talloc_ctx, count, size_per_buf, blockr_a, blockw_a);
	q.b = spsc_init(talloc_ctx, count, size_per_buf, blockr_b, blockw_b);
	return q;
}

/*! Creates a bidirectional queue channel that consists of two queues, one in each direction,
 *  commonly referred to as a and b side.
 *  \param[in] talloc_ctx allocation context.
 *  \param[in] count number of buffers per queue.
 *  \param[in] size_per_buf size of buffers per queue.
 *  \returns queue channel */
struct qchan spsc_chan_init(void *talloc_ctx, unsigned int count, unsigned int size_per_buf)
{
	return spsc_chan_init_ex(talloc_ctx, count, size_per_buf, false, true, false, true);
}

/*! Closes a bidirectional queue channel.
 *  \param[in] q queue */
void spsc_chan_close(struct qchan *q)
{
	spsc_deinit(q->a);
	spsc_deinit(q->b);
	free(q);
}

/*! Gets queue channel read/write fd for a/b side according to function name.
 *  \param[in] q queue channel.
 *  \returns fd */
int spsc_get_a_rdfd(struct qchan *q)
{
	return q->a->efd_r;
}
/*! Gets queue channel read/write fd for a/b side according to function name.
 *  \param[in] q queue channel.
 *  \returns fd */
int spsc_get_b_rdfd(struct qchan *q)
{
	return q->b->efd_r;
}
/*! Gets queue channel read/write fd for a/b side according to function name.
 *  \param[in] q queue channel.
 *  \returns fd */
int spsc_get_a_wrfd(struct qchan *q)
{
	return q->a->efd_w;
}
/*! Gets queue channel read/write fd for a/b side according to function name.
 *  \param[in] q queue channel.
 *  \returns fd */
int spsc_get_b_wrfd(struct qchan *q)
{
	return q->b->efd_w;
}
