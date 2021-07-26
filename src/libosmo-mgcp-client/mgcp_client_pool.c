/* (C) 2021 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/mgcp_client/mgcp_client.h>
#include <osmocom/mgcp_client/mgcp_client_internal.h>
#include <osmocom/mgcp_client/mgcp_client_pool_internal.h>
#include <osmocom/mgcp_client/mgcp_client_pool.h>
#include <stddef.h>

/*! Allocate MGCP client pool. This is called once on startup and before the pool is used with
 *  mgcp_client_pool_vty_init(). Since the pool is linked with the VTY it must exist througout the entire runtime.
 *  \param[in] talloc_ctx talloc context. */
struct mgcp_client_pool *mgcp_client_pool_alloc(void *talloc_ctx)
{
	struct mgcp_client_pool *pool;

	pool = talloc_zero(talloc_ctx, struct mgcp_client_pool);
	if (!pool)
		return NULL;

	INIT_LLIST_HEAD(&pool->pool);

	return pool;
}

/*! Initialize and connect an mcgp client pool.
 *  \param[in,out] mgcp MGCP client pool descriptor.
 *  \returns number of successfully initialized pool members. */
unsigned int mgcp_client_pool_connect(struct mgcp_client_pool *pool)
{
	struct mgcp_client_pool_member *pool_member;
	unsigned int pool_members_initialized = 0;

	llist_for_each_entry(pool_member, &pool->pool, list) {

		/* Initialize client */
		pool_member->client = mgcp_client_init(pool_member, &pool_member->conf);
		if (!pool_member->client) {
			LOGP(DLMGCP, LOGL_ERROR, "MGW %u initialization failed\n", pool_member->nr);
			continue;
		}

		/* Set backpointer so that we can detect later that this MGCP client is managed
		 * by this pool. */
		pool_member->client->pool = pool;

		/* Connect client */
		if (mgcp_client_connect2(pool_member->client, 0)) {
			LOGP(DLMGCP, LOGL_ERROR, "MGW %u connect failed at (%s:%u)\n",
			     pool_member->nr, pool_member->conf.remote_addr, pool_member->conf.remote_port);
			talloc_free(pool_member->client);
			pool_member->client = NULL;
			continue;
		}

		pool_members_initialized++;
	}

	return pool_members_initialized;
}

/*! register a single mgcp_client instance to the pool.
 *  \param[out] pool MGCP client pool descriptor.
 *  \param[in] mgcp MGCP client descriptor. */
void mgcp_client_pool_register_single(struct mgcp_client_pool *pool, struct mgcp_client *mgcp_client)
{
	/*! Some applications still support the non-pooled MGW VTY configuration variant provided by
	 *  mgcp_client_vty_init(). If this is the case the mgcp_client instance created by mgcp_client_init()
	 *  can be registered here so that it will appear as if it were part of the pool. When the user actively
	 *  configures MGW pool members, the MGCP client registered here will be ignored. (The registration of
	 *  multiple singe mgcp_client instances is not possible.) */
	pool->mgcp_client_single = mgcp_client;
}

/* Not every pool member may have a functional MGCP client, we will run through the pool once until we meet a
 * pool member that is suitable (has a client, is not blocked, has a low load). */
static struct mgcp_client_pool_member *mgcp_client_pool_pick(struct mgcp_client_pool *pool)
{
	struct mgcp_client_pool_member *pool_member;
	struct mgcp_client_pool_member *pool_member_picked = NULL;
	unsigned int n_pool_members = llist_count(&pool->pool);

	llist_for_each_entry(pool_member, &pool->pool, list) {
		if (pool_member->blocked == false && pool_member->client) {
			if (!pool_member_picked)
				pool_member_picked = pool_member;
			else if (pool_member_picked->refcount > pool_member->refcount)
				pool_member_picked = pool_member;
		} else {
			LOGP(DLMGCP, LOGL_DEBUG, "MGW pool has %u members -- MGW %u is unusable\n", n_pool_members,
			     pool_member->nr);
		}
	}

	if (pool_member_picked) {
		LOGP(DLMGCP, LOGL_DEBUG, "MGW pool has %u members -- using MGW %u (active calls: %u)\n",
		     n_pool_members, pool_member_picked->nr, pool_member_picked->refcount);
		return pool_member_picked;
	}

	LOGP(DLMGCP, LOGL_ERROR,
	     "MGW pool has %u members, but no functional MGW pool member found -- check configuration!\n",
	     n_pool_members);

	return NULL;
}

/*! get an MGCP client from the pool (increment reference counter).
 *  \param[in,out] pool MGCP client pool descriptor.
 *  \returns MGCP client descriptor, NULL if no member was found (empty pool). */
struct mgcp_client *mgcp_client_pool_get(struct mgcp_client_pool *pool)
{
	struct mgcp_client_pool_member *pool_member;

	/*! When an MGCP client is taken from the pool it is still available for other calls. In fact only a reference
	 *  counter is incremented to keep track on how many references to a specific MGCP client are currently used
	 *  by the application code. */

	/* When the pool is empty, return a single MGCP client if it is registered. */
	if (llist_empty(&pool->pool) && pool->mgcp_client_single) {
		LOGP(DLMGCP, LOGL_DEBUG, "MGW pool is empty -- using (single) MGW\n");
		return pool->mgcp_client_single;
	}

	/* Abort when the pool is empty */
	if (llist_empty(&pool->pool)) {
		LOGP(DLMGCP, LOGL_ERROR, "MGW pool is empty -- no MGW available!\n");
		return NULL;
	}

	/* Pick a suitable pool member */
	pool_member = mgcp_client_pool_pick(pool);
	if (pool_member) {
		pool_member->refcount++;
		return pool_member->client;
	}

	return NULL;
}

/*! put an MGCP client back into the pool (decrement reference counter).
 *  \param[in,out] pool MGCP client pool descriptor.
 *  \param[in] mgcp MGCP client descriptor.
 *
 * This function is able to detect automatically to which pool the mgcp_client belongs. If the mgcp_client does
 * not belong to a pool at all, the function call will have no effect. */
void mgcp_client_pool_put(struct mgcp_client *mgcp_client)
{
	struct mgcp_client_pool_member *pool_member;
	struct mgcp_client_pool *pool;

	if (!mgcp_client)
		return;

	if (mgcp_client->pool)
		pool = mgcp_client->pool;
	else
		return;

	llist_for_each_entry(pool_member, &pool->pool, list) {
		if (pool_member->client == mgcp_client) {
			if (pool_member->refcount == 0) {
				LOGP(DLMGCP, LOGL_ERROR, "MGW %u has invalid refcount\n", pool_member->nr);
				return;
			}
			pool_member->refcount--;
		}
	}
}
