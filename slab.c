/*
 *
 * Copyright 2025 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __SLAB__CONF_ALLOC_BATCH_SIZE
#define __SLAB__CONF_ALLOC_BATCH_SIZE (1UL << 20)
#endif

struct slab_statistics {
	uint64_t mem_used;
	uint64_t mem_size;
	pthread_spinlock_t lock;
} slab_stat;

struct slab_thread_data {
	struct {
		uint64_t mem_used;
		uint64_t mem_size;
	} stat;
};

static void *kv_ops_slab_alloc(uint64_t s, void *opaque)
{
	struct slab_thread_data *std = SLAB_OPS_OPAQUE2STD(opaque);
	if (std->stat.mem_used + s > std->stat.mem_size) {
		uint8_t do_eviction = 0;
		pthread_spin_lock(&slab_stat.lock);
		if (slab_stat.mem_used + __SLAB__CONF_ALLOC_BATCH_SIZE > slab_stat.mem_size)
			do_eviction = 1;
		else
			slab_stat.mem_used += __SLAB__CONF_ALLOC_BATCH_SIZE;
		pthread_spin_unlock(&slab_stat.lock);
		if (do_eviction)
			kv_eviction(__SLAB__CONF_ALLOC_BATCH_SIZE, opaque);
		else
			std->stat.mem_size += __SLAB__CONF_ALLOC_BATCH_SIZE;
	}
	if (std->stat.mem_used + s <= std->stat.mem_size) {
		void *r = malloc(s);
		if (r)
			std->stat.mem_used += s;
		return r;
	} else
		return NULL;
}

static void kv_ops_slab_free(void *p, uint64_t s, void *opaque)
{
	free(p);
	{
		struct slab_thread_data *std = SLAB_OPS_OPAQUE2STD(opaque);
		std->stat.mem_used -= s;
		if (std->stat.mem_used + __SLAB__CONF_ALLOC_BATCH_SIZE * 2 < std->stat.mem_size) {
			std->stat.mem_size -= __SLAB__CONF_ALLOC_BATCH_SIZE;
			pthread_spin_lock(&slab_stat.lock);
			slab_stat.mem_used -= __SLAB__CONF_ALLOC_BATCH_SIZE;
			pthread_spin_unlock(&slab_stat.lock);
		}
	}
}

static void slab_init(void)
{
	memset(&slab_stat, 0, sizeof(slab_stat));
	pthread_spin_init(&slab_stat.lock, PTHREAD_PROCESS_PRIVATE);
}
