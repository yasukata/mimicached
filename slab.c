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

struct slab_statistics {
	uint64_t mem_used;
	uint64_t mem_size;
} slab_stat;

static void *kv_ops_slab_alloc(uint64_t s, void *opaque)
{
	if (slab_stat.mem_used + s > slab_stat.mem_size) { /* XXX: lazy sync */
		kv_eviction(slab_stat.mem_used / 10, opaque);
		return NULL;
	} else {
		void *p = malloc(s);
		if (p)
			(void) SLAB_OPS_ATOMIC_ADD_FETCH(&slab_stat.mem_used, s, SLAB_FLAG_ATOMIC_RELEASE);
		return p;
	}
	{ /* unused */
		(void) opaque;
	}
}

static void kv_ops_slab_free(void *p, uint64_t s, void *opaque)
{
	mp_assert(p);
	(void) SLAB_OPS_ATOMIC_SUB_FETCH(&slab_stat.mem_used, s, SLAB_FLAG_ATOMIC_RELEASE);
	free(p);
	{ /* unused */
		(void) s;
		(void) opaque;
	}
}

static void slab_init(void)
{
	memset(&slab_stat, 0, sizeof(slab_stat));
}
