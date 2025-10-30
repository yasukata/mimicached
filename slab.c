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

struct slab_thread_data {
	struct slab_metadata *slab_chains[6]; /* 512B, 1024B, 2048B, 4096B, 8192B, 1048576B */
	struct slab_metadata *released[____KV__CONF_MAX_THREAD_NUM];
};

struct slab_metadata {
	struct slab_thread_data *owner;
	struct slab_metadata *next;
	uint64_t chain_idx;
};

static void *kv_ops_slab_alloc(uint64_t s, void *opaque)
{
	struct slab_thread_data *std = SLAB_OPS_OPAQUE2STD(opaque);
	{
		uint64_t chain_idx = (uint64_t) -1;
		if (s + sizeof(struct slab_metadata) <= 512)
			chain_idx = 0;
		else if (s + sizeof(struct slab_metadata) <= 1024)
			chain_idx = 1;
		else if (s + sizeof(struct slab_metadata) <= 2048)
			chain_idx = 2;
		else if (s + sizeof(struct slab_metadata) <= 4096)
			chain_idx = 3;
		else if (s + sizeof(struct slab_metadata) <= 8192)
			chain_idx = 4;
		else if (s + sizeof(struct slab_metadata) <= 1048576)
			chain_idx = 5;
		if (chain_idx == (uint64_t) -1)
			return NULL;
		else {
			struct slab_metadata *md = std->slab_chains[chain_idx];
			if (!md) { /* bring released items back to the chains */
				struct slab_metadata *released[____KV__CONF_MAX_THREAD_NUM];
				{
					uint64_t i;
					for (i = 0; i < ____KV__CONF_MAX_THREAD_NUM; i++) {
						KV_OPS_ATOMIC_LOAD(&std->released[i], &released[i], KV_FLAG_ATOMIC_ACQUIRE);
						{
							struct slab_metadata *none = NULL;
							KV_OPS_ATOMIC_STORE(&std->released[i], &none, KV_FLAG_ATOMIC_RELEASE);
						}
					}
				}
				{
					uint64_t i;
					for (i = 0; i < ____KV__CONF_MAX_THREAD_NUM; i++) {
						struct slab_metadata *_md = released[i];
						while (_md) {
							struct slab_metadata *next = _md->next;
							_md->next = std->slab_chains[_md->chain_idx];
							std->slab_chains[_md->chain_idx] = _md->next;
							_md = next;
						}
					}
				}
				md = std->slab_chains[chain_idx];
			}
			if (!md) {
				if (slab_stat.mem_used + 1048576 > slab_stat.mem_size) { /* XXX: lazy sync */
					kv_eviction(slab_stat.mem_used / 10, opaque);
					return NULL;
				} else { /* try to alloc batch */
					void *buf = mem_alloc_local(1048576);
					assert(buf);
					(void) SLAB_OPS_ATOMIC_ADD_FETCH(&slab_stat.mem_used, 1048576, SLAB_FLAG_ATOMIC_RELEASE);
					{
						uint64_t buf_size;
						switch (chain_idx) {
							case 0:
								buf_size = 512;
								break;
							case 1:
								buf_size = 1024;
								break;
							case 2:
								buf_size = 2048;
								break;
							case 3:
								buf_size = 4096;
								break;
							case 4:
								buf_size = 8192;
								break;
							case 5:
								buf_size = 1048576;
								break;
						}
						{
							uint64_t s = 0;
							for (s = 0; s < 1048576; s += buf_size) {
								struct slab_metadata *new_md = (struct slab_metadata *)((uintptr_t) buf + s);
								new_md->owner = std;
								new_md->chain_idx = chain_idx;
								new_md->next = std->slab_chains[chain_idx];
								std->slab_chains[chain_idx] = new_md;;
							}
						}
					}
					md = std->slab_chains[chain_idx];
				}
			}
			assert(md);
			std->slab_chains[chain_idx] = md->next;
			return (void *)((uintptr_t) md + sizeof(struct slab_metadata));
		}
	}
}

static void kv_ops_slab_free(void *p, uint64_t s, void *opaque)
{
	mp_assert(p);
	{
		struct slab_thread_data *std = SLAB_OPS_OPAQUE2STD(opaque);
		{
			struct slab_metadata *md = (struct slab_metadata *)((uintptr_t) p - sizeof(struct slab_metadata));
			if (md->owner == std) {
				md->next = std->slab_chains[md->chain_idx];
				std->slab_chains[md->chain_idx] = md->next;
			} else {
				struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
				while (1) {
					struct slab_metadata *head;
					KV_OPS_ATOMIC_LOAD(&md->owner->released[ktd->ktd_id], &head, KV_FLAG_ATOMIC_ACQUIRE);
					md->next = head;
					if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&md->owner->released[ktd->ktd_id], &head, &md, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED))
						continue; /* consumer has updated the head, so we do retry */
					else
						break;
				}
			}
		}
	}
	{ /* unused */
		(void) s;
	}
}

static void slab_init(void)
{
	memset(&slab_stat, 0, sizeof(slab_stat));
}
