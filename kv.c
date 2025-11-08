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

#ifndef ____KV__CONF_HASH_TABLE_CNT
#define ____KV__CONF_HASH_TABLE_CNT (1)
#endif

#ifndef ____KV__CONF_MAX_THREAD_NUM
#define ____KV__CONF_MAX_THREAD_NUM (256)
#endif

struct kv_item {
	struct kv_item *next;
	uint16_t extra_flags;
	uint8_t cls;
	uint8_t key_len;
	uint32_t val_len;
	uint64_t flags;
	uint64_t exptime;
	uint64_t cas_unique;
	uint64_t last_access;
	uint64_t add_time;
	uint8_t data[];
};

struct kv_thread_data {
	uint64_t ktd_id;
	void *val_buf;
	uint64_t random;
	uint64_t eviction_goal;
};

static struct kv_item **hash_table;
static pthread_spinlock_t *lock;
static uint64_t global_flush_time;

static void mp_ops_kv_flush_all(uint64_t expr_sec, void *opaque)
{
	uint64_t expr = MP_OPS_UTIL_TIME_NS(opaque) + expr_sec * 1000000000UL;
	KV_OPS_ATOMIC_LOAD(&expr, &global_flush_time, KV_FLAG_ATOMIC_ACQUIRE);
}

static void mp_ops_kv_cmd(void *mpr, const uint8_t *key, uint64_t key_len, uint8_t *cmd, void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	uint64_t hash, flush_time = global_flush_time /* XXX: lazy sync */, now = MP_OPS_UTIL_TIME_NS(opaque);
	{ /* fnv-1 hash function */
		uint64_t i;
		for (i = 0, hash = 0xcbf29ce484222325; i < key_len; i++) {
			hash *= 0x100000001b3;
			hash ^= key[i];
		}
	}
	pthread_spin_lock(&lock[hash % ____KV__CONF_HASH_TABLE_CNT]);
	while (1) {
		struct kv_item *item, *prev;
		for (item = hash_table[hash % ____KV__CONF_HASH_TABLE_CNT], prev = NULL; item != NULL; item = item->next) {
			if (key_len == item->key_len) {
				if (!mp_memcmp(key, item->data, key_len))
					break;
			}
			prev = item;
		}
		if (item) {
			char retry_after_delete = 0;
			uint64_t cached_opflags = 0;
			if ((item->exptime && item->exptime < now) || (now > flush_time && item->add_time < flush_time)) {
				retry_after_delete = 1;
				cached_opflags = MP_KV_CMD_OPFLAGS(cmd);
				MP_KV_CMD_OPFLAGS(cmd) = MC_KV_CMD_OPFLAG_DELETE;
			}
			if (!retry_after_delete && (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_CAS) && (MP_KV_CMD_CAS_UNIQUE(cmd) != item->cas_unique)) {
				MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_FOUND;
				break; /* flag is not set */
			}
			if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_DELETE) {
				if (prev)
					prev->next = item->next;
				else
					hash_table[hash % ____KV__CONF_HASH_TABLE_CNT] = item->next;
				KV_OPS_SLAB_FREE(item, sizeof(struct kv_item) + item->key_len + item->val_len, opaque);
				if (retry_after_delete) {
					MP_KV_CMD_OPFLAGS(cmd) = cached_opflags;
					continue;
				} else {
					MP_KV_CMD_OPFLAGS(cmd) &= ~MC_KV_CMD_OPFLAG_DELETE;
					MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_FOUND;
				}
			} else if (!item->exptime || (item->exptime && item->exptime > now)) {
				uint8_t do_write = 0;
				uint64_t ring_idx = MP_KV_CMD_VAL_PTR_0(cmd), ring_off = MP_KV_CMD_VAL_PTR_1(cmd); /* EXTRACT_DATA overwrites indexes, we preserve them for the case of retry */
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_UPDATE)
					do_write = 1;
				else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE) && !(item->extra_flags & MC_KV_EXTRA_FLAG_STALE))
					do_write = 1;
				else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE) && (item->extra_flags & MC_KV_EXTRA_FLAG_STALE))
					MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_INVALIDATE);
				else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE)
						&& !(item->extra_flags & MC_KV_EXTRA_FLAG_WON)
						&& (item->exptime && (item->exptime < MP_KV_CMD_RECACHE_EXPTIME(cmd))))
					do_write = 1;
				else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE)
						&& (item->extra_flags & MC_KV_EXTRA_FLAG_STALE)
						&& !(item->extra_flags & MC_KV_EXTRA_FLAG_WON))
					do_write = 1;
				if (do_write) {
					uint8_t val_int_tmp[20];
					uint64_t val_len = MP_KV_CMD_VAL_LEN(cmd);
					if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL) {
						uint64_t num;
						{
							uint64_t minus, e;
							STR2INT(&item->data[key_len], item->val_len, num, minus, e);
							if (minus || e) {
								MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
								MP_KV_CMD_ERRNO(cmd) = EINVAL;
								break;
							}
						}
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL_INCREMENT)
							num += MP_KV_CMD_INCDEC_VAL(cmd);
						else {
							if (MP_KV_CMD_INCDEC_VAL(cmd) < num)
								num -= MP_KV_CMD_INCDEC_VAL(cmd);
							else
								num = 0;
						}
						{
							uint64_t l, e;
							UINT2STR(val_int_tmp, sizeof(val_int_tmp), l, num, e);
							if (e) {
								MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
								MP_KV_CMD_ERRNO(cmd) = EINVAL;
								break;
							}
							val_len = l;
						}
					}
					if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_CONCAT)
						val_len = MP_KV_CMD_VAL_LEN(cmd) + item->val_len;
					if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_COPY_VAL)
						val_len = item->val_len;
					{
						struct kv_item *new_item = (struct kv_item *) KV_OPS_SLAB_ALLOC(sizeof(struct kv_item) + key_len + val_len, opaque);
						if (!new_item) {
							MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
							MP_KV_CMD_ERRNO(cmd) = ENOMEM;
							break;
						}
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_FLAG)
							new_item->flags = MP_KV_CMD_FLAGS(cmd);
						else
							new_item->flags = item->flags;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_EXPTIME) {
							if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_IMMEDIATE_EXPIRE)
								new_item->exptime = now;
							else if (MP_KV_CMD_EXPTIME(cmd))
								new_item->exptime = MP_KV_CMD_EXPTIME(cmd) * 1000000000UL + now;
							else
								new_item->exptime = 0;
						} else
							new_item->exptime = item->exptime;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_BUMP_CAS_UNIQUE)
							new_item->cas_unique = item->cas_unique + 1;
						else
							new_item->cas_unique = item->cas_unique;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_UPDATE)
							new_item->extra_flags = 0;
						else if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE || ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE_WITH_CAS) && (MP_KV_CMD_NEW_CAS_UNIQUE(cmd) < item->cas_unique)))
							new_item->extra_flags = MC_KV_EXTRA_FLAG_STALE;
						else if (MP_KV_CMD_OPFLAGS(cmd) & (MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE))
							new_item->extra_flags = item->extra_flags | MC_KV_EXTRA_FLAG_WON;
						else
							new_item->extra_flags = item->extra_flags;
						mp_memcpy(new_item->data, key, key_len);
						new_item->key_len = key_len;
						new_item->cls = item->cls;
						new_item->add_time = item->add_time;
						new_item->val_len = val_len;
						new_item->next = item->next;
						if (val_len) {
							if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL)
								mp_memcpy(&new_item->data[key_len], val_int_tmp, val_len);
							else if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_CONCAT) {
								if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_CONCAT_APPEND) {
									mp_memcpy(&new_item->data[key_len], &item->data[key_len], item->val_len);
									{
										uint64_t vl;
										EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), &new_item->data[key_len + item->val_len], vl);
										mp_assert(MP_KV_CMD_VAL_LEN(cmd) == vl);
									}
								} else {
									mp_memcpy(&new_item->data[key_len + MP_KV_CMD_VAL_LEN(cmd)], &item->data[key_len], item->val_len);
									{
										uint64_t vl;
										EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), &new_item->data[key_len], vl);
										mp_assert(MP_KV_CMD_VAL_LEN(cmd) == vl);
									}
								}
							} else if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_COPY_VAL)
								mp_memcpy(&new_item->data[key_len], &item->data[key_len], item->val_len);
							else {
								uint64_t vl;
								EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), &new_item->data[key_len], vl);
								mp_assert(MP_KV_CMD_VAL_LEN(cmd) == vl);
							}
						}
						if (prev)
							prev->next = new_item;
						else
							hash_table[hash % ____KV__CONF_HASH_TABLE_CNT] = new_item;
						mp_memcpy(ktd->val_buf, &new_item->data[key_len], new_item->val_len);
						MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_UPDATE|MC_KV_CMD_OPFLAG_INVALIDATE|MC_KV_CMD_OPFLAG_INVALIDATE_WITH_CAS|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE);
						MP_KV_CMD_VAL(cmd) = ktd->val_buf;
						MP_KV_CMD_VAL_LEN(cmd) = new_item->val_len;
						MP_KV_CMD_FLAGS(cmd) = new_item->flags;
						MP_KV_CMD_EXPTIME(cmd) = new_item->exptime;
						MP_KV_CMD_CAS_UNIQUE(cmd) = new_item->cas_unique;
						MP_KV_CMD_EXTRA_FLAGS(cmd) = new_item->extra_flags;
						MP_KV_CMD_LAST_ACCESS(cmd) = item->last_access; /* XXX: old val */
						MP_KV_CMD_CLS(cmd) = new_item->cls;
						MP_KV_CMD_ADD_TIME(cmd) = new_item->add_time;
						KV_OPS_SLAB_FREE(item, sizeof(struct kv_item) + item->key_len + item->val_len, opaque);
					}
				} else {
					mp_memcpy(ktd->val_buf, &item->data[key_len], item->val_len);
					MP_KV_CMD_VAL(cmd) = ktd->val_buf;
					MP_KV_CMD_VAL_LEN(cmd) = item->val_len;
					MP_KV_CMD_FLAGS(cmd) = item->flags;
					MP_KV_CMD_EXPTIME(cmd) = item->exptime;
					MP_KV_CMD_CAS_UNIQUE(cmd) = item->cas_unique;
					MP_KV_CMD_EXTRA_FLAGS(cmd) = item->extra_flags;
					MP_KV_CMD_LAST_ACCESS(cmd) = item->last_access;
					MP_KV_CMD_CLS(cmd) = item->cls;
					MP_KV_CMD_ADD_TIME(cmd) = item->add_time;
					item->last_access = now;
				}
				MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_FOUND;
			} else
				MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_FOUND);
		} else {
			MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_FOUND);
			if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_VIVIFY_ON_MISS) {
				uint64_t ring_idx = MP_KV_CMD_VAL_PTR_0(cmd), ring_off = MP_KV_CMD_VAL_PTR_1(cmd); /* EXTRACT_DATA overwrites indexes, we preserve them for the case of retry */
				uint8_t val_int_tmp[20];
				uint64_t val_len = MP_KV_CMD_VAL_LEN(cmd);
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL) {
					uint64_t l, e;
					UINT2STR(val_int_tmp, sizeof(val_int_tmp), l, MP_KV_CMD_NEW_INCDEC_VAL(cmd), e);
					if (e) {
						MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
						MP_KV_CMD_ERRNO(cmd) = EINVAL;
						break;
					}
					val_len = l;
				}
				item = (struct kv_item *) KV_OPS_SLAB_ALLOC(sizeof(struct kv_item) + key_len + val_len, opaque);
				if (!item) {
					MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
					MP_KV_CMD_ERRNO(cmd) = ENOMEM;
					break;
				}
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_FLAG)
					item->flags = MP_KV_CMD_FLAGS(cmd);
				else
					item->flags = 0;
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_EXPTIME) {
					if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_IMMEDIATE_EXPIRE)
						item->exptime = now;
					else if (MP_KV_CMD_EXPTIME(cmd))
						item->exptime = MP_KV_CMD_EXPTIME(cmd) * 1000000000UL + now;
					else
						item->exptime = 0;
				} else
					item->exptime = 0;
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_CAS_UNIQUE_IF_NEW)
					item->cas_unique = MP_KV_CMD_NEW_CAS_UNIQUE(cmd);
				else
					item->cas_unique = 2;
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE)
					item->extra_flags = MC_KV_EXTRA_FLAG_WON;
				else
					item->extra_flags = 0;
				item->key_len = key_len;
				mp_memcpy(item->data, key, key_len);
				item->cls = 1;
				item->last_access = item->add_time = now;
				item->val_len = val_len;
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL)
					mp_memcpy(&item->data[key_len], val_int_tmp, val_len);
				else {
					uint64_t vl;
					EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), &item->data[key_len], vl);
					mp_assert(vl == MP_KV_CMD_VAL_LEN(cmd));
				}
				item->next = hash_table[hash % ____KV__CONF_HASH_TABLE_CNT];
				hash_table[hash % ____KV__CONF_HASH_TABLE_CNT] = item;
				MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_VIVIFY_ON_MISS|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE);
				mp_memcpy(ktd->val_buf, &item->data[key_len], item->val_len);
				MP_KV_CMD_VAL(cmd) = ktd->val_buf;
				MP_KV_CMD_VAL_LEN(cmd) = item->val_len;
				MP_KV_CMD_FLAGS(cmd) = item->flags;
				MP_KV_CMD_EXPTIME(cmd) = item->exptime;
				MP_KV_CMD_CAS_UNIQUE(cmd) = item->cas_unique;
				MP_KV_CMD_EXTRA_FLAGS(cmd) = item->extra_flags;
				MP_KV_CMD_CLS(cmd) = item->cls;
				MP_KV_CMD_LAST_ACCESS(cmd) = item->last_access;
			}
		}
		break;
	}
	pthread_spin_unlock(&lock[hash % ____KV__CONF_HASH_TABLE_CNT]);
}

static void kv_thread_access_start(void *opaque)
{
	(void) opaque;
}

static void kv_thread_access_done(void *opaque)
{
	(void) opaque;
}

static void kv_maintenance(void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	if (ktd->eviction_goal) { /* random eviction */
		uint64_t released = 0, loopcnt = 0;
		while (released < ktd->eviction_goal && loopcnt++ < 3 /* TODO: find an appropriate value */) {
			{ /* xorshift64 */
				ktd->random ^= ktd->random << 13;
				ktd->random ^= ktd->random >> 7;
				ktd->random ^= ktd->random << 17;
			}
			{
				uint64_t hash_table_idx = ktd->random % ____KV__CONF_HASH_TABLE_CNT;
				{
					uint64_t i;
					for (i = 0; (i < ____KV__CONF_HASH_TABLE_CNT) && (released < ktd->eviction_goal); i++) {
						uint64_t idx = (hash_table_idx + i) % ____KV__CONF_HASH_TABLE_CNT;
						pthread_spin_lock(&lock[idx]);
						{
							struct kv_item *head = hash_table[idx];
							if (head) {
								struct kv_item *item = head;
								while (item->next) item = item->next;
								{
									uint8_t cmd[MP_KV_CMD_SIZE];
									memset(&cmd, 0, sizeof(cmd));
									MP_KV_CMD_OPFLAGS(cmd) = MC_KV_CMD_OPFLAG_DELETE;
									pthread_spin_unlock(&lock[idx]);
									mp_ops_kv_cmd(NULL /* XXX: we are sure delete does not touch mpr */, item->data, item->key_len, cmd, opaque);
									pthread_spin_lock(&lock[idx]);
								}
								released += sizeof(struct kv_item) + item->key_len + item->val_len;
							}
						}
						pthread_spin_unlock(&lock[idx]);
					}
				}
			}
		}
		if (ktd->eviction_goal <= released)
			ktd->eviction_goal = 0;
		else
			ktd->eviction_goal -= released;
	}
}

static void kv_eviction(uint64_t goal, void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	ktd->eviction_goal = goal;
}

static int kv_register_ktd(struct kv_thread_data *ktd, uint64_t ktd_id)
{
	if (ktd_id >= ____KV__CONF_MAX_THREAD_NUM)
		return -1;
	ktd->ktd_id = ktd_id;
	ktd->val_buf = mem_alloc_local(1UL<<21);
	ktd->random = 88172645463325252UL * (ktd_id + 1);
	return 0;
}

static void kv_init(void)
{
	mp_assert(____KV__CONF_HASH_TABLE_CNT);
	mp_assert(____KV__CONF_MAX_THREAD_NUM);
	hash_table = (struct kv_item **) calloc(____KV__CONF_HASH_TABLE_CNT, sizeof(struct kv_item *));
	mp_assert(hash_table);
	lock = (pthread_spinlock_t *) calloc(____KV__CONF_HASH_TABLE_CNT, sizeof(pthread_spinlock_t));
	mp_assert(lock);
	{
		uint64_t i;
		for (i = 0; i < ____KV__CONF_HASH_TABLE_CNT; i++)
			pthread_spin_init(&lock[i], PTHREAD_PROCESS_PRIVATE);
	}
}
