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

struct kv_val {
	uint64_t flags;
	uint64_t exptime;
	uint64_t cas_unique;
	uint64_t last_access;
	uint64_t cls;
	uint64_t len;
	uint64_t extra_flags;
	uint64_t add_time;
	struct kv_val *gc_next;
	uint64_t delete_time;
	uint8_t val[1];
};

struct kv_key {
	struct kv_key *next;
	uint64_t hash;
	struct kv_val *v;
	uint64_t len;
	struct kv_key *gc_next;
	uint64_t delete_time;
	uint8_t key[1];
};

struct kv_thread_data {
	uint64_t enter_time;
	uint64_t random;
	uint64_t prev_gc_check_time;
	struct kv_val *val_garbage_list;
	struct kv_key *key_garbage_list;
	uint64_t flush_time_copied;
};

static struct kv_key **hash_table;
static struct kv_thread_data **ktd_ptr_array;

static void mp_ops_kv_flush_all(uint64_t expr_sec, void *opaque)
{
	uint64_t expr = MP_OPS_UTIL_TIME_NS(opaque) + expr_sec * 1000000000UL;
	{
		uint64_t i;
		for (i = 0; i < ____KV__CONF_MAX_THREAD_NUM; i++) {
			if (ktd_ptr_array[i])
				KV_OPS_ATOMIC_LOAD(&expr, &ktd_ptr_array[i]->flush_time_copied, KV_FLAG_ATOMIC_RELAXED); /* XXX: lazy sync */
		}
	}
	{ /* unused */
		(void) opaque;
	}
}

static void mp_ops_kv_cmd(void *mpr, const uint8_t *key, uint64_t key_len, uint8_t *_cmd, void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	uint64_t hash, flush_time;
	{ /* fnv-1 hash function */
		uint64_t i;
		for (i = 0, hash = 0xcbf29ce484222325; i < key_len; i++) {
			hash *= 0x100000001b3;
			hash ^= key[i];
		}
	}
	KV_OPS_ATOMIC_LOAD(&ktd->flush_time_copied, &flush_time, KV_FLAG_ATOMIC_ACQUIRE);
	{
		uint8_t cmd[MP_KV_CMD_SIZE];
		while (1) {
			uint64_t now = MP_OPS_UTIL_TIME_NS(opaque);
			struct kv_key *head, *k, *prev = NULL;
			memcpy(cmd, _cmd, MP_KV_CMD_SIZE);
			KV_OPS_ATOMIC_LOAD(&hash_table[hash % ____KV__CONF_HASH_TABLE_CNT], &head, KV_FLAG_ATOMIC_ACQUIRE);
			for (k = head, prev = NULL; k != NULL; k = k->next) {
				if (!k->delete_time /* XXX: lazy synchronization, this implementation accepts to read a deleted entry */) {
					if (key_len == k->len && hash == k->hash) {
						if (!mp_memcmp(key, k->key, key_len))
							break;
					}
				}
				prev = k;
			}
			if (k) {
				char retry_after_delete = 0;
				struct kv_val *v;
				KV_OPS_ATOMIC_LOAD(&k->v, &v, KV_FLAG_ATOMIC_ACQUIRE);
				if ((v->exptime && v->exptime < now) || (now > flush_time && v->add_time < flush_time)) {
					MP_KV_CMD_OPFLAGS(cmd) = MC_KV_CMD_OPFLAG_DELETE;
					retry_after_delete = 1;
				}
				if (!retry_after_delete && (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_CAS) && (MP_KV_CMD_CAS_UNIQUE(cmd) != v->cas_unique)) {
					MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_FOUND;
					break; /* flag is not set */
				}
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_DELETE) {
					if (prev) {
						if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&prev->next, &k, &k->next, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED)) {
							/* other thread may have unlinked this key, so recheck */
							KV_OPS_ATOMIC_LOAD(&hash_table[hash % ____KV__CONF_HASH_TABLE_CNT], &head, KV_FLAG_ATOMIC_ACQUIRE);
							continue;
						}
						/* supposedly unlinked, we do recheck */
						{
							struct kv_key *_k = head;
							while (_k) {
								if (key_len == _k->len && hash == _k->hash) {
									if (!mp_memcmp(key, _k->key, key_len))
										break;
								}
								_k = _k->next;
							}
							if (_k) { /* this key has been relinked by other concurrent thread, so retry */
								/* here, we do not update head so that we won't remove too many same keys */
								continue;
							} else {
								/* item is not found, this means the deletion has been succeeded */
							}
						}
					} else {
						if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&hash_table[hash % ____KV__CONF_HASH_TABLE_CNT], &head, &k->next, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED)) {
							/* we haven't deleted because other thread has manipulated the list, so retry */
							KV_OPS_ATOMIC_LOAD(&hash_table[hash % ____KV__CONF_HASH_TABLE_CNT], &head, KV_FLAG_ATOMIC_ACQUIRE);
							continue;
						} else {
							/* head won't disappear, so we are done */
						}
					}
					{
						uint64_t _zero = 0, _t = MP_OPS_UTIL_TIME_NS(opaque);
						if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&k->v->delete_time, &_zero, &_t, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED)) {
							/* other thread has linked this val to its garbage list, so we don't need further work to release this val  */
						} else {
							k->v->gc_next = ktd->val_garbage_list;
							ktd->val_garbage_list = k->v;
						}
					}
					{
						uint64_t _zero = 0, _t = MP_OPS_UTIL_TIME_NS(opaque);
						if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&k->delete_time, &_zero, &_t, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED)) {
							mp_assert(0); /* other thread will never release the same key because of compare_exchange above  */
						} else {
							k->next = ktd->key_garbage_list;
							ktd->key_garbage_list = k;
						}
					}
					MP_KV_CMD_OPFLAGS(cmd) &= ~MC_KV_CMD_OPFLAG_DELETE;
					MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_FOUND;
					if (retry_after_delete)
						continue;
				} else if (!v->exptime || (v->exptime && v->exptime > now)) {
					uint8_t do_write = 0;
					uint64_t ring_idx = MP_KV_CMD_VAL_PTR_0(cmd), ring_off = MP_KV_CMD_VAL_PTR_1(cmd); /* EXTRACT_DATA overwrites indexes, we preserve them for the case of retry */
					if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_UPDATE)
						do_write = 1;
					else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE) && !(v->extra_flags & MC_KV_EXTRA_FLAG_STALE))
						do_write = 1;
					else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE) && (v->extra_flags & MC_KV_EXTRA_FLAG_STALE))
						MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_INVALIDATE);
					else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE)
							&& !(v->extra_flags & MC_KV_EXTRA_FLAG_WON)
							&& (v->exptime && (v->exptime < MP_KV_CMD_RECACHE_EXPTIME(cmd))))
						do_write = 1;
					else if ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE)
							&& (v->extra_flags & MC_KV_EXTRA_FLAG_STALE)
							&& !(v->extra_flags & MC_KV_EXTRA_FLAG_WON))
						do_write = 1;
					if (do_write) {
						uint8_t val_int_tmp[20];
						uint64_t val_len = MP_KV_CMD_VAL_LEN(cmd);
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL) {
							uint64_t num;
							{
								uint64_t minus, e;
								STR2INT(v->val, v->len, num, minus, e);
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
							val_len = MP_KV_CMD_VAL_LEN(cmd) + v->len;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_COPY_VAL)
							val_len = v->len;
						{
							struct kv_val *new_v = (struct kv_val *) KV_OPS_SLAB_ALLOC(sizeof(struct kv_val) + val_len, opaque);
							if (!new_v) {
								MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
								MP_KV_CMD_ERRNO(cmd) = ENOMEM;
								break;
							}
							mp_assert(new_v); /* TODO handle this */
							if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_FLAG)
								new_v->flags = MP_KV_CMD_FLAGS(cmd);
							else
								new_v->flags = v->flags;
							if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_EXPTIME) {
								if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_IMMEDIATE_EXPIRE)
									new_v->exptime = now;
								else if (MP_KV_CMD_EXPTIME(cmd))
									new_v->exptime = MP_KV_CMD_EXPTIME(cmd) * 1000000000UL + now;
								else
									new_v->exptime = 0;
							} else
								new_v->exptime = v->exptime;
							if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_BUMP_CAS_UNIQUE)
								new_v->cas_unique = v->cas_unique + 1;
							else
								new_v->cas_unique = v->cas_unique;
							if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_UPDATE)
								new_v->extra_flags = 0;
							else if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE || ((MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_INVALIDATE_WITH_CAS) && (MP_KV_CMD_NEW_CAS_UNIQUE(cmd) < v->cas_unique)))
								new_v->extra_flags = MC_KV_EXTRA_FLAG_STALE;
							else if (MP_KV_CMD_OPFLAGS(cmd) & (MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE))
								new_v->extra_flags = v->extra_flags | MC_KV_EXTRA_FLAG_WON;
							else
								new_v->extra_flags = v->extra_flags;
							new_v->cls = v->cls;
							new_v->add_time = v->add_time;
							new_v->len = val_len;
							new_v->last_access = MP_OPS_UTIL_TIME_NS(opaque);;
							new_v->delete_time = 0;
							new_v->gc_next = NULL;
							if (val_len) {
								if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL)
									mp_memcpy(new_v->val, val_int_tmp, val_len);
								else if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_CONCAT) {
									if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_CONCAT_APPEND) {
										mp_memcpy(new_v->val, v->val, v->len);
										{
											uint64_t vl;
											EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), &new_v->val[v->len], vl);
											mp_assert(MP_KV_CMD_VAL_LEN(cmd) == vl);
										}
									} else {
										mp_memcpy(&new_v->val[MP_KV_CMD_VAL_LEN(cmd)], v->val, v->len);
										{
											uint64_t vl;
											EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), new_v->val, vl);
											mp_assert(MP_KV_CMD_VAL_LEN(cmd) == vl);
										}
									}
								} else if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_COPY_VAL)
									mp_memcpy(new_v->val, v->val, v->len);
								else {
									uint64_t vl;
									EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), new_v->val, vl);
									mp_assert(MP_KV_CMD_VAL_LEN(cmd) == vl);
								}
							}
							if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&k->v, &v, &new_v, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED)) {
								KV_OPS_SLAB_FREE(new_v, sizeof(struct kv_val) + new_v->len, opaque);
								continue;
							} else {
								uint64_t _zero = 0, _t = MP_OPS_UTIL_TIME_NS(opaque);
								if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&v->delete_time, &_zero, &_t, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED)) {
									/* other thread has linked this val to its garbage list, so we don't need further work to release this val  */
								} else {
									mp_assert(!v->gc_next);
									v->gc_next = ktd->val_garbage_list;
									ktd->val_garbage_list = v;
									MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_UPDATE|MC_KV_CMD_OPFLAG_INVALIDATE|MC_KV_CMD_OPFLAG_INVALIDATE_WITH_CAS|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE);
								}
							}
							MP_KV_CMD_VAL(cmd) = new_v->val;
							MP_KV_CMD_VAL_LEN(cmd) = new_v->len;
							MP_KV_CMD_FLAGS(cmd) = new_v->flags;
							MP_KV_CMD_EXPTIME(cmd) = new_v->exptime;
							MP_KV_CMD_CAS_UNIQUE(cmd) = new_v->cas_unique;
							MP_KV_CMD_EXTRA_FLAGS(cmd) = new_v->extra_flags;
							MP_KV_CMD_LAST_ACCESS(cmd) = v->last_access; /* old val */
							MP_KV_CMD_CLS(cmd) = new_v->cls;
							MP_KV_CMD_ADD_TIME(cmd) = new_v->add_time;
						}
					} else {
						MP_KV_CMD_VAL(cmd) = v->val;
						MP_KV_CMD_VAL_LEN(cmd) = v->len;
						MP_KV_CMD_FLAGS(cmd) = v->flags;
						MP_KV_CMD_EXPTIME(cmd) = v->exptime;
						MP_KV_CMD_CAS_UNIQUE(cmd) = v->cas_unique;
						MP_KV_CMD_EXTRA_FLAGS(cmd) = v->extra_flags;
						MP_KV_CMD_LAST_ACCESS(cmd) = v->last_access;
						MP_KV_CMD_CLS(cmd) = v->cls;
						MP_KV_CMD_ADD_TIME(cmd) = v->add_time;
						{
							uint64_t _t = MP_OPS_UTIL_TIME_NS(opaque);
							KV_OPS_ATOMIC_STORE(&v->last_access, &_t, KV_FLAG_ATOMIC_RELAXED); /* XXX: not transactional */
						}
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
					struct kv_val *new_v;
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
					k = (struct kv_key *) KV_OPS_SLAB_ALLOC(sizeof(struct kv_key) + key_len, opaque);
					if (!k) {
						MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
						MP_KV_CMD_ERRNO(cmd) = ENOMEM;
						break;
					}
					new_v = k->v = (struct kv_val *) KV_OPS_SLAB_ALLOC(sizeof(struct kv_val) + val_len, opaque);
					if (!new_v) {
						MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_ERROR;
						MP_KV_CMD_ERRNO(cmd) = ENOMEM;
						KV_OPS_SLAB_FREE(k, sizeof(struct kv_key) + key_len, opaque);
						break;
					}
					{
						k->delete_time = 0;
						k->gc_next = NULL;
						k->next = head;
						k->len = key_len;
						k->hash = hash;
						mp_memcpy(k->key, key, key_len);
					}
					{
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_FLAG)
							new_v->flags = MP_KV_CMD_FLAGS(cmd);
						else
							new_v->flags = 0;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_EXPTIME) {
							if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_IMMEDIATE_EXPIRE)
								new_v->exptime = now;
							else if (MP_KV_CMD_EXPTIME(cmd))
								new_v->exptime = MP_KV_CMD_EXPTIME(cmd) * 1000000000UL + now;
							else
								new_v->exptime = 0;
						} else
							new_v->exptime = 0;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_SET_CAS_UNIQUE_IF_NEW)
							new_v->cas_unique = MP_KV_CMD_NEW_CAS_UNIQUE(cmd);
						else
							new_v->cas_unique = 2;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE)
							new_v->extra_flags = MC_KV_EXTRA_FLAG_WON;
						else
							new_v->extra_flags = 0;
						new_v->cls = 1;
						new_v->last_access = new_v->add_time = MP_OPS_UTIL_TIME_NS(opaque);
						new_v->len = val_len;
						new_v->delete_time = 0;
						new_v->gc_next = NULL;
						if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_NUMERICAL)
							mp_memcpy(new_v->val, val_int_tmp, val_len);
						else {
							uint64_t vl;
							EXTRACT_DATA(mpr, ring_idx, ring_off, MP_KV_CMD_VAL_LEN(cmd), new_v->val, vl);
							mp_assert(vl == MP_KV_CMD_VAL_LEN(cmd));
						}
					}
					if (!KV_OPS_ATOMIC_COMPARE_EXCHANGE(&hash_table[hash % ____KV__CONF_HASH_TABLE_CNT], &head, &k, false, KV_FLAG_ATOMIC_ACQ_REL, KV_FLAG_ATOMIC_RELAXED)) {
						KV_OPS_SLAB_FREE(k->v, sizeof(struct kv_val) + val_len, opaque);
						KV_OPS_SLAB_FREE(k, sizeof(struct kv_key) + key_len, opaque);
						continue;
					} else
						MP_KV_CMD_OPFLAGS(cmd) &= ~(MC_KV_CMD_OPFLAG_VIVIFY_ON_MISS|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE|MC_KV_CMD_OPFLAG_WIN_FOR_RECACHE_IF_STALE);
					MP_KV_CMD_VAL(cmd) = new_v->val;
					MP_KV_CMD_VAL_LEN(cmd) = new_v->len;
					MP_KV_CMD_FLAGS(cmd) = new_v->flags;
					MP_KV_CMD_EXPTIME(cmd) = new_v->exptime;
					MP_KV_CMD_CAS_UNIQUE(cmd) = new_v->cas_unique;
					MP_KV_CMD_EXTRA_FLAGS(cmd) = new_v->extra_flags;
					MP_KV_CMD_LAST_ACCESS(cmd) = new_v->last_access;
				}
			}
			break;
		}
		memcpy(_cmd, cmd, MP_KV_CMD_SIZE);
	}
}

static void kv_thread_access_start(void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	uint64_t _t = MP_OPS_UTIL_TIME_NS(opaque);
	KV_OPS_ATOMIC_STORE(&ktd->enter_time, &_t, KV_FLAG_ATOMIC_RELEASE);
}

static void kv_thread_access_done(void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	uint64_t _zero = 0;
	KV_OPS_ATOMIC_STORE(&ktd->enter_time, &_zero, KV_FLAG_ATOMIC_RELEASE);
}

static void kv_garbage_collection(void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	uint64_t _t = MP_OPS_UTIL_TIME_NS(opaque);
	if ((ktd->val_garbage_list || ktd->key_garbage_list)
			&& (_t - ktd->prev_gc_check_time > 10000000UL /* 10 ms */)) {
		uint64_t last_enter_time = 0;
		{
			uint64_t i;
			for (i = 0; i < ____KV__CONF_MAX_THREAD_NUM; i++) {
				if (ktd_ptr_array[i]) {
					uint64_t t;
					KV_OPS_ATOMIC_LOAD(&ktd_ptr_array[i]->enter_time, &t, KV_FLAG_ATOMIC_ACQUIRE);
					if (!last_enter_time || (t && t < last_enter_time))
						last_enter_time = t;
				}
			}
		}
		{
			struct kv_val *v = ktd->val_garbage_list, *p = NULL;
			while (v) {
				struct kv_val *n = v->gc_next;
				if (!last_enter_time || (v->delete_time < last_enter_time)) {
					if (v == ktd->val_garbage_list)
						ktd->val_garbage_list = n;
					if (p)
						p->gc_next = n;
					KV_OPS_SLAB_FREE(v, sizeof(struct kv_val) + v->len, opaque);
				} else
					p = v;
				v = n;
			}
		}
		{
			struct kv_key *k = ktd->key_garbage_list, *p = NULL;
			while (k) {
				struct kv_key *n = k->gc_next;
				if (!last_enter_time || (k->delete_time < last_enter_time)) {
					if (k == ktd->key_garbage_list)
						ktd->key_garbage_list = n;
					if (p)
						p->gc_next = n;
					KV_OPS_SLAB_FREE(k, sizeof(struct kv_key) + k->len, opaque);
				} else
					p = k;
				k = n;
			}
		}
		ktd->prev_gc_check_time = _t;
	}
}

static void kv_eviction(uint64_t goal, void *opaque)
{
	struct kv_thread_data *ktd = KV_OPS_OPAQUE2KTD(opaque);
	{ /* random eviction */
		uint64_t released = 0;
		while (released < goal) {
			{ /* xorshift64 */
				ktd->random ^= ktd->random << 13;
				ktd->random ^= ktd->random >> 7;
				ktd->random ^= ktd->random << 17;
			}
			{
				uint64_t i;
				for (i = 0; i < ____KV__CONF_HASH_TABLE_CNT; i++) {
					struct kv_key *head;
					KV_OPS_ATOMIC_LOAD(&hash_table[(ktd->random + i) % ____KV__CONF_HASH_TABLE_CNT], &head, KV_FLAG_ATOMIC_ACQUIRE);
					if (head) {
						struct kv_key *k = head;
						while (k->next) k = k->next;
						{
							uint8_t cmd[MP_KV_CMD_SIZE];
							memset(&cmd, 0, sizeof(cmd));
							MP_KV_CMD_OPFLAGS(cmd) = MC_KV_CMD_OPFLAG_DELETE;
							mp_ops_kv_cmd(NULL /* XXX: we are sure delete does not touch mpr */, k->key, k->len, cmd, opaque);
						}
						released += sizeof(struct kv_key) + sizeof(struct kv_val) + k->len + k->v->len /* XXX: lazy sync */;
						break;
					}
				}
			}
		}
	}
}

static int kv_register_ktd(struct kv_thread_data *ktd, uint64_t ktd_id)
{
	if (ktd_id >= ____KV__CONF_MAX_THREAD_NUM)
		return -1;
	ktd_ptr_array[ktd_id] = ktd;
	ktd->random = 88172645463325252UL * (ktd_id + 1);
	return 0;
}

static void kv_init(void)
{
	mp_assert(____KV__CONF_HASH_TABLE_CNT);
	mp_assert(____KV__CONF_MAX_THREAD_NUM);
	hash_table = (struct kv_key **) calloc(____KV__CONF_HASH_TABLE_CNT, sizeof(struct kv_key *));
	mp_assert(hash_table);
	ktd_ptr_array = (struct kv_thread_data **) calloc(____KV__CONF_MAX_THREAD_NUM, sizeof(struct kv_thread_data *));
	mp_assert(ktd_ptr_array);
}
