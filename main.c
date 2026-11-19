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

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>

#include <arpa/inet.h>

#ifdef __cplusplus
#include <atomic>
#endif

#if defined(__linux__)
#include <numa.h>
#define mem_alloc_local	numa_alloc_local
#define mem_free	numa_free
#elif defined(__FreeBSD__)
static void *mem_alloc_local(size_t len)
{
	return malloc(len);
}

static void mem_free(void *ptr, size_t len)
{
	free(ptr);
	{
		(void) len;
	}
}
#endif

#include <pthread.h>

static uint8_t verbose_level = 0;

#ifndef IIP_OPS_DEBUG_PRINTF
static void __debug_printf(const char *format, ...)
{
	if (verbose_level) {
		va_list v;
		va_start(v, format);
		vprintf(format, v);
		va_end(v);
		fflush(stdout);
	}
}
#define IIP_OPS_DEBUG_PRINTF __debug_printf
#endif

#define IIP_OPS_ERROR_FATAL_EXT() do { printf("[%s:%u]: ERROR EXT\n", __func__, __LINE__); } while (0)
#define IIP_OPS_ERROR_FATAL_SYS() do { printf("[%s:%u]: ERROR SYS\n", __func__, __LINE__); } while (0)
#define IIP_OPS_ERROR_FATAL_MEM() do { printf("[%s:%u]: ERROR MEM\n", __func__, __LINE__); } while (0)

#define IIP_TCP_CONN_STRUCT_EXTRA struct tcp_opaque *opaque
typedef struct tcp_opaque * tcp_opaque_ptr_t;
#define IIP_TCP_OPAQUE_P tcp_opaque_ptr_t

#ifndef IIP_MAIN_C
#define IIP_MAIN_C "iip/main.c"
#endif

#define SKIP_IOSUB_IMPLEMENTATION
#define M2S(s) _M2S(s)
#define _M2S(s) #s
#include M2S(IOSUB_MAIN_C)
#undef _M2S
#undef M2S
#undef SKIP_IOSUB_IMPLEMENTATION

#define SKIP_IIP_IMPLEMENTATION
#include IIP_MAIN_C
#undef SKIP_IIP_IMPLEMENTATION

#if !defined(APP_IIP_OPS_UTIL_NOW_NS_NONE)
static void iip_ops_util_now_ns(uint32_t t[3], void *opaque)
{
	struct timespec ts;
	assert(!clock_gettime(CLOCK_REALTIME, &ts));
	t[0] = (ts.tv_sec >> 32) & 0xffffffff;
	t[1] = (ts.tv_sec >>  0) & 0xffffffff;
	t[2] = ts.tv_nsec;
	{ /* unused */
		(void) opaque;
	}
}
#endif

static uint16_t helper_ip4_get_connection_affinity(uint16_t, uint32_t, uint16_t, uint32_t, uint16_t, void *);

#ifndef MAX_THREAD
#define MAX_THREAD (256)
#endif
#ifndef MAX_PAYLOAD_LEN
#define MAX_PAYLOAD_LEN (63488)
#endif

#ifndef MAX_PAYLOAD_PKT_CNT
#define MAX_PAYLOAD_PKT_CNT (2048)
#endif

#ifndef __APP_PRINTF
#define __APP_PRINTF printf
#endif

static int __printf_nothing(const char *format, ...) { (void) format; return 0; }
#ifndef MP_OPS_DEBUG_PRINTF
#define MP_OPS_DEBUG_PRINTF __printf_nothing
#endif

#define mp_assert assert
#define mp_memcmp memcmp
#define mp_memcpy memcpy
#define mp_memmove memmove

#define MP_OPS_UTIL_TIME_NS(__o) ({ struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); (void)(__o); ts.tv_sec * 1000000000UL + ts.tv_nsec; })

static void mp_ops_clear_response(void *);
#define MP_OPS_CLEAR_RESPONSE mp_ops_clear_response
static long mp_ops_push_response(void *, const char *, size_t);
#define MP_OPS_PUSH_RESPONSE mp_ops_push_response
static void mp_ops_kv_cmd(void *, const uint8_t *, uint64_t, uint8_t *, void *);
#define MP_OPS_KV_CMD mp_ops_kv_cmd
static void mp_ops_kv_flush_all(uint64_t, void *);
#define MP_OPS_KV_FLUSH_ALL  mp_ops_kv_flush_all
static int mp_ops_allow_shutdown(void *opaque) { return 0; (void) opaque; }
#define MP_OPS_ALLOW_SHUTDOWN mp_ops_allow_shutdown
static void mp_ops_shutdown(uint64_t op, void *opaque)
{
	if (op) /* graceful */
		raise(SIGUSR1);
	else
		raise(SIGINT);
	{ /* unused */
		(void) opaque;
	}
}
#define MP_OPS_SHUTDOWN mp_ops_shutdown

#define MP_TEST_HOOK() do {  } while (0)

#include "memcached-protocol-parser/main.c"

static void *kv_ops_slab_alloc(uint64_t, void *);
#define KV_OPS_SLAB_ALLOC kv_ops_slab_alloc
static void kv_ops_slab_free(void *, uint64_t, void *);
#define KV_OPS_SLAB_FREE  kv_ops_slab_free

#define KV_OPS_ATOMIC_LOAD __atomic_load
#define KV_OPS_ATOMIC_STORE __atomic_store
#define KV_OPS_ATOMIC_COMPARE_EXCHANGE __atomic_compare_exchange

#define KV_FLAG_ATOMIC_RELAXED __ATOMIC_RELAXED
#define KV_FLAG_ATOMIC_ACQ_REL __ATOMIC_ACQ_REL
#define KV_FLAG_ATOMIC_RELEASE __ATOMIC_RELEASE
#define KV_FLAG_ATOMIC_ACQUIRE __ATOMIC_ACQUIRE

#define KV_OPS_MALLOC(__s, __o) malloc(__s)
#define KV_OPS_FREE(__p, __s, __o) free(__p)

#define KV_OPS_OPAQUE2KTD(__o) ((struct kv_thread_data *)(__o)) /* assuming opaque has kv_thread_data at its top */

static uint64_t kv_conf_hash_table_cnt = 1;
#define ____KV__CONF_HASH_TABLE_CNT (kv_conf_hash_table_cnt)

#include "kv.c"

#define SLAB_OPS_ATOMIC_ADD_FETCH __atomic_add_fetch
#define SLAB_OPS_ATOMIC_SUB_FETCH __atomic_sub_fetch

#define SLAB_FLAG_ATOMIC_RELAXED __ATOMIC_RELAXED
#define SLAB_FLAG_ATOMIC_ACQ_REL __ATOMIC_ACQ_REL
#define SLAB_FLAG_ATOMIC_RELEASE __ATOMIC_RELEASE
#define SLAB_FLAG_ATOMIC_ACQUIRE __ATOMIC_ACQUIRE

#define SLAB_OPS_OPAQUE2STD(__o) ((struct slab_thread_data *)((uintptr_t)(__o) + sizeof(struct kv_thread_data))) /* assuming this is subsequent to kv_thread_data */

#include "slab.c"

#define NUM_MPR_SLOT (128)

struct tcp_opaque {
	IIP_MEM_P mem;
	IIP_OPAQUE_P opaque;
	uintptr_t handle;
	uint16_t cur;
	uint8_t txbuf[1280];
	IIP_PKT_P pbuf[NUM_MPR_SLOT];
	uint8_t mpr[MPR_MEM_SIZE(NUM_MPR_SLOT)];
	uint8_t rx_buf[NUM_MPR_SLOT][0xffff];
};

struct thread_data {
	struct kv_thread_data ktd;
	struct slab_thread_data std;
	void *gc_key_list;
	void *gc_val_list;
	pthread_t th;

	struct thread_data **tds;
	struct tcp_opaque *o;

	uint16_t core_id;
	uint8_t close_state;
	uint8_t should_stop;
	struct {
		struct tcp_opaque *conn_list[1U << 16];
		uint16_t conn_list_cnt;
		uint8_t used_port_bm[0xffff / 8];
	} tcp;
};

static int ii_call_pkt_alloc(IIP_PKT_P *pkt, IIP_OPAQUE_P opaque);
static int ii_call_pkt_free(IIP_PKT_P pkt, IIP_OPAQUE_P opaque);
static long ii_call_pkt_data_read(IIP_PKT_P pkt, uint8_t *buf, IIP_PKT_LEN_T len, IIP_PKT_LEN_T off, IIP_OPAQUE_P opaque);
static long ii_call_pkt_data_write(IIP_PKT_P pkt, const uint8_t *buf, IIP_PKT_LEN_T len, IIP_PKT_LEN_T off, IIP_OPAQUE_P opaque);
static int ii_call_pkt_set_len(IIP_PKT_P pkt, IIP_PKT_LEN_T len, IIP_OPAQUE_P opaque);

static enum iip_rc ii_pb_tcp_payload_len(IIP_MEM_P w, II_PB_P pb_id, IIP_PKT_LEN_T *payload_len);
static enum iip_rc ii_pb_ipv4_payload_copy(IIP_MEM_P w, II_PB_P pb_id, IIP_PKT_LEN_T skip, uint8_t *buf, IIP_PKT_LEN_T buf_len, IIP_PKT_LEN_T *copied_len, IIP_OPAQUE_P opaque);

static void mp_ops_clear_response(void *opaque)
{
	struct thread_data *td = (struct thread_data *) opaque;
	struct tcp_opaque *o = (struct tcp_opaque *) td->o;
	o->cur = 0;
}

static long mp_ops_push_response(void *opaque, const char *msg, size_t len)
{
	struct thread_data *td = (struct thread_data *) opaque;
	struct tcp_opaque *o = (struct tcp_opaque *) td->o;
	uint64_t copied = 0;
	while (copied != len) {
		uint64_t l = len - copied;
		if (sizeof(o->txbuf) - o->cur < l)
			l = sizeof(o->txbuf) - o->cur;
		memcpy(&o->txbuf[o->cur], &msg[copied], l);
		o->cur += l;
		if (o->cur == sizeof(o->txbuf)) {
			IIP_PKT_P pkt;
			if (ii_call_pkt_alloc(&pkt, o->opaque) != IIP_ERR_OK) {
				assert(0);
			}
			ii_call_pkt_data_write(pkt, o->txbuf, o->cur, 0, o->opaque);
			ii_call_pkt_set_len(pkt, o->cur, o->opaque);
			{
				IIP_PKT_P pkts[1];
				pkts[0] = pkt;
				iip_tcp_send(o->mem, o->handle, pkts, 1, o->opaque);
			}
			o->cur = 0;
		}
		copied += l;
	}
	return 0;
}

static uint8_t __app_close_posted = 0;

struct app_data {
#ifdef __cplusplus
	std::atomic<uint64_t> active_conn;
#else
	_Atomic uint64_t active_conn;
#endif
	struct thread_data *tds[MAX_THREAD];
	uint16_t l4_port_be;
	uint8_t mode_binary;
};

static uint8_t __app_should_stop(void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	return td->should_stop;
}

static void __app_loop(void *mem, uint8_t mac[], uint32_t ip4_be, uint32_t *next_us, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	*next_us = 1000000U;
	if (__app_close_posted) {
		switch (td->close_state) {
		case 0:
			if (!td->core_id) {
				time_t t = time(NULL);
				struct tm lt;
				localtime_r(&t, &lt);
				__APP_PRINTF("%04u-%02u-%02u %02u:%02u:%02u : close requested\n",
						lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
						lt.tm_hour, lt.tm_min, lt.tm_sec); fflush(stdout);
			}
			if (td->tcp.conn_list_cnt) {
				uint16_t i;
				for (i = 0; i < td->tcp.conn_list_cnt; i++)
					iip_tcp_close(mem, td->tcp.conn_list[i]->handle, opaque);
			}
			td->close_state = 1;
			break;
		case 1:
			if (!td->tcp.conn_list_cnt)
				td->should_stop = 1;
			break;
		default:
			break;
		}
	}
	kv_maintenance((void *) td);
	{ /* unused */
		(void) mac;
		(void) ip4_be;
	}
}

static void *__app_thread_init(void *workspace, uint16_t core_id, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	struct thread_data *td;
	assert((td = (struct thread_data *) mem_alloc_local(sizeof(struct thread_data))) != NULL);
	memset(td, 0, sizeof(struct thread_data));
	td->core_id = core_id;
	td->tds = ad->tds;
	ad->tds[td->core_id] = td;
	kv_register_ktd(&td->ktd, core_id);
	if (!core_id)
		printf("mimicached server has been started\n");
	return td;
	{ /* unused */
		(void) workspace;
	}
}

static uint8_t ii_extract_ipv4_hdr_len(const uint8_t *buf);
static uint16_t ii_read_uint16(const uint8_t *buf);

static bool iip_ops_tcp_accept(uint8_t *tcp_hdr, IIP_OPAQUE_P opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	if (ii_read_uint16(&tcp_hdr[2]) == ad->l4_port_be)
		return true;
	else
		return false;
}
#define IIP_OPS_TCP_ACCEPT() do { iip_ret_bool = iip_ops_tcp_accept(tcp_hdr, opaque); } while (0)

static IIP_TCP_OPAQUE_P iip_ops_tcp_accepted(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	struct tcp_opaque *to = (struct tcp_opaque *) mem_alloc_local(sizeof(struct tcp_opaque));
	assert(to);
	memset(to, 0, sizeof(struct tcp_opaque));
	to->mem = w;
	to->opaque = opaque;
	to->handle = conn_id;
	{
		void **opaque_array = (void **) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		IIP_OPS_DEBUG_PRINTF("[%u] accept new connection (%lu)\n", td->core_id, ++ad->active_conn);
	}
	{
		void **opaque_array = (void **) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		td->tcp.conn_list[td->tcp.conn_list_cnt++] = to;
	}
	MPR_MODE_BINARY(to->mpr)   = ad->mode_binary;
	MPR_RING_NUM_SLOT(to->mpr) = NUM_MPR_SLOT;
	MPR_RING_HEAD_IDX(to->mpr) = 0;
	MPR_RING_HEAD_OFF(to->mpr) = 0;
	MPR_RING_TAIL_IDX(to->mpr) = 0;
	MPR_RING_TAIL_OFF(to->mpr) = 0;
	return (void *) to;
}
#define IIP_OPS_TCP_ACCEPTED() do { II_TCP_CONN(conn_id).opaque = iip_ops_tcp_accepted(w, conn_id, opaque); iip_ret_int = 0; } while (0)

static uint16_t ii_pb_tcp_hdr_len(IIP_MEM_P w, II_PB_P pb_id);

static int iip_ops_tcp_payload(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id, IIP_OPAQUE_P opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	struct tcp_opaque *o = II_TCP_CONN(conn_id).opaque;
	{
		MPR_SLOT_LEN(o->mpr, MPR_RING_TAIL_IDX(o->mpr)) = II_PB(pb_id).tcp.payload_len - II_PB(pb_id).tcp.inc_head - II_PB(pb_id).tcp.dec_tail;
		MPR_SLOT_PTR(o->mpr, MPR_RING_TAIL_IDX(o->mpr)) = (uintptr_t) o->rx_buf[MPR_RING_TAIL_IDX(o->mpr)];
		{
			IIP_PKT_LEN_T copied_len;
			if (ii_pb_ipv4_payload_copy(w, pb_id, ii_pb_tcp_hdr_len(w, pb_id) + II_PB(pb_id).tcp.inc_head, (uint8_t *) MPR_SLOT_PTR(o->mpr, MPR_RING_TAIL_IDX(o->mpr)), MPR_SLOT_LEN(o->mpr, MPR_RING_TAIL_IDX(o->mpr)), &copied_len, opaque) != IIP_ERR_OK) {
				assert(0);
			}
			if (MPR_SLOT_LEN(o->mpr, MPR_RING_TAIL_IDX(o->mpr)) != copied_len) {
				assert(0);
			}
		}
	}
	MPR_RING_TAIL_IDX(o->mpr)++;
	if (MPR_RING_TAIL_IDX(o->mpr) == MPR_RING_NUM_SLOT(o->mpr))
		MPR_RING_TAIL_IDX(o->mpr) = 0;
	td->o = o;
	{
		uint8_t closed = 0;
		if (MPR_RING_HEAD_IDX(o->mpr) == (MPR_RING_TAIL_IDX(o->mpr) + 1 == MPR_RING_NUM_SLOT(o->mpr) ? 0 : MPR_RING_TAIL_IDX(o->mpr) + 1)) {
			IIP_OPS_DEBUG_PRINTF("[%u] ring is full, close connection\n", td->core_id);
			iip_tcp_close(w, conn_id, opaque);
			closed = 1;
		} else {
			uint64_t head_idx = MPR_RING_HEAD_IDX(o->mpr);
			{
				while (!((MPR_RING_HEAD_IDX(o->mpr) == MPR_RING_TAIL_IDX(o->mpr)
							&& MPR_RING_HEAD_OFF(o->mpr) == MPR_RING_TAIL_OFF(o->mpr)))) {
					uint64_t _head_idx = MPR_RING_HEAD_IDX(o->mpr), _head_off = MPR_RING_HEAD_OFF(o->mpr);
					{
						long r;
						{
							kv_thread_access_start((void *) td);
							r = parse_memcached_request(o->mpr, (void *) td);
							kv_thread_access_done((void *) td);
						}
						if (o->cur) {
							IIP_PKT_P pkt;
							if (ii_call_pkt_alloc(&pkt, opaque) != IIP_ERR_OK) {
								assert(0);
							}
							if (ii_call_pkt_data_write(pkt, o->txbuf, o->cur, 0, opaque) != o->cur) {
								assert(0);
							}
							ii_call_pkt_set_len(pkt, o->cur, opaque);
							{
								IIP_PKT_P pkts[1];
								pkts[0] = pkt;
								iip_tcp_send(w, conn_id, pkts, 1, opaque);
							}
							o->cur = 0;
						}
						if (r < 0) {
							iip_tcp_close(w, conn_id, opaque);
							closed = 1;
							break;
						}
					}
					if (_head_idx == MPR_RING_HEAD_IDX(o->mpr) && _head_off == MPR_RING_HEAD_OFF(o->mpr))
						break;
				}
			}
			while (head_idx != MPR_RING_HEAD_IDX(o->mpr)) {
				iip_tcp_rxbuf_consumed(w, conn_id, MPR_SLOT_LEN(o->mpr, head_idx), opaque);
				ii_call_pkt_free(o->pbuf[head_idx], opaque);
				head_idx++;
				if (head_idx == NUM_MPR_SLOT)
					head_idx = 0;
			}
		}
		if (!closed) {
			if (o->cur) {
				IIP_PKT_P pkt;
				if (ii_call_pkt_alloc(&pkt, opaque) != IIP_ERR_OK) {
					assert(0);
				}
				if (ii_call_pkt_data_write(pkt, o->txbuf, o->cur, 0, opaque) != IIP_ERR_OK) {
					assert(0);
				}
				ii_call_pkt_set_len(pkt, o->cur, opaque);
				{
					IIP_PKT_P pkts[1];
					pkts[0] = pkt;
					iip_tcp_send(w, conn_id, pkts, 1, opaque);
				}
				o->cur = 0;
			}
		}
	}
	td->o = NULL;
	return 0;
}
#define IIP_OPS_TCP_PAYLOAD() do { iip_ret_int = iip_ops_tcp_payload(w, conn_id, pb_id, opaque); } while (0)

static int iip_ops_tcp_closed(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, IIP_OPAQUE_P opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			uint16_t i;
			for (i = 0; i < td->tcp.conn_list_cnt; i++) {
				struct tcp_opaque *tcp_opaque = II_TCP_CONN(conn_id).opaque;
				if (tcp_opaque == td->tcp.conn_list[i]) {
					{
						uint64_t head_idx = MPR_RING_HEAD_IDX(tcp_opaque->mpr);
						while (head_idx != MPR_RING_TAIL_IDX(tcp_opaque->mpr)) {
							ii_call_pkt_free(tcp_opaque->pbuf[head_idx], opaque);
							head_idx = (head_idx + 1 == MPR_RING_NUM_SLOT(tcp_opaque->mpr) ? 0 : head_idx + 1);
						}
					}
					td->tcp.conn_list[i] = td->tcp.conn_list[--td->tcp.conn_list_cnt];
					mem_free(tcp_opaque, sizeof(struct tcp_opaque));
					break;
				}
			}
		}
	}
	IIP_OPS_DEBUG_PRINTF("tcp connection closed (%lu)\n", --ad->active_conn);
	return 0;
}
#define IIP_OPS_TCP_CLOSED() do { iip_ret_int = iip_ops_tcp_closed(w, conn_id, opaque); } while (0)

#define IIP_OPS_TCP_STATE_CLOSE_WAIT() do { iip_ret_int = iip_tcp_close(w, conn_id, opaque); } while (0)

static void sig_h(int sig __attribute__((unused)))
{
	__app_close_posted = 1;
	signal(SIGINT, SIG_DFL);
}

static void __app_exit(void *app_global_opaque)
{
	mem_free(app_global_opaque, sizeof(struct app_data));
}

static void *__app_init(int argc, char *const *argv)
{
	struct app_data *ad = (struct app_data *) mem_alloc_local(sizeof(struct app_data));
	assert(ad);
	ad->l4_port_be = htons(11211);
	ad->mode_binary = 0;
	slab_init();
	slab_stat.mem_size = 2 * 1048576;
	{ /* parse arguments */
		int ch, cnt = 0;
		while ((ch = getopt(argc, argv, "bm:p:v:z:")) != -1) {
			cnt += 2;
			switch (ch) {
			case 'b':
				ad->mode_binary = 0x80;
				break;
			case 'm':
				slab_stat.mem_size = atol(optarg) * 1048576;
				break;
			case 'p':
				ad->l4_port_be = htons(atoi(optarg));
				break;
			case 'v':
				verbose_level = atoi(optarg);
				break;
			case 'z':
				kv_conf_hash_table_cnt = atol(optarg);
				break;
			default:
				assert(0);
				break;
			}
		}
		argc -= cnt;
		argv += cnt - 1;
	}
	kv_init();
	signal(SIGINT, sig_h);
	return (void *) ad;
}

#define SKIP_IOSUB_DEFINITION
#define M2S(s) _M2S(s)
#define _M2S(s) #s
#include M2S(IOSUB_MAIN_C)
#undef _M2S
#undef M2S
#undef SKIP_IOSUB_DEFINITION

#define SKIP_IIP_DEFINITION
#include IIP_MAIN_C
#undef SKIP_IIP_DEFINITION

int main(int argc, char *const *argv)
{
	return __iosub_main(argc, argv);
	{ /* unused */
		(void) helper_ip4_get_connection_affinity;
		(void) iip_tcp_ipv4_ethernet_connect;
		(void) iip_arp_ethernet_request;
	}
}
