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

#include <numa.h>
#define mem_alloc_local	numa_alloc_local
#define mem_free	numa_free

static uint8_t verbose_level = 0;

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

#define __iip_memcpy	memcpy
#define __iip_memset	memset
#define __iip_memcmp	memcmp
#define __iip_memmove	memmove
#define __iip_assert	assert

#ifndef IIP_OPS_DEBUG_PRINTF
#define IIP_OPS_DEBUG_PRINTF __debug_printf
#endif

#ifndef IIP_MAIN_C
#define IIP_MAIN_C "iip/main.c"
#endif

#include IIP_MAIN_C

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

#define MP_OPS_UTIL_TIME_NS(__o) ({ struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec * 1000000000UL + ts.tv_nsec; })

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
	void *mem;
	void *opaque;
	void *handle;
	uint16_t cur;
	uint8_t txbuf[1280];
	void *pbuf[NUM_MPR_SLOT];
	uint8_t mpr[MPR_MEM_SIZE(NUM_MPR_SLOT)];
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
			void *pkt = iip_ops_pkt_alloc(o->opaque);
			assert(pkt);
			memcpy(iip_ops_pkt_get_data(pkt, o->opaque), o->txbuf, o->cur);
			iip_ops_pkt_set_len(pkt, o->cur, o->opaque);
			iip_tcp_send(o->mem, o->handle, pkt, 0, o->opaque);
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
	kv_garbage_collection((void *) td);
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

static void iip_ops_arp_reply(void *_mem, void *m, void *opaque)
{
	IIP_OPS_DEBUG_PRINTF("arp reply: %u.%u.%u.%u at %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n",
			PB_ARP_IP_SENDER(m)[0],
			PB_ARP_IP_SENDER(m)[1],
			PB_ARP_IP_SENDER(m)[2],
			PB_ARP_IP_SENDER(m)[3],
			PB_ARP_HW_SENDER(m)[0],
			PB_ARP_HW_SENDER(m)[1],
			PB_ARP_HW_SENDER(m)[2],
			PB_ARP_HW_SENDER(m)[3],
			PB_ARP_HW_SENDER(m)[4],
			PB_ARP_HW_SENDER(m)[5]
	      );
	{ /* unused */
		(void) _mem;
		(void) opaque;
	}
}

static void iip_ops_icmp_reply(void *_mem __attribute__((unused)), void *m __attribute__((unused)), void *opaque __attribute__((unused)))
{
	IIP_OPS_DEBUG_PRINTF("received icmp reply from %u.%u.%u.%u\n",
			(PB_IP4(m)->dst_be >>  0) & 0xff,
			(PB_IP4(m)->dst_be >>  8) & 0xff,
			(PB_IP4(m)->dst_be >> 16) & 0xff,
			(PB_IP4(m)->dst_be >> 24) & 0xff);
}

static uint8_t iip_ops_tcp_accept(void *mem __attribute__((unused)), void *m, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	if (PB_TCP(m)->dst_be == ad->l4_port_be)
		return 1;
	else
		return 0;
}

static void *iip_ops_tcp_accepted(void *mem __attribute__((unused)), void *handle, void *m __attribute__((unused)), void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	struct tcp_opaque *to = (struct tcp_opaque *) mem_alloc_local(sizeof(struct tcp_opaque));
	assert(to);
	memset(to, 0, sizeof(struct tcp_opaque));
	to->mem = mem;
	to->opaque = opaque;
	to->handle = handle;
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

static void *iip_ops_tcp_connected(void *mem, void *handle, void *m, void *opaque)
{
	assert(0);
	return NULL;
	{ /* unused */
		(void) mem;
		(void) handle;
		(void) m;
		(void) opaque;
	}
}

static void iip_ops_tcp_payload(void *mem, void *handle, void *m,
				void *tcp_opaque, uint16_t head_off, uint16_t tail_off,
				void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	struct tcp_opaque *o = (struct tcp_opaque *) tcp_opaque;
	o->pbuf[MPR_RING_TAIL_IDX(o->mpr)] = iip_ops_pkt_clone(m, opaque);
	MPR_SLOT_PTR(o->mpr, MPR_RING_TAIL_IDX(o->mpr)) = (uintptr_t) &(PB_TCP_PAYLOAD(o->pbuf[MPR_RING_TAIL_IDX(o->mpr)])[head_off]);
	MPR_SLOT_LEN(o->mpr, MPR_RING_TAIL_IDX(o->mpr)) = PB_TCP_PAYLOAD_LEN(o->pbuf[MPR_RING_TAIL_IDX(o->mpr)]) - head_off - tail_off;
	MPR_RING_TAIL_IDX(o->mpr)++;
	if (MPR_RING_TAIL_IDX(o->mpr) == MPR_RING_NUM_SLOT(o->mpr))
		MPR_RING_TAIL_IDX(o->mpr) = 0;
	td->o = o;
	{
		uint8_t closed = 0;
		if (MPR_RING_HEAD_IDX(o->mpr) == (MPR_RING_TAIL_IDX(o->mpr) + 1 == MPR_RING_NUM_SLOT(o->mpr) ? 0 : MPR_RING_TAIL_IDX(o->mpr) + 1)) {
			IIP_OPS_DEBUG_PRINTF("[%u] ring is full, close connection\n", td->core_id);
			iip_tcp_close(mem, handle, opaque);
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
							void *pkt = iip_ops_pkt_alloc(opaque);
							memcpy(iip_ops_pkt_get_data(pkt, opaque), o->txbuf, o->cur);
							iip_ops_pkt_set_len(pkt, o->cur, opaque);
							iip_tcp_send(mem, handle, pkt, 0, opaque);
							o->cur = 0;
						}
						if (r < 0) {
							iip_tcp_close(mem, handle, opaque);
							closed = 1;
							break;
						}
					}
					if (_head_idx == MPR_RING_HEAD_IDX(o->mpr) && _head_off == MPR_RING_HEAD_OFF(o->mpr))
						break;
				}
			}
			while (head_idx != MPR_RING_HEAD_IDX(o->mpr)) {
				iip_ops_pkt_free(o->pbuf[head_idx], opaque);
				head_idx++;
				if (head_idx == NUM_MPR_SLOT)
					head_idx = 0;
			}
		}
		if (!closed) {
			if (o->cur) {
				void *pkt = iip_ops_pkt_alloc(opaque);
				assert(pkt);
				memcpy(iip_ops_pkt_get_data(pkt, opaque), o->txbuf, o->cur);
				iip_ops_pkt_set_len(pkt, o->cur, opaque);
				iip_tcp_send(mem, handle, pkt, 0, opaque);
				o->cur = 0;
			}
		}
	}
	td->o = NULL;
	iip_tcp_rxbuf_consumed(mem, handle, 1, opaque);
}

static void iip_ops_tcp_acked(void *mem,
			      void *handle,
			      void *m,
			      void *tcp_opaque,
			      void *opaque)
{
	(void) mem;
	(void) handle;
	(void) m;
	(void) tcp_opaque;
	(void) opaque;
}

static void iip_ops_tcp_closed(void *handle __attribute__((unused)),
			       uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			       uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			       void *tcp_opaque, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct app_data *ad = (struct app_data *) opaque_array[1];
	{
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		{
			uint16_t i;
			for (i = 0; i < td->tcp.conn_list_cnt; i++) {
				if (tcp_opaque == td->tcp.conn_list[i]) {
					{
						uint64_t head_idx = MPR_RING_HEAD_IDX(((struct tcp_opaque *) tcp_opaque)->mpr);
						while (head_idx != MPR_RING_TAIL_IDX(((struct tcp_opaque *) tcp_opaque)->mpr)) {
							iip_ops_pkt_free(((struct tcp_opaque *) tcp_opaque)->pbuf[head_idx], opaque);
							head_idx = (head_idx + 1 == MPR_RING_NUM_SLOT(((struct tcp_opaque *) tcp_opaque)->mpr) ? 0 : head_idx + 1);
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
	{ /* unused */
		(void) local_mac;
		(void) local_ip4_be;
		(void) local_port_be;
		(void) peer_mac;
		(void) peer_ip4_be;
		(void) peer_port_be;
	}
}

static void iip_ops_udp_payload(void *mem, void *m, void *opaque)
{
	(void) mem;
	(void) m;
	(void) opaque;
}

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

#define M2S(s) _M2S(s)
#define _M2S(s) #s
#include M2S(IOSUB_MAIN_C)
#undef _M2S
#undef M2S

int main(int argc, char *const *argv)
{
	return __iosub_main(argc, argv);
	{ /* unused */
		(void) helper_ip4_get_connection_affinity;
		(void) iip_arp_request;
		(void) iip_tcp_connect;
		(void) iip_udp_send;
	}
}
