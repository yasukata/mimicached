# mimicached: a memcached-compatible cache server

mimicached is a cache server that mimics the behavior of memcached.

mimicached achieves [high performance](#rough-performance-numbers) by leveraging a performance-optimized portable TCP/IP stack called [iip](https://github.com/yasukata/iip) and by using [a multi-core scalable hash table implementation](https://github.com/yasukata/mimicached/blob/master/kv.c). Along with this, [a version that uses the standard kernel TCP/IP stack](#mimicached-with-the-kernel-tcpip-stack) is also available.

**WARNING: The authors will not bear any responsibility if the implementations, provided by the authors, cause any problems.**

## usage

### build

Please first download the source code of mimicached and enter the ```mimicached``` directory.

```
git clone https://github.com/yasukata/mimicached.git
```

```
cd mimicached
```

In the ```mimicached``` directory, please download the source code of the iip TCP/IP stack, the DPDK-based I/O backend for iip ([netmap](https://github.com/yasukata/iip-netmap) and [AF_XDP](https://github.com/yasukata/iip-af_xdp) versions are also available), and memcached-protocol-parser.

```
git clone https://github.com/yasukata/iip.git
```

```
git clone https://github.com/yasukata/iip-dpdk.git
```

```
git clone https://github.com/yasukata/memcached-protocol-parser.git
```

Then, please type the following command to build mimicached. Note that the following command downloads the source code of DPDK and build and install it in ```mimicached/iip-dpdk/dpdk``` directory.

```
IOSUB_DIR=./iip-dpdk make
```

After the command abobe finishes, we will have a binary named ```a.out```.

### run

**WARNING: Several commands need the root permission (sudo). So, please conduct the following procedure only when you understand what you are doing.**

The following command launches the mimicached server; here, DPDK requests the kernel to create a tap device (virtual interface) named tap001, and iip uses an IP address 10.100.0.20 for tap001.

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --vdev=net_tap,iface=tap001 --no-pci -- -a 0,10.100.0.20
```

Once the mimicached server starts successfully, we will see output ```mimicached server has been started```.

If mimicached fails to start with an error message ```EAL: Cannot get hugepage information.```, please type the following command to setup huge pages which are necessary for DPDK.

```
sudo ./iip-dpdk/dpdk/dpdk-23.07/usertools/dpdk-hugepages.py -p 2M -r 2G
```

Once the mimicached server has correctly started, please open another console/terminal and type the following command to assign an IP address to the tap001 device. Note that we need to type the following command everytime when we newly launch the mimicached server process with a tap device; if we use a physical NIC rather than a tap device, we do not need this command.

```
sudo ifconfig tap001 10.100.0.10 netmask 255.255.255.0
```

Now, the setup has been completed.

To check the behavior of mimicached, please type the following command that sends a set request to the mimicached server; this set request asks the mimicached server to store a key-value pair whose key is "hello" and value is "world". Along with the key and value specifications, the set command below specifies 100 for the flags value and 0 for the expiration time, and 5 is the length of the value "world".

```
echo -e "set hello 100 0 5\r\nworld\r\nquit\r\n\0" | nc 10.100.0.20 11211
```

We will supposedly receive a response ```STORED``` that indicates a key-value pair, hello and world, has been stored.

Then, please type the following command to retrieve the key-value pair whose key is "hello".

```
echo -e "get hello\r\nquit\r\n\0" | nc 10.100.0.20 11211
```

We will have the following output that includes its key, flags, value length, and value.

```
VALUE hello 100 5
world
END
```

### command options

- ```-b```: launch mimicached with the [binary protocol](https://docs.memcached.org/protocols/binary/) mode; if this option is not specified, mimicached works with the [text protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt) mode.
- ```-m```: memory size (in mega bytes) allowed for storing key-value items.
- ```-p```: TCP port number that the mimicached server listens on.
- ```-v```: verbose level setting.
- ```-z```: the size of the hash table.

The following is an example command. The commands are splitted by ```--```; ```-n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --vdev=net_tap,iface=tap001 --no-pci``` is passed to DPDK, the third part ```-a 0,10.100.0.20``` is handled by iip, and ```-m 128 -p 11212 -z 1000``` is passed to mimicached.

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --vdev=net_tap,iface=tap001 --no-pci -- -a 0,10.100.0.20 -- -m 128 -p 11212 -z 1000
```

## mimicached with the kernel TCP/IP stack

While the build instruction above describes the setup using iip as its TCP/IP stack, we can also run mimicached with the kernel TCP/IP stack rather than iip.

The following shows how to build mimicached that uses the kernel TCP/IP stack.

First, please create a directory ```mimicached/kernel-netstack``` and enter it.

```
mkdir kernel-netstack
```

```
cd kernel-netstack
```

Then, please save the following C program as a file named ```main.c```.

<details>
<summary>please click here to show the program</summary>

```c
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <pthread.h>

#define mp_assert assert
#define mp_memcmp memcmp
#define mp_memcpy memcpy
#define mp_memmove memmove

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

#define MP_OPS_DEBUG_PRINTF __debug_printf

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

static uint64_t ____test_line = 0;
#define MP_TEST_HOOK() do { ____test_line = __LINE__; } while (0)

static uint64_t kv_conf_hash_table_cnt = 1;
#define ____KV__CONF_HASH_TABLE_CNT (kv_conf_hash_table_cnt)

#include "../memcached-protocol-parser/main.c"

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

#include "../kv.c"

#define SLAB_OPS_ATOMIC_ADD_FETCH __atomic_add_fetch
#define SLAB_OPS_ATOMIC_SUB_FETCH __atomic_sub_fetch

#define SLAB_FLAG_ATOMIC_RELAXED __ATOMIC_RELAXED
#define SLAB_FLAG_ATOMIC_ACQ_REL __ATOMIC_ACQ_REL
#define SLAB_FLAG_ATOMIC_RELEASE __ATOMIC_RELEASE
#define SLAB_FLAG_ATOMIC_ACQUIRE __ATOMIC_ACQUIRE

#include "../slab.c"

#define MAX_CORE (____KV__CONF_MAX_THREAD_NUM)

#define INPUT_RING_SIZE (1024)

struct mc_conn {
	int fd;
	int err;
	uint64_t cur;
	uint8_t txbuf[0x10000];
	uint8_t rxbuf[INPUT_RING_SIZE][2048];
	uint8_t mpr[1];
};

struct thread_data {
	struct kv_thread_data ktd;
	int core;
	uint8_t mpr[MPR_MEM_SIZE(INPUT_RING_SIZE)];
	pthread_t th;
	int fd;
	struct mc_conn *mc;
};

static void mp_ops_clear_response(void *opaque)
{
	struct thread_data *td = (struct thread_data *) opaque;
	struct mc_conn *conn = (struct mc_conn *) td->mc;
	conn->cur = 0;
}

static ssize_t mp_ops_push_response(void *opaque, const char *msg, size_t len)
{
	struct thread_data *td = (struct thread_data *) opaque;
	struct mc_conn *conn = (struct mc_conn *) td->mc;
	size_t l = 0;
	while (l != len) {
		size_t _l = len - l;
		if (sizeof(conn->txbuf) - conn->cur < _l)
			_l = sizeof(conn->txbuf) - conn->cur;
		memcpy(&conn->txbuf[conn->cur], &msg[l], _l);
		conn->cur += _l;
		l += _l;
		if (conn->cur == sizeof(conn->txbuf)) {
			ssize_t tx = send(conn->fd, conn->txbuf, conn->cur, MSG_NOSIGNAL);
			if (tx != (ssize_t) conn->cur) {
				conn->err = -EIO;
				return -1;
			}
			conn->cur = 0;
		}
	}
	return 0;
}

static char should_stop = 0;

static void sig_h(int s __attribute__((unused)))
{
	should_stop = 1;
	signal(SIGINT, SIG_DFL);
} 

static uint64_t mode_binary = 0;

static void *server_thread(void *data)
{
	struct thread_data *td = (struct thread_data *) data;
	{
		cpu_set_t c;
		CPU_ZERO(&c);
		CPU_SET(td->core, &c);
		pthread_setaffinity_np(pthread_self(), sizeof(c), &c);
	}
	{
		int epfd;
		assert((epfd = epoll_create1(EPOLL_CLOEXEC)) != -1);
		{
			struct epoll_event ev;
			memset(&ev, 0, sizeof(ev));
			ev.events = EPOLLIN;
			ev.data.ptr = 0;
			{
				int err = epoll_ctl(epfd, EPOLL_CTL_ADD, td->fd, &ev);
				assert(!err);
			}
		}
		while (!should_stop) {
			struct epoll_event ev[64];
			int nfd = epoll_wait(epfd, ev, 64, 100), i;
			for (i = 0; i < nfd; i++) {
				if (ev[i].data.ptr == 0) {
					struct sockaddr_in sin;
					socklen_t addrlen = 0;
					memset(&sin, 0, sizeof(sin));
					int fd = accept(td->fd, (struct sockaddr *) &sin, &addrlen);
					if (fd == -1) {
						if (errno != EAGAIN) {
							perror("accept");
							exit(0);
						}
						assert(errno == EAGAIN);
						continue;
					}
					{
						struct epoll_event _ev;
						memset(&_ev, 0, sizeof(_ev));
						_ev.events = EPOLLIN;
						_ev.data.ptr = calloc(1, sizeof(struct mc_conn) + MPR_MEM_SIZE(INPUT_RING_SIZE));
						assert(_ev.data.ptr);
						{
							struct mc_conn *mc = (struct mc_conn *) _ev.data.ptr;
							{
								MPR_MODE_BINARY(mc->mpr)   = mode_binary;
								MPR_RING_NUM_SLOT(mc->mpr) = INPUT_RING_SIZE;
								MPR_RING_HEAD_IDX(mc->mpr) = 0;
								MPR_RING_HEAD_OFF(mc->mpr) = 0;
								MPR_RING_TAIL_IDX(mc->mpr) = 0;
								MPR_RING_TAIL_OFF(mc->mpr) = 0;
								{
									int i;
									for (i = 0; i < INPUT_RING_SIZE; i++)
										MPR_SLOT_PTR(mc->mpr, i) = (uint64_t) mc->rxbuf[i];
								}
							}
							mc->fd = fd;
						}
						{
							int err = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &_ev);
							assert(!err);
						}
					}
				} else {
					struct mc_conn *mc = (struct mc_conn *) ev[i].data.ptr;
					if (MPR_RING_HEAD_IDX(mc->mpr) == (MPR_RING_TAIL_IDX(mc->mpr) + 1 == MPR_RING_NUM_SLOT(mc->mpr) ? 0 : MPR_RING_TAIL_IDX(mc->mpr) + 1)) {
						printf("ring is full, close connection\n");
						close(mc->fd);
						free(mc);
					} else {
						ssize_t rx = read(mc->fd, (char *) mc->rxbuf[MPR_RING_TAIL_IDX(mc->mpr)], sizeof(mc->rxbuf[MPR_RING_TAIL_IDX(mc->mpr)]));
						if (rx <= 0) {
							close(mc->fd);
							free(mc);
						} else {
							MPR_SLOT_LEN(mc->mpr, MPR_RING_TAIL_IDX(mc->mpr)) += rx;
							MPR_RING_TAIL_OFF(mc->mpr) = MPR_SLOT_LEN(mc->mpr, MPR_RING_TAIL_IDX(mc->mpr));
							MPR_RING_TAIL_IDX(mc->mpr)++;
							if (MPR_RING_TAIL_IDX(mc->mpr) == MPR_RING_NUM_SLOT(mc->mpr))
								MPR_RING_TAIL_IDX(mc->mpr) = 0;
							MPR_RING_TAIL_OFF(mc->mpr) = 0;
							MPR_SLOT_LEN(mc->mpr, MPR_RING_TAIL_IDX(mc->mpr)) = 0;
							td->mc = mc;
							mc->err = 0;
							while (!(MPR_RING_HEAD_IDX(mc->mpr) == MPR_RING_TAIL_IDX(mc->mpr)
										&& MPR_RING_HEAD_OFF(mc->mpr) == MPR_RING_TAIL_OFF(mc->mpr))) {
								uint64_t head_idx = MPR_RING_HEAD_IDX(mc->mpr), head_off = MPR_RING_HEAD_OFF(mc->mpr);
								{
									long r;
									{
										kv_thread_access_start((void *) td);
										r = parse_memcached_request(mc->mpr, (void *) td);
										kv_thread_access_done((void *) td);
									}
									if (mc->cur) {
										ssize_t tx = send(mc->fd, mc->txbuf, mc->cur, MSG_NOSIGNAL);
										if (tx != (ssize_t) mc->cur) {
											close(mc->fd);
											free(mc);
											break;
										}
										mc->cur = 0;
									}
									if ((r < 0) || mc->err) {
										close(mc->fd);
										free(mc);
										break;
									}
									if (r == EAGAIN)
										break;
								}
								if (head_idx == MPR_RING_HEAD_IDX(mc->mpr) && head_off == MPR_RING_HEAD_OFF(mc->mpr))
									break;
							}
							td->mc = NULL;
						}
					}
				}
			}
			kv_garbage_collection((void *) td);
		}
		close(epfd);
	}
	pthread_exit(NULL);
}

int main(int argc, char *const *argv)
{
	unsigned short port = 11211, num_cores = 1, core_list[MAX_CORE];
	slab_init();
	slab_stat.mem_size = 2 * 1048576;
	{
		int ch;
		while ((ch = getopt(argc, argv, "bhm:o:Uc:p:v:z:")) != -1) {
			switch (ch) {
			case 'b':
				mode_binary = 0x80;
				break;
			case 'h':
				exit(0);
				break;
			case 'm':
				slab_stat.mem_size = atol(optarg) * 1048576;
				break;
			case 'o':
				break;
			case 'U':
				break;
			case 'c':
				{
					ssize_t num_comma = 0, num_hyphen = 0;
					{
						size_t i;
						for (i = 0; i < strlen(optarg); i++) {
							switch (optarg[i]) {
							case ',':
								num_comma++;
								break;
							case '-':
								num_hyphen++;
								break;
							}
						}
					}
					if (num_hyphen) {
						assert(num_hyphen == 1);
						assert(!num_comma);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i;
								for (i = 0; i < strlen(optarg); i++) {
									if (m[i] == '-') {
										m[i] = '\0';
										break;
									}
								}
								assert(i != strlen(optarg) - 1 && i != strlen(optarg));
								{
									uint16_t from = atoi(&m[0]), to = atoi(&m[i + 1]);
									assert(from <= to);
									{
										uint16_t j, k;
										for (j = 0, k = from; k <= to; j++, k++)
											core_list[j] = k;
										num_cores = j;
									}
								}
							}
							free(m);
						}
					} else if (num_comma) {
						assert(num_comma + 1 < MAX_CORE);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i, j, k;
								for (i = 0, j = 0, k = 0; i < strlen(optarg) + 1; i++) {
									if (i == strlen(optarg) || m[i] == ',') {
										m[i] = '\0';
										if (j != i)
											core_list[k++] = atoi(&m[j]);
										j = i + 1;
									}
									if (i == strlen(optarg))
										break;
								}
								assert(k);
								num_cores = k;
							}
							free(m);
						}
					} else {
						core_list[0] = atoi(optarg);
						num_cores = 1;
					}
				}
				break;

			case 'p':
				port = atoi(optarg);
				break;
			case 'v':
				verbose_level = atoi(optarg);
				break;
			case 'z':
				kv_conf_hash_table_cnt = atoi(optarg);
				break;
			default:
				assert(0);
				break;
			}
		}
	}
	kv_init();
	{
		int fd;
		assert((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != -1);
		{
			int v = 1;
			assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)));
		}
		{
			int v = 1;
			assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)));
		}
		{
			int v = 1;
			assert(!setsockopt(fd, SOL_TCP, TCP_NODELAY, &v, sizeof(v)));
		}
		{
			int v = 1;
			assert(!ioctl(fd, FIONBIO, &v));
		}
		{
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = htonl(INADDR_ANY);
			sin.sin_port = htons(port);
			assert(!bind(fd, (struct sockaddr *) &sin, sizeof(sin)));
		}
		assert(!listen(fd, SOMAXCONN));
		signal(SIGINT, sig_h);
		{
			struct thread_data *td = (struct thread_data *) calloc(num_cores, sizeof(struct thread_data));
			assert(td);
			{
				unsigned short i;
				for (i = 0; i < num_cores; i++) {
					assert(!kv_register_ktd(&td->ktd, i));
					td[i].fd = fd;
					td[i].core = core_list[i];
					{
						int err = pthread_create(&td[i].th, NULL, server_thread, &td[i]);
						assert(!err);
					}
				}
			}
			{
				int debug_fd;
				assert((debug_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != -1);
				{
					int v = 1;
					assert(!setsockopt(debug_fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)));
				}
				{
					int v = 1;
					assert(!setsockopt(debug_fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)));
				}
				{
					struct sockaddr_in debug_sin;
					memset(&debug_sin, 0, sizeof(debug_sin));
					debug_sin.sin_family = AF_INET;
					debug_sin.sin_addr.s_addr = htonl(INADDR_ANY);
					debug_sin.sin_port = htons(10000);
					assert(!bind(debug_fd, (struct sockaddr *) &debug_sin, sizeof(debug_sin)));
				}
				assert(!listen(debug_fd, SOMAXCONN));
				while (!should_stop) {
					struct pollfd pfd[1];
					pfd[0].fd = debug_fd;
					pfd[0].events = POLLIN;
					pfd[0].revents = 0;
					{
						int r = poll(pfd, 1, 100);
						if (r < 0)
							break;
						else if (r > 0) {
							struct sockaddr_in _sin;
							socklen_t addrlen = 0;
							memset(&_sin, 0, sizeof(_sin));
							{
								int nfd = accept(debug_fd, (struct sockaddr *) &_sin, &addrlen);
								assert(nfd != -1);
								{
									char buf[23];
									memset(buf, 0, sizeof(buf));
									snprintf(buf, sizeof(buf), "%lu", ____test_line);
									{
										ssize_t l = strlen(buf);
										assert(write(nfd, buf, l) == l);
									}
								}
								usleep(500);
								close(nfd);
							}
						}
					}
				}
				close(debug_fd);
			}
			{
				unsigned short i;
				for (i = 0; i < num_cores; i++) {
					int err = pthread_join(td[i].th, NULL);
					assert(!err);
				}
			}
			free(td);
		}
		close(fd);
	}
	return 0;
}
```

</details>

Afterwrad, please type the following command to compile ```main.c```; we will have an executable binary named ```a.out```.

```
gcc -O3 -pipe -g -rdynamic -Werror -Wextra -Wall -D_GNU_SOURCE ./main.c -lpthread
```

We can start the program by the following command.

```
./a.out
```

We can try the set command storing a key-value pair whose key is "hello" and value is "world" that is basically similar to the build instruction above. The difference is that we are trying to connect to localhost (rather than 10.100.0.20) by the nc command because mimicached runs on the kernel TCP/IP stack this time.

```
echo -e "set hello 100 0 5\r\nworld\r\nquit\r\n\0" | nc localhost 11211
```

```
echo -e "get hello\r\nquit\r\n\0" | nc localhost 11211
```

The command options are as follows. They essentially the same as the version using iip, but ```-c``` option is specific to this version.

- ```-b```: activate the binary protocol mode; if this option is not specified, it works with the text protocol mode.
- ```-c```: the CPU cores to be used; the number of concurrent threads is the same as the number of CPU cores specified with this option, so if you wish to use multiple threads, please specify multiple CPU cores using this option. (```-c 1```: use CPU core 1, ```-c 1,3```: use CPU core 1 and 3, ```-c 0-3```: use CPU core 0,1,2,3)
- ```-m```: memory size (in mega bytes) allowed for mimicached to store key-value items.
- ```-p```: TCP port number the mimicached server listens on.
- ```-z```: the size of the hash table.

## error handling test for the memcached protocol parser

The following bash script perfoms error handling tests for the memcached protocol parser by comparing the output of mimicached and the original memcached implementation; it proceeds with the following steps.
- it launches the original memcached server listening on port 11211
- it launches the mimicached server listening on port 11212
- it extracts test queries embedded in the [memcached protocol parser implementation](https://github.com/yasukata/memcached-protocol-parser/blob/master/main.c)
- it sends a test query to both mimicached and memcached, and compare the obtained responses; a test is passed if the responses are the exactly the same, otherwise, it fails.

This test requires the originam memcached implementation to obtain the referense output.

This test leverages mimicached that uses the kernel TCP/IP stack shown [above](#mimicached-with-the-kernel-tcpip-stack); if you have not compiled the verion using the kernel TCP/IP stack yet, please compile it.

This test assumes to be executed in ```mimicached/kernel-netstack```, so, please enter it first.

In the ```kernel-netstack``` directory, please save the following bash script as a file named ```error-test.sh```; **WARNING: error-test.sh executes ```pkill``` to stop currently running memcached processes, therefore, please never run error-test.sh on a computer that runs a memcached server for operating services.**

<details>
<summary>please click here to show the program</summary>

```bash
#!/bin/bash

MEMCACHED_PATH=
MEMCACHED_OPT=

while getopts "m:o:" OPT
do
	case $OPT in
		m) MEMCACHED_PATH=$OPTARG ;;
		o) MEMCACHED_OPT=$OPTARG ;;
	esac
done

if [ "${MEMCACHED_PATH}x" = "x" ]; then
	echo "please specify path to memcached with -m"
	exit
fi

echo "start testing binary query"

echo "pkill memcached"
pkill memcached
echo "pkill a.out"
pkill a.out
echo "launch memcached with binary protocol mode"
$MEMCACHED_PATH --protocol=binary $MEMCACHED_OPT &
echo "launch a.out"
./a.out -p 11212 -b &
echo "sleep 1 second to wait for the setup of the servers"
sleep 1
echo ""

test_binary_request() {
	echo "TEST: $1"
	_a=`echo -e $2 | nc localhost 11211 | xxd`
	_b=`echo -e $2 | nc localhost 11212 | xxd`
	_l=`echo a | nc localhost 10000`
	if [ "${4}x" = "x" ]; then
		if [ "${_l}x" != "${3}x" ]; then
			echo -e "\e[36mEXPECTED LINE: $3\e[0m"
			echo -e "\e[36mPASSED   LINE: $_l\e[0m"
			pkill memcached
			pkill a.out
			exit 1
		fi
	else
		echo -e "\e[36mNO LINE CHECK\e[0m"
	fi
	if [ "${_a}x" != "${_b}x" ]; then
		echo "RESULT: NOT OK (${#_a} bytes, ${#_b} bytes)"
		echo -e "\e[33m-- result 1 --\e[0m"
		echo -e "\e[33m$_a\e[0m"
		echo -e "\e[35m-- result 2 --\e[0m"
		echo -e "\e[35m$_b\e[0m"
		pkill memcached
		pkill a.out
		exit 1
	else
		echo "RESULT: OK (${#_a} bytes)"
		echo ""
	fi
}

RUN_TEST=$(cat -n ../memcached-protocol-parser/main.c|grep -e TEST_BINARY_QUERY_ERROR_RESPONSE -e MP_TEST_HOOK|awk '{ if (match($2, "MP_TEST_HOOK()")) { print "TESTID=\"" $1 "\"" } else { print $0 } }'|sed -e 's/^[[:space:]]*[0-9]\+[[:space:]]*//' -e 's/\* TEST_BINARY_QUERY_ERROR_RESPONSE: //' -e 's/\*\///' -e 's/^\t*//')
eval "${RUN_TEST}"

echo "binary query testing has been done, start testing text query"

echo "pkill memcached"
pkill memcached
echo "pkill a.out"
pkill a.out
echo "sleep 1 second to wait for the shutdown of the servers"
sleep 1
echo "launch memcached with text protocol mode"
$MEMCACHED_PATH $MEMCACHED_OPT &
echo "launch a.out"
./a.out -p 11212 &
echo "sleep 1 second to wait for the setup of the servers"
sleep 1
echo ""

test_text_request() {
	echo "TEST: $1"
	_a=`echo -e $2 | nc localhost 11211`
	_b=`echo -e $2 | nc localhost 11212`
	_l=`echo a | nc localhost 10000`
	if [ "${4}x" = "x" ]; then
		if [ "${_l}x" != "${3}x" ]; then
			echo -e "\e[36mEXPECTED LINE: $3\e[0m"
			echo -e "\e[36mPASSED   LINE: $_l\e[0m"
			pkill memcached
			pkill a.out
			exit 1
		fi
	else
		echo -e "\e[36mNO LINE CHECK\e[0m"
	fi
	if [ "${_a}x" != "${_b}x" ]; then
		echo "RESULT: NOT OK (${#_a} bytes, ${#_b} bytes)"
		echo -e "\e[33m-- result 1 --\e[0m"
		echo -e "\e[33m$_a\e[0m"
		echo -e "\e[35m-- result 2 --\e[0m"
		echo -e "\e[35m$_b\e[0m"
		pkill memcached
		pkill a.out
		exit 1
	else
		echo "RESULT: OK (${#_a} bytes)"
		echo ""
	fi
}

RUN_TEST=$(cat -n ../memcached-protocol-parser/main.c|grep -e TEST_TEXT_QUERY_ERROR_RESPONSE -e MP_TEST_HOOK|awk '{ if (match($2, "MP_TEST_HOOK()")) { print "TESTID=\"" $1 "\"" } else { print $0 } }'|sed -e 's/^[[:space:]]*[0-9]\+[[:space:]]*//' -e 's/\* TEST_TEXT_QUERY_ERROR_RESPONSE: //' -e 's/\*\///' -e 's/^\t*//')

eval "${RUN_TEST}"

pkill memcached
pkill a.out
```

</details>

Afterward, please type the following command to make it executable.

```
chmod +x error-test.sh
```

The following command runs the test. ```-m``` option is to specify the path to the original memcached implementation.

```
./error-test.sh -m PATH_TO_ORIGINAL_MEMCACHED
```

Note that this implementation has been tested with memcached version 1.6.38.

## network benchmark client


While the performance of mimicached can be measured by using other existing memcached benchmark tools, it is often hard for them to achieve sufficiently high request rates mainly because of the performance of the underlying TCP/IP stack.

Therefore, this section provides a benchmark client that runs on top of iip and can send memcached requests with uniformly random or approximated zipfian distributions with varied key and value sizes and different set and get ratios.

To build the benchark client, please create a directory ```mimicached/network-benchmark``` and enter it.

```
mkdir network-benchmark
```

```
cd network-benchmark
```

Then, please download a benchmark program that only implements simple workloads by the following command.

```
git clone https://github.com/yasukata/bench-iip.git
```

The following programs extend the downloaded bench-iip program to send randomized memcached requests.

In ```mimicached/network-benchmark```, please save the following program as a file named ```iip_main.c```.

<details>
<summary>please click here to show the program</summary>

```c
#include "../iip/main.c"
#define iip_ops_tcp_connected	    		    __o_iip_ops_tcp_connected
#define iip_ops_tcp_payload	    		    __o_iip_ops_tcp_payload
#define iip_ops_tcp_closed	    		    __o_iip_ops_tcp_closed
```

</details>

In ```mimicached/network-benchmark```, please save the following program as a file named ```main.c```.

<details>
<summary>please click here to show the program</summary>

```c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <math.h>

#define __app_init __o__app_init
#define __app_loop __o__app_loop

#pragma push_macro("IOSUB_MAIN_C")
#undef IOSUB_MAIN_C
#define IOSUB_MAIN_C pthread.h

static int __iosub_main(int argc, char *const *argv);

#define IIP_MAIN_C "./iip_main.c"

#include "bench-iip/main.c"

#undef IOSUB_MAIN_C
#pragma pop_macro("IOSUB_MAIN_C")

#undef __app_loop
#undef __app_init

#undef iip_ops_tcp_connected
#undef iip_ops_tcp_payload
#undef iip_ops_tcp_closed

#define ANTICIPATED_PKT_BUF_LEN (1280U)

struct mc_conn {
	uint64_t req_type;
	uint64_t len;
	char rxbuf[(1UL<<21)];
};

struct mc_td {
	char key_base[256];
	uint32_t key_len;
	uint32_t val_len;
	uint32_t write_ratio;
	uint64_t num_pairs;
	uint64_t random;
	uint64_t set_req_len;
	uint64_t get_req_len;
	char *set_req_base;
	char *get_req_base;
	uint64_t mc_dbg_prev_print;
	uint8_t dist_zipfian;
	uint8_t load_first;
	struct {
		double alpha;
		double zetan;
		double eta;
		double theta;
	} zipfian;
	struct {
		struct {
			uint64_t success;
			uint64_t failed;
			uint64_t error;
		} op[2];
	} mcnt[2];
	struct mc_conn *mcn[0xffff /* port */]; /* XXX: assuming a single client */
};

static char _dist_zipfian;
static double zipf_alpha, zipf_zetan, zipf_eta, zipf_theta;
static uint64_t _num_pairs;
static uint32_t _key_len, _val_len, _write_ratio;
static _Atomic uint8_t mc_cnt_idx;
static _Atomic uint64_t load_req_id;
static uint8_t _load_first;
static struct mc_td *mtds[MAX_THREAD];
static pthread_spinlock_t mtds_lock;

static void *iip_ops_tcp_connected(void *mem, void *handle, void *m, void *opaque)
{
	void *ret = __o_iip_ops_tcp_connected(mem, handle, m, opaque);
	assert(ret);
	{
		void **opaque_array = (void **) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		if (td->tcp.conn_list_cnt == 1) {
			struct mc_td *mtd = (struct mc_td *) mem_alloc_local(sizeof(struct mc_td));
			mtd->key_len = _key_len;
			mtd->val_len = _val_len;
			mtd->write_ratio = _write_ratio;
			mtd->num_pairs = _num_pairs;
			mtd->dist_zipfian = _dist_zipfian;
			mtd->load_first = _load_first;
			{
				char _set[2048], set[4096];
				snprintf(_set, sizeof(_set), "set %%0%dx 0 0 %u\r\n", mtd->key_len, mtd->val_len);
				snprintf(set, sizeof(set), _set, 0, mtd->val_len);
				mtd->set_req_len = strlen(set);
				mtd->set_req_base = (char *) mem_alloc_local(mtd->set_req_len);
				memcpy(mtd->set_req_base, set, mtd->set_req_len);
			}
			{
				char _get[2048], get[4096];
				snprintf(_get, sizeof(_get), "get %%0%dx\r\n", mtd->key_len);
				snprintf(get, sizeof(get), _get, 0);
				mtd->get_req_len = strlen(get);
				mtd->get_req_base = (char *) mem_alloc_local(mtd->get_req_len);
				memcpy(mtd->get_req_base, get, mtd->get_req_len);
			}
			snprintf(mtd->key_base, sizeof(mtd->key_base), "%%0%dx", mtd->key_len);
			mtd->zipfian.alpha = zipf_alpha;
			mtd->zipfian.zetan = zipf_zetan;
			mtd->zipfian.eta   = zipf_eta;
			mtd->zipfian.theta = zipf_theta;
			mtd->random = 88172645463325252UL * (td->core_id + 1);
			td->prev_arp = (uintptr_t) mtd; /* XXX: reuse variable field for random number generator */
			mtds[td->core_id] = mtd;
		}
		{
			struct mc_td *mtd = (struct mc_td *) td->prev_arp;
			{
				uint16_t port = ntohs(PB_TCP(m)->dst_be);
				mtd->mcn[port] = mem_alloc_local(sizeof(struct mc_conn));
				assert(mtd->mcn[port]);
				mtd->mcn[port]->req_type = 0;
			}
		}
	}
	return ret;
}

static void iip_ops_tcp_closed(void *handle,
			       uint8_t local_mac[], uint32_t local_ip4_be, uint16_t local_port_be,
			       uint8_t peer_mac[], uint32_t peer_ip4_be, uint16_t peer_port_be,
			       void *tcp_opaque, void *opaque)
{
	__o_iip_ops_tcp_closed(handle, local_mac, local_ip4_be, local_port_be, peer_mac, peer_ip4_be, peer_port_be, tcp_opaque, opaque);
	{
		void **opaque_array = (void **) opaque;
		struct thread_data *td = (struct thread_data *) opaque_array[2];
		pthread_spin_lock(&mtds_lock);
		mtds[td->core_id] = NULL;
		pthread_spin_unlock(&mtds_lock);
		{
			struct mc_td *mtd = (struct mc_td *) td->prev_arp;
			{
				uint16_t port = ntohs(local_port_be);
				mem_free(mtd->mcn[port], sizeof(struct mc_conn));
				mtd->mcn[port] = NULL;
			}
		}
		if (td->tcp.conn_list_cnt == 0) {
			struct mc_td *mtd = (struct mc_td *) td->prev_arp;
			mem_free(mtd->set_req_base, mtd->set_req_len);
			mem_free(mtd->get_req_base, mtd->get_req_len);
			mem_free(mtd, sizeof(struct mc_td));
			td->prev_arp = 0; /* XXX: reuse variable field for random number generator */
		}
	}
}

#define RANDOM_XORSHIFT64(__r) \
	do { \
		(__r) ^= (__r) << 13; \
		(__r) ^= (__r) >> 7; \
		(__r) ^= (__r) << 17; \
	} while (0)

static void send_set_request(uint64_t req_id, void *mem, void *handle, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	struct mc_td *mtd = (struct mc_td *) td->prev_arp;
	{
		void *p = NULL;
		uint16_t tmp_len = 0;
		{
			uint64_t l = 0;
			while (l < mtd->set_req_len) {
				assert(!p);
				assert(!tmp_len);
				p = iip_ops_pkt_alloc(opaque);
				assert(p);
				{
					uint64_t _l = mtd->set_req_len - l;
					if (_l > ANTICIPATED_PKT_BUF_LEN)
						_l = ANTICIPATED_PKT_BUF_LEN;
					memcpy(iip_ops_pkt_get_data(p, opaque), &mtd->set_req_base[l], _l);
					if (!l) {
						char key[250];
						assert(_l > 4 + mtd->key_len); /* XXX: lazy check */
						snprintf(key, sizeof(key), mtd->key_base, req_id);
						memcpy(iip_ops_pkt_get_data(p, opaque) + 4, key, mtd->key_len);
					}
					if (_l == ANTICIPATED_PKT_BUF_LEN) {
						iip_ops_pkt_set_len(p, ANTICIPATED_PKT_BUF_LEN, opaque);
						iip_tcp_send(mem, handle, p, 0, opaque);
						td->monitor.counter[td->monitor.idx].tx_bytes += _l;
						td->monitor.counter[td->monitor.idx].tx_pkt += 1;
						p = NULL;
						tmp_len = 0;
					} else
						tmp_len += _l;
					l += _l;
				}
			}
		}
		{
			uint64_t l = 0;
			while (l < mtd->val_len) {
				if (!p)
					p = iip_ops_pkt_alloc(opaque);
				assert(p);
				{
					uint64_t _l = mtd->val_len - l;
					if (_l > ANTICIPATED_PKT_BUF_LEN - tmp_len)
						_l = ANTICIPATED_PKT_BUF_LEN - tmp_len;
					memset((char *) iip_ops_pkt_get_data(p, opaque) + tmp_len, 'A', _l);
					if (_l == ANTICIPATED_PKT_BUF_LEN - tmp_len) {
						iip_ops_pkt_set_len(p, ANTICIPATED_PKT_BUF_LEN, opaque);
						iip_tcp_send(mem, handle, p, 0, opaque);
						td->monitor.counter[td->monitor.idx].tx_bytes += _l;
						td->monitor.counter[td->monitor.idx].tx_pkt += 1;
						p = NULL;
						tmp_len = 0;
					} else
						tmp_len += _l;
					l += _l;
				}
			}
		}
		{
			uint64_t l = 0;
			char edge[2];
			edge[0] = '\r';
			edge[1] = '\n';
			while (l < 2) {
				if (!p)
					p = iip_ops_pkt_alloc(opaque);
				assert(p);
				{
					uint64_t _l = 2 - l;
					if (_l > ANTICIPATED_PKT_BUF_LEN - tmp_len)
						_l = ANTICIPATED_PKT_BUF_LEN - tmp_len;
					memcpy((char *) iip_ops_pkt_get_data(p, opaque) + tmp_len, &edge[l], _l);
					if (_l == ANTICIPATED_PKT_BUF_LEN - tmp_len) {
						iip_ops_pkt_set_len(p, ANTICIPATED_PKT_BUF_LEN, opaque);
						iip_tcp_send(mem, handle, p, 0, opaque);
						td->monitor.counter[td->monitor.idx].tx_bytes += _l;
						td->monitor.counter[td->monitor.idx].tx_pkt += 1;
						p = NULL;
						tmp_len = 0;
					} else
						tmp_len += _l;
					l += _l;
				}
			}
		}
		if (p) {
			assert(tmp_len);
			iip_ops_pkt_set_len(p, tmp_len, opaque);
			iip_tcp_send(mem, handle, p, 0x08U, opaque);
			td->monitor.counter[td->monitor.idx].tx_bytes += tmp_len;
			td->monitor.counter[td->monitor.idx].tx_pkt += 1;
		}
	}
}

static void iip_ops_tcp_payload(void *mem, void *handle, void *m,
				void *tcp_opaque, uint16_t head_off, uint16_t tail_off,
				void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	struct mc_td *mtd = (struct mc_td *) td->prev_arp;
	uint16_t port = ntohs(PB_TCP(m)->dst_be);
	uint8_t send_next = 0;
	assert(sizeof(mtd->mcn[port]->rxbuf[mtd->mcn[port]->len] - mtd->mcn[port]->len > PB_TCP_PAYLOAD_LEN(m) - head_off - tail_off));
	memcpy(&mtd->mcn[port]->rxbuf[mtd->mcn[port]->len], PB_TCP_PAYLOAD(m) + head_off, PB_TCP_PAYLOAD_LEN(m) - head_off - tail_off);
	mtd->mcn[port]->len += PB_TCP_PAYLOAD_LEN(m) - head_off - tail_off;
	mtd->mcn[port]->rxbuf[mtd->mcn[port]->len] = '\0';
	td->monitor.counter[td->monitor.idx].rx_bytes += PB_TCP_PAYLOAD_LEN(m) - head_off - tail_off;
	td->monitor.counter[td->monitor.idx].rx_pkt += 1;
	{
		uint64_t now = BENCH_IIP_NOW(opaque);
		td->monitor.latency.val[td->monitor.latency.cnt++ % NUM_MONITOR_LATENCY_RECORD] = now - ((struct tcp_opaque *) tcp_opaque)->monitor.ts;
		((struct tcp_opaque *) tcp_opaque)->monitor.ts = now;
	}
	while (mtd->mcn[port]->len) {
		char found_error = 0;
		if (mtd->mcn[port]->req_type == 2) {
			if (mtd->mcn[port]->len >= 7 && mtd->mcn[port]->rxbuf[0] == 'E') {
				if (!memcmp(mtd->mcn[port]->rxbuf, "ERROR\r\n", 7)) {
					memmove(mtd->mcn[port]->rxbuf, &mtd->mcn[port]->rxbuf[7], mtd->mcn[port]->len - 7);
					mtd->mcn[port]->len -= 7;
					send_next = 1;
					{
						uint8_t cid = mc_cnt_idx;
						mtd->mcnt[cid].op[1].error++;
					}
					continue;
				} else
					found_error = 1;
			} else if (mtd->mcn[port]->len >= 8 && mtd->mcn[port]->rxbuf[0] == 'S') {
				if (!memcmp(mtd->mcn[port]->rxbuf, "STORED\r\n", 8)) {
					memmove(mtd->mcn[port]->rxbuf, &mtd->mcn[port]->rxbuf[8], mtd->mcn[port]->len - 8);
					mtd->mcn[port]->len -= 8;
					send_next = 1;
					{
						uint8_t cid = mc_cnt_idx;
						mtd->mcnt[cid].op[1].success++;
					}
					continue;
				} else
					found_error = 1;
			} else
				break;
		} else if (mtd->mcn[port]->req_type == 1) {
			if (mtd->mcn[port]->len >= 7 && mtd->mcn[port]->rxbuf[0] == 'E') {
				if (!memcmp(mtd->mcn[port]->rxbuf, "ERROR\r\n", 7)) {
					memmove(mtd->mcn[port]->rxbuf, &mtd->mcn[port]->rxbuf[7], mtd->mcn[port]->len - 7);
					mtd->mcn[port]->len -= 7;
					send_next = 1;
					{
						uint8_t cid = mc_cnt_idx;
						mtd->mcnt[cid].op[0].error++;
					}
					continue;
				} else
					found_error = 1;
			} else if (mtd->mcn[port]->len >= 5 && mtd->mcn[port]->rxbuf[0] == 'E') {
				if (!memcmp(mtd->mcn[port]->rxbuf, "END\r\n", 5)) {
					memmove(mtd->mcn[port]->rxbuf, &mtd->mcn[port]->rxbuf[5], mtd->mcn[port]->len - 5);
					mtd->mcn[port]->len -= 5;
					send_next = 1;
					{
						uint8_t cid = mc_cnt_idx;
						mtd->mcnt[cid].op[0].failed++;
					}
					continue;
				} else
					found_error = 1;
			} else if (mtd->mcn[port]->len >= 6 && mtd->mcn[port]->rxbuf[0] == 'V') {
				if (!memcmp(mtd->mcn[port]->rxbuf, "VALUE ", 6)) {
					uint64_t j;
					int64_t word_cnt = 0, prev_space = 0, prev_r = 0, word_begin = 0;
					for (j = 0; j < mtd->mcn[port]->len && !found_error; j++) {
						switch (mtd->mcn[port]->rxbuf[j]) {
						case ' ':
							if (!prev_space)
								word_cnt++;
							prev_space = 1;
							prev_r = 0;
							break;
						case '\r':
							prev_space = 0;
							prev_r = 1;
							break;
						case '\n':
							if (prev_r) {
								if (word_cnt == 3) {
									uint64_t val_len;
									mtd->mcn[port]->rxbuf[j-1] = '\0';
									val_len = atol(&mtd->mcn[port]->rxbuf[word_begin]);
									mtd->mcn[port]->rxbuf[j-1] = '\r';
									if (mtd->mcn[port]->len >= j + 1 + val_len + 2 + 5) {
										if (!memcmp(&mtd->mcn[port]->rxbuf[j + 1 + val_len + 2], "END\r\n", 5)) {
											memmove(mtd->mcn[port]->rxbuf, &mtd->mcn[port]->rxbuf[j + 1 + val_len + 2 + 5], mtd->mcn[port]->len - (j + 1 + val_len + 2 + 5));
											mtd->mcn[port]->len -= j + 1 + val_len + 2 + 5;
											{
												uint8_t cid = mc_cnt_idx;
												mtd->mcnt[cid].op[0].success++;
											}
											send_next = 1;
											continue;
										} else
											found_error = 1;
									}
								} else
									found_error = 1;
								break;
							}
							prev_space = 0;
							prev_r = 0;
							break;
						default:
							if (prev_space)
								word_begin = j;
							prev_space = 0;
							prev_r = 0;
							break;
						}
					}
				} else
					found_error = 1;
			} else
				found_error = 1;
		} else {
			mtd->mcn[port]->len = 0;
			send_next = 1;
		}
		if (found_error)
			break;
	}
	if (send_next) {
		char first_loading = 0;
		if (mtd->load_first) {
			uint64_t req_id = load_req_id++;
			if (req_id < mtd->num_pairs) {
				mtd->mcn[port]->req_type = 2;
				send_set_request(req_id, mem, handle, opaque);
				first_loading = 1;
			} else {
				if (req_id == mtd->num_pairs)
					printf("%lu items has been loaded\n", mtd->num_pairs);
				mtd->load_first = 0;
			}
		}
		if (!first_loading && !mtd->load_first) {
			uint64_t req_id;
			RANDOM_XORSHIFT64(mtd->random);
			if (mtd->dist_zipfian) {
				double u, uz;
				u = (((double) mtd->random) / UINT64_MAX);
				uz = u * mtd->zipfian.zetan;
				if (uz < 1)
					req_id = 0; /* base */
				else if (uz < 1 + pow(0.5, mtd->zipfian.theta))
					req_id = 0 /* base */ + 1;
				else
					req_id = 0 /* base */ + (long)(mtd->num_pairs * pow(mtd->zipfian.eta * u - mtd->zipfian.eta + 1, mtd->zipfian.alpha));
			} else
				req_id = mtd->random % mtd->num_pairs;
			RANDOM_XORSHIFT64(mtd->random);
			if ((mtd->random % 100) < mtd->write_ratio) {
				mtd->mcn[port]->req_type = 2;
				send_set_request(req_id, mem, handle, opaque);
			} else {
				mtd->mcn[port]->req_type = 1;
				{
					uint64_t l = 0;
					while (l < mtd->get_req_len) {
						void *p = iip_ops_pkt_alloc(opaque);
						assert(p);
						{
							uint64_t _l = mtd->get_req_len;
							if (_l > ANTICIPATED_PKT_BUF_LEN)
								_l = ANTICIPATED_PKT_BUF_LEN;
							memcpy(iip_ops_pkt_get_data(p, opaque), &mtd->get_req_base[l], _l);
							if (!l) {
								char key[250];
								assert(_l > 4 + mtd->key_len); /* XXX: lazy check */
								snprintf(key, sizeof(key), mtd->key_base, req_id);
								memcpy(iip_ops_pkt_get_data(p, opaque) + 4, key, mtd->key_len);
							}
							iip_ops_pkt_set_len(p, _l, opaque);
							iip_tcp_send(mem, handle, p, 0x08U, opaque);
							td->monitor.counter[td->monitor.idx].tx_bytes += _l;
							td->monitor.counter[td->monitor.idx].tx_pkt += 1;
							l += _l;
						}
					}
				}
			}
		}
	}
	iip_tcp_rxbuf_consumed(mem, handle, 1, opaque);
}

static void __app_loop(void *mem, uint8_t mac[], uint32_t ip4_be, uint32_t *next_us, void *opaque)
{
	void **opaque_array = (void **) opaque;
	struct thread_data *td = (struct thread_data *) opaque_array[2];
	if (!__app_close_posted && !td->core_id && mtds[0]) {
		struct mc_td *mtd = (struct mc_td *) td->prev_arp;
		uint64_t now = BENCH_IIP_NOW(opaque);
		pthread_spin_lock(&mtds_lock);
		if (1000000000UL < now - mtd->mc_dbg_prev_print) {
			uint8_t cid = mc_cnt_idx;
			mc_cnt_idx = (cid == 0 ? 1 : 0);
			{
				uint64_t total[6];
				memset(total, 0, sizeof(total));
				{
					uint16_t i;
					for (i = 0; i < MAX_THREAD; i++) {
						if (mtds[i]) {
							printf("[%u] set success %lu failed %lu error %lu, get success %lu failed %lu error %lu\n",
									i,
									mtds[i]->mcnt[cid].op[1].success,
									mtds[i]->mcnt[cid].op[1].failed,
									mtds[i]->mcnt[cid].op[1].error,
									mtds[i]->mcnt[cid].op[0].success,
									mtds[i]->mcnt[cid].op[0].failed,
									mtds[i]->mcnt[cid].op[0].error);
							total[0] += mtds[i]->mcnt[cid].op[1].success;
							total[1] += mtds[i]->mcnt[cid].op[1].failed;
							total[2] += mtds[i]->mcnt[cid].op[1].error;
							total[3] += mtds[i]->mcnt[cid].op[0].success;
							total[4] += mtds[i]->mcnt[cid].op[0].failed;
							total[5] += mtds[i]->mcnt[cid].op[0].error;
							memset(&mtds[i]->mcnt[cid], 0, sizeof(mtds[i]->mcnt[cid]));
						}
					}
					printf("total %lu: set %lu (success %lu failed %lu error %lu), get %lu (success %lu failed %lu error %lu)\n",
							total[0] + total[1] + total[2] + total[3] + total[4] + total[5],
							total[0] + total[1] + total[2],
							total[0], total[1], total[2],
							total[3] + total[4] + total[5],
							total[3], total[4], total[5]);
				}
			}
			mtd->mc_dbg_prev_print = now;
		}
		pthread_spin_unlock(&mtds_lock);
	}
	__o__app_loop(mem, mac, ip4_be, next_us, opaque);
}

static void *__app_init(int argc, char *const *argv)
{
	void *ret = __o__app_init(argc, argv);
	{
		zipf_theta = 0.9;
		load_req_id = 0;
		mc_cnt_idx = 0;
		_load_first = 0;
		_dist_zipfian = 0;
		_num_pairs = 1;
		_key_len = 32;
		_val_len = 32;
		_write_ratio = 0;
		memset(mtds, 0, sizeof(mtds));
		pthread_spin_init(&mtds_lock, PTHREAD_PROCESS_PRIVATE);
	}
	{ /* parse arguments */
		int ch;
		while ((ch = getopt(argc, argv, "dln:k:v:w:")) != -1) {
			switch (ch) {
			case 'd':
				_dist_zipfian = 1;
				break;
			case 'k':
				_key_len = atoi(optarg);
				break;
			case 'l':
				_load_first = 1;
				break;
			case 'n':
				_num_pairs = atoi(optarg);
				break;
			case 'v':
				_val_len = atoi(optarg);
				break;
			case 'w':
				_write_ratio = atoi(optarg);
				break;
			default:
				assert(0);
				break;
			}
		}
	}
	assert(_key_len <= 250);
	assert(_val_len <= (1UL << 20));
	assert(_num_pairs > 0);
	assert(_write_ratio <= 100);
	printf("%lu pairs, key %u bytes, val %u bytes, set %u%% get %u%%\n",
			_num_pairs, _key_len, _val_len, _write_ratio, 100 - _write_ratio);
	if (_load_first)
		printf("load items first. note that this load is not optimized for speed\n");
	if (_dist_zipfian) { /* zipfian preparation */
		/*
		 * Jim Gray et al, "Quickly Generating Billion-Record Synthetic Databases", SIGMOD 1994
		 *
		 * Brian F. Cooper et al, "Benchmarking Cloud Serving Systems with YCSB", SoCC 2010
		 * YCSB/core/src/main/java/site/ycsb/generator/ZipfianGenerator.java
		 *
		 */
		zipf_alpha = 1 / (1 - zipf_theta);
		{
			uint64_t i;
			for (i = 0, zipf_zetan = 0; i < _num_pairs; i++)
				zipf_zetan += 1 / pow(1 + i, zipf_theta);
		}
		{
			double zipf_zeta2 = 0;
			{
				uint64_t i;
				for (i = 0; i < 2; i++)
					zipf_zeta2 += 1 / pow(i + 1, zipf_theta);
			}
			zipf_eta = (1 - pow(2.0 / (double) _num_pairs, 1 - zipf_theta)) / (1 - zipf_zeta2 / zipf_zetan);
		}
		printf("zipfian distribution\n");
	} else
		printf("uniform distribution\n");
	return ret;
}

#define M2S(s) _M2S(s)
#define _M2S(s) #s
#include M2S(IOSUB_MAIN_C)
#undef _M2S
#undef M2S
```

</details>

In ```mimicached/network-benchmark```, please type the following command to build the benchmark client; we will have a executable binary named ```a.out```.

```
APP_EXTRA_LDFLAGS="-lm" IOSUB_DIR=../iip-dpdk make -f ../Makefile
```

To check the behavior of this benchmark client on a single host, we assume [mimicached with the kernel TCP/IP stack](#mimicached-with-the-kernel-tcpip-stack) has been launched beforehand.

The following is an example command to launch the benchmark client sending requests to a server whose IP address is 10.100.0.10; ```vdev=net_tap,iface=tap001 --no-pci``` is handled by DPDK, ```-a 0,10.100.0.20``` is for iip, `-s 10.100.0.10 -p 11211 -m "```echo -e "version\r\n\0"```"` is for bench-iip, and ```-k 8 -v 8 -n 100 -w 10 -d -l``` is passed to this benchmark client.

```
sudo LD_LIBRARY_PATH=../iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --vdev=net_tap,iface=tap001 --no-pci -- -a 0,10.100.0.20 -- -s 10.100.0.10 -p 11211 -m "```echo -e "version\r\n\0"```" -- -k 8 -v 8 -n 100 -w 10 -d -l
```

If we use a tap device, we need to open another console/terminal and configure its IP address by the following command.

```
sudo ifconfig tap001 10.100.0.10 netmask 255.255.255.0
```

After this configuration, the benchmark cilent above supposedly begins to send requests to the mimicached server running on the kernel TCP/IP stack.

The following is the commandline options.

- ```-d```: if this option is specified, the keys for the requests are generated based on approximated zipfian distribution, and otherwise, the distribution will be uniformly random.
- ```-k```: specifies key length.
- ```-v```: specifies value length.
- ```-n```: the number of the keys used in the benchmark.
- ```-l```: if this option is specified, before starting to send randomized requests, this benchmark client loads N of key-value items to the server where N is the number specified by the ```-n``` option.
- ```-w```: the ratio of set commands in percent (0~100); if 10 is specified for this option, the workload will be set 10% and get 90%.

## key-value storage benchmark without networking

We sometimes wish to investigate the efficiency of the key-value storage component without involving the networking overhead.

To this end, this section provides a benchmark program that does not include the networking component; it also provides the option to bypass the memcached protocol parser.

To try this benchmark, pleae make a directory named ```mimicached/local-benchmark``` and enter it.

```
mkdir local-benchmark
```

```
cd local-benchmark
```

Then, please save the following program as a file named ```main.c```.

<details>
<summary>please click here to show the program</summary>

```c
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <math.h>

#include <pthread.h>

#define mp_assert assert
#define mp_memcmp memcmp
#define mp_memcpy memcpy
#define mp_memmove memmove

int printf_nothing(const char *format, ...) { (void) format; return 0; }
#define MP_OPS_DEBUG_PRINTF printf_nothing

#define MP_OPS_UTIL_TIME_NS(__o) ({ struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec * 1000000000UL + ts.tv_nsec; })

static void mp_ops_clear_response(void *);
#define MP_OPS_CLEAR_RESPONSE mp_ops_clear_response
static long mp_ops_push_response(void *, const char *, size_t);
#define MP_OPS_PUSH_RESPONSE mp_ops_push_response
static void mp_ops_kv_cmd(void *, const uint8_t *, uint64_t, uint8_t *, void *);
#define MP_OPS_KV_CMD        mp_ops_kv_cmd
static void mp_ops_kv_flush_all(uint64_t, void *);
#define MP_OPS_KV_FLUSH_ALL  mp_ops_kv_flush_all
static int mp_ops_allow_shutdown(void *opaque) { return 0; (void) opaque; }
#define MP_OPS_ALLOW_SHUTDOWN mp_ops_allow_shutdown
static void mp_ops_shutdown(uint64_t op, void *opaque) { (void) op; (void) opaque; }
#define MP_OPS_SHUTDOWN mp_ops_shutdown

#define MP_TEST_HOOK() do { } while (0)

#include "../memcached-protocol-parser/main.c"

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

#include "../kv.c"

#define SLAB_OPS_ATOMIC_ADD_FETCH __atomic_add_fetch
#define SLAB_OPS_ATOMIC_SUB_FETCH __atomic_sub_fetch

#define SLAB_FLAG_ATOMIC_RELAXED __ATOMIC_RELAXED
#define SLAB_FLAG_ATOMIC_ACQ_REL __ATOMIC_ACQ_REL
#define SLAB_FLAG_ATOMIC_RELEASE __ATOMIC_RELEASE
#define SLAB_FLAG_ATOMIC_ACQUIRE __ATOMIC_ACQUIRE

#include "../slab.c"

#define MAX_CORE (____KV__CONF_MAX_THREAD_NUM)

#define INPUT_RING_SIZE (16)

struct thread_data {
	struct kv_thread_data ktd;
	void *gc_key_list;
	void *gc_val_list;
	pthread_t th;
	uint32_t core;
	uint32_t num_cores;
	uint32_t thread_id;
	char rxbuf[INPUT_RING_SIZE][(1UL << 21)];
	uint32_t tx_cur;
	char txbuf[(1UL << 21)];
	uint8_t mpr[MPR_MEM_SIZE(INPUT_RING_SIZE)];
	struct {
		uint64_t set_cnt[2];
		uint64_t get_cnt[2];
		uint64_t hit_cnt[2];
		uint64_t miss_cnt[2];
		uint64_t stored_cnt[2];
		uint64_t not_stored_cnt[2];
	} stat;
	struct {
		int tmp_opt;
		char bypass_parser;
		char zipfian;
		uint64_t random;
		uint32_t *wait;
		uint64_t num_pairs;
		uint16_t key_len;
		uint32_t val_len;
		uint8_t write_ratio;
		uint64_t *set_req_len;
		uint64_t *get_req_len;
		char **set_req;
		char **get_req;
	} workload;
};

#define RANDOM_XORSHIFT64(__r) \
	do { \
		(__r) ^= (__r) << 13; \
		(__r) ^= (__r) >> 7; \
		(__r) ^= (__r) << 17; \
	} while (0)

static volatile char should_stop = 0;

static void sig_h(int s __attribute__((unused)))
{
	should_stop = 1;
	signal(SIGINT, SIG_DFL);
}

static uint8_t cnt_idx = 0;

static void mp_ops_clear_response(void *opaque)
{
	struct thread_data *td = (struct thread_data *) opaque;
	td->tx_cur = 0;
}

static long mp_ops_push_response(void *opaque, const char *msg, size_t len)
{
	struct thread_data *td = (struct thread_data *) opaque;
	assert(len < sizeof(td->txbuf) - td->tx_cur);
	memcpy(&td->txbuf[td->tx_cur], msg, len);
	td->tx_cur += len;
	return 0;
	{
		(void) opaque;
		(void) msg;
		(void) len;
	}
}

static double zipf_alpha, zipf_zetan, zipf_eta, zipf_theta;

static void *server_thread(void *data)
{
	struct thread_data *td = (struct thread_data *) data;
	{
		cpu_set_t c;
		CPU_ZERO(&c);
		CPU_SET(td->core, &c);
		pthread_setaffinity_np(pthread_self(), sizeof(c), &c);
	}
	memset(td->rxbuf[1], 'A', sizeof(td->rxbuf[1]));
	MPR_SLOT_LEN(td->mpr, 1) = td->workload.val_len;
	memcpy(td->rxbuf[2], "\r\n", 2);
	MPR_SLOT_LEN(td->mpr, 2) = 2;
	asm volatile ("" ::: "memory");
	kv_register_ktd(&td->ktd, td->core);
	printf("core %u loads %lu entries\n", td->core, td->workload.num_pairs / td->num_cores);
	{
		uint64_t i;
		for (i = 0; i < (td->workload.num_pairs / td->num_cores) && !should_stop; i++) {
			if (!td->workload.bypass_parser) {
				MPR_SLOT_PTR(td->mpr, 0) = (uint64_t) td->workload.set_req[(td->workload.num_pairs / td->num_cores) * td->thread_id + i];
				MPR_SLOT_LEN(td->mpr, 0) = td->workload.set_req_len[(td->workload.num_pairs / td->num_cores) * td->thread_id + i];
				MPR_RING_HEAD_IDX(td->mpr) = 0;
				MPR_RING_HEAD_OFF(td->mpr) = 0;
				MPR_RING_TAIL_IDX(td->mpr) = 3;
				MPR_RING_TAIL_OFF(td->mpr) = 0;
				td->stat.set_cnt[cnt_idx]++;
				td->workload.tmp_opt = 1;
				td->tx_cur = 0;
				td->txbuf[0] = '\0';
				while (1) {
					long r;
					{
						kv_thread_access_start((void *) td);
						r = parse_memcached_request(td->mpr, (void *) td);
						kv_thread_access_done((void *) td);
					}
					assert(r == 0);
					if (td->tx_cur >= 7 && memcmp(td->txbuf, "STORED\r\n", 7)) {
						printf("%s", td->txbuf);
						if (td->tx_cur >= 43 && !memcmp(td->txbuf, "SERVER_ERROR out of memory storing object\r\n", 43)) {
							kv_garbage_collection((void *) td);
							printf("NOTE: some key value pairs would be evicted\n");
						} else
							assert(0);
					} else
						td->stat.stored_cnt[cnt_idx]++;
					break;
				}
			} else {
				uint8_t cmd[MP_KV_CMD_SIZE];
				memset(cmd, 0, MP_KV_CMD_SIZE);
				MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_VIVIFY_ON_MISS | MC_KV_CMD_OPFLAG_UPDATE | MC_KV_CMD_OPFLAG_BUMP_CAS_UNIQUE | MC_KV_CMD_OPFLAG_SET_FLAG | MC_KV_CMD_OPFLAG_SET_EXPTIME;
				MP_KV_CMD_VAL_PTR_0(cmd) = 1;
				MP_KV_CMD_VAL_PTR_1(cmd) = 0;
				MP_KV_CMD_VAL_LEN(cmd) = td->workload.val_len;
				MP_KV_CMD_FLAGS(cmd) = 0;
				MP_KV_CMD_EXPTIME(cmd) = 0;
				td->workload.tmp_opt = 1;
				td->tx_cur = 0;
				td->txbuf[0] = '\0';
				td->stat.set_cnt[cnt_idx]++;
				MP_OPS_KV_CMD(td->mpr,
						(const uint8_t *) &((td->workload.set_req[(td->workload.num_pairs / td->num_cores) * td->thread_id + i])[4]),
						td->workload.key_len,
						cmd,
						(void *) td);
				if (!(MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_VIVIFY_ON_MISS))
					td->stat.stored_cnt[cnt_idx]++;
				else {
					if (MP_KV_CMD_ERRNO(cmd) == MP_ERR_ENOMEM) {
						kv_garbage_collection((void *) td);
						printf("NOTE: some key value pairs would be evicted\n");
					} else
						assert(0);
				}
			}
		}
	}
	{
		uint32_t i = 1;
		(void) SLAB_OPS_ATOMIC_ADD_FETCH(td->workload.wait, i, SLAB_FLAG_ATOMIC_RELEASE);
	}
	while (!should_stop) {
		uint32_t wait;
		KV_OPS_ATOMIC_LOAD(td->workload.wait, &wait, KV_FLAG_ATOMIC_ACQUIRE);
		if (wait == td->num_cores)
			break;
		usleep(100);
	}
	printf("core %u start benchmarking\n", td->core);
	while (!should_stop) {
		uint64_t req_id;
		RANDOM_XORSHIFT64(td->workload.random);
		if (td->workload.zipfian) {
			double u, uz;
			u = (((double) td->workload.random) / UINT64_MAX);
			uz = u * zipf_zetan;
			if (uz < 1)
				req_id = 0; /* base */
			else if (uz < 1 + pow(0.5, zipf_theta))
				req_id = 0 /* base */ + 1;
			else
				req_id = 0 /* base */ + (long)(td->workload.num_pairs * pow(zipf_eta * u - zipf_eta + 1, zipf_alpha));
		} else
			req_id = td->workload.random % td->workload.num_pairs;
		if (!td->workload.bypass_parser) {
			RANDOM_XORSHIFT64(td->workload.random);
			if ((td->workload.random % 100) < td->workload.write_ratio) {
				MPR_SLOT_PTR(td->mpr, 0) = (uint64_t) td->workload.set_req[req_id];
				MPR_SLOT_LEN(td->mpr, 0) = td->workload.set_req_len[req_id];
				MPR_RING_HEAD_IDX(td->mpr) = 0;
				MPR_RING_HEAD_OFF(td->mpr) = 0;
				MPR_RING_TAIL_IDX(td->mpr) = 3;
				MPR_RING_TAIL_OFF(td->mpr) = 0;
				td->workload.tmp_opt = 1;
				td->stat.set_cnt[cnt_idx]++;
			} else {
				MPR_SLOT_PTR(td->mpr, 0) = (uint64_t) td->workload.get_req[req_id];
				MPR_SLOT_LEN(td->mpr, 0) = td->workload.get_req_len[req_id];
				MPR_RING_HEAD_IDX(td->mpr) = 0;
				MPR_RING_HEAD_OFF(td->mpr) = 0;
				MPR_RING_TAIL_IDX(td->mpr) = 1;
				MPR_RING_TAIL_OFF(td->mpr) = 0;
				td->workload.tmp_opt = 0;
				td->stat.get_cnt[cnt_idx]++;
			}
			while (!should_stop && !(MPR_RING_HEAD_IDX(td->mpr) == MPR_RING_TAIL_IDX(td->mpr) && MPR_RING_HEAD_OFF(td->mpr) == MPR_RING_TAIL_OFF(td->mpr))) {
				uint64_t head_idx = MPR_RING_HEAD_IDX(td->mpr), head_off = MPR_RING_HEAD_OFF(td->mpr);
				td->tx_cur = 0;
				td->txbuf[0] = '\0';
				{
					long r;
					{
						kv_thread_access_start((void *) td);
						r = parse_memcached_request(td->mpr, (void *) td);
						kv_thread_access_done((void *) td);
					}
					assert(r == 0);
				}
				if (td->tx_cur) {
					if (td->workload.tmp_opt) {
						if (!memcmp(td->txbuf, "STORED\r\n", 7))
							td->stat.stored_cnt[cnt_idx]++;
						else
							td->stat.not_stored_cnt[cnt_idx]++;
					} else {
						if (!memcmp(td->txbuf, "VALUE", 5))
							td->stat.hit_cnt[cnt_idx]++;
						else
							td->stat.miss_cnt[cnt_idx]++;
					}
				}
				if (head_idx == MPR_RING_HEAD_IDX(td->mpr) && head_off == MPR_RING_HEAD_OFF(td->mpr))
					break;
			}
		} else {
			uint8_t cmd[MP_KV_CMD_SIZE];
			memset(cmd, 0, MP_KV_CMD_SIZE);
			RANDOM_XORSHIFT64(td->workload.random);
			if ((td->workload.random % 100) < td->workload.write_ratio) {
				MP_KV_CMD_OPFLAGS(cmd) |= MC_KV_CMD_OPFLAG_VIVIFY_ON_MISS | MC_KV_CMD_OPFLAG_UPDATE | MC_KV_CMD_OPFLAG_BUMP_CAS_UNIQUE | MC_KV_CMD_OPFLAG_SET_FLAG | MC_KV_CMD_OPFLAG_SET_EXPTIME;
				MP_KV_CMD_VAL_PTR_0(cmd) = 1;
				MP_KV_CMD_VAL_PTR_1(cmd) = 0;
				MP_KV_CMD_VAL_LEN(cmd) = td->workload.val_len;
				MP_KV_CMD_FLAGS(cmd) = 0;
				MP_KV_CMD_EXPTIME(cmd) = 0;
				td->workload.tmp_opt = 1;
				td->stat.set_cnt[cnt_idx]++;
			} else {
				td->workload.tmp_opt = 0;
				td->stat.get_cnt[cnt_idx]++;
			}
			MP_OPS_KV_CMD(td->mpr,
					(const uint8_t *) &((td->workload.set_req[req_id])[4]),
					td->workload.key_len,
					cmd,
					(void *) td);
			if (td->workload.tmp_opt) {
				if (!(MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_UPDATE))
					td->stat.stored_cnt[cnt_idx]++;
				else
					td->stat.not_stored_cnt[cnt_idx]++;
			} else {
				if (MP_KV_CMD_OPFLAGS(cmd) & MC_KV_CMD_OPFLAG_FOUND)
					td->stat.hit_cnt[cnt_idx]++;
				else
					td->stat.miss_cnt[cnt_idx]++;
			}
		}
		kv_garbage_collection((void *) td);
	}
	printf("core %u returns\n", td->core);
	pthread_exit(NULL);
}

int main(int argc, char *const *argv)
{
	unsigned short num_cores = 0, core_list[MAX_CORE];
	char bypass_parser = 0, zipfian = 0;
	uint64_t num_pairs = 128;
	uint16_t key_len = 32;
	uint32_t val_len = 256;
	uint16_t write_ratio = 0;
	zipf_theta = 0.9;
	slab_init(); /* TODO: better init */
	slab_stat.mem_size = 2 * 1048576;
	{
		int ch;
		while ((ch = getopt(argc, argv, "c:dn:m:k:v:w:xz:")) != -1) {
			switch (ch) {
			case 'c':
				{
					ssize_t num_comma = 0, num_hyphen = 0;
					{
						size_t i;
						for (i = 0; i < strlen(optarg); i++) {
							switch (optarg[i]) {
							case ',':
								num_comma++;
								break;
							case '-':
								num_hyphen++;
								break;
							}
						}
					}
					if (num_hyphen) {
						assert(num_hyphen == 1);
						assert(!num_comma);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i;
								for (i = 0; i < strlen(optarg); i++) {
									if (m[i] == '-') {
										m[i] = '\0';
										break;
									}
								}
								assert(i != strlen(optarg) - 1 && i != strlen(optarg));
								{
									uint16_t from = atoi(&m[0]), to = atoi(&m[i + 1]);
									assert(from <= to);
									{
										uint16_t j, k;
										for (j = 0, k = from; k <= to; j++, k++)
										core_list[j] = k;
										num_cores = j;
									}
								}
							}
							free(m);
						}
					} else if (num_comma) {
						assert(num_comma + 1 < MAX_CORE);
						{
							char *m;
							assert((m = strdup(optarg)) != NULL);
							{
								size_t i, j, k;
								for (i = 0, j = 0, k = 0; i < strlen(optarg) + 1; i++) {
									if (i == strlen(optarg) || m[i] == ',') {
										m[i] = '\0';
										if (j != i)
										core_list[k++] = atoi(&m[j]);
										j = i + 1;
									}
									if (i == strlen(optarg))
										break;
								}
								assert(k);
								num_cores = k;
							}
							free(m);
						}
					} else {
						core_list[0] = atoi(optarg);
						num_cores = 1;
					}
				}
				break;
			case 'd':
				zipfian = 1;
				break;
			case 'k':
				key_len = atoi(optarg);
				break;
			case 'n':
				num_pairs = atoi(optarg);
				break;
			case 'm':
				slab_stat.mem_size = atol(optarg) * 1048576;
				break;
			case 'v':
				val_len = atoi(optarg);
				break;
			case 'w':
				write_ratio = atoi(optarg);
				break;
			case 'x':
				bypass_parser = 1;
				break;
			case 'z':
				kv_conf_hash_table_cnt = atoi(optarg);
				break;
			default:
				assert(0);
				break;
			}
		}
	}
	{
		assert(num_cores > 0);
		assert(num_pairs > 0);
		assert(kv_conf_hash_table_cnt > 0);
		assert(key_len <= 250);
		assert(val_len <= (1UL << 20));
		assert(write_ratio <= 100);
	}
	printf("%lu pairs, key %u bytes, val %u bytes, set %u%% get %u%%\n",
			num_pairs, key_len, val_len, write_ratio, 100 - write_ratio);
	{
		char tmp[512];
		snprintf(tmp, sizeof(tmp), "%%0%dx", key_len);
		{
			char keymin[512], keymax[512];
			snprintf(keymin, sizeof(keymin), tmp, 0);
			snprintf(keymax, sizeof(keymax), tmp, num_pairs);
			printf("key: min %s max %s\n", keymin, keymax);
		}
	}
	printf("protocol parser is %sbypassed\n", bypass_parser ? "" : "NOT ");
	printf("hash table size %lu, memory size ", kv_conf_hash_table_cnt);
	{
		uint64_t s = kv_conf_hash_table_cnt * sizeof(void *);
		if (s < 1000)
			printf("%lu bytes\n", s);
		else if (s < 1000000)
			printf("%lu.%03lu KB\n", s / 1000, s % 1000);
		else if (s < 1000000000)
			printf("%lu.%03lu MB\n", s / 1000000, (s % 1000000) / 1000);
		else
			printf("%lu.%03lu GB\n", s / 1000000000, (s % 1000000000) / 1000000);
	}
	kv_init(); /* TODO: better init */
	if (zipfian) { /* zipfian preparation */
		/*
		 * Jim Gray et al, "Quickly Generating Billion-Record Synthetic Databases", SIGMOD 1994
		 *
		 * Brian F. Cooper et al, "Benchmarking Cloud Serving Systems with YCSB", SoCC 2010
		 * YCSB/core/src/main/java/site/ycsb/generator/ZipfianGenerator.java
		 *
		 */
		zipf_alpha = 1 / (1 - zipf_theta);
		{
			uint64_t i;
			for (i = 0, zipf_zetan = 0; i < num_pairs; i++)
				zipf_zetan += 1 / pow(1 + i, zipf_theta);
		}
		{
			double zipf_zeta2 = 0;
			{
				uint64_t i;
				for (i = 0; i < 2; i++)
					zipf_zeta2 += 1 / pow(i + 1, zipf_theta);
			}
			zipf_eta = (1 - pow(2.0 / (double) num_pairs, 1 - zipf_theta)) / (1 - zipf_zeta2 / zipf_zetan);
		}
		printf("zipfian distribution\n");
	} else
		printf("uniform distribution\n");
	signal(SIGINT, sig_h);
	{
		uint64_t *set_req_len = (uint64_t *) calloc(num_pairs, sizeof(uint64_t));
		uint64_t *get_req_len = (uint64_t *) calloc(num_pairs, sizeof(uint64_t));
		char **set_req = (char **) calloc(num_pairs, sizeof(const char *));
		char **get_req = (char **) calloc(num_pairs, sizeof(const char *));
		assert(set_req_len);
		assert(get_req_len);
		assert(set_req);
		assert(get_req);
		{
			uint64_t _mem = 0;
			{
				char _set[2048], set[4096];
				snprintf(_set, sizeof(_set), "set %%0%dx 0 0 %%lu\r\n", key_len);
				{
					uint64_t i;
					for (i = 0; i < num_pairs && !should_stop; i++) {
						snprintf(set, sizeof(set), _set, i, val_len);
						set_req[i] = strdup(set);
						set_req_len[i] = strlen(set_req[i]);
						_mem += set_req_len[i] + 1;
					}
				}
			}
			{
				char _get[2048], get[4096];
				snprintf(_get, sizeof(_get), "get %%0%dx\r\n", key_len);
				{
					uint64_t i;
					for (i = 0; i < num_pairs && !should_stop; i++) {
						snprintf(get, sizeof(get), _get, i);
						get_req[i] = strdup(get);
						get_req_len[i] = strlen(get_req[i]);
						_mem += get_req_len[i] + 1;
					}
				}
			}
			printf("query set size ");
			if (_mem < 1000)
				printf("%lu bytes\n", _mem);
			else if (_mem < 1000000)
				printf("%lu.%03lu KB\n", _mem / 1000, _mem % 1000);
			else if (_mem < 1000000000)
				printf("%lu.%03lu MB\n", _mem / 1000000, (_mem % 1000000) / 1000);
			else
				printf("%lu.%03lu GB\n", _mem / 1000000000, (_mem % 1000000000) / 1000000);
		}
		{
			uint32_t wait = 0;
			struct thread_data *td = (struct thread_data *) calloc(num_cores, sizeof(struct thread_data));
			assert(td);
			{
				unsigned short i;
				for (i = 0; i < num_cores; i++) {
					td[i].thread_id = i;
					td[i].num_cores = num_cores;
					td[i].core = core_list[i];
					td[i].workload.bypass_parser = bypass_parser;
					td[i].workload.zipfian = zipfian;
					td[i].workload.set_req = set_req;
					td[i].workload.set_req_len = set_req_len;
					td[i].workload.get_req = get_req;
					td[i].workload.get_req_len = get_req_len;
					td[i].workload.random = 88172645463325252UL * (i + 1);
					td[i].workload.wait = &wait;
					td[i].workload.num_pairs = num_pairs;
					td[i].workload.key_len = key_len;
					td[i].workload.val_len = val_len;
					td[i].workload.write_ratio = write_ratio;
					MPR_RING_NUM_SLOT(td[i].mpr) = INPUT_RING_SIZE;
					MPR_RING_HEAD_IDX(td[i].mpr) = 0;
					MPR_RING_HEAD_OFF(td[i].mpr) = 0;
					MPR_RING_TAIL_IDX(td[i].mpr) = 0;
					MPR_RING_TAIL_OFF(td[i].mpr) = 0;
					{
						int j;
						for (j = 0; j < INPUT_RING_SIZE; j++)
							MPR_SLOT_PTR(td[i].mpr, j) = (uint64_t) td[i].rxbuf[j];
					}
					{
						int err = pthread_create(&td[i].th, NULL, server_thread, (void *) &td[i]);
						assert(!err);
					}
				}
			}
			while (!should_stop) {
				sleep(1);
				{
					uint8_t idx = cnt_idx;
					cnt_idx = (idx ? 0 : 1);
					{
						uint64_t total_set = 0, total_get = 0;
						{
							unsigned short i;
							for (i = 0; i < num_cores; i++) {
								printf("[%u]: set %lu ops (stored %lu not stored %lu), get %lu ops (hit %lu miss %lu)\n",
										core_list[i],
										td[i].stat.set_cnt[idx], td[i].stat.stored_cnt[idx], td[i].stat.not_stored_cnt[idx],
										td[i].stat.get_cnt[idx], td[i].stat.hit_cnt[idx], td[i].stat.miss_cnt[idx]);
								total_set += td[i].stat.set_cnt[idx];
								total_get += td[i].stat.get_cnt[idx];
								memset(&td[i].stat, 0, sizeof(td[i].stat));
							}
						}
						printf("total: set %lu ops, get %lu ops\n", total_set, total_get);
					}
				}
			}
			{
				unsigned short i;
				for (i = 0; i < num_cores; i++) {
					int err = pthread_join(td[i].th, NULL);
					assert(!err);
				}
			}
			free(td);
		}
		{
			uint64_t i;
			for (i = 0; i < num_pairs; i++)
				free(set_req[i]);
		}
		{
			uint64_t i;
			for (i = 0; i < num_pairs; i++)
				free(get_req[i]);
		}
		free(get_req);
		free(set_req);
		free(get_req_len);
		free(set_req_len);
	}
	return 0;
}
```

</details>

Please type the following command to compile the benchmark program. We will have an executable file named ```a.out```.

```
gcc -O3 -pipe -g -rdynamic -Werror -Wextra -Wall -D_GNU_SOURCE ./main.c -lpthread -lm
```

The following is an example command.

```
./a.out -c 0 -m 128 -z 1000 -n 1000 -w 10 -k 8 -v 8 -x -d
```

The following is the command options.

- ```-c```: specifies CPU cores to be used. (```-c 0```: use CPU core 0, ```-c 1,3```: use CPU core 1 and 3, ```-c 0-2```: use CPU core 0,1,2)
- ```-d```: if this option is specified, the keys for the requests are generated based on the approximated zipfian distribution, and otherwise, it will be uniformly random.
- ```-k```: specifies key length.
- ```-v```: specifies value length.
- ```-n```: the number of total key-value pairs.
- ```-w```: the ratio of the set command.
- ```-x```: if this option is specified, this benchmark program bypasses the memcached protocol parser and directly executes the key-value operation.
- ```-z```: the hash table size.

## rough performance numbers

### benchmark enviornment

The benchmarks are run on two identical machines, and each of the two machines installs the following.

- CPU: Two of 16-core Intel(R) Xeon(R) Gold 6326 CPU @ 2.90GHz (32 cores in total)
- NIC: Mellanox ConnectX-5 100 Gbps NIC (the NICs of the two machines are directly connected via a cable)
- DRAM: DDR4-3200 128 GB
- OS: Linux 6.8

### networked benchmark

This benchmark runs either the original memcached server version 1.6.39 or [mimicached built with iip](#build) on one of the two machines, and the benchmark client shown [above](#network-benchmark-client) on the other machine.

The servers use 1, 2, 4, 8, 16, or 32 CPU cores, and the client always uses 32 CPU cores.

We apply the following workload configuration on the client.

- set 10% get 90%
- approximated zipfian distribution
- 1 million key-value items
- key size is 8 bytes
- value size is 8 bytes
- text protocol

<details>
<summary>please click here to show the command details</summary>

mimicached server: the number of CPU cores of the servers: 1, 2, 4, 8, 16, or 32, and to change the number of CPU cores used, ```-l 0```, ```-l 0-1```, ```-l 0-3```, ```-l 0-7```, ```-l 0-15```, and ```-l 0-31``` for 1, 2, 4, 8, 16, and 32 CPU core cases, respectively; the following is the 1 CPU core case.

```
sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -m 16384 -z 100000000
```

The original memcached server version 1.6.39: to change the number of CPU cores used, ```-t 1```, ```-t 2```, ```-t 4```, ```-t 8 ```, ```-t 16```, and ```-t 32``` for 1, 2, 4, 8, 16, and 32 CPU core cases, respectively; the following is the 1 CPU core case.

```
./memcached -m 16384 -t 1
```

client program shown [above](#network-benchmark-client): this client changes the number of concurrent TCP connections established with the servers by specifying ```-c 1```, ```-c 2```, ```-c 4```, ```-c 8```, ```-c 16```, and ```-c 32``` for 1, 2, 4, 8, 16, and 32 CPU core cases, respectively, so that each thread of a server process will handle 32 concurrent TCP connections; the following is the 1 CPU core case.

```
sudo LD_LIBRARY_PATH=../iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 11211 -m "```echo -e "version\r\n\0"```" -c 1 -- -k 8 -v 8 -n 1000000 -w 10 -d -l
```

</details>

The following table shows the requests per second results for the original memcached server implementation and mimicached. Note that the numbers for the original memcached server is for reference purposes; the comparison between the two implementations having different features is not fair.

| CPU cores | memcached | mimicached |
| --- | --- | --- |
|  1 |  202487 |  1201418 |
|  2 |  392694 |  2041757 |
|  4 |  718106 |  3915976 |
|  8 | 1378252 |  7650862 |
| 16 | 2344839 | 14625274 |
| 32 | 3192569 | 23194445 |

