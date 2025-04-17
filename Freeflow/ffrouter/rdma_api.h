// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef RDMA_API_H
#define RDMA_API_H

#include "constant.h"

#include <infiniband/verbs.h>
// #include <infiniband/verbs_exp.h>
#include <infiniband/arch.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_user_ioctl_cmds.h>
#include "kern-abi.h"
// #include <infiniband/driver.h>
// #include <infiniband/driver_exp.h>
// #include <infiniband/kern-abi.h>
// #include <infiniband/kern-abi_exp.h>
// #include <rdma/rdma_cma.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <sys/time.h>
#include <netinet/in.h>
#include <malloc.h>
#include <errno.h>
#include <byteswap.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/shm.h>

struct ib_conn_data
{
	int lid;
	int out_reads;
	int qpn;
	int psn;
	unsigned rkey;
	unsigned long long vaddr;
	union ibv_gid gid;
	unsigned srqn;
	int gid_index;
};

struct ib_data
{
	char *mem_name;
	void *mem_start;
	struct ibv_device *ib_device;
	struct ibv_context *ib_context;
	union ibv_gid ib_gid;
	struct ibv_device_attr ib_dev_attr;
	struct ibv_port_attr ib_port_attr;

	/* not used */
	struct ibv_pd *ib_pd;
	struct ibv_qp *ib_qp;
	struct ibv_cq *ib_cq;
	struct ibv_mr *ib_mr;
	int msg_size;
	char *ib_buffer;
};

void move_qp_to_init(struct ibv_qp *qp);

void move_qp_to_rtr(struct ibv_qp *qp, struct ib_conn_data *dest);

void move_qp_to_rts(struct ibv_qp *qp);

void post_receive(struct ib_data *myib);

void post_send(struct ib_data *myib, struct ib_conn_data *dest, int opcode);

void poll_completion(struct ib_data *myib);

struct ibv_device *get_first_device();

void setup_ib(struct ib_data *myib);

void fill_ib_conn_data(struct ib_data *myib, struct ib_conn_data *my_ib_conn_data);

int receiver_accept_connection();

int sender_make_connection(char *receiver_ip);

void exchange_conn_data(int socket, struct ib_conn_data *my, struct ib_conn_data *remote);

void wait_for_nudge(int socket);

void send_nudge(int socket);

struct ibv_recv_wr *create_recv_request(struct ib_data *myib);

struct ibv_send_wr *create_send_request(struct ib_data *myib, struct ib_conn_data *dest, int opcode);

void fill_sge(struct ibv_sge *sge, struct ib_data *myib);

/*
 * For write() only commands that have fixed core structures and may take uhw
 * driver data. The last arguments are the same ones passed into the typical
 * ibv_cmd_* function. execute_cmd_write deduces the length of the core
 * structure based on the KABI struct linked to the enum op code.
 */
int _execute_cmd_write(struct ibv_context *ctx, unsigned int write_method,
					   void *req, size_t core_req_size,
					   size_t req_size, void *resp, size_t core_resp_size,
					   size_t resp_size);
#define execute_cmd_write(ctx, enum, cmd, cmd_size, resp, resp_size) \
	({                                                               \
		(cmd)->response = ioctl_ptr_to_u64(resp);                    \
		_execute_cmd_write(                                          \
			ctx, enum, cmd,                                          \
			sizeof(*(cmd)), cmd_size,                                \
			resp,                                                    \
			sizeof(*(resp)), resp_size);                             \
	})

static inline uint64_t ioctl_ptr_to_u64(const void *ptr)
{
	if (sizeof(ptr) == sizeof(uint64_t))
		return (uintptr_t)ptr;

	/*
	 * Some CPU architectures require sign extension when converting from
	 * a 32 bit to 64 bit pointer.  This should match the kernel
	 * implementation of compat_ptr() for the architecture.
	 */
#if defined(__tilegx__)
	return (int64_t)(intptr_t)ptr;
#else
	return (uintptr_t)ptr;
#endif
}

/*
 * For write() commands that use the _ex protocol. _full allows the caller to
 * specify all 4 sizes directly. This version is used when the core structs
 * end in a flex array. The normal and req versions are similar to write() and
 * deduce the length of the core struct from the enum.
 */
int _execute_cmd_write_ex(struct ibv_context *ctx, unsigned int write_method,
						  struct ex_hdr *req, size_t core_req_size,
						  size_t req_size, void *resp, size_t core_resp_size,
						  size_t resp_size);
#define execute_cmd_write_ex_full(ctx, enum, cmd, core_cmd_size, cmd_size, \
								  resp, core_resp_size, resp_size)         \
	_execute_cmd_write_ex(                                                 \
		ctx, enum, &(cmd)->hdr,                                            \
		core_cmd_size, cmd_size,                                           \
		resp,                                                              \
		core_resp_size, resp_size)
#define execute_cmd_write_ex(ctx, enum, cmd, cmd_size, resp, resp_size) \
	execute_cmd_write_ex_full(ctx, enum, cmd, sizeof(*(cmd)), cmd_size, \
							  resp, sizeof(*(resp)), resp_size)
#define execute_cmd_write_ex_req(ctx, enum, cmd, cmd_size) \
	({                                                     \
		_execute_cmd_write_ex(                             \
			ctx, enum,                                     \
			&(cmd)->hdr,                                   \
			sizeof(*(cmd)), cmd_size, NULL, 0, 0);         \
	})

static inline size_t __check_divide(size_t val, unsigned int div)
{
	assert(val % div == 0);
	return val / div;
}

/*#elif defined(__x86_64__)*/
#define mmio_flush_writes() asm volatile("sfence" ::: "memory")
/* Prevent WC writes from being re-ordered relative to other MMIO
   writes. This should be used before a write to WC memory.

   This must act as a barrier to prevent write re-ordering from different
   memory types:
	 *mmio_mem = 1;
	 mmio_flush_writes();
	 *wc_mem = 2;
   Must always produce a TLP '1' followed by '2'.

   This barrier implies udma_to_device_barrier()

   This is intended to be used in conjunction with WC memory to generate large
   PCI-E MemWr TLPs from the CPU.
*/
#define mmio_wc_start() mmio_flush_writes()
#endif /* RDMA_API_H */
