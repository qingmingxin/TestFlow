#include <cstdint>
#include <stdlib.h>

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <fcntl.h>  // open() 函数和 O_RDWR 宏的定义
#include <unistd.h> // close() 等系统调用的定义
#include <stddef.h> // offsetof 宏

#include "log.h"
#include "types_sxq.h"
#include <sys/mman.h>

#define FFR_SOCK "/freeflow/router1"

struct cm_con_data_t
{
    uint64_t addr;   /* Buffer address */
    uint32_t rkey;   /* Remote key */
    uint32_t qp_num; /* QP number */
    uint16_t lid;    /* LID of the IB port */
    uint8_t gid[16]; /* gid */
} __attribute__((packed));

struct tempres
{
    int res;
};
static int ffr_sock_init()
{
    // 创建Unix域套接字
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
    {
        return -1;
    }

    // 设置服务器地址结构
    sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr)); // 清零
    server_addr.sun_family = AF_UNIX;

    // 设置Unix域套接字路径（与服务器一致）
    const char *socket_path = FFR_SOCK;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        close(sock);
        return -1;
    }
    return sock;
}

int request_ffrouter(int *sock, RDMA_FUNCTION_CALL req, void *req_body, void *rsp, int *rsp_size)
{
    struct FfrRequestHeader header;
    header.client_id = atoi("80");
    header.func = req;
    header.body_size = 0;

    int fixed_size_rsp = 1;

    switch (req)
    {
    case SXQ_IBV_OPEN_DEVICE:
        *rsp_size = sizeof(struct SXQ_IBV_OPEN_DEVICE_RSP);
        break;
    case SXQ_IBV_QUERY_PORT:
        *rsp_size = sizeof(struct SXQ_IBV_QUERY_PORT_RSP);
        header.body_size = sizeof(struct SXQ_IBV_QUERY_PORT_REQ);
        break;

    case SXQ_IBV_ALLOC_PD:
        *rsp_size = sizeof(struct SXQ_IBV_ALLOC_PD_RSP);
        break;

    case SXQ_IBV_REG_MR:
        *rsp_size = sizeof(struct SXQ_IBV_REG_MR_RSP);
        header.body_size = sizeof(struct SXQ_IBV_REG_MR_REQ);
        break;

    case SXQ_IBV_CREATE_CQ:
        *rsp_size = sizeof(struct SXQ_IBV_CREATE_CQ_RSP);
        header.body_size = sizeof(struct SXQ_IBV_CREATE_CQ_REQ);
        break;
    case SXQ_IBV_CREATE_QP:
        *rsp_size = sizeof(struct SXQ_IBV_CREATE_QP_RSP);
        header.body_size = sizeof(struct SXQ_IBV_CREATE_QP_REQ);
        break;

    case SXQ_IBV_QUERY_GID:
        *rsp_size = sizeof(struct SXQ_IBV_QUERY_GID_RSP);
        header.body_size = sizeof(struct SXQ_IBV_QUERY_GID_REQ);
        break;
    case SXQ_IBV_MODIFY_QP:
        *rsp_size = sizeof(struct SXQ_IBV_MODIFY_QP_RSP);
        header.body_size = sizeof(struct SXQ_IBV_MODIFY_QP_REQ);
        break;
    case SXQ_IBV_POST_RECV:
        *rsp_size = sizeof(struct SXQ_IBV_POST_RECV_RSP);
        header.body_size = ((struct SXQ_IBV_POST_RECV_REQ *)req_body)->wr_size;
        req_body = ((struct SXQ_IBV_POST_RECV_REQ *)req_body)->wr;
        break;
    case SXQ_IBV_POST_SEND:
        *rsp_size = sizeof(struct SXQ_IBV_POST_SEND_RSP);
        header.body_size = ((struct SXQ_IBV_POST_SEND_REQ *)req_body)->wr_size;
        req_body = ((struct SXQ_IBV_POST_SEND_REQ *)req_body)->wr;
        break;
    case SXQ_IBV_POLL_CQ:
        fixed_size_rsp = 0;
        header.body_size = sizeof(struct SXQ_IBV_POLL_CQ_REQ);
        break;
    case IBV_QUERY_PORT:
        *rsp_size = sizeof(struct IBV_QUERY_PORT_RSP);
        header.body_size = sizeof(struct IBV_QUERY_PORT_REQ);
        break;

    case IBV_ALLOC_PD:
        *rsp_size = sizeof(struct IBV_ALLOC_PD_RSP);
        break;

    case IBV_DEALLOC_PD:
        *rsp_size = sizeof(struct IBV_DEALLOC_PD_RSP);
        header.body_size = sizeof(struct IBV_DEALLOC_PD_REQ);
        break;

    case IBV_CREATE_CQ:
        *rsp_size = sizeof(struct IBV_CREATE_CQ_RSP);
        header.body_size = sizeof(struct IBV_CREATE_CQ_REQ);
        break;

    case IBV_DESTROY_CQ:
        *rsp_size = sizeof(struct IBV_DESTROY_CQ_RSP);
        header.body_size = sizeof(struct IBV_DESTROY_CQ_REQ);
        break;

    case IBV_REQ_NOTIFY_CQ:
        *rsp_size = sizeof(struct IBV_REQ_NOTIFY_CQ_RSP);
        header.body_size = sizeof(struct IBV_REQ_NOTIFY_CQ_REQ);
        break;

    case IBV_CREATE_QP:
        *rsp_size = sizeof(struct IBV_CREATE_QP_RSP);
        header.body_size = sizeof(struct IBV_CREATE_QP_REQ);
        break;

    case IBV_DESTROY_QP:
        *rsp_size = sizeof(struct IBV_DESTROY_QP_RSP);
        header.body_size = sizeof(struct IBV_DESTROY_QP_REQ);
        break;

    case IBV_REG_MR:
        *rsp_size = sizeof(struct IBV_REG_MR_RSP);
        header.body_size = sizeof(struct IBV_REG_MR_REQ);
        break;

    case IBV_REG_MR_MAPPING:
        *rsp_size = sizeof(struct IBV_REG_MR_MAPPING_RSP);
        header.body_size = sizeof(struct IBV_REG_MR_MAPPING_REQ);
        break;

    case IBV_DEREG_MR:
        *rsp_size = sizeof(struct IBV_DEREG_MR_RSP);
        header.body_size = sizeof(struct IBV_DEREG_MR_REQ);
        break;

    case IBV_MODIFY_QP:
        *rsp_size = sizeof(struct IBV_MODIFY_QP_RSP);
        header.body_size = sizeof(struct IBV_MODIFY_QP_REQ);
        break;

    case IBV_QUERY_QP:
        *rsp_size = sizeof(struct IBV_QUERY_QP_RSP);
        header.body_size = sizeof(struct IBV_QUERY_QP_REQ);
        break;

    case IBV_POST_SEND:
        *rsp_size = sizeof(struct IBV_POST_SEND_RSP);
        header.body_size = ((struct IBV_POST_SEND_REQ *)req_body)->wr_size;
        req_body = ((struct IBV_POST_SEND_REQ *)req_body)->wr;
        break;

    case IBV_POST_RECV:
        *rsp_size = sizeof(struct IBV_POST_RECV_RSP);
        header.body_size = ((struct IBV_POST_RECV_REQ *)req_body)->wr_size;
        req_body = ((struct IBV_POST_RECV_REQ *)req_body)->wr;
        break;

    case IBV_POST_SRQ_RECV:
        *rsp_size = sizeof(struct IBV_POST_SRQ_RECV_RSP);
        header.body_size = ((struct IBV_POST_SRQ_RECV_REQ *)req_body)->wr_size;
        req_body = ((struct IBV_POST_SRQ_RECV_REQ *)req_body)->wr;
        break;

    case IBV_POLL_CQ:
        fixed_size_rsp = 0;
        header.body_size = sizeof(struct IBV_POLL_CQ_REQ);
        break;

    case IBV_CREATE_COMP_CHANNEL:
        *rsp_size = sizeof(struct IBV_CREATE_COMP_CHANNEL_RSP);
        break;

    case IBV_DESTROY_COMP_CHANNEL:
        *rsp_size = sizeof(struct IBV_DESTROY_COMP_CHANNEL_RSP);
        header.body_size = sizeof(struct IBV_DESTROY_COMP_CHANNEL_REQ);
        break;

    case IBV_ACK_CQ_EVENT:
        *rsp_size = sizeof(struct IBV_ACK_CQ_EVENT_RSP);
        header.body_size = sizeof(struct IBV_ACK_CQ_EVENT_REQ);
        break;

    case IBV_CREATE_AH:
        *rsp_size = sizeof(struct IBV_CREATE_AH_RSP);
        header.body_size = sizeof(struct IBV_CREATE_AH_REQ);
        break;

    case IBV_DESTROY_AH:
        *rsp_size = sizeof(struct IBV_DESTROY_AH_RSP);
        header.body_size = sizeof(struct IBV_DESTROY_AH_REQ);
        break;

    case IBV_CREATE_FLOW:
        *rsp_size = sizeof(struct IBV_CREATE_FLOW_RSP);
        header.body_size = sizeof(struct IBV_CREATE_FLOW_REQ);
        break;

    case IBV_DESTROY_FLOW:
        *rsp_size = sizeof(struct IBV_DESTROY_FLOW_RSP);
        header.body_size = sizeof(struct IBV_DESTROY_FLOW_REQ);
        break;

    case IBV_CREATE_SRQ:
        *rsp_size = sizeof(struct IBV_CREATE_SRQ_RSP);
        header.body_size = sizeof(struct IBV_CREATE_SRQ_REQ);
        break;

    case IBV_MODIFY_SRQ:
        *rsp_size = sizeof(struct IBV_MODIFY_SRQ_RSP);
        header.body_size = sizeof(struct IBV_MODIFY_SRQ_REQ);
        break;

    case IBV_DESTROY_SRQ:
        *rsp_size = sizeof(struct IBV_DESTROY_SRQ_RSP);
        header.body_size = sizeof(struct IBV_DESTROY_SRQ_REQ);
        break;

    default:
        fprintf(stderr, "request function cannot switch.");
        break;
    }
    int n;
    if ((n = write(*sock, &header, sizeof(header))) < sizeof(header))
    {
        if (n < 0)
        {
            fprintf(stderr, "router disconnected in writing req header.");
            return 1;
        }
        else
        {
            printf("partial write.\n");
        }
    }
    if (header.body_size > 0)
    {
        if ((n = write(*sock, req_body, header.body_size)) < header.body_size)
        {
            if (n < 0)
            {
                printf("router disconnected in writing req body.\n");
                fflush(stdout);
                return 1;
            }
            else
            {
                printf("partial write.\n");
            }
        }
    }
    if (!fixed_size_rsp)
    {
        struct FfrResponseHeader rsp_hr;
        int bytes = 0;
        while (bytes < sizeof(rsp_hr))
        {
            n = read(*sock, ((char *)&rsp_hr) + bytes, sizeof(rsp_hr) - bytes);
            if (n < 0)
            {
                printf("router disconnected when reading rsp.\n");
                fflush(stdout);
                *sock = -1;
                return 1;
            }
            bytes = bytes + n;
        }

        *rsp_size = rsp_hr.rsp_size;
    }
    int bytes = 0;
    memset(rsp, 0, *rsp_size);
    while (bytes < *rsp_size)
    {
        n = read(*sock, (char *)rsp + bytes, *rsp_size - bytes);
        if (n < 0)
        {
            printf("router disconnected when reading rsp.\n");
            fflush(stdout);
            return 1;
        }
        bytes = bytes + n;
    }
    return 0;
}

int custom_ffr_init_source(int *sock, struct cm_con_data_t *local_con_data)
{
    int rsp_size = sizeof(cm_con_data_t);
    struct FfrRequestHeader header;
    header.client_id = atoi("80");
    header.func = RDMA_1;
    header.body_size = 0;

    int n;
    if ((n = write(*sock, &header, sizeof(header))) < sizeof(header))
    {
        if (n < 0)
        {
            fprintf(stderr, "router disconnected in writing req header.");
            return 1;
        }
        else
        {
            printf("partial write.\n");
        }
    }

    int bytes = 0;
    while (bytes < rsp_size)
    {
        n = read(*sock, local_con_data + bytes, rsp_size - bytes);
        if (n < 0)
        {
            printf("router disconnected when reading rsp.\n");
            fflush(stdout);
            return 1;
        }
        bytes = bytes + n;
    }
}

int custom_ffr_init_source_2(int *sock, struct cm_con_data_t *remote_con_data)
{

    int rsp_size = sizeof(struct tempres);
    struct FfrRequestHeader header;
    header.client_id = atoi("80");
    header.func = RDMA_2;
    header.body_size = sizeof(struct cm_con_data_t);
    fprintf(stdout, "Remote address = 0x%" PRIx64 "\n", remote_con_data->addr);

    int n;
    if ((n = write(*sock, &header, sizeof(header))) < sizeof(header))
    {
        if (n < 0)
        {
            fprintf(stderr, "router disconnected in writing req header.");
            return 1;
        }
        else
        {
            printf("partial write.\n");
        }
    }
    if (header.body_size > 0)
    {
        if ((n = write(*sock, remote_con_data, header.body_size)) < header.body_size)
        {
            if (n < 0)
            {
                printf("router disconnected in writing req body.\n");
                fflush(stdout);
                return 1;
            }
            else
            {
                printf("partial write.\n");
            }
        }
    }
    int bytes = 0;
    struct tempres result;
    while (bytes < rsp_size)
    {
        n = read(*sock, &result + bytes, rsp_size - bytes);
        if (n < 0)
        {
            printf("router disconnected when reading rsp.\n");
            fflush(stdout);
            return 1;
        }
        bytes = bytes + n;
    }

    if (result.res)
    {
        fprintf(stderr, "source 2 failed");
        return 1;
    }

    return 0;
}

int custom_ffr_init_source_3(int *sock)
{
    int rsp_size = sizeof(struct tempres);
    struct FfrRequestHeader header;
    header.client_id = atoi("80");
    header.func = RDMA_3;
    header.body_size = 0;

    int n;
    if ((n = write(*sock, &header, sizeof(header))) < sizeof(header))
    {
        if (n < 0)
        {
            fprintf(stderr, "router disconnected in writing req header.");
            return 1;
        }
        else
        {
            printf("partial write.\n");
        }
    }
    int bytes = 0;
    struct tempres result;
    while (bytes < rsp_size)
    {
        n = read(*sock, &result + bytes, rsp_size - bytes);
        if (n < 0)
        {
            printf("router disconnected when reading rsp.\n");
            fflush(stdout);
            return 1;
        }
        bytes = bytes + n;
    }
    if (result.res)
    {
        fprintf(stderr, "source 3 failed");
        return 1;
    }
    return 0;
}
int custom_ffr_init_source_4(int *sock, struct cm_con_data_t *remote_con_data)
{

    int rsp_size = sizeof(struct tempres);
    struct FfrRequestHeader header;
    header.client_id = atoi("80");
    header.func = RDMA_4;
    header.body_size = sizeof(struct cm_con_data_t);

    int n;
    if ((n = write(*sock, &header, sizeof(header))) < sizeof(header))
    {
        if (n < 0)
        {
            fprintf(stderr, "router disconnected in writing req header.");
            return 1;
        }
        else
        {
            printf("partial write.\n");
        }
    }
    if (header.body_size > 0)
    {
        if ((n = write(*sock, remote_con_data, header.body_size)) < header.body_size)
        {
            if (n < 0)
            {
                printf("router disconnected in writing req body.\n");
                fflush(stdout);
                return 1;
            }
            else
            {
                printf("partial write.\n");
            }
        }
    }
    int bytes = 0;
    struct tempres result;
    while (bytes < rsp_size)
    {
        n = read(*sock, &result + bytes, rsp_size - bytes);
        if (n < 0)
        {
            printf("router disconnected when reading rsp.\n");
            fflush(stdout);
            return 1;
        }
        bytes = bytes + n;
    }
    if (result.res)
    {
        fprintf(stderr, "source 2 failed");
        return 1;
    }
    return 0;
}

int custom_ffr_init_source_5(int *sock)

{

    int rsp_size = sizeof(struct tempres);
    struct FfrRequestHeader header;
    header.client_id = atoi("80");
    header.func = RDMA_5;
    header.body_size = 0;

    int n;
    if ((n = write(*sock, &header, sizeof(header))) < sizeof(header))
    {
        if (n < 0)
        {
            fprintf(stderr, "router disconnected in writing req header.");
            return 1;
        }
        else
        {
            printf("partial write.\n");
        }
    }
    int bytes = 0;
    struct tempres result;
    while (bytes < rsp_size)
    {
        n = read(*sock, &result + bytes, rsp_size - bytes);
        if (n < 0)
        {
            printf("router disconnected when reading rsp.\n");
            fflush(stdout);
            return 1;
        }
        bytes = bytes + n;
    }
    if (result.res)
    {
        fprintf(stderr, "source 5 failed");
        return 1;
    }
    return 0;
}

// ===================拆分的小函数=======================

/**
 * 自定义函数用于打开InfiniBand设备
 *
 * @param sock 指向一个整型变量，作为与设备通信的套接字描述符
 *
 * @return 返回0表示成功，非0表示失败
 *
 * 此函数通过向路由器发送请求来打开InfiniBand设备它不接受任何输入参数，
 * 但需要一个套接字描述符来与路由器通信如果通信成功，设备将被打开，
 * 否则，函数将打印错误消息并返回失败代码
 */
int custom_ibv_open_device(int *sock, int *async_fd, int *num_comp_vectors)
{
    int rc = 0;
    struct SXQ_IBV_OPEN_DEVICE_RSP rsp;
    int rsp_size = sizeof(struct SXQ_IBV_OPEN_DEVICE_RSP);
    rc = request_ffrouter(sock, SXQ_IBV_OPEN_DEVICE, NULL, &rsp, &rsp_size);
    *async_fd = rsp.async_fd;
    *num_comp_vectors = rsp.num_comp_vectors;
    return rc;
}

/**
 * Queries the attributes of a specified port.
 *
 * This function sends a query request for the attributes of a specified port to the router through a socket, and the router responds with the port attributes.
 * The purpose is to obtain the current state and capabilities of the port.
 *
 * @param sock Pointer to the socket file descriptor for communication with the router.
 * @param port_num The port number to query.
 * @param port_attr Pointer to the structure where the obtained port attributes are stored.
 * @return Returns 0 on success, a negative value on failure.
 *
 * Note: This function relies on the request_ffrouter function to send the request and receive the response. It assumes that request_ffrouter has been implemented.
 */
int custom_ibv_query_port(int *sock, int port_num, struct ibv_port_attr *port_attr)
{
    // Initialize the return value to 0
    int rc = 0;

    // Define the response structure for the query port
    struct IBV_QUERY_PORT_REQ req;
    req.port_num = port_num;
    struct IBV_QUERY_PORT_RSP rsp;

    int rsp_size = sizeof(struct IBV_QUERY_PORT_RSP);

    // Send the query port request to the router and receive the response
    rc = request_ffrouter(sock, IBV_QUERY_PORT, &req, &rsp, &rsp_size);
    *port_attr = rsp.port_attr;
    // Return the result of the request
    return rc;
}

/**
 * 分配保护域（Protection Domain）资源函数
 *
 * @param sock 套接字文件描述符，用于与FFRouter通信
 * @param pd_handle 用于存储分配的保护域句柄的指针
 * @return 返回分配保护域资源的结果，0表示成功，非0表示失败
 *
 * 此函数通过向FFRouter发送请求来分配保护域资源，并将分配的保护域句柄返回给调用者
 * 保护域是InfiniBand架构中的一个重要概念，它提供了一组资源，如内存区域和队列对，
 * 并且这些资源只能由特定的进程或线程访问，从而提供了一种资源保护机制
 */
int custom_ibv_alloc_pd(int *sock, uint32_t *pd_handle)
{
    // 初始化返回值变量
    int rc = 0;

    // 定义用于接收响应的结构体变量
    // struct SXQ_IBV_ALLOC_PD_RSP rsp;
    struct IBV_ALLOC_PD_RSP rsp;
    // 计算响应结构体的大小
    int rsp_size = sizeof(struct SXQ_IBV_ALLOC_PD_RSP);

    // 向FFRouter发送请求并接收响应
    rc = request_ffrouter(sock, IBV_ALLOC_PD, NULL, &rsp, &rsp_size);
    *pd_handle = rsp.pd_handle;
    // 返回请求结果
    return rc;
}

/**
 * 注册内存区域到保护域
 *
 * @param sock 套接字文件描述符，用于与设备通信
 * @param size 要注册的内存区域的大小
 * @param pd_handle 保护域的句柄
 * @param mr_flags 内存区域的访问标志
 * @return 如果成功，返回0；否则返回错误代码
 *
 * 此函数向设备发送请求，以在指定的保护域中注册一块内存区域
 * 它构造了注册内存区域的请求，并通过提供的套接字与设备进行通信
 * 函数首先准备请求数据结构，然后调用request_ffrouter函数发送请求并接收响应
 */
int custom_ibv_reg_mr(int *sock, int size, int pd_handle, int mr_flags, uint32_t *mr_handle, int *rkey, int *lkey, void **shm_ptr)
{
    // 初始化返回代码
    int rc = 0;

    // 响应数据结构，用于接收设备的响应
    // struct SXQ_IBV_REG_MR_RSP rsp;
    struct IBV_REG_MR_RSP rsp;
    // 响应数据结构的大小
    int rsp_size = sizeof(struct IBV_REG_MR_RSP);

    // 请求数据结构，用于向设备发送注册内存区域的请求
    struct IBV_REG_MR_REQ req = {pd_handle, size, mr_flags, '\0'};
    memset(&rsp, 0, sizeof(struct IBV_REG_MR_RSP));
    // 调用函数向设备发送请求，并接收响应
    if (request_ffrouter(sock, IBV_REG_MR, &req, &rsp, &rsp_size))
    {
        LOG_ERROR("request_ffrouter error");
        return -1;
    }
    *mr_handle = rsp.handle;
    *rkey = rsp.rkey;
    *lkey = rsp.lkey;
    LOG_INFO("shm_name: " << rsp.shm_name);
    int sh_fd = shm_open(rsp.shm_name, O_CREAT | O_RDWR, 0666);
    if (ftruncate(sh_fd, size))
    {
        LOG_ERROR("ftruncate error");
        return -1;
    }
    *shm_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, sh_fd, 0);
    if (*shm_ptr == (char *)MAP_FAILED)
    {
        LOG_ERROR("mmap error");
        return -1;
    }
    LOG_DEBUG("shm_pter : " << *shm_ptr);
    close(sh_fd);
    // 返回处理结果
    return rc;
}

int custom_ibv_create_cq(int *sock, int cqe_num, uint32_t *cq_handle, int channel_fd, int comp_vector)
{
    int rc = 0;
    // struct SXQ_IBV_CREATE_CQ_RSP rsp;
    struct IBV_CREATE_CQ_RSP rsp;
    int rsp_size = sizeof(struct SXQ_IBV_CREATE_CQ_RSP);
    // struct SXQ_IBV_CREATE_CQ_REQ req;
    struct IBV_CREATE_CQ_REQ req;
    req.channel_fd = channel_fd;
    req.comp_vector = comp_vector;
    req.cqe = cqe_num;
    rc = request_ffrouter(sock, IBV_CREATE_CQ, &req, &rsp, &rsp_size);
    *cq_handle = rsp.handle;
    return rc;
}

int custom_ibv_create_qp(int *sock, int pd_handle, enum ibv_qp_type qp_type, int send_cq_handle, int recv_cq_handle, struct ibv_qp_cap *cap, int sq_sig_all, uint32_t *qp_handle, int *qp_num)
{
    int rc = 0;
    int rsp_size = sizeof(struct IBV_CREATE_QP_RSP);
    struct IBV_CREATE_QP_REQ req;
    memset(&req, 0, sizeof(req));
    req.pd_handle = pd_handle;
    req.qp_type = qp_type;
    req.sq_sig_all = sq_sig_all;
    req.send_cq_handle = send_cq_handle;
    req.recv_cq_handle = recv_cq_handle;
    req.srq_handle = (uint32_t)-1;
    req.cap.max_recv_sge = cap->max_recv_sge;
    req.cap.max_recv_wr = cap->max_recv_wr;
    req.cap.max_send_sge = cap->max_send_sge;
    req.cap.max_send_wr = cap->max_send_wr;
    struct IBV_CREATE_QP_RSP rsp;
    rc = request_ffrouter(sock, IBV_CREATE_QP, &req, &rsp, &rsp_size);
    *qp_num = rsp.qp_num;
    *qp_handle = rsp.handle;
    *cap = rsp.cap;
    return rc;
}

int custom_ibv_query_gid(int *sock, int port_num, int gid_index, union ibv_gid *gid)
{
    int rc = 0;
    struct SXQ_IBV_QUERY_GID_REQ req;
    req.gid_index = gid_index;
    req.port_num = port_num;
    struct SXQ_IBV_QUERY_GID_RSP rsp;
    int rsp_size = sizeof(rsp);
    rc = request_ffrouter(sock, SXQ_IBV_QUERY_GID, &req, &rsp, &rsp_size);
    memcpy(gid, &rsp.gid, 16);
    return rc;
}

int custom_ibv_modify_qp(int *sock, int qp_hanle, struct ibv_qp_attr *attr, int flags, int *res)
{
    int rc = 0;
    struct IBV_MODIFY_QP_REQ req;
    memset(&req, 0, sizeof(req));
    struct IBV_MODIFY_QP_RSP rsp;
    req.handle = (uint32_t)qp_hanle;
    req.attr = *attr;
    req.attr_mask = (uint32_t)flags;
    int rsp_size = sizeof(struct IBV_MODIFY_QP_RSP);
    rc = request_ffrouter(sock, IBV_MODIFY_QP, &req, &rsp, &rsp_size);
    *res = rsp.ret;
    qp_hanle = rsp.handle;
    return rc;
}

int custom_ibv_query_qp(int *sock, int qp_handle, struct ibv_qp_attr *attr, int *attr_mask, struct ibv_qp_init_attr *init_attr)
{
    int rc = 0;
    struct SXQ_IBV_QUERY_QP_REQ req;
    struct SXQ_IBV_QUERY_QP_RSP rsp;
    req.qp_handle = qp_handle;
    int rsp_size = sizeof(struct SXQ_IBV_QUERY_QP_RSP);
    rc = request_ffrouter(sock, SXQ_IBV_QUERY_QP, &req, &rsp, &rsp_size);
    *attr = rsp.qp_attr;
    *attr_mask = rsp.qp_attr_mask;
    *init_attr = rsp.qp_init_attr;
    return rc;
}

int custom_ibv_post_recv(int *sock, int qp_handle, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr)
{
    // 需要考虑批量发送的情况，以及wr和sge的拷贝以及传递
    int rc = 0;
    struct ibv_recv_wr *i;
    struct ibv_sge *sge_start;
    struct ibv_recv_wr *w_start, *tmp = NULL;
    uint32_t wr_count = 0, sge_count = 0, ret_errno;
    struct IBV_POST_RECV_REQ req;
    int j = 0;
    for (i = wr; i; i = i->next)
    {
        wr_count++;
        sge_count += i->num_sge;
    }
    size_t total_size = sizeof(struct ib_uverbs_post_recv) + wr_count * sizeof(struct ibv_recv_wr) + sge_count * sizeof(struct ibv_sge);
    struct ib_uverbs_post_recv *cmd = (struct ib_uverbs_post_recv *)calloc(1, total_size);
    cmd->qp_handle = (uint32_t)qp_handle;
    cmd->wr_count = (uint32_t)wr_count;
    cmd->sge_count = (uint32_t)sge_count;
    w_start = (struct ibv_recv_wr *)((void *)cmd + sizeof *cmd);
    sge_start = (struct ibv_sge *)(w_start + wr_count);
    tmp = w_start;
    for (i = wr; i; i = i->next)
    {
        memcpy(tmp, i, sizeof(struct ibv_recv_wr));
        tmp->sg_list = sge_start;
        if (tmp->num_sge)
        {
            memcpy(sge_start, i->sg_list, sizeof(struct ibv_sge) * tmp->num_sge);
        }
        tmp++;
    }
    struct IBV_POST_RECV_RSP rsp;
    req.wr = (char *)cmd;
    req.wr_size = sizeof *cmd + wr_count * sizeof *w_start + sge_count * sizeof *sge_start;
    int rsp_size = sizeof(struct IBV_POST_RECV_RSP);
    rc = request_ffrouter(sock, IBV_POST_RECV, &req, &rsp, &rsp_size);
    wr_count = rsp.bad_wr;
    if (wr_count)
    {
        i = wr;
        while (--wr_count)
            i = i->next;
        *bad_wr = i;
        rc = 1;
    }
    else if (rsp.ret_errno)
    {
        *bad_wr = wr;
        rc = 1;
    }
    free(cmd);
    return rc;
}

int custom_ibv_post_send(int *sock, int qp_handle, struct ibv_send_wr *sr, struct ibv_send_wr **bad_wr)
{
    // 需要考虑批量发送的情况，以及wr和sge的拷贝以及传递
    int rc = 0;
    struct ibv_send_wr *i;
    struct ibv_sge *sge_start;
    struct ibv_send_wr *s_start, *tmp = NULL;
    uint32_t sr_count = 0, sge_count = 0, ret_errno;
    struct IBV_POST_SEND_REQ req;
    int j = 0;
    for (i = sr; i; i = i->next)
    {
        sr_count++;
        sge_count += i->num_sge;
    }
    size_t total_size = sizeof(struct ib_uverbs_post_send) + sr_count * sizeof(struct ibv_send_wr) + sge_count * sizeof(struct ibv_sge);
    struct ib_uverbs_post_send *cmd = (struct ib_uverbs_post_send *)calloc(1, total_size);
    cmd->qp_handle = (uint32_t)qp_handle;
    cmd->wr_count = (uint32_t)sr_count;
    cmd->sge_count = (uint32_t)sge_count;

    s_start = (struct ibv_send_wr *)((void *)cmd + sizeof *cmd);
    sge_start = (struct ibv_sge *)(s_start + sr_count);
    tmp = s_start;
    for (i = sr; i; i = i->next)
    {
        memcpy(tmp, i, sizeof(struct ibv_send_wr));
        tmp->sg_list = sge_start;
        if (tmp->num_sge)
        {
            memcpy(sge_start, i->sg_list, sizeof(struct ibv_sge) * tmp->num_sge);
        }
        tmp++;
    }

    struct IBV_POST_SEND_RSP rsp;
    int rsp_size = sizeof(struct IBV_POST_SEND_RSP);
    req.wr = (char *)cmd;
    req.wr_size = sizeof *cmd + sr_count * sizeof *s_start + sge_count * sizeof *sge_start;
    rc = request_ffrouter(sock, IBV_POST_SEND, &req, &rsp, &rsp_size);
    free(cmd);
    sr_count = rsp.bad_wr;
    if (sr_count)
    {
        i = sr;
        while (--sr_count)
            i = i->next;
        *bad_wr = i;
        rc = 1;
    }
    else if (rsp.ret_errno)
    {
        *bad_wr = sr;
        rc = 1;
    }
    return rc;
}

int custom_ibv_poll_cq(int *sock, int cq_handle, int num_entries, struct ibv_wc *wc)
{
    struct IBV_POLL_CQ_REQ req;
    req.cq_handle = cq_handle;
    req.ne = num_entries;
    struct ibv_wc *wc_list = NULL;
    printf("sizeof(struct ibv_wc): %zu\n", sizeof(struct ibv_wc));
    if (num_entries <= 0 || num_entries > 10000000)
    {
        LOG_ERROR("num_entries is invalid" << num_entries);
        return -1;
    }
    else
    {
        wc_list = (struct ibv_wc *)calloc(1, sizeof(struct ibv_wc));
    }

    int rsp_size = sizeof(struct IBV_POLL_CQ_RSP);
    if (request_ffrouter(sock, IBV_POLL_CQ, &req, wc_list, &rsp_size))
    {
        return -1;
    }
    if (rsp_size % sizeof(struct ibv_wc) != 0)
    {
        LOG_ERROR("rsp_size %d is not a multiple of sizeof(struct ibv_wc)");
        return -1;
    }
    int count = rsp_size / sizeof(struct ibv_wc);
    memcpy((char *)wc, (char const *)wc_list, rsp_size);
    free(wc_list);
    return count;
}

int custom_ibv_destory_cq(int *sock, int cq_handle, int *res)
{
    struct IBV_DESTROY_CQ_REQ req;
    req.cq_handle = cq_handle;
    struct IBV_DESTROY_CQ_RSP rsp;
    int rsp_size = sizeof(struct IBV_DESTROY_CQ_RSP);
    if (request_ffrouter(sock, IBV_DESTROY_CQ, &req, &rsp, &rsp_size))
    {
        return -1;
    }
    *res = rsp.ret;
    return 0;
}

int custom_ibv_destroy_qp(int *sock, int qp_handle, int *res)
{
    struct IBV_DESTROY_QP_REQ req;
    req.qp_handle = qp_handle;
    struct IBV_DESTROY_QP_RSP rsp;
    int rsp_size = sizeof(struct IBV_DESTROY_QP_RSP);
    if (request_ffrouter(sock, IBV_DESTROY_QP, &req, &rsp, &rsp_size))
    {
        return -1;
    }
    *res = rsp.ret;
    return 0;
}

int custom_ibv_dealloc_pd(int *sock, int pd_handle, int *res)
{
    struct IBV_DEALLOC_PD_REQ req;
    req.pd_handle = pd_handle;
    struct IBV_DEALLOC_PD_RSP rsp;
    int rsp_size = sizeof(struct IBV_DEALLOC_PD_RSP);
    if (request_ffrouter(sock, IBV_DEALLOC_PD, &req, &rsp, &rsp_size))
    {
        return -1;
    }
    *res = rsp.ret;
    return 0;
}

int custom_ibv_dereg_mr(int *sock, int mr_handle, int *res)
{
    struct IBV_DEREG_MR_REQ req;
    req.handle = mr_handle;
    struct IBV_DEREG_MR_RSP rsp;
    int rsp_size = sizeof(struct IBV_DEREG_MR_RSP);
    if (request_ffrouter(sock, IBV_DEREG_MR, &req, &rsp, &rsp_size))
    {
        return -1;
    }
    return 0;
}