////#include <assert.h>
////#include <stdint.h>
////#include <stdlib.h>
////#include <string.h>
////#include <stdio.h>
////#include <errno.h>
////#include <unistd.h>
////#include <arpa/inet.h>
////#include <sys/socket.h>
////#include <netinet/ip.h>
////#include <string>
////#include <vector>
////// proj
////#include "common.h"
////
////
////static void msg(const char *msg) {
////    fprintf(stderr, "%s\n", msg);
////}
////
////static void die(const char *msg) {
////    int err = errno;
////    fprintf(stderr, "[%d] %s\n", err, msg);
////    abort();
////}
////
////static int32_t read_full(int fd, char *buf, size_t n) {
////    while (n > 0) {
////        ssize_t rv = read(fd, buf, n);
////        if (rv <= 0) {
////            return -1;  // error, or unexpected EOF
////        }
////        assert((size_t)rv <= n);
////        n -= (size_t)rv;
////        buf += rv;
////    }
////    return 0;
////}
////
////static int32_t write_all(int fd, const char *buf, size_t n) {
////    while (n > 0) {
////        ssize_t rv = write(fd, buf, n);
////        if (rv <= 0) {
////            return -1;  // error
////        }
////        assert((size_t)rv <= n);
////        n -= (size_t)rv;
////        buf += rv;
////    }
////    return 0;
////}
////
////const size_t k_max_msg = 4096;
////
////static int32_t send_req(int fd, const std::vector<std::string> &cmd) {
////    uint32_t len = 4;
////    for (const std::string &s : cmd) {
////        len += 4 + s.size();
////    }
////    if (len > k_max_msg) {
////        return -1;
////    }
////
////    char wbuf[4 + k_max_msg];
////    memcpy(&wbuf[0], &len, 4);  // assume little endian
////    uint32_t n = cmd.size();
////    memcpy(&wbuf[4], &n, 4);
////    size_t cur = 8;
////    for (const std::string &s : cmd) {
////        uint32_t p = (uint32_t)s.size();
////        memcpy(&wbuf[cur], &p, 4);
////        memcpy(&wbuf[cur + 4], s.data(), s.size());
////        cur += 4 + s.size();
////    }
////    return write_all(fd, wbuf, 4 + len);
////}
////
////static int32_t on_response(const uint8_t *data, size_t size) {
////    if (size < 1) {
////        msg("bad response");
////        return -1;
////    }
////    switch (data[0]) {
////    case SER_NIL:
////        printf("(nil)\n");
////        return 1;
////    case SER_ERR:
////        if (size < 1 + 8) {
////            msg("bad response");
////            return -1;
////        }
////        {
////            int32_t code = 0;
////            uint32_t len = 0;
////            memcpy(&code, &data[1], 4);
////            memcpy(&len, &data[1 + 4], 4);
////            if (size < 1 + 8 + len) {
////                msg("bad response");
////                return -1;
////            }
////            printf("(err) %d %.*s\n", code, len, &data[1 + 8]);
////            return 1 + 8 + len;
////        }
////    case SER_STR:
////        if (size < 1 + 4) {
////            msg("bad response");
////            return -1;
////        }
////        {
////            uint32_t len = 0;
////            memcpy(&len, &data[1], 4);
////            if (size < 1 + 4 + len) {
////                msg("bad response");
////                return -1;
////            }
////            printf("(str) %.*s\n", len, &data[1 + 4]);
////            return 1 + 4 + len;
////        }
////    case SER_INT:
////        if (size < 1 + 8) {
////            msg("bad response");
////            return -1;
////        }
////        {
////            int64_t val = 0;
////            memcpy(&val, &data[1], 8);
////            printf("(int) %ld\n", val);
////            return 1 + 8;
////        }
////    case SER_DBL:
////        if (size < 1 + 8) {
////            msg("bad response");
////            return -1;
////        }
////        {
////            double val = 0;
////            memcpy(&val, &data[1], 8);
////            printf("(dbl) %g\n", val);
////            return 1 + 8;
////        }
////    case SER_ARR:
////        if (size < 1 + 4) {
////            msg("bad response");
////            return -1;
////        }
////        {
////            uint32_t len = 0;
////            memcpy(&len, &data[1], 4);
////            printf("(arr) len=%u\n", len);
////            size_t arr_bytes = 1 + 4;
////            for (uint32_t i = 0; i < len; ++i) {
////                int32_t rv = on_response(&data[arr_bytes], size - arr_bytes);
////                if (rv < 0) {
////                    return rv;
////                }
////                arr_bytes += (size_t)rv;
////            }
////            printf("(arr) end\n");
////            return (int32_t)arr_bytes;
////        }
////    default:
////        msg("bad response");
////        return -1;
////    }
////}
////
////static int32_t read_res(int fd) {
////    // 4 bytes header
////    char rbuf[4 + k_max_msg + 1];
////    errno = 0;
////    int32_t err = read_full(fd, rbuf, 4);
////    if (err) {
////        if (errno == 0) {
////            msg("EOF");
////        } else {
////            msg("read() error");
////        }
////        return err;
////    }
////
////    uint32_t len = 0;
////    memcpy(&len, rbuf, 4);  // assume little endian
////    if (len > k_max_msg) {
////        msg("too long");
////        return -1;
////    }
////
////    // reply body
////    err = read_full(fd, &rbuf[4], len);
////    if (err) {
////        msg("read() error");
////        return err;
////    }
////
////    // print the result
////    int32_t rv = on_response((uint8_t *)&rbuf[4], len);
////    if (rv > 0 && (uint32_t)rv != len) {
////        msg("bad response");
////        rv = -1;
////    }
////    return rv;
////}
////
////int main(int argc, char **argv) {
////    int fd = socket(AF_INET, SOCK_STREAM, 0);
////    if (fd < 0) {
////        die("socket()");
////    }
////
////    struct sockaddr_in addr = {};
////    addr.sin_family = AF_INET;
////    addr.sin_port = ntohs(1234);
////    addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);  // 127.0.0.1
////    int rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
////    if (rv) {
////        die("connect");
////    }
////
////    std::vector<std::string> cmd;
////    for (int i = 1; i < argc; ++i) {
////        cmd.push_back(argv[i]);
////    }
////    int32_t err = send_req(fd, cmd);
////    if (err) {
////        goto L_DONE;
////    }
////    err = read_res(fd);
////    if (err) {
////        goto L_DONE;
////    }
////
////L_DONE:
////    close(fd);
////    return 0;
////}
//
//#include <iostream>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <unistd.h>
//#include <errno.h>
//#include <string.h>
//#include <pthread.h>
//#include <sys/types.h>
//#include <signal.h>
//#include <atomic>
//#include <sstream>
//#include <vector>
//
//#define MAX_CLIENTS 100
//#define BUFFER_SZ 2048
//const size_t k_max_msg = 4096;
//
//std::atomic<unsigned int> cli_count;
//static int uid = 10;
//
//int idActualMessage = 0;
////auto redisConnection = rediscpp::make_stream("localhost", "6379");
//int numberUsers = 0;
//
//typedef struct {
//    struct sockaddr_in address;
//    int sockfd;
//    int uid;
//    char name[32];
//} client_t;
//
//client_t* clients[MAX_CLIENTS];
//
//pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
//
//void str_overwrite_stdout() {
//    printf("\r%s", "> ");
//    fflush(stdout);
//}
//
//void str_trim_lf(char* arr, int length) {
//    int i;
//    for (i = 0; i < length; i++) {
//        if (arr[i] == '\n') {
//            arr[i] = '\0';
//            break;
//        }
//    }
//}
//
//void print_client_addr(struct sockaddr_in addr) {
//    printf("%d.%d.%d.%d",
//        addr.sin_addr.s_addr & 0xff,
//        (addr.sin_addr.s_addr & 0xff00) >> 8,
//        (addr.sin_addr.s_addr & 0xff0000) >> 16,
//        (addr.sin_addr.s_addr & 0xff000000) >> 24);
//}
//
//void queue_add(client_t* cl) {
//    pthread_mutex_lock(&clients_mutex);
//
//    for (int i = 0; i < MAX_CLIENTS; ++i) {
//        if (!clients[i]) {
//            clients[i] = cl;
//            break;
//        }
//    }
//
//    pthread_mutex_unlock(&clients_mutex);
//}
//
//void queue_remove(int uid) {
//    pthread_mutex_lock(&clients_mutex);
//
//    for (int i = 0; i < MAX_CLIENTS; ++i) {
//        if (clients[i]) {
//            if (clients[i]->uid == uid) {
//                clients[i] = NULL;
//                break;
//            }
//        }
//    }
//    pthread_mutex_unlock(&clients_mutex);
//}
//
//void broadcastMessage(const char* message) {
//    for (int i = 0; i < MAX_CLIENTS; ++i) {
//        if (clients[i] && strlen(message) != 0) {
//            write(clients[i]->sockfd, message, strlen(message));
//        }
//    }
//}
//
//void sendLastMessages(void) {
//    pthread_mutex_lock(&clients_mutex);
//
//    int oldMessage = idActualMessage - 20;
//    while (oldMessage < 0)
//        oldMessage++;
//    for (; oldMessage < idActualMessage; oldMessage++) {
//        try {
//            auto const oldMessageStr = std::to_string(oldMessage);
//            //rediscpp::execute_no_flush(*redisConnection, "get", oldMessageStr);
//            //std::flush(*redisConnection);
//            //rediscpp::value value{*redisConnection};
//
//            auto messageReturned = value.as<std::string>();
//            int n = messageReturned.size();
//
//            char messageReturnedChar[n + 1];
//            strcpy(messageReturnedChar, messageReturned.c_str());
//
//            char const* idChar = std::to_string(oldMessage).c_str();
//            broadcastMessage(idChar);
//            broadcastMessage(" -> ");
//            broadcastMessage(messageReturnedChar);
//        }
//        catch (std::exception const&) {}
//    }
//    pthread_mutex_unlock(&clients_mutex);
//}
//
//void printHeader(void) {
//    const char* header = "== COCUS CHAT ROOM ==\n\n";
//    broadcastMessage(header);
//}
//
//void clearScreen(void) {
//    pthread_mutex_lock(&clients_mutex);
//    const char* clearMessage = "system-clear";
//    broadcastMessage(clearMessage);
//    usleep(100000);
//    pthread_mutex_unlock(&clients_mutex);
//}
//
//void setRedis(char* message) {
//    std::string messageSet(message);
//    auto const idActualMessageString = std::to_string(idActualMessage);
//    //static_cast<void>(rediscpp::execute(*redisConnection, "set", idActualMessageString, messageSet));
//
//    if (idActualMessage > 19) {
//        auto const itemDel = std::to_string(idActualMessage - 20);
//        //static_cast<void>(rediscpp::execute(*redisConnection, "del", itemDel));
//    }
//    idActualMessage++;
//    clearScreen();
//    printHeader();
//    sendLastMessages();
//}
//
//std::string getMessageOwner(int idMessage) {
//    //static_cast<void>(rediscpp::execute_no_flush(*redisConnection, "get", std::to_string(idMessage)));
//    //std::flush(*redisConnection);
//    //rediscpp::value value{*redisConnection};
//    //auto messageReturned = value.as<std::string>();
//    //size_t operator_position = messageReturned.find_first_of(":");
//    //std::string messageOwner = messageReturned.substr(0, operator_position);
//    //return messageOwner;
//}
//
//void remove_message(std::string user, std::string command) {
//    std::string numberDeleted = command.substr(5);
//
//    std::stringstream intValue(numberDeleted);
//    int numberInt = 0;
//    intValue >> numberInt;
//
//    try {
//        std::string messageOwner = getMessageOwner(numberInt);
//
//        if (messageOwner == user) {
//            //static_cast<void>(rediscpp::execute(*redisConnection, "del", std::to_string(numberInt)));
//            std::cout << user << " removed message: " << numberInt << std::endl;
//        }
//        else {
//            std::cout <<
//                user << " tried to remove message: " <<
//                numberInt << " but this was write by " <<
//                messageOwner << std::endl;
//        }
//
//    }
//
//    catch (std::exception const&) {
//        std::cout << "message doesn't exist" << std::endl;
//    }
//    clearScreen();
//    printHeader();
//    sendLastMessages();
//}
//
//void* handle_client(void* arg) {
//    char buff_out[BUFFER_SZ];
//    char name[32];
//    int leave_flag = 0;
//
//    cli_count++;
//    client_t* cli = (client_t*)arg;
//
//    if (recv(cli->sockfd, name, 32, 0) <= 0 || strlen(name) < 2 || strlen(name) >= 32 - 1) {
//        printf("Didn't enter the name.\n");
//        leave_flag = 1;
//    }
//    else {
//        strcpy(cli->name, name);
//        std::cout << name << " has joined" << std::endl;
//        sprintf(buff_out, "%s has joined\n", cli->name);
//
//        //setRedis(buff_out);
//        numberUsers++;
//    }
//
//    bzero(buff_out, BUFFER_SZ);
//
//    while (1) {
//        if (leave_flag) {
//            break;
//        }
//
//        int receive = recv(cli->sockfd, buff_out, BUFFER_SZ, 0);
//        if (receive > 0) {
//            printf("%s", buff_out);
//            std::string bufferIn(buff_out),
//                name,
//                command;
//
//            size_t operator_position = bufferIn.find_first_of(":");
//            name = bufferIn.substr(0, operator_position);
//            command = bufferIn.substr(operator_position + 2);
//
//            if (command.find("--rm") != std::string::npos) {
//                remove_message(name, command);
//            }
//            else {
//                if (strlen(buff_out) > 0) {
//                    //setRedis(buff_out);
//                }
//            }
//        }
//        else if (receive == 0 || strcmp(buff_out, "exit") == 0) {
//            std::cout << name << " has left" << std::endl;
//            sprintf(buff_out, "%s has left\n", cli->name);
//            //setRedis(buff_out);
//            numberUsers--;
//            if (numberUsers < 1) {
//                int idActual = idActualMessage - 20;
//                while (idActual < 0)
//                    idActual++;
//                for (; idActual < idActualMessage; idActual++) {
//                    auto const itemDel = std::to_string(idActual);
//                    //static_cast<void>(rediscpp::execute(*redisConnection, "del", itemDel));
//                }
//                idActualMessage = 0;
//            }
//            leave_flag = 1;
//        }
//        else {
//            printf("ERROR: -1\n");
//            leave_flag = 1;
//        }
//
//        bzero(buff_out, BUFFER_SZ);
//    }
//
//    close(cli->sockfd);
//    queue_remove(cli->uid);
//    free(cli);
//    cli_count--;
//    pthread_detach(pthread_self());
//
//    return NULL;
//}
//
//int main(int argc, char** argv) {
//    int fd = socket(AF_INET, SOCK_STREAM, 0);
//    if (fd < 0) {
//        fprintf(stderr, "socket()");
//        return EXIT_FAILURE;
//    }
//
//    struct sockaddr_in addr = {};
//    addr.sin_family = AF_INET;
//    addr.sin_port = ntohs(1234);
//    addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);
//    int rv = connect(fd, (const struct sockaddr*)&addr, sizeof(addr));
//    if (rv) {
//        fprintf(stderr, "connect");
//        return EXIT_FAILURE;
//    }
//
//    std::vector<std::string> cmd;
//    for (int i = 1; i < argc; ++i) {
//        cmd.push_back(argv[i]);
//    }
//
//    // Now the client becomes a chatroom server as well
//    if (argc == 2) {
//        const char* ip = "127.0.0.1";
//        int port = atoi(argv[1]);
//        int option = 1;
//        int listenfd = 0, connfd = 0;
//        struct sockaddr_in serv_addr;
//        struct sockaddr_in cli_addr;
//        pthread_t tid;
//
//        signal(SIGPIPE, SIG_IGN);
//
//        if (setsockopt(listenfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR), (char*)&option, sizeof(option)) < 0) {
//            perror("ERROR: setsockopt failed");
//            return EXIT_FAILURE;
//        }
//
//        listenfd = socket(AF_INET, SOCK_STREAM, 0);
//        serv_addr.sin_family = AF_INET;
//        serv_addr.sin_addr.s_addr = inet_addr(ip);
//        serv_addr.sin_port = htons(port);
//
//        if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
//            perror("ERROR: Socket binding failed");
//            return EXIT_FAILURE;
//        }
//
//        if (listen(listenfd, 10) < 0) {
//            perror("ERROR: Socket listening failed");
//            return EXIT_FAILURE;
//        }
//
//        printf("=== CHAT ROOM COCUS C++ ===\n");
//
//        while (1) {
//            socklen_t clilen = sizeof(cli_addr);
//            connfd = accept(listenfd, (struct sockaddr*)&cli_addr, &clilen);
//
//            if ((cli_count + 1) == MAX_CLIENTS) {
//                printf("Max clients reached. Rejected: ");
//                print_client_addr(cli_addr);
//                printf(":%d\n", cli_addr.sin_port);
//                close(connfd);
//                continue;
//            }
//
//            client_t* cli = (client_t*)malloc(sizeof(client_t));
//            cli->address = cli_addr;
//            cli->sockfd = connfd;
//            cli->uid = uid++;
//
//            queue_add(cli);
//            pthread_create(&tid, NULL, &handle_client, (void*)cli);
//
//            sleep(1);
//        }
//    }
//
//L_DONE:
//    close(fd);
//    return 0;
//}

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <pthread.h>
#include <vector>
#include <string>
#include <iostream>

// proj
#include "common.h"

const size_t k_max_msg = 4096;
const int MAX_CLIENTS = 10;

struct ClientInfo {
    int fd;
    struct sockaddr_in addr;
};

static std::vector<ClientInfo> clients;

static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

static void msg(const char* msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char* msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static int32_t read_full(int fd, char* buf, size_t n) {
    while (n > 0) {
        ssize_t rv = read(fd, buf, n);
        if (rv <= 0) {
            return -1;  // error, or unexpected EOF
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

static int32_t write_all(int fd, const char* buf, size_t n) {
    while (n > 0) {
        ssize_t rv = write(fd, buf, n);
        if (rv <= 0) {
            return -1;  // error
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

static void broadcast(const std::string& message) {
    pthread_mutex_lock(&clients_mutex);
    for (const auto& client : clients) {
        write_all(client.fd, message.c_str(), message.size());
    }
    pthread_mutex_unlock(&clients_mutex);
}

static void* client_handler(void* arg) {
    int client_fd = *(int*)arg;
    char buffer[k_max_msg];
    ssize_t bytes_read;

    pthread_mutex_lock(&clients_mutex);
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    getpeername(client_fd, (struct sockaddr*)&client_addr, &client_len);

    clients.push_back({ client_fd, client_addr });
    pthread_mutex_unlock(&clients_mutex);

    while ((bytes_read = read(client_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        std::string message(buffer);
        printf("Received message from %s:%d: %s", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), message.c_str());

        // Broadcast the message to all clients
        broadcast(message);
    }

    // Client disconnected
    printf("Client %s:%d disconnected\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    pthread_mutex_unlock(&clients_mutex);

    close(client_fd);
    return NULL;
}

static int32_t send_req(int fd, const std::vector<std::string>& cmd) {
    uint32_t len = 4;
    for (const std::string& s : cmd) {
        len += 4 + s.size();
    }
    if (len > k_max_msg) {
        return -1;
    }

    char wbuf[4 + k_max_msg];
    memcpy(&wbuf[0], &len, 4);  // assume little endian
    uint32_t n = cmd.size();
    memcpy(&wbuf[4], &n, 4);
    size_t cur = 8;
    for (const std::string& s : cmd) {
        uint32_t p = (uint32_t)s.size();
        memcpy(&wbuf[cur], &p, 4);
        memcpy(&wbuf[cur + 4], s.data(), s.size());
        cur += 4 + s.size();
    }
    return write_all(fd, wbuf, 4 + len);
}

static int32_t read_res(int fd) {
    // 4 bytes header
    char rbuf[4 + k_max_msg + 1];
    errno = 0;
    int32_t err = read_full(fd, rbuf, 4);
    if (err) {
        if (errno == 0) {
            msg("EOF");
        }
        else {
            msg("read() error");
        }
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, rbuf, 4);  // assume little endian
    if (len > k_max_msg) {
        msg("too long");
        return -1;
    }

    // reply body
    err = read_full(fd, &rbuf[4], len);
    if (err) {
        msg("read() error");
        return err;
    }

    // print the result
    uint32_t rescode = 0;
    if (len < 4) {
        msg("bad response");
        return -1;
    }
    memcpy(&rescode, &rbuf[4], 4);
    printf("server says: [%u] %.*s\n", rescode, len - 4, &rbuf[8]);
    return 0;
}

static void start_server() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        die("socket()");
    }

    struct sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1234);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        die("bind()");
    }

    if (listen(server_fd, 5) < 0) {
        die("listen()");
    }

    printf("Server listening on port 1234...\n");

    while (1) {
        struct sockaddr_in client_addr = {};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            msg("accept() error");
            continue;
        }
    }

    close(server_fd);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        // Client mode
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            die("socket()");
        }

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = ntohs(1234);
        addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);  // 127.0.0.1
        int rv = connect(fd, (const struct sockaddr*)&addr, sizeof(addr));
        if (rv) {
            die("connect");
        }

        std::vector<std::string> cmd;
        for (int i = 1; i < argc; ++i) {
            cmd.push_back(argv[i]);
        }
        int32_t err = send_req(fd, cmd);
        if (err) {
            goto L_DONE;
        }
        err = read_res(fd);
        if (err) {
            goto L_DONE;
        }

    L_DONE:
        close(fd);
    }
    else {
        // Server mode
        start_server();
    }

    return 0;
}
