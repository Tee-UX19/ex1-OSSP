#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFERLENGTH 256

/* displays error messages from system calls */
void error(char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int sockfd, n;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;

    char buffer[BUFFERLENGTH];
    if (argc < 4)
    {
        fprintf(stderr, "error:\nCorrect usage:\n%s hostname port <commandtype> <iprange> <portrange>\n", argv[0]);
        exit(1);
    }

    // validate arguments before connecting to server
    // extract command type, ip range and port range
    char *commandtype = argv[3];
    char *ipRange = argv[4];
    char *portRange = argv[5];

    if (*commandtype == 'A' || *commandtype == 'D' || *commandtype == 'C')
    {
        if (ipRange == NULL || portRange == NULL)
        {
            error("Invalid command for A, D, C: IP and port must be specified");
        }
    }
    else if (*commandtype == 'C')
    {
        if (ipRange == NULL || portRange == NULL)
        {
            fprintf(stderr, "Invalid IP or port\n");
            exit(1);
        }
    }
    else if (*commandtype == 'L' || *commandtype == 'R')
    {
        if (ipRange != NULL || portRange != NULL)
        {
            fprintf(stderr, "Invalid usage\n");
            exit(1);
        }
    }
    else
    {
        fprintf(stderr, "Invalid command type\n");
        exit(1);
    }
    {
        /* code */
    }

    /* Obtain address(es) matching host/port */
    /* code taken from the manual page for getaddrinfo */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0; /* Any protocol */

    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */
    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sockfd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);

        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break; /* Success */

        close(sockfd);
    }

    if (rp == NULL)
    { /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result); /* No longer needed */

    /* prepare message */
    bzero(buffer, BUFFERLENGTH);

    // combine all arguments into one string
    int i;
    for (i = 3; i < argc; i++)
    {
        if (i > 3)
        {
            strcat(buffer, " ");
        }
        strcat(buffer, argv[i]);
    }

    // check if the command is valid with a copy of the command

    /* send message */
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0)
    {
        error("ERROR writing to socket");
    }
    bzero(buffer, BUFFERLENGTH);

    /* wait for reply */
    n = read(sockfd, buffer, BUFFERLENGTH - 1);
    if (n == 0)
    {
        fprintf(stderr, "Server closed connection\n");
        close(sockfd);
        exit(1);
    }
    else if (n < 0)
    {
        error("ERROR reading from socket");
    }
    printf("%s", buffer);

    close(sockfd);
    return 0;
}
