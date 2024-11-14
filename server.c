#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFERLENGTH 256

#define IP_RANGESIZE 32
#define PORT_RANGESIZE 12

typedef struct Query
{
    char ip[16];        // The IP address checked, e.g., "192.168.1.10"
    uint16_t port;      // The port checked, e.g., 80
    struct Query *next; // Pointer to the next query in the linked list
} Query;

typedef struct Rule
{
    char ip_start[16];      // Starting IP in range, or single IP
    char ip_end[16];        // Ending IP in range; same as ip_start if it's a single IP
    uint16_t port_start;    // Starting port in range, or single port
    uint16_t port_end;      // Ending port in range; same as port_start if it's a single port
    struct Rule *next;      // Pointer to the next rule in the linked list
    Query *matched_queries; // Array of queries that matched this rule
} Rule;

typedef struct RuleSet
{
    Rule *head;  // Array of rules
    size_t size; // Number of rules in the array
} RuleSet;

typedef struct Request
{
    char command[100];
    struct Request *next;
} Request;

// function to extract ranged or single ip and port from the command, and add it to the rule

// int is_valid_port_range(const char *portStart, const char *portEnd)
// {
//     int port_start = atoi(portStart);
//     int port_end = atoi(portEnd);

//     if (port_start < 0 || port_start > 65535 || port_end < 0 || port_end > 65535 || port_start > port_end)
//     {
//         return 0; // Invalid port range
//     }

//     return 1; // Valid port range
// }

void error(char *msg)
{
    perror(msg);
    exit(0);
}

int is_valid_ip(const char *ip)
{
    int num, dots = 0;
    char *ptr;
    char ip_copy[16];
    strncpy(ip_copy, ip, 16);

    if (ip == NULL)
        return 0;

    ptr = strtok(ip_copy, ".");
    if (ptr == NULL)
        return 0;

    while (ptr)
    {
        if (!isdigit(*ptr))
            return 0;

        num = atoi(ptr);
        if (num >= 0 && num <= 255)
        {
            ptr = strtok(NULL, ".");
            if (ptr != NULL)
                dots++;
        }
        else
            return 0;
    }

    return dots == 3;
}

int is_valid_ipRange(const char *ipRange)
{
    char ipRange_copy[16];
    strncpy(ipRange_copy, ipRange, 16);
    // Split IP range
    char *ip_start = strtok(ipRange_copy, "-");
    char *ip_end = strtok(NULL, "-");
    if (ip_end == NULL)
        ip_end = ip_start; // Single IP

    if (!is_valid_ip(ip_start) || !is_valid_ip(ip_end))
    {
        return 0; // Invalid rule
    }

    return 1; // Valid rule
}

// function for A, C, D
int is_valid_rule(char *ipRange, char *portRange)
{
    if (ipRange == NULL || portRange == NULL)
    {
        return 0; // Invalid rule
    }

    // Make a copy of the ipRange and portRange
    char ipRange_copy[IP_RANGESIZE];
    char portRange_copy[PORT_RANGESIZE];
    strncpy(ipRange_copy, ipRange, sizeof(ipRange_copy) - 1);
    strncpy(portRange_copy, portRange, sizeof(portRange_copy) - 1);
    ipRange_copy[sizeof(ipRange_copy) - 1] = '\0';
    portRange_copy[sizeof(portRange_copy) - 1] = '\0';

    // Split IP range
    char *ip_start = strtok(ipRange_copy, "-");
    char *ip_end = strtok(NULL, "-");
    if (ip_start == NULL)
    {
        return 0; // Invalid IP range
    }
    if (ip_end == NULL)
        ip_end = ip_start; // Single IP

    // Split port range
    char *port_start_str = strtok(portRange_copy, "-");
    char *port_end_str = strtok(NULL, "-");
    if (port_start_str == NULL)
    {
        return 0; // Invalid port range
    }
    uint16_t port_start = atoi(port_start_str);
    uint16_t port_end = (port_end_str == NULL) ? port_start : atoi(port_end_str); // Single port

    // Validate IP addresses and ports
    if (!is_valid_ip(ip_start) || !is_valid_ip(ip_end) || port_start < 0 || port_start > 65535 || port_end < 0 || port_end > 65535)
    {
        return 0; // Invalid rule
    }

    return 1; // Valid rule
}

int is_valid_command(char *command)
{
    char command_copy[100];
    strncpy(command_copy, command, 100);
    // Split the command by whitespace
    char *commandtype = strtok(command_copy, " ");
    char *ipRange = strtok(NULL, " ");
    char *portRange = strtok(NULL, " ");

    if (commandtype == NULL){
    // {   error("Null command");
        return 0; // Invalid command
    }

    if (strncmp(commandtype, "A", 1) == 0 || strncmp(commandtype, "D", 1) == 0)
    {
        // Check for valid rule
        if (ipRange == NULL || portRange == NULL)
        {
            return 0; // Invalid rule
        }
        return is_valid_rule(ipRange, portRange);
    }
    else if (strncmp(commandtype, "C", 1) == 0)
    {
        // Check for single IP and port
        if (ipRange == NULL || portRange == NULL)
        {
            return 0; // Invalid IP or port
        }
        return is_valid_ip(ipRange) && atoi(portRange) >= 0 && atoi(portRange) <= 65535;
    }
    else if (strncmp(commandtype, "L", 1) == 0 || strncmp(commandtype, "R", 1) == 0)
    {
        // L and R should not be used with anything else
        if (ipRange != NULL || portRange != NULL)
        {
            return 0; // Invalid usage
        }
        return 1; // Valid command
    }

    return 0; // Invalid command type
}

void add_query_to_rule(Rule *rule, const char *ip, uint16_t port)
{
    Query *new_query = (Query *)malloc(sizeof(Query));
    if (!new_query)
    {
        perror("Failed to allocate memory for new query");
        return;
    }

    // Initialize the query with the given IP and port
    strncpy(new_query->ip, ip, 16);
    new_query->port = port;
    new_query->next = rule->matched_queries;

    // Add the new query to the beginning of the list of matched queries
    rule->matched_queries = new_query;
}

/* displays error messages from system calls */

// functions to handle commands with rules
void list_requests(Request *head, char *response)
{
    Request *current = head;
    int index = 1;

    if (current == NULL)
    {
        snprintf(response, BUFFERLENGTH, "No requests available.\n");
        return;
    }

    // Clear response buffer
    response[0] = '\0';

    while (current != NULL)
    {
        char temp[BUFFERLENGTH];
        snprintf(temp, BUFFERLENGTH, "Request %d: %s\n", index++, current->command);
        strcat(response, temp);
        current = current->next;
    }
}
void add_rule(RuleSet *rules, const char *ip_start, const char *ip_end, uint16_t port_start, uint16_t port_end, char *response)
{
    bzero(response, BUFFERLENGTH);

    // Validate the IP and port ranges
    if (!is_valid_ip(ip_start) || !is_valid_ip(ip_end) ||
        port_start <= 0 || port_end >= 65535 ||
        port_start > port_end)
    {
        snprintf(response, BUFFERLENGTH, "Invalid rule\n");
        return;
    }

    Rule *new_rule = (Rule *)malloc(sizeof(Rule));
    if (!new_rule)
    {
        printf("Failed to allocate memory for new rule\n");
        return;
    }

    // Copy IP and port ranges to the rule
    strncpy(new_rule->ip_start, ip_start, 16);
    strncpy(new_rule->ip_end, ip_end ? ip_end : ip_start, 16); // If ip_end is NULL, use ip_start
    new_rule->port_start = port_start;
    new_rule->port_end = port_end ? port_end : port_start; // If port_end is 0, use port_start
    new_rule->next = NULL;
    new_rule->matched_queries = NULL;

    if (rules->head == NULL)
    {
        // If the list is empty, set the new rule as the head
        rules->head = new_rule;
    }
    else
    {
        // Traverse to the end of the list and insert the new rule
        Rule *current = rules->head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = new_rule;
    }

    rules->size++;
    snprintf(response, BUFFERLENGTH, "Rule added\n");
}

void check_rule(RuleSet *rules, char *ip, uint16_t port, char *response)
{
    bzero(response, BUFFERLENGTH);

    if (!is_valid_ip(ip) || port <= 0 || port >= 65535)
    {
        snprintf(response, BUFFERLENGTH, "Illegal IP address or port specified\n");
        return;
    }

    Rule *current = rules->head;
    struct in_addr ip_addr, ip_start_addr, ip_end_addr;

    // Convert the input IP to binary format
    if (inet_pton(AF_INET, ip, &ip_addr) != 1)
    {
        snprintf(response, BUFFERLENGTH, "Illegal IP address or port specified\n");
        return;
    }

    // Convert the input IP to a 32-bit integer in host byte order for comparison
    uint32_t ip_int = ntohl(ip_addr.s_addr);

    while (current != NULL)
    {
        // Convert rule IP start and end to binary format
        if (inet_pton(AF_INET, current->ip_start, &ip_start_addr) != 1 ||
            inet_pton(AF_INET, current->ip_end, &ip_end_addr) != 1)
        {
            snprintf(response, BUFFERLENGTH, "Illegal IP address or port \n");
            current = current->next;
            continue;
        }

        // Convert rule IP start and end to host byte order for accurate comparison
        uint32_t ip_start_int = ntohl(ip_start_addr.s_addr);
        uint32_t ip_end_int = ntohl(ip_end_addr.s_addr);

        // Check if the IP is within the IP range and port is within the port range
        if (ip_int >= ip_start_int && ip_int <= ip_end_int &&
            port >= current->port_start && port <= current->port_end)
        {

            // IP and port match, add this query to the rule's matched queries
            snprintf(response, BUFFERLENGTH, "Connection accepted\n");
            add_query_to_rule(current, ip, port);
            return; // Exit after finding the first matching rule
        }
        current = current->next;
    }

    // If no match is found, reject the connection
    snprintf(response, BUFFERLENGTH, "Connection rejected\n");
}

void free_rules(RuleSet *rules)
{
    Rule *current = rules->head;
    while (current != NULL)
    {
        Rule *next = current->next;
        free(current);
        current = next;
    }
    rules->head = NULL;
    rules->size = 0;
}

void list_rules(RuleSet *rules, char *response)
{
    Rule *current = rules->head;
    char temp[BUFFERLENGTH];

    if (current == NULL)
    {
        snprintf(response, BUFFERLENGTH, "No rules available\n");
        return;
    }

    // Clear response buffer
    response[0] = '\0';

    while (current != NULL)
    {
        // Accumulate each rule's info
        if (strcmp(current->ip_start, current->ip_end) == 0)
        {
            snprintf(temp, BUFFERLENGTH, "Rule: %s %d\n",
                     current->ip_start, current->port_start);
        }
        else
        {
            snprintf(temp, BUFFERLENGTH, "Rule: %s-%s %d-%d\n",
                     current->ip_start, current->ip_end,
                     current->port_start, current->port_end);
        }
        if (current->matched_queries != NULL)
        {
            strcat(temp, "Matched queries:\n");
            Query *query = current->matched_queries;
            while (query != NULL)
            {
                char query_temp[BUFFERLENGTH];
                snprintf(query_temp, BUFFERLENGTH, "IP: %s, Port: %d\n", query->ip, query->port);
                strcat(temp, query_temp);
                query = query->next;
            }
        }

        strcat(response, temp);
        current = current->next;
    }
}

void delete_rule(RuleSet *rules, char *ip_start, char *ip_end, uint16_t port_start, uint16_t port_end, char *response)
{
    bzero(response, BUFFERLENGTH);

    if (!is_valid_ip(ip_start) || !is_valid_ip(ip_end) ||
        port_start <= 0 || port_end >= 65535 ||
        port_start > port_end)
    {
        snprintf(response, BUFFERLENGTH, "Invalid rule\n");
        return;
    }
    Rule *current = rules->head;
    Rule *previous = NULL;

    while (current != NULL)
    {
        // Check if the rule matches the specified IP and port range
        if (strcmp(current->ip_start, ip_start) == 0 && strcmp(current->ip_end, ip_end) == 0 &&
            current->port_start == port_start && current->port_end == port_end)
        {
            // Rule found, delete it
            if (previous == NULL)
            {
                // The rule to be deleted is the head of the list
                rules->head = current->next;
            }
            else
            {
                // The rule to be deleted is in the middle or end of the list
                previous->next = current->next;
            }

            free(current);
            rules->size--;
            snprintf(response, BUFFERLENGTH, "Rule deleted\n");
            return;
        }

        previous = current;
        current = current->next;
    }

    snprintf(response, BUFFERLENGTH, "Rule not found\n");
}

int main(int argc, char **argv)
{

    Request *head = NULL;
    RuleSet rules = {NULL, 0};
    char response[BUFFERLENGTH];

    // RuleSet rules= {NULL, 0};
    // linked list of requests

    if (argc < 2 || argc > 2)
    {
        fprintf(stderr, "usage %s <port> or normal mode %s -i for interactive mode\n", argv[0], argv[0]);
        exit(1);
    }

    else if (strcmp(argv[1], "-i") == 0 && argc == 2)
    {
        // printf("Server running in interactive mode. use \"exit\" to exit\n");

        while (1)
        {
            char command[100];
            bzero(response, BUFFERLENGTH);
            
            // if(feof(stdin)){
            //     break;
            // }

            // printf("\n Enter command: ");
            if (fgets(command, sizeof(command), stdin) == NULL)
            {
                break;
            }
            // remove newline character
            command[strcspn(command, "\n")] = 0;

            // if(!is_valid_command(command)){
            //     error("Invalid command");
            // }

            if (strncmp(command, "exit", 4) == 0)
            {
                exit(0);
            }

            Request *new_request = (Request *)malloc(sizeof(Request));
            if (!new_request)
            {
                perror("Failed to allocate memory for new request");
                return 1;
            }
            strncpy(new_request->command, command, 100);
            new_request->next = NULL;
            if (head == NULL)
            {
                head = new_request;
            }
            else
            {
                Request *current = head;
                while (current->next != NULL)
                {
                    current = current->next;
                }
                current->next = new_request;
            }
            // temp rule obj to extract single ip and port or rannged ip and port
            //  Rule temp_rule;

            char *commandtype = strtok(command, " ");
            char *ipAddress = strtok(NULL, " ");
            char *port = strtok(NULL, " ");
            // printf("Command: %s, IP: %s, Port: %s\n", commandtype, ipAddress, port);
            // printf("Command: %s, IP: %s, Port: %s\n", commandtype, ipAddress, port);

            // check or split ip and port into start and end
            char *ip_start = strtok(ipAddress, "-");
            char *ip_end = strtok(NULL, "-");
            if (ip_end == NULL)
                ip_end = ip_start; // Single IP

            // // Split port range
            char *port_start = strtok(port, "-");
            char *port_end = strtok(NULL, "-");
            if (port_end == NULL)
                port_end = port_start; // Single port

            // printf("IP start: %s, IP end: %s, Port start: %s, Port end: %s\n", ip_start, ip_end, port_start, port_end);

            // Parse and handle each command
            if (strncmp(commandtype, "A", 1) == 0)
            {
                // Handle "Add rule" command
                add_rule(&rules, ip_start, ip_end, atoi(port_start), atoi(port_end), response);
                printf("%s", response);
            }
            else if (strncmp(commandtype, "D", 1) == 0)
            {
                // Handle "Delete rule" command

                delete_rule(&rules, ip_start, ip_end, atoi(port_start), atoi(port_end), response);
                printf("%s", response);
            }
            else if (strncmp(commandtype, "L", 1) == 0)
            {
                // Handle "List rules" command
                if (is_valid_command(command))
                {
                    list_rules(&rules, response);
                    printf("%s", response);
                }
                else
                {
                    snprintf(response, BUFFERLENGTH, "Invalid use of command L. L should be only argument\n");
                    printf("%s", response);
                }
            }
            else if (strncmp(commandtype, "C", 1) == 0)
            {
                // Handle "Check rule" command
                if (is_valid_ip(ipAddress) && atoi(port_start) > 0 && atoi(port_end) < 65535 && atoi(port_start) <= atoi(port_end) && is_valid_rule(ipAddress, port))
                {
                    check_rule(&rules, ipAddress, atoi(port), response);
                    printf("%s", response);
                }
                else
                {
                    snprintf(response, BUFFERLENGTH, "Illegal IP address or port specified\n");
                    printf("%s", response);
                }
            }
            else if (strncmp(commandtype, "R", 1) == 0)
            {
                // remove R requests from list of requests

                list_requests(head, response);
                printf("%s", response);
            }
            else
            {
                snprintf(response, BUFFERLENGTH, "Illegal Request\n");
                printf("%s", response);
            }
        }
    }
    else
    {
        // Implement server's regular mode (e.g., listening on a socket)
        socklen_t clilen;
        int sockfd, newsockfd, portno;
        char buffer[BUFFERLENGTH];
        struct sockaddr_in6 serv_addr, cli_addr;
        int n;
        if (argc < 2)
        {
            fprintf(stderr, "ERROR, no port provided\n");
            exit(1);
        }

        /* create socket */
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            error("ERROR opening socket");
        }

        int yes = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
        {
            error("ERROR setting socket options");
        }

        bzero((char *)&serv_addr, sizeof(serv_addr));
        portno = atoi(argv[1]);
        serv_addr.sin6_family = AF_INET6;
        serv_addr.sin6_addr = in6addr_any;
        serv_addr.sin6_port = htons(portno);

        /* bind it */
        if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            error("ERROR on binding");
        }

        /* ready to accept connections */
        listen(sockfd, 5);
        clilen = sizeof(cli_addr);

        /* now wait in an endless loop for connections and process them */
        while (1)
        {
            /* waiting for connections */
            newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
            if (newsockfd < 0)
            {
                error("ERROR on accept");
            }
            bzero(buffer, BUFFERLENGTH);
            bzero(response, BUFFERLENGTH);

            /* read the data */
            n = read(newsockfd, buffer, BUFFERLENGTH - 1);
            if (n < 0)
            {
                error("ERROR reading from socket");
            }

            // Process command using your existing handlers
            bzero(response, BUFFERLENGTH);

            // Store request
            Request *new_request = (Request *)malloc(sizeof(Request));
            if (new_request)
            {
                strncpy(new_request->command, buffer, 100);
                new_request->next = NULL;
                if (head == NULL)
                {
                    head = new_request;
                }
                else
                {
                    Request *current = head;
                    while (current->next != NULL)
                    {
                        current = current->next;
                    }
                    current->next = new_request;
                }
            }

            printf("Here is the message: %s\n", buffer);

            char command_copy[100];
            strncpy(command_copy, buffer, 100);
            // Split the command by whitespace
            char *commandtype = strtok(command_copy, " ");
            char *ipRange = strtok(NULL, " ");
            char *portRange = strtok(NULL, " ");

            // check or split ip and port into start and end
            char *ip_start = strtok(ipRange, "-");
            char *ip_end = strtok(NULL, "-");
            if (ip_end == NULL)
                ip_end = ip_start; // Single IP

            // Split port range
            char *port_start = strtok(portRange, "-");
            char *port_end = strtok(NULL, "-");
            if (port_end == NULL)
                port_end = port_start; // Single port

            if (strncmp(commandtype, "A", 1) == 0)
            {
                // Handle "Add rule" command

                add_rule(&rules, ip_start, ip_end, atoi(port_start), atoi(port_end), response);
                printf("%s", response);
            }
            else if (strncmp(commandtype, "D", 1) == 0)
            {
                // Handle "Delete rule" command

                delete_rule(&rules, ip_start, ip_end, atoi(port_start), atoi(port_end), response);
                printf("%s", response);
            }
            else if (strncmp(commandtype, "L", 1) == 0)
            {
                // Handle "List rules" command
                if (is_valid_command(command_copy))
                {
                    list_rules(&rules, response);
                    printf("%s", response);
                }
                else
                {
                    snprintf(response, BUFFERLENGTH, "Invalid use of command L. L should be only argument\n");
                    printf("%s", response);
                }
            }
            else if (strncmp(commandtype, "C", 1) == 0)
            {
                // Handle "Check rule" command
                if (is_valid_ipRange(ipRange) && atoi(port_start) > 0 && atoi(port_end) < 65535 && atoi(port_start) <= atoi(port_end) && is_valid_rule(ipRange, portRange))
                {
                    check_rule(&rules, ipRange, atoi(portRange), response);
                    printf("%s", response);
                }
                else
                {
                    snprintf(response, BUFFERLENGTH, "Illegal IP address or port specified\n");
                    printf("%s", response);
                }
            }
            else if (strncmp(commandtype, "R", 1) == 0)
            {
                list_requests(head, response);
                printf("%s", response);
            }
            else
            {
                snprintf(response, BUFFERLENGTH, "Illegal Request\n");
                printf("%s", response);
            }

            /* send the reply back */
            n = write(newsockfd, response, strlen(response));
            if (n < 0)
            {
                error("ERROR writing to socket");
            }

            close(newsockfd); /* important to avoid memory leak */
        }

        return 0;
    }

    return 0;
}
