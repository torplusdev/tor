#include <stdbool.h>

#define CONST_ROUTE_NODE_ID_LENGTH 100


typedef struct tor_route {
    char node1[CONST_ROUTE_NODE_ID_LENGTH];
    char node2[CONST_ROUTE_NODE_ID_LENGTH];
    char node3[CONST_ROUTE_NODE_ID_LENGTH];
} tor_route;


typedef struct tor_command {
    char * commandBody;
    char * commandId;
    char * commandType;
    char * nodeId;
    char * sessionId;
} tor_command;

typedef struct payment_completed {
    char * sessionId;
    int status;
} payment_completed;


typedef struct tor_command_replay {
    char * commandResponse;
    char * commandId;
    char * nodeId;
    char * sessionId;
} tor_command_replay;

#ifdef __cplusplus
extern "C" {
#endif

int runServer(int port, void (*routeFunction)(const char* targetNode, tor_route *route),
              int (*commandProcessingFunction)(tor_command *command),
              int (*commandProcessingReplayFunction)(tor_command_replay *command),
              int (*commandProcessingCompletedFunction)(payment_completed *command));

#ifdef __cplusplus
}
#endif