#include <stdbool.h>
#include <stdlib.h>

#ifndef MAX_HEX_NICKNAME_LEN
    #define HEX_DIGEST_LEN_ 40
    #define MAX_HEX_NICKNAME_LEN (HEX_DIGEST_LEN_+1)
#endif
#ifndef STELLAR_ADDRESS_LEN
    #define STELLAR_ADDRESS_LEN 100
#endif
#ifndef SESSION_ID_LEN
    #define SESSION_ID_LEN 40
#endif

typedef struct tor_http_api_request_param_st{
    const char *name;
    const char *value;
} tor_http_api_request_param_t;

typedef struct tor_http_api_request_st {
    const char *method;
    const char *url;
    const char *body;
    size_t param_count;
    tor_http_api_request_param_t *params;
    char *answer_body;
    void(*release)(void *);
} tor_http_api_request_t;

typedef struct tor_command {
    const char * commandBody;
    const char * commandId;
    const char * commandType;
    const char * nodeId;
    const char * sessionId;
    const char * json_body;
} tor_command;

typedef struct payment_completed {
    const char * sessionId;
    int status;
    const char * json_body;
} payment_completed;

typedef struct tor_command_replay {
    const char * commandResponse;
    const char * commandId;
    const char * nodeId;
    const char * sessionId;
    const char * json_body;
    const char * commandType;
} tor_command_replay;

#ifdef __cplusplus
extern "C" {
#endif

int runServer(
        int port,
        int (*commandProcessingFunction)(tor_command *command),
        int (*commandProcessingReplayFunction)(tor_command_replay *command),
        int (*commandProcessingCompletedFunction)(payment_completed *command),
        void (*log_function)(const char *message),
        const char *appVersionString /*= NULL*/,
        int (*handler)(tor_http_api_request_t *request) /* = nullptr*/
    );
int stopServer(void);

#ifdef __cplusplus
}
#endif
