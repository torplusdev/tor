#include <stdbool.h>
#include <stdlib.h>

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
    int answer_plain_text;
    void(*release)(void *);
} tor_http_api_request_t;

#ifdef __cplusplus
extern "C" {
#endif

int runServer(
        int port,
        void (*log_function)(const char *message),
        int (*handler)(tor_http_api_request_t *request) /* = nullptr*/
    );
int stopServer(void);

#ifdef __cplusplus
}
#endif
