#include "trunnel/circpad_negotiation.h"
#include "lib/evloop/timers.h"
#include <json-c/json.h>
typedef struct payment_creation_request_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} payment_creation_request_t;

typedef struct payment_creation_response_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} payment_creation_response_t;

typedef struct payment_request_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} payment_request_t;

typedef struct payment_response_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} payment_response_t;

typedef struct utility_process_command_request_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} utility_process_command_request_t;

typedef struct utility_process_command_response_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} utility_process_command_response_t;

typedef struct utility_replay_command_request_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} utility_replay_command_request_t;

typedef struct utility_replay_command_response_t {
    char* prm_1;
    char* prm_2 ;
    char* prm_3;

} utility_replay_command_response_t;


typedef struct request_response_t {
    int error_code;
    json_object* json_response ;

} request_response_t;




//public API
payment_creation_response_t*
    send_payment_request_creation(char *url, payment_creation_request_t* request);
utility_replay_command_response_t* send_utility_replay_command(char *url, utility_replay_command_request_t* request);
utility_process_command_response_t* send_process_command(char *url, utility_process_command_request_t* request);
payment_response_t* send_payment_request(char *url, payment_request_t* request);

request_response_t* send_http_request(char* url_input, json_object* body);