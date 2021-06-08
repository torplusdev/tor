#ifndef __PAYMENT_HTTP_CLIENT_H__INCLUDED__
#define __PAYMENT_HTTP_CLIENT_H__INCLUDED__

#include "trunnel/circpad_negotiation.h"
#include "lib/evloop/timers.h"
#include <json-c/json.h>
#include <src/core/or/origin_circuit_st.h>

typedef struct log_args_st {
    const char *url;
    const char* requestBody;
    const char* responseBody;
} log_args_t;

typedef struct  routing_node {
    char* node_id;
    char* address;
} routing_node_t;

typedef struct create_payment_info {
    const char* service_type;
    const char* commodity_type;
    int amount;
} create_payment_info_t;

typedef struct process_payment_request {
    routing_node_t* routing_node;
    char* call_back_url; 		        // process command url
    char* status_call_back_url; 		        // process command url
    char* payment_request;	        // json body
    char* node_id;           		// request reference identification
    char* session_id;

} process_payment_request_t;

typedef struct utility_command{
    int command_type;
    char* command_body;
    char* callback_url;
    char* command_id;
    char* node_id;
    char* session_id;
} utility_command_t;

typedef struct utility_response{
    char* command_id;
    char* response_body;
    char* node_id;
    char* session_id;
} utility_response_t;


typedef struct payment_response_t {
    char* response_body;

} payment_response_t;

char* tp_create_payment_info(char *url, create_payment_info_t* request); //1
payment_response_t* tp_http_payment(char *url, process_payment_request_t* request, int hup_num); //2
payment_response_t* tp_http_command(char *url, utility_command_t* request); //4
payment_response_t* tp_http_response(char *url, utility_response_t* request); //5
void ship_log(log_args_t* args);
json_object* tp_http_get_request(const char* url_input);
char* tp_http_post_request(const char* url_input, const char* json);

#endif // __PAYMENT_HTTP_CLIENT_H__INCLUDED__