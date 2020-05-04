#include "trunnel/circpad_negotiation.h"
#include "lib/evloop/timers.h"
#include <json-c/json.h>

typedef struct  routing_node {
    char* node_id;
    char* address;
} routing_node_t;

typedef struct create_payment_info {
    char* service_type;
    char* commodity_type;
    int amount;
} create_payment_info_t;

typedef struct process_payment_request {
    routing_node_t routing_node[3];
    char* ll_back_url; 		        // process command url
    char* payment_request;	        // json body
    char* node_id;           		// request reference identification

} process_payment_request_t;

typedef struct utility_command{
    int command_type;
    char* command_body;
} utility_command_t;

typedef struct utility_response{
    char* command_id;
    char* response_body;
    char* node_id;
} utility_response_t;


typedef struct payment_response_t {
    char* response_body;

} payment_response_t;

//public API
payment_response_t*
create_payment_info(char *url, create_payment_info_t* request); //1
payment_response_t*
process_payment(char *url, process_payment_request_t* request); //2
payment_response_t*
process_command(char *url, utility_command_t* request); //4
payment_response_t*
process_response(char *url, utility_response_t* request); //5

char* send_http_request(char* url_input, json_object* body);
