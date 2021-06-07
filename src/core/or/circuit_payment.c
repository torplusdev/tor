/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */


//file circuitpayment.c
//brief Circuit-level payment implementation

 
#include "core/or/or.h"
#include "core/or/circuitpadding.h"
#include "core/or/circuit_payment.h"
#include "core/or/circuitlist.h"
#include "core/or/relay.h"
#include "core/or/channel.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "core/or/crypt_path_st.h"
#include "core/or/circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "feature/nodelist/routerstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "core/or/cell_st.h"
#include "core/or/extend_info_st.h"
#include "feature/nodelist/nodelist.h"
#include "app/config/config.h"
#include "trunnel-impl.h"
#include "core/mainloop/mainloop.h"
#include <src/core/or/or_circuit_st.h>
#include "lib/version/torversion.h"

#define tm_zero_mem(buf, len) memset((buf), 0, (len))

#define TRUNNEL_SET_ERROR_CODE(obj) \
  do {                              \
    (obj)->trunnel_error_code_ = 1; \
  } while (0)

#if defined(__COVERITY__) || defined(__clang_analyzer__)
/* If we're running a static analysis tool, we don't want it to complain
 * that some of our remaining-bytes checks are dead-code. */
int sendmecell_deadcode_dummy__ = 0;
#define OR_DEADCODE_DUMMY || sendmecell_deadcode_dummy__
#else
#define OR_DEADCODE_DUMMY
#endif
#define CHECK_REMAINING(nbytes, label)                           \
  do {                                                           \
    if (remaining < (nbytes) OR_DEADCODE_DUMMY) {                \
      goto label;                                                \
    }                                                            \
  } while (0)

static smartlist_t *global_payment_session_list = NULL;
static smartlist_t *global_payment_info_list = NULL;
static smartlist_t *global_chunks_list = NULL;
static smartlist_t *payment_messsages_for_sending = NULL;
static smartlist_t *payment_curl_request = NULL;
static pthread_rwlock_t rwlock;


static error_t circuit_payment_send_command_to_hop(origin_circuit_t *circ, uint8_t hopnum, uint8_t relay_command, const uint8_t *payload, ssize_t payload_len);

static void tp_get_route(const char* sessionId, tor_route *route) {
    route->call_back_url = (char*)tor_calloc_(1, PAYMENT_URL_LEN*sizeof(char));
    route->status_call_back_url = (char*)tor_calloc_(1, PAYMENT_URL_LEN*sizeof(char));
    route->call_back_url[0] = '\0';
    route->status_call_back_url[0] = '\0';

    int callback_port = get_options()->PPChannelCallbackPort;
    // int port = get_options()->PPChannelPort;

    snprintf(route->call_back_url, PAYMENT_URL_LEN, "%s:%d/%s", "http://127.0.0.1", callback_port,"api/command");
    snprintf(route->status_call_back_url, PAYMENT_URL_LEN, "%s:%d/%s", "http://127.0.0.1", callback_port,"api/paymentComplete");

    smartlist_t *list = circuit_get_global_origin_circuit_list();
    route->nodes = NULL;
    if (list != NULL) {
        SMARTLIST_FOREACH_BEGIN(list, origin_circuit_t *, origin_circuit) {
            if (origin_circuit != NULL) {
                if (TO_CIRCUIT(origin_circuit)->state != CIRCUIT_STATE_OPEN) {
                    printf("circuit (%d) - was not opened:",
                            TO_CIRCUIT(origin_circuit)->n_circ_id);
                    continue;
                }
                if (TO_CIRCUIT(origin_circuit)->purpose != CIRCUIT_PURPOSE_C_GENERAL) {
                    printf("circuit (%d) - purpose was not general:",
                            TO_CIRCUIT(origin_circuit)->n_circ_id);

                    continue;
                }

                if (origin_circuit->path_state != PATH_STATE_BUILD_SUCCEEDED) {
                    printf("circuit (%d) - path was not use succeeded:",
                            TO_CIRCUIT(origin_circuit)->n_circ_id);

                    continue;
                }
                route->nodes = (rest_node_t *) tor_malloc_(4*sizeof(rest_node_t));

                crypt_path_t *next = origin_circuit->cpath;
                route->nodes_len = 3;
                for (int i = 0; i < route->nodes_len; ++i) {
                    if (strcmp(next->extend_info->stellar_address, "") == 0) {
                        tor_free_(route->nodes);
                        route->nodes = NULL;
                        continue;
                    }
                    route->nodes[i].node_id = (char *) tor_calloc_(1, (MAX_HEX_NICKNAME_LEN+1) * sizeof(char));
                    strncpy(route->nodes[i].node_id, next->extend_info->nickname, MAX_HEX_NICKNAME_LEN+1);
                    route->nodes[i].address = (char *) tor_calloc_(1, (STELLAR_ADDRESS_LEN) * sizeof(char));
                    strncpy(route->nodes[i].address, next->extend_info->stellar_address,STELLAR_ADDRESS_LEN);
                    next = next->next;
                }
                route->nodes_len = 3;

                set_to_session_context(sessionId, "nickname",
                    TO_CIRCUIT(origin_circuit)->n_chan->global_identifier,
                    TO_CIRCUIT(origin_circuit)->n_circ_id);

                log_args_t* log_input = tor_malloc_(sizeof(log_args_t));
                log_input->requestBody = (char*) tor_calloc_(1, 500);
                log_input->responseBody = "";

                snprintf(log_input->requestBody, 500, "[%s:%s],[%s:%s],[%s:%s]", route->nodes[0].node_id, route->nodes[0].address,
                /*log_input->requestBody,*/ route->nodes[1].node_id, route->nodes[1].address,
                /*log_input->requestBody,*/ route->nodes[2].node_id, route->nodes[2].address);

                log_input->url = "/api/paymentRoute";
                ship_log(log_input);

                tor_free_((void *)log_input->requestBody);
                tor_free_(log_input);
                return;
            }
        } SMARTLIST_FOREACH_END(origin_circuit);
    }
}

static int tp_payment_chain_completed(payment_completed* command)
{
    payment_message_for_sending_t* message = tor_malloc(sizeof(payment_message_for_sending_t));
    message->nodeId = "-1";
    message->sessionId = command->sessionId;
    message->message = NULL;
    smartlist_add(payment_messsages_for_sending, message);
    log_args_t log_input;
    char request[200];
    snprintf(request, 200, "{\"SessionId\":%s, \"Status\":%d}", command->sessionId, command->status);
    log_input.responseBody="";
    log_input.requestBody=request;
    log_input.url = "/api/paymentComplete";
    ship_log(&log_input);
    return 0;
}

static void divideString(List_of_str_t* output, char *str, int len, int n)
{
    int str_size = len;
    int i;
    int part_size;
    part_size = str_size / n;
    int oddment = str_size % n;


// Check if string can be divided in
// n equal parts
    if (str_size / n == 0)
    {
        tm_zero_mem(output[0].msg, MAX_MESSAGE_LEN);
        strncpy(output[0].msg, str, str_size);
    }
// Calculate the size of parts to
// find the division points

    for (i = 0; i < part_size; i++)
    {
        tm_zero_mem(output[i].msg, MAX_MESSAGE_LEN);
        strncpy(output[i].msg, &str[i*n], n);
    }

    tm_zero_mem(output[part_size].msg, MAX_MESSAGE_LEN);
    strncpy(output[part_size].msg, &str[part_size*n], oddment);
}

static int tp_process_command(tor_command* command)
{
    const int chunck_size = MAX_MESSAGE_LEN - 1;
    int part_size = strlen(command->commandBody) / chunck_size;
    int oddment = strlen(command->commandBody) % chunck_size;
    List_of_str_t array[part_size + 1];

    divideString(array, command->commandBody, strlen(command->commandBody), chunck_size);

    pthread_rwlock_wrlock(&rwlock);

    for(int g = 0 ; g < part_size+1 ;g++) {
        payment_message_for_sending_t* message = tor_malloc(sizeof(payment_message_for_sending_t));
        OR_OP_request_t *input = tor_malloc(sizeof(OR_OP_request_t));
        input->command = RELAY_COMMAND_PAYMENT_COMMAND_TO_NODE;
        strcpy(input->nickname, command->nodeId);
        input->command_type = atoi(command->commandType);
        input->nicknameLength = strlen(command->nodeId);
        input->version = 0;
        strcpy(input->session_id, command->sessionId);
        input->session_id_length = strlen(command->sessionId);
        strcpy(input->command_id, command->commandId);
        input->command_id_length = strlen(command->commandId);
        strncpy(input->message, array[g].msg, chunck_size);
        if (g < part_size) {

            input->message[chunck_size] = '\0';
            input->messageLength = chunck_size;
            input->is_last = 0;
        } else {
            input->message[oddment] = '\0';
            input->messageLength = oddment;
            input->is_last = 1;
        }

        message->message = input;
        message->nodeId = command->nodeId;
        message->sessionId = command->sessionId;
        smartlist_add(payment_messsages_for_sending, message);
    }
    log_args_t log_input;
    char request[10000];
    snprintf(request, 10000,"{\"CommandBody\":%s, \"CommandId\":%s, \"CommandType\":%s, \"NodeId\":%s, \"SessionId\":%s},",
            command->commandBody, command->commandId, command->commandType, command->nodeId, command->sessionId);
    log_input.responseBody="";
    log_input.requestBody=request;

    log_input.url = "/api/command";
    ship_log(&log_input);

    pthread_rwlock_unlock(&rwlock);
    return 0;
}

static int tp_process_command_replay(tor_command_replay* command)
{
    //tor_command_replay* command = ((thread_args_main_t*)args)->tor_command_replay;

    int chunck_size = MAX_MESSAGE_LEN - 1;

    int part_size = strlen(command->commandResponse) / chunck_size;
    int oddment = strlen(command->commandResponse) % chunck_size;
    List_of_str_t array[part_size + 1];

    divideString(array, command->commandResponse, strlen(command->commandResponse), chunck_size);


    pthread_rwlock_wrlock(&rwlock);
    for(int g = 0 ; g < part_size+1 ;g++) {
        payment_message_for_sending_t* message = tor_malloc(sizeof(payment_message_for_sending_t));
        OR_OP_request_t *input = tor_malloc(sizeof(OR_OP_request_t));
        input->command = RELAY_COMMAND_PAYMENT_COMMAND_TO_NODE;
        strcpy(input->nickname, command->nodeId);
        input->command_type = 0;
        input->nicknameLength = strlen(command->nodeId);
        input->version = 0;

        input->message_type = 4;
        strcpy(input->session_id, command->sessionId);
        input->session_id_length = strlen(command->sessionId);
        strcpy(input->command_id, command->commandId);
        input->command_id_length = strlen(command->commandId);
        strncpy(input->message, array[g].msg, chunck_size);
        if (g < part_size) {
            input->is_last = 0;
            input->message[chunck_size] = '\0';
            input->messageLength = chunck_size;
        }
        else {
            input->message[oddment] = '\0';
            input->messageLength = oddment;
            input->is_last = 1;
        }
        message->message = input;
        message->sessionId = command->sessionId;
        message->nodeId = command->nodeId;
        smartlist_add(payment_messsages_for_sending, message);
    }
    log_args_t log_input;
    char request[10000];
    log_input.responseBody="";
    snprintf(request, 10000, "{\"CommandResponse\":%s, \"CommandId\":%s, \"NodeId\":%s, \"SessionId\":%s},",
            command->commandResponse, command->commandId, command->nodeId, command->sessionId);

    log_input.requestBody=request;
    log_input.url = "/api/response";
    ship_log(&log_input);
    pthread_rwlock_unlock(&rwlock);

    return 0;
}

static void add_payment_curl_request(thread_args_t* args){
    smartlist_add(payment_curl_request, args);
}

void tp_init()
{
  or_options_t *options = get_options_mutable();
  int request_port = get_options()->PPChannelPort;
  char url[PAYMENT_URL_LEN];
  snprintf(url, PAYMENT_URL_LEN, "%s:%d/%s", "http://127.0.0.1", request_port, "api/utility/stellarAddress");
  char* stellar = get_stellar_address(url)->address;
  if(NULL == stellar)
  {
      stellar = "";
  }
  options->StellarAddress = stellar;
  int port = options->PPChannelCallbackPort;
  payment_messsages_for_sending = smartlist_new();
  payment_curl_request = smartlist_new();
  if ( port != -1 ) {
    const char *server_version_string = get_version();
    runServer(port, tp_get_route, tp_process_command, tp_process_command_replay, tp_payment_chain_completed, server_version_string);
  }
}

static const node_t* circuit_payment_get_nth_node(origin_circuit_t *circ, int hop) {
    crypt_path_t *iter = circuit_get_cpath_hop(circ, hop);

    if (!iter || iter->state != CPATH_STATE_OPEN)
        return NULL;

    return node_get_by_id(iter->extend_info->identity_digest);
}

static error_t circuit_payment_send_OP(circuit_t *circ, uint8_t target_hopnum, OR_OP_request_t* input)
{


    cell_t cell;
    ssize_t len;

    origin_circuit_t* orig_circ = TO_ORIGIN_CIRCUIT(circ);

    if (!circuit_payment_get_nth_node(orig_circ, target_hopnum)) {
        return 0;
    }

    memset(&cell, 0, sizeof(cell_t));

    cell.command = CELL_RELAY;

    if ((len = circuit_payment_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE, input)) < 0)
        return 0;

    error_t res = circuit_payment_send_command_to_hop(orig_circ, target_hopnum,
                                               RELAY_COMMAND_PAYMENT_COMMAND_TO_NODE,
                                               cell.payload, len);


    return res;
}

static error_t circuit_payment_send_OR(circuit_t *circ, OR_OP_request_t* input)
{
    uint8_t payload[RELAY_PAYLOAD_SIZE];
    ssize_t len;
    if (CIRCUIT_IS_ORIGIN(circ))
        return 0;
    if ((len = circuit_payment_negotiate_encode(payload, CELL_PAYLOAD_SIZE,  input)) < 0)
        return 0;
    return circuit_payment_send_command_to_origin(circ,
        RELAY_COMMAND_PAYMENT_COMMAND_TO_ORIGIN, payload, len);
}

static error_t circuit_payment_send_command_to_hop(origin_circuit_t *circ, uint8_t hopnum,uint8_t relay_command, const uint8_t *payload, ssize_t payload_len) {
    crypt_path_t *target_hop = circuit_get_cpath_hop(circ, hopnum);
    error_t ret;

/* Check that the cpath has the target hop */
    if (!target_hop) {
        log_fn(LOG_WARN, LD_BUG, "Padding circuit %u has %d hops, not %d",
               circ->global_identifier, circuit_get_cpath_len(circ), hopnum);
        return 0;
    }

/* Check that the target hop is opened */
    if (target_hop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_WARN, LD_CIRC,
               "Padding circuit %u has %d hops, not %d",
               circ->global_identifier,
               circuit_get_cpath_opened_len(circ), hopnum);
        return 0;
    }

/* Send the drop command to the hop */
    ret = relay_send_command_from_edge(0, TO_CIRCUIT(circ), relay_command,
                                       (void*)payload, (size_t)payload_len,
                                       target_hop);
    return ret;
}

error_t circuit_payment_send_command_to_origin(circuit_t *circ, uint8_t relay_command, const uint8_t *payload, ssize_t payload_len) {
    error_t ret;

/* Send the drop command to the origin */
    ret = relay_send_command_from_edge(0, circ, relay_command,
                                       (void*)payload, (size_t)payload_len,
                                       NULL);
    return ret;
}


static OR_OP_request_t* circuit_payment_handle_payment_negotiate(const cell_t *cell){
    OR_OP_request_t *negotiate;

    if (circuit_payment_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                                        CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_CIRC,
               "Received malformed PADDING_NEGOTIATE cell; dropping.");
        return NULL;
    }

    return negotiate;
}

static void circuit_payment__free(OR_OP_request_t *obj)
{
    if (obj == NULL)
        return;
    trunnel_memwipe(obj, sizeof(circpad_negotiate_t));
    trunnel_free_(obj);
}

ssize_t circuit_payment_negotiate_parse(OR_OP_request_t **output, const uint8_t *input, const size_t len_in)
{
    ssize_t result;
    *output = payment_payload_new();
    if (NULL == *output)
        return -1;
    result = payment_into(*output, input, len_in);
    if (result < 0) {
        circuit_payment__free(*output);
        *output = NULL;
    }
    return result;
}

OR_OP_request_t * payment_payload_new(void)
{
    OR_OP_request_t *val = tor_malloc_(sizeof(OR_OP_request_t));
    if (NULL == val)
        return NULL;
    val->command = CELL_PAYMENT;
    return val;
}



ssize_t
payment_into(OR_OP_request_t *obj, const uint8_t *input, const size_t len_in)
{
    const uint8_t *ptr = input;
    size_t remaining = len_in;
    ssize_t result = 0;
    (void)result;

    /* Parse u8 version IN [0] */
    CHECK_REMAINING(1, truncated);
    obj->version = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;

    /* Parse u8 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(1, truncated);
    obj->command = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;

    /* Parse u8 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(1, truncated);
    obj->message_type = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;

    /* Parse u8 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(1, truncated);
    obj->is_last = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;

    /* Parse u8 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(2, truncated);
    obj->command_type = (trunnel_get_int16(ptr));
    remaining -= 2; ptr += 2;

    CHECK_REMAINING(2, truncated);
    obj->session_id_length = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;

    /* Parse char name[len] */
    CHECK_REMAINING(SESSION_ID_LEN, fail);
    memcpy(obj->session_id, ptr, SESSION_ID_LEN);
    remaining -= SESSION_ID_LEN; ptr += SESSION_ID_LEN;

    CHECK_REMAINING(2, truncated);
    obj->command_id_length = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;

    /* Parse char name[len] */
    CHECK_REMAINING(COMMAND_ID_LEN, fail);
    memcpy(obj->command_id, ptr, COMMAND_ID_LEN);
    remaining -= COMMAND_ID_LEN; ptr += COMMAND_ID_LEN;

    CHECK_REMAINING(2, truncated);
    obj->nicknameLength = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;


    /* Parse char name[len] */
    CHECK_REMAINING(USER_NAME_LEN, fail);
    memcpy(obj->nickname, ptr, USER_NAME_LEN);
    remaining -= USER_NAME_LEN; ptr += USER_NAME_LEN;

    CHECK_REMAINING(2, truncated);
    obj->messageLength = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;

    /* Parse char name[len] */
    CHECK_REMAINING(MAX_MESSAGE_LEN, fail);
    memcpy(obj->message, ptr, MAX_MESSAGE_LEN);
    remaining -= MAX_MESSAGE_LEN; ptr += MAX_MESSAGE_LEN;

    CHECK_REMAINING(2, truncated);
    obj->messageTotalLength = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;

    trunnel_assert(ptr + remaining == input + len_in);
    return len_in - remaining;

    truncated:
    return -2;
    fail:
    result = -1;
    return result;
}

ssize_t circuit_payment_negotiate_encode(uint8_t *output, const size_t avail, const OR_OP_request_t *obj)
{
    ssize_t result = 0;
    size_t written = 0;
    uint8_t *ptr = output;
#ifdef TRUNNEL_CHECK_ENCODED_LEN
    const ssize_t encoded_len = circpad_negotiate_encoded_len(obj);
#endif

#ifdef TRUNNEL_CHECK_ENCODED_LEN
    trunnel_assert(encoded_len >= 0);
#endif

    /* Encode u8 version IN [0] */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->version));
    written += 1; ptr += 1;

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->command));
    written += 1; ptr += 1;

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->message_type));
    written += 1; ptr += 1;

    /* Encode u8 command IN  */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->is_last));
    written += 1; ptr += 1;

    /* Encode u8 command IN  */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_int16(ptr, (obj->command_type));
    written += 2; ptr += 2;

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->session_id_length));
    written += 2; ptr += 2;

    /* Encode u4 data[TRUNNEL_PAYMENT_LEN] */
    trunnel_assert(written <= avail);
    if (avail - written < SESSION_ID_LEN)
        goto truncated;
    memcpy(ptr, obj->session_id,SESSION_ID_LEN);
    written += SESSION_ID_LEN; ptr += SESSION_ID_LEN;
    trunnel_assert(ptr == output + written);

 /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->command_id_length));
    written += 2; ptr += 2;

    /* Encode u4 data[TRUNNEL_PAYMENT_LEN] */
    trunnel_assert(written <= avail);
    if (avail - written < COMMAND_ID_LEN)
        goto truncated;
    memcpy(ptr, obj->command_id,COMMAND_ID_LEN);
    written += COMMAND_ID_LEN; ptr += COMMAND_ID_LEN;
    trunnel_assert(ptr == output + written);

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->nicknameLength));
    written += 2; ptr += 2;

    /* Encode u4 data[TRUNNEL_PAYMENT_LEN] */
    trunnel_assert(written <= avail);
    if (avail - written < USER_NAME_LEN)
        goto truncated;
    memcpy(ptr, obj->nickname,USER_NAME_LEN);
    written += USER_NAME_LEN; ptr += USER_NAME_LEN;
    trunnel_assert(ptr == output + written);

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->messageLength));
    written += 2; ptr += 2;

    trunnel_assert(written <= avail);
    if (avail - written < MAX_MESSAGE_LEN)
        goto truncated;
    memcpy(ptr, obj->message, MAX_MESSAGE_LEN);
    written += MAX_MESSAGE_LEN; ptr += MAX_MESSAGE_LEN;
    trunnel_assert(ptr == output + written);

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->messageTotalLength));
    written += 2; ptr += 2;

#ifdef TRUNNEL_CHECK_ENCODED_LEN
    {
    trunnel_assert(encoded_len >= 0);
    trunnel_assert((size_t)encoded_len == written);
  }

#endif

    return written;

    truncated:
    result = -2;
    goto fail;
    result = -1;
    goto fail;
    fail:
    trunnel_assert(result < 0);
    return result;
}


int
circuit_get_num_by_nickname(origin_circuit_t * circ, char* nickname)
{
    char nickname_array[USER_NAME_LEN];
    strcpy(nickname_array, nickname);

    int n = 1;
    if(strcmp(circ->cpath->extend_info->nickname, nickname) == 0)
        return 1;
    if (circ != NULL && circ->cpath != NULL) {
        crypt_path_t *cpath, *cpath_next = NULL;
        for (cpath = circ->cpath;
             cpath->state == CPATH_STATE_OPEN
             && cpath_next != circ->cpath;
             cpath = cpath_next) {
            cpath_next = cpath->next;
            ++n;
            if(cpath_next->extend_info == NULL) return 0;
            if(strcmp(cpath_next->extend_info->nickname, nickname_array) == 0)
                return n;
        }
    }
    return 0;
}

static int circuit_get_length(origin_circuit_t * circ)
{
    int n = 0;
    if (circ != NULL && circ->cpath != NULL) {
        crypt_path_t *cpath, *cpath_next = NULL;
        for (cpath = circ->cpath;
             cpath->state == CPATH_STATE_OPEN
             && cpath_next != circ->cpath;
             cpath = cpath_next) {
            cpath_next = cpath->next;
            ++n;
            if(cpath_next->extend_info == NULL) return n;
        }
    }
    return n;
}

static extend_info_t* circuit_get_extended_data_by_nickname(origin_circuit_t * circ, char* nickname)
{
    char nickname_array[USER_NAME_LEN];
    strcpy(nickname_array, nickname);
    int n = 1;
    if(strcmp(circ->cpath->extend_info->nickname, nickname) == 0)
        return circ->cpath->extend_info;
    if (circ != NULL && circ->cpath != NULL) {
        crypt_path_t *cpath, *cpath_next = NULL;
        for (cpath = circ->cpath;
             cpath->state == CPATH_STATE_OPEN
             && cpath_next != circ->cpath;
             cpath = cpath_next) {
            cpath_next = cpath->next;
            ++n;
            if(strcmp(cpath_next->extend_info->nickname, nickname_array) == 0)
                return cpath_next->extend_info;
        }
    }
    return NULL;
}

void set_to_session_context(const char* session, const char* nickname, uint64_t channel_global_id, uint32_t circuit_id) {

    if (NULL == global_payment_session_list)
        global_payment_session_list = smartlist_new();

    payment_session_context_t *origin = NULL;

    SMARTLIST_FOREACH_BEGIN(global_payment_session_list, payment_session_context_t *, element)
                            {
                                if (strcmp(element->session_id, session) == 0) {
                                    origin = element;
                                }
                            }
    SMARTLIST_FOREACH_END(element);

    if (origin == NULL) {
        payment_session_context_t *ent = (payment_session_context_t *) tor_malloc_zero_(
                sizeof(payment_session_context_t));
        strcpy(ent->session_id, session);
        strcpy(ent->nickname, nickname);
        ent->channel_global_id = channel_global_id;
        ent->circuit_id = circuit_id;
        smartlist_add(global_payment_session_list, ent);
    } else {
        strcpy(origin->session_id, session);
        strcpy(origin->nickname, nickname);
        origin->channel_global_id = channel_global_id;
        origin->circuit_id = circuit_id;
    }
}

void set_circuit_payment_info(uint32_t circuit_id) {

    if (NULL == global_payment_info_list)
        global_payment_info_list = smartlist_new();

    payment_info_context_t *origin = NULL;

    SMARTLIST_FOREACH_BEGIN(global_payment_info_list, payment_info_context_t *, element)
                            {
                                if (element->circuit_id == circuit_id) {
                                    origin = element;
                                }
                            }
    SMARTLIST_FOREACH_END(element);

    if (origin == NULL) {
        payment_info_context_t *ent = (payment_info_context_t *) tor_malloc_zero_(
                sizeof(payment_info_context_t));
        ent->circuit_id = circuit_id;
        ent->delay_payments_counter = 1;
        origin = ent;
        smartlist_add(global_payment_info_list, ent);
    } else {
        origin->delay_payments_counter++;
    }
}

payment_session_context_t* get_from_session_context_by_session_id(const char* session) {

    if (NULL == global_payment_session_list)
        global_payment_session_list = smartlist_new();

    payment_session_context_t *origin = NULL;

    SMARTLIST_FOREACH_BEGIN(global_payment_session_list, payment_session_context_t *, element)
                            {
                                if (strcmp(element->session_id, session) == 0) {
                                    return element;
                                }
                            }
    SMARTLIST_FOREACH_END(element);

    return origin;
}


payment_info_context_t* get_circuit_payment_info(int circuit_id) {

    if (NULL == global_payment_info_list)
        global_payment_info_list = smartlist_new();

    payment_info_context_t *origin = NULL;

    SMARTLIST_FOREACH_BEGIN(global_payment_info_list, payment_info_context_t *, element)
                            {
                                if (element->circuit_id == circuit_id) {
                                    return element;
                                }
                            }
    SMARTLIST_FOREACH_END(element);

    return origin;
}

void remove_from_session_context(payment_session_context_t* element) {

    smartlist_remove(global_payment_session_list, element);
    tor_free_(element);
}

void tp_remove_circuit_payment_info(payment_info_context_t* element) {
    smartlist_remove(global_payment_info_list, element);
    tor_free_(element);
}

static payment_chunks_t * get_from_hash(const OR_OP_request_t* payment_request_payload, const char* key){

    if (NULL == global_chunks_list)
        global_chunks_list = smartlist_new();

    payment_chunks_t *origin=NULL;

    SMARTLIST_FOREACH_BEGIN(global_chunks_list, payment_chunks_t *, element)
                            {
                                if(strcmp(element->key, key) == 0){
                                    origin = element;
                                }
                            }
            SMARTLIST_FOREACH_END(element);

    if(origin == NULL){
        payment_chunks_t* ent = (payment_chunks_t*)tor_malloc_(sizeof(payment_chunks_t));
        strncpy(ent->key, key, PAYMENT_HASH_KEY_LEN);
        strncpy(ent->value, payment_request_payload->message, MAX_MESSAGE_LEN);
        origin = ent;
        smartlist_add(global_chunks_list, ent);
    }
    else {
        strncat(origin->value, payment_request_payload->message, payment_request_payload->messageLength);
    }

    return origin;
}

int tp_process_payment_command_cell_to_node_async(const cell_t *cell, circuit_t *circ) {

    thread_args_t* args = tor_malloc_(sizeof(thread_args_t));

    args->circ = circ;

    args->step_type = 1;
    OR_OP_request_t *payment_request_payload = circuit_payment_handle_payment_negotiate(cell);
    args->payment_request_payload = payment_request_payload;
    add_payment_curl_request(args);
    return 0;
}

int tp_process_payment_cell_async(const cell_t *cell, circuit_t *circ){

    thread_args_t* args = tor_malloc_(sizeof(thread_args_t));

    args->circ = circ;

    args->step_type = 2;
    OR_OP_request_t *payment_request_payload = circuit_payment_handle_payment_negotiate(cell);
    args->payment_request_payload = payment_request_payload;
    add_payment_curl_request(args);
    return 0;
}

void tp_send_payment_request_to_client_async(circuit_t *circ, int message_number) {
    pthread_rwlock_wrlock(&rwlock);
    circ->total_package_received = 0;
    circ->total_package_sent = 0;
    thread_args_t* args = tor_malloc_(sizeof(thread_args_t));

    args->circ = circ;
    args->relay_type = message_number;
    args->step_type = 3;

//    pthread_t tid;
//    pthread_create(&tid, NULL, send_payment_request_to_client, (void *)args);
//    pthread_join(tid, NULL);
    add_payment_curl_request(args);

    return;
    pthread_rwlock_unlock(&rwlock);
}

void send_payment_request_to_client(thread_args_t* args) {

    // int message_number = ((thread_args_t *) args)->relay_type;
    circuit_t *circ = ((thread_args_t *) args)->circ;


    or_circuit_t *or_circut = TO_OR_CIRCUIT(circ);
    const or_options_t *options = get_options();
    char *nickname = options->Nickname;
    // if(strcmp(nickname, "test004r") != 0) return;


    create_payment_info_t request;
    request.service_type = "tor";
    request.commodity_type = "data";
    request.amount = 10;

    int port = get_options()->PPChannelPort;
    char url [PAYMENT_URL_LEN];
    snprintf(url, PAYMENT_URL_LEN, "%s:%d/%s", "http://localhost", port, "api/utility/createPaymentInfo");

    char *response = create_payment_info(url, &request);

    if (response == NULL) return;

    struct json_object *parsed_json;
    parsed_json = json_tokener_parse(response);

    struct json_object *session_id;
    json_object_object_get_ex(parsed_json, "ServiceSessionId", &session_id);
    const char *session = json_object_get_string(session_id);

    if (session == NULL || !strcmp(session, "")) return;

    set_circuit_payment_info(or_circut->p_circ_id);

    OR_OP_request_t input;
    input.version = 0;
    input.message_type = 1;
    tm_zero_mem(input.command_id, COMMAND_ID_LEN);
    tm_zero_mem(input.session_id, SESSION_ID_LEN);
    input.command_id_length = 0;
    input.session_id_length = strlen(session);
    strncpy(input.session_id, session, SESSION_ID_LEN);
    input.command = RELAY_COMMAND_PAYMENT_COMMAND_TO_ORIGIN;
    tm_zero_mem(input.nickname, USER_NAME_LEN);
    strncpy(input.nickname, nickname, USER_NAME_LEN);
    input.nicknameLength = strlen(nickname);
    input.is_last = 0;
    int chunck_size = MAX_MESSAGE_LEN - 1;
    input.messageTotalLength = strlen(response);
    int part_size = strlen(response) / chunck_size;
    int oddment = strlen(response) % chunck_size;
    List_of_str_t array[part_size + 1];
    divideString(array, response, strlen(response), chunck_size);
    for (int g = 0; g < part_size; g++) {
        tm_zero_mem(input.message, MAX_MESSAGE_LEN);
        strncpy(input.message, array[g].msg, chunck_size);
        input.message[chunck_size] = '\0';
        input.messageLength = chunck_size;
        circuit_payment_send_OR(circ, &input);
    }
    tm_zero_mem(input.message, MAX_MESSAGE_LEN);
    strncpy(input.message, array[part_size].msg, oddment);
    input.message[oddment] = '\0';
    input.messageLength = oddment;
    input.is_last = 1;
    circuit_payment_send_OR(circ, &input);


    tor_free_(response);

    return;

}

static int process_payment_cell(thread_args_t* args){

    OR_OP_request_t *payment_request_payload = ((thread_args_t*)args)->payment_request_payload;
    circuit_t *circ = ((thread_args_t*)args)->circ;

    char key [PAYMENT_HASH_KEY_LEN];

    int callback_port = get_options()->PPChannelCallbackPort;
    int port = get_options()->PPChannelPort;
    char callback_url [PAYMENT_URL_LEN];
    char url [PAYMENT_URL_LEN];

    snprintf(callback_url, PAYMENT_URL_LEN,  "%s:%d/%s", "http://127.0.0.1", callback_port, "api/response");
    snprintf(url, PAYMENT_URL_LEN, "%s:%d/%s", "http://localhost", port, "api/utility/processCommand");
    snprintf(key, PAYMENT_HASH_KEY_LEN, "%s|%s", payment_request_payload->nickname, payment_request_payload->session_id);

    payment_chunks_t* origin = get_from_hash(payment_request_payload, key);

    if(payment_request_payload ->is_last == 0) return 0;

    if(payment_request_payload->message_type == 100)
    {
        payment_info_context_t *info = get_circuit_payment_info(TO_OR_CIRCUIT(circ)->p_circ_id);
        if(info != NULL) {
            tp_remove_circuit_payment_info(info);
        }
        payment_session_context_t *session_context = get_from_session_context_by_session_id(
                payment_request_payload->session_id);
        if(session_context != NULL)
        {
            remove_from_session_context(session_context);
        }
        return 0;
    }
    utility_command_t request;
    request.command_type = payment_request_payload->command_type;
    request.command_body = origin->value;
    request.node_id = payment_request_payload->nickname;
    request.callback_url = callback_url;
    request.command_id = payment_request_payload->command_id;
    request.session_id = payment_request_payload->session_id;
    set_to_session_context(payment_request_payload->session_id, payment_request_payload->nickname, TO_OR_CIRCUIT(circ)->p_chan->global_identifier, TO_OR_CIRCUIT(circ)->p_circ_id);

    process_command(url, &request);

    tor_free_(payment_request_payload);
    smartlist_remove(global_chunks_list, origin);
    tor_free_(origin);
    return 0;
}

static int process_payment_command_cell_to_node(thread_args_t* args) {

    OR_OP_request_t *payment_request_payload = ((thread_args_t*)args)->payment_request_payload;
    circuit_t *circ = ((thread_args_t*)args)->circ;

    int callback_port = get_options()->PPChannelCallbackPort;
    int port = get_options()->PPChannelPort;
    char callback_url[PAYMENT_URL_LEN];
    char status_callback_url [PAYMENT_URL_LEN];
    char url[PAYMENT_URL_LEN];
    char key[PAYMENT_HASH_KEY_LEN];

    snprintf(callback_url, PAYMENT_URL_LEN, "%s:%d/%s", "http://127.0.0.1", callback_port, "api/command");
    snprintf(status_callback_url, PAYMENT_URL_LEN, "%s:%d/%s", "http://127.0.0.1", callback_port, "api/paymentComplete");
    snprintf(key, PAYMENT_HASH_KEY_LEN, "%s|%s", payment_request_payload->nickname, payment_request_payload->session_id);

    payment_chunks_t* origin = get_from_hash(payment_request_payload, key);

    if(payment_request_payload ->is_last == 0) return 0;
    if(payment_request_payload->message_type == 1) {  //payment creation request method
        snprintf(url, PAYMENT_URL_LEN, "%s:%d/%s", "http://localhost", port, "api/gateway/processPayment");
        // routing_node_t nodes[0];
        origin_circuit_t* origin_circuit = TO_ORIGIN_CIRCUIT(circ);
        int hop_num = circuit_get_num_by_nickname(origin_circuit, payment_request_payload->nickname);
        if(hop_num == 0) return 0;
        routing_node_t nodes[hop_num-1];
        crypt_path_t * next = origin_circuit->cpath;
        for (int i = 0; i < hop_num-1; ++i) {
            nodes[i].node_id = next->extend_info->nickname;
            nodes[i].address = next->extend_info->stellar_address;
            next = next->next;
        }

        // struct json_object *parsed_json;
        // parsed_json = json_tokener_parse(origin->value);

        set_to_session_context(payment_request_payload->session_id, payment_request_payload->nickname, circ->n_chan->global_identifier, circ->n_circ_id);

        process_payment_request_t request;
        request.payment_request = origin->value;
        request.node_id = payment_request_payload->nickname;
        request.routing_node = nodes;
        request.call_back_url = callback_url;
        request.status_call_back_url = status_callback_url;
        process_payment(url, &request, hop_num);
    }
    if(payment_request_payload->message_type == 4) {
        snprintf(url, PAYMENT_URL_LEN, "%s:%d/%s", "http://localhost", port, "api/gateway/processResponse");
        utility_response_t request;
        request.command_id = payment_request_payload->command_id;
        request.session_id = payment_request_payload->session_id;
        request.node_id = payment_request_payload->nickname;
        request.response_body = origin->value;
        process_response(url, &request);
    }

    // ht_set(hashtable, key, "");
    tor_free_(payment_request_payload);
    smartlist_remove(global_chunks_list, origin);
    tor_free_(origin);
    return 0;
}

int tp_payment_requests_callback(time_t now, const or_options_t *options)
{
  pthread_rwlock_wrlock(&rwlock);
  SMARTLIST_FOREACH_BEGIN(payment_messsages_for_sending, payment_message_for_sending_t*, message) {
    if(message->message == NULL) {
      payment_session_context_t *session_context = get_from_session_context_by_session_id(
              message->sessionId);
      if(session_context != NULL) {
        OR_OP_request_t *input = tor_malloc(sizeof(OR_OP_request_t));
        input->command = RELAY_COMMAND_PAYMENT_COMMAND_TO_NODE;
        input->is_last = 1;
        strncpy(input->session_id, message->sessionId, strlen(message->sessionId));
        input->session_id_length = strlen(message->sessionId);
        input->message_type = 100;
        input->command_type = 0;
        input->version = 0;
        input->messageTotalLength = 0;
        input->command_id_length = 0;
        input->nicknameLength = 0;
        /* Get the channel */
        channel_t *chan = channel_find_by_global_id(session_context->channel_global_id);
        /* Get the circuit */
        circuit_t *circ = circuit_get_by_circid_channel_even_if_marked(
                session_context->circuit_id, chan);
        if (circ != NULL) {
            origin_circuit_t *origin_circuit = TO_ORIGIN_CIRCUIT(circ);
            int length = circuit_get_length(origin_circuit);
            for (int i = 1; i < length + 1; ++i) {
                circuit_payment_send_OP(circ, i, input);
            }
            if (session_context != NULL) {
                remove_from_session_context(session_context);
            }
        }
        tor_free_(input);
      }
    }
    else {
      payment_session_context_t *session_context
        = get_from_session_context_by_session_id(message->sessionId);
      if(session_context != NULL) {
        /* Get the channel */
        channel_t *chan = channel_find_by_global_id(session_context->channel_global_id);
        /* Get the circuit */
        circuit_t *circ = circuit_get_by_circid_channel_even_if_marked(
                session_context->circuit_id, chan);
        if (circ != NULL) {
          if (CIRCUIT_IS_ORIGIN(circ)) {
            origin_circuit_t *origin_circuit = TO_ORIGIN_CIRCUIT(circ);
            int hop_num = circuit_get_num_by_nickname(origin_circuit,
                                                      message->nodeId);
            circuit_payment_send_OP(circ, hop_num, message->message);
          } else {
            circuit_payment_send_OR(circ, message->message);
          }
        }
      }
    }
    tor_free_(message->message);
    tor_free_(message);
  }
  SMARTLIST_FOREACH_END(message);
  smartlist_clear(payment_messsages_for_sending);

  SMARTLIST_FOREACH_BEGIN(payment_curl_request, thread_args_t*, message) {
    if(message->step_type == 1){
        process_payment_command_cell_to_node(message);
    }
    if(message->step_type == 2){
        process_payment_cell(message);
    }
    if(message->step_type == 3){
        send_payment_request_to_client(message);
    }
    // tor_free_(message->payment_request_payload);
    tor_free_(message);
  }
  SMARTLIST_FOREACH_END(message);
  smartlist_clear(payment_curl_request);
  pthread_rwlock_unlock(&rwlock);
  return 1;
}
