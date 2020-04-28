/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */


//file circuitpayment.c
//brief Circuit-level payment implementation


#include "core/or/or.h"
#include "core/or/circuitpadding.h"
#include "core/or/circuitpayment.h"
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



error_t circuit_payment_send_OP(circuit_t *circ, uint8_t target_hopnum, OP_request_t* input)
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

    return circuit_payment_send_command_to_hop(orig_circ, target_hopnum,
                                               RELAY_COMMAND_PAYMENT_COMMAND_TO_NODE,
                                               cell.payload, len);
}

error_t circuit_payment_send_OR(circuit_t *circ, OR_request_t* input)
{
    uint8_t payload[RELAY_PAYLOAD_SIZE];
    ssize_t len;

    if (CIRCUIT_IS_ORIGIN(circ)) {
        return 0;
    }

    if ((len = circuit_payment_request_negotiate_encode(payload, CELL_PAYLOAD_SIZE,  input)) < 0)
        return 0;

    return circuit_payment_send_command_to_origin(circ,
                                                  RELAY_COMMAND_PAYMENT_COMMAND_TO_ORIGIN,
                                                  payload, len);
}

node_t* circuit_payment_get_nth_node(origin_circuit_t *circ, int hop) {
    crypt_path_t *iter = circuit_get_cpath_hop(circ, hop);

    if (!iter || iter->state != CPATH_STATE_OPEN)
        return NULL;

    return node_get_by_id(iter->extend_info->identity_digest);
}

error_t circuit_payment_send_command_to_hop(origin_circuit_t *circ, uint8_t hopnum,uint8_t relay_command, const uint8_t *payload, ssize_t payload_len) {
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

/* Send the drop command to the second hop */
    ret = relay_send_command_from_edge(0, TO_CIRCUIT(circ), relay_command,
                                       (const char *) payload, payload_len,
                                       target_hop);
    return ret;
}

error_t circuit_payment_send_command_to_origin(circuit_t *circ, uint8_t relay_command, const uint8_t *payload, ssize_t payload_len) {
    error_t ret;

/* Send the drop command to the second hop */
    ret = relay_send_command_from_edge(0, circ, relay_command,
                                       (const char *) payload, payload_len,
                                       NULL);
    return ret;
}

OP_request_t*
circuit_payment_request_handle_payment_request_negotiate(circuit_t *circ, cell_t *cell) {
    OP_request_t *negotiate = NULL;

    if (!CIRCUIT_IS_ORIGIN(circ)) {
         return negotiate;
    }

    if (circuit_payment_request_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                                        CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_CIRC,
               "Received malformed PADDING_NEGOTIATE cell; dropping.");
        return negotiate;
    }


    return negotiate;
}
OR_request_t*
circuit_payment_handle_payment_negotiate(cell_t *cell){
    int retval = 0;
    OR_request_t *negotiate;

    if (circuit_payment_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                                CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_CIRC,
               "Received malformed PADDING_NEGOTIATE cell; dropping.");
        return -1;
    }

    return 0;
}

ssize_t
circuit_payment_negotiate_parse(OR_request_t **output, const uint8_t *input, const size_t len_in)
{
    ssize_t result;
    *output = payment_payload_new();
    if (NULL == *output)
        return -1;
    result = payment_parse_into(*output, input, len_in);
    if (result < 0) {
        circuit_payment__free(*output);
        *output = NULL;
    }
    return result;
}

void
circuit_payment__free(OR_request_t *obj)
{
    if (obj == NULL)
        return;
    circuit_payment_negotiate_clear(obj);
    trunnel_memwipe(obj, sizeof(circpad_negotiate_t));
    trunnel_free_(obj);
}

static void
circuit_payment_negotiate_clear(OR_request_t *obj)
{
    (void) obj;
}



void
circuit_payment__free_1(OP_request_t *obj)
{
    if (obj == NULL)
        return;
    circuit_payment_negotiate_clear_1(obj);
    trunnel_memwipe(obj, sizeof(circpad_negotiate_t));
    trunnel_free_(obj);
}

static void
circuit_payment_negotiate_clear_1(OP_request_t *obj)
{
    (void) obj;
}


ssize_t
circuit_payment_request_negotiate_parse(OP_request_t **output, const uint8_t *input, const size_t len_in)
{
    ssize_t result;
    *output = payment_request_payload_new();
    if (NULL == *output)
        return -1;
    result = payment_request_parse_into(*output, input, len_in);
    if (result < 0) {
        circuit_payment__free_1(*output);
        *output = NULL;
    }
    return result;
}


OR_request_t * payment_payload_new(void)
{
    OR_request_t *val = trunnel_calloc(1, sizeof(OR_request_t));
    if (NULL == val)
        return NULL;
    val->command = CELL_PAYMENT;
    return val;
}

OP_request_t * payment_request_payload_new(void)
{
    OP_request_t *val = trunnel_calloc(1, sizeof(OP_request_t));
    if (NULL == val)
        return NULL;
    val->command = CELL_PAYMENT_REQUEST;
    return val;
}


ssize_t
payment_request_parse_into(OP_request_t *obj, const uint8_t *input, const size_t len_in)
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
    CHECK_REMAINING(4, truncated);
    obj->u_id = (trunnel_get_uint32(ptr));
    remaining -= 4; ptr += 4;

    /* Parse u8 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(1, truncated);
    obj->is_last = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;

    CHECK_REMAINING(2, truncated);
    obj->nicknameLength = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;

    CHECK_REMAINING(obj->nicknameLength, fail);
    obj->nickname = (char *)calloc(sizeof(char), obj->nicknameLength);
    memcpy(obj->nickname, ptr, obj->nicknameLength);
    remaining -= obj->nicknameLength; ptr += obj->nicknameLength;

    CHECK_REMAINING(2, truncated);
    obj->messageLength = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;

    /* Parse char data[message] */
    CHECK_REMAINING(obj->messageLength, fail);
    obj->message = (char *)calloc (sizeof(char), obj->messageLength);
    memcpy(obj->message,ptr, obj->messageLength);
    remaining -= obj->messageLength; ptr += obj->messageLength;

    trunnel_assert(ptr + remaining == input + len_in);
    return len_in - remaining;

    truncated:
    return -2;
    fail:
    result = -1;
    return result;
}

ssize_t
payment_parse_into(OR_request_t *obj, const uint8_t *input, const size_t len_in)
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
    CHECK_REMAINING(4, truncated);
    obj->u_id = (trunnel_get_uint32(ptr));
    remaining -= 4; ptr += 4;

    /* Parse u8 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(1, truncated);
    obj->is_last = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;

    CHECK_REMAINING(2, truncated);
    obj->nicknameLength = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;


    CHECK_REMAINING(obj->nicknameLength, fail);
    obj->nickname = (char *)calloc (sizeof(char), obj->nicknameLength);
    memcpy(obj->nickname,ptr, obj->nicknameLength);
    remaining -= obj->nicknameLength; ptr += obj->nicknameLength;

    CHECK_REMAINING(2, truncated);
    obj->messageLength = (trunnel_get_uint16(ptr));
    remaining -= 2; ptr += 2;

    /* Parse char data[message] */
    CHECK_REMAINING(obj->messageLength, fail);
    obj->message = (char *)calloc(sizeof(char), obj->messageLength);
    memcpy(obj->message,ptr, obj->messageLength);
    remaining -= obj->messageLength; ptr += obj->messageLength;

    trunnel_assert(ptr + remaining == input + len_in);
    return len_in - remaining;

    truncated:
    return -2;
    fail:
    result = -1;
    return result;
}


ssize_t circuit_payment_request_negotiate_encode(uint8_t *output, const size_t avail, const OR_request_t *obj)
{
    ssize_t result = 0;
    size_t written = 0;
    uint8_t *ptr = output;
    const char *msg;
#ifdef TRUNNEL_CHECK_ENCODED_LEN
    const ssize_t encoded_len = circpad_negotiate_encoded_len(obj);
#endif

    if (obj == NULL)
        return "Object was NULL";

#ifdef TRUNNEL_CHECK_ENCODED_LEN
        trunnel_assert(encoded_len >= 0);
#endif

    /* Encode u8 version IN [0] */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->version));
    written += 1; ptr += 1;

    /* Encode u8 command IN  */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->command));
    written += 1; ptr += 1;

    /* Encode u8 command IN  */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->message_type));
    written += 1; ptr += 1;

    /* Encode u8 command IN  */
    trunnel_assert(written <= avail);
    if (avail - written < 4)
        goto truncated;
    trunnel_set_uint32(ptr, (obj->u_id));
    written += 4; ptr += 4;

    /* Encode u8 command IN  */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->is_last));
    written += 1; ptr += 1;

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->nicknameLength));
    written += 2; ptr += 2;

    /* Encode u4 data[TRUNNEL_PAYMENT_LEN] */
    trunnel_assert(written <= avail);
    if (avail - written < obj->nicknameLength)
        goto truncated;
    memcpy(ptr, obj->nickname, obj->nicknameLength);
    written += obj->nicknameLength; ptr += obj->nicknameLength;
    trunnel_assert(ptr == output + written);

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->messageLength));
    written += 2; ptr += 2;

    trunnel_assert(written <= avail);
    if (avail - written < obj->messageLength)
        goto truncated;
    memcpy(ptr, obj->message, obj->messageLength);
    written += obj->messageLength; ptr += obj->messageLength;
    trunnel_assert(ptr == output + written);

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
    check_failed:
    (void)msg;
    result = -1;
    goto fail;
    fail:
    trunnel_assert(result < 0);
    return result;
}

ssize_t circuit_payment_negotiate_encode(uint8_t *output, const size_t avail, const OP_request_t *obj)
{
    ssize_t result = 0;
    size_t written = 0;
    uint8_t *ptr = output;
    const char *msg;
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
    if (avail - written < 4)
        goto truncated;
    trunnel_set_uint32(ptr, (obj->u_id));
    written += 4; ptr += 4;

    /* Encode u8 command IN  */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint8(ptr, (obj->is_last));
    written += 1; ptr += 1;

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->nicknameLength));
    written += 2; ptr += 2;

    /* Encode u4 data[TRUNNEL_PAYMENT_LEN] */
    trunnel_assert(written <= avail);
    if (avail - written < obj->nicknameLength)
        goto truncated;
    memcpy(ptr, obj->nickname, obj->nicknameLength);
    written += obj->nicknameLength; ptr += obj->nicknameLength;
    trunnel_assert(ptr == output + written);

    /* Encode u8 command IN [CIRCPAD_COMMAND_START, CIRCPAD_COMMAND_STOP] */
    trunnel_assert(written <= avail);
    if (avail - written < 2)
        goto truncated;
    trunnel_set_uint16(ptr, (obj->messageLength));
    written += 2; ptr += 2;

    trunnel_assert(written <= avail);
    if (avail - written < obj->messageLength)
        goto truncated;
    memcpy(ptr, obj->message, obj->messageLength);
    written += obj->messageLength; ptr += obj->messageLength;
    trunnel_assert(ptr == output + written);

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
    check_failed:
    (void)msg;
    result = -1;
    goto fail;
    fail:
    trunnel_assert(result < 0);
    return result;
}

int32_t uuid_generate(unsigned long u_id){
    struct timeval t;
    unsigned long id;
    gettimeofday(&t,NULL);
    id = (t.tv_sec * 1000 * 1000) + (t.tv_usec * 1000) << 42;
    id |= (u_id % 16777216) << 24;
    printf("%lu\n ",id);
    return id;
}

char **divideString(char *str, int n)
{
    int str_size = strlen(str);
    int i;
    int part_size;
    part_size = str_size / n;
    int oddment = str_size % n;
    int size = (part_size + 1);

    char** array = malloc(size);
// Check if string can be divided in
// n equal parts
    if (str_size / n == 0)
    {
        array[0] = malloc(sizeof(str) * sizeof(char));
        strcpy(array[0], str);
        return array;
    }

// Calculate the size of parts to
// find the division points

    for (i = 0; i < part_size; i++)
    {

        array[i] = malloc(n * sizeof(char));
        memcpy(array[i], &str[i*n], n);
    }
    array[part_size] = malloc(oddment * sizeof(char));
    memcpy(array[part_size], &str[part_size*n], oddment);
    return array;
}

Node create_node(char* id, const char *value){
    Node node;
    node = (Node) malloc(sizeof(struct ListNode));
    if(node == NULL){
        fprintf(stderr, "Error: not enough memory.\n");
        return NULL;
    }
    node->id = strdup(id);
    node->value = strdup(value);
    node->next = NULL;
    return node;
}

void free_node(Node node){
    if(node){
        if(node->value){
            free(node->value);
        }
        free(node);
    }
}

void prepend_node(Node *head, Node node){
    node->next = *head;
    *head = node;
}

void append_node(Node *head, Node node){
    Node tmp = *head;
    if(*head == NULL) { /*no node (empty)*/
        *head = node;
    }else{
        while(tmp->next){
            tmp = tmp->next;
        }
        tmp->next = node;
    }
}

int insert_node(Node *head, Node node, int pos){
    int i = 0;
    /*tmp is the head*/
    Node tmp = *head;

    /*insert at the beginning of the list*/
    if(pos == 1){
        *head = node;
        (*head)->next = tmp;
        return 0;
    }
    /*get position*/
    while(tmp){
        /*invalid or matching position*/
        if(++i >= pos-1){
            break;
        }
        tmp = tmp->next;
    }
    if(i != pos-1){
        fprintf(stderr, "Error: can not insert at pos %d", pos);
        return -1;
    }
    /*update all links*/
    node->next = tmp->next;
    tmp->next = node;
    return 0;
}

Node find_node(Node head, char* id){
    while(head != NULL && /*reached last element*/
                          strstr(head->id,id) == NULL && strstr(id, head->id) == NULL){

        head = head->next;
    }
    /*found it: return it*/
    return head;
}

void remove_node(Node *head, Node node){
    Node tmp = *head;

    /*handle empty list*/
    if(*head == NULL){
        return;
    } else if (*head == node) {
        *head = (*head)->next;
        /*give memory back to its owner (free)*/
        free_node(node);
    } else {
        while(tmp->next){
            /*we found the node*/
            if(tmp->next == node){
                /*unlink it*/
                tmp->next = tmp->next->next;
                /*give memory back*/
                free_node(node);
                return;
            }
            tmp = tmp->next;
        }
    }
}

void clear_node(Node head){
    Node node;

    while(head){
        node = head;
        head = head->next;
        free_node(node);
    }
}

void print_node(Node node){
    if(node){
        printf("id = %d, name = %s\n", node->id, node->value);
    }
}

void print_list(Node head){
    while(head){
        print_node(head);
        head = head->next;
    }
}