/*
 * Copyright (c) 2017-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitpayment.h
 * \brief Header file for circuitpayment.c.
 **/





#include "trunnel/circpad_negotiation.h"
#include "lib/evloop/timers.h"


struct circuit_t;
struct origin_circuit_t;
struct cell_t;
#define USER_NAME_LEN 50
#define MAX_MESSAGE_LEN 301
typedef int error_t;

struct OR_OP_request_st {
    uint8_t version;
    uint8_t message_type;
    uint8_t command;
    uint8_t is_last;
    uint16_t nicknameLength;
    char nickname[USER_NAME_LEN];
    uint16_t messageLength;
    char message[MAX_MESSAGE_LEN];
};
struct List_of_str_st {
    char msg[MAX_MESSAGE_LEN];
};

struct ListNode{
    char* id;
    char *value;
    struct ListNode *next;
};

typedef struct ListNode *Node;

typedef struct List_of_str_st List_of_str_t;


typedef struct OR_OP_request_st OR_OP_request_t;


error_t circuit_payment_send_command_to_hop(
                            origin_circuit_t *circ,
                            uint8_t hopnum,
                            uint8_t relay_command,
                            const uint8_t *payload,
                            ssize_t payload_len);

node_t* circuit_payment_get_nth_node(origin_circuit_t *circ, int hop);

OR_OP_request_t * payment_payload_new(void);
ssize_t
payment_into(OR_OP_request_t *obj, const uint8_t *input, const size_t len_in);
ssize_t
circuit_payment_negotiate_parse(OR_OP_request_t **output, const uint8_t *input, const size_t len_in);

error_t circuit_payment_send_command_to_origin(circuit_t *circ, uint8_t relay_command, const uint8_t *payload, ssize_t payload_len);
void
circuit_payment__free(OR_OP_request_t *obj);
static void circuit_payment_negotiate_clear(OR_OP_request_t *obj);
ssize_t circuit_payment_negotiate_encode(uint8_t *output, const size_t avail, const OR_OP_request_t *obj);

int uuid_generate(unsigned long u_id);
void divideString(List_of_str_t* output, char *str, int n);
// public API
extern Node create_node(char* id, const char *name);
extern void free_node(Node node);
extern void prepend_node(Node *head, Node node);
extern void append_node(Node *head, Node node);
extern int insert_node(Node *head, Node node, int pos);
extern Node find_node(Node head, char* id);
extern void remove_node(Node *head, Node node);
extern void print_node(Node node);
extern void print_list(Node head);
extern void clear_node(Node head);


OR_OP_request_t*
circuit_payment_handle_payment_negotiate(cell_t *cell);


error_t circuit_payment_send_OP(circuit_t *circ, uint8_t target_hopnum, OR_OP_request_t* input);
error_t circuit_payment_send_OR(circuit_t *circ, OR_OP_request_t* input);