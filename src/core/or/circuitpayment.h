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

#define CIRCUIT_PAYMENT_COMMAND 1
#define TRUNNEL_PAYMENT_LEN 256
typedef int error_t;

typedef struct circuit_payment_state_t {

    // The circuit for this machine
    struct circuit_t *circuit;

    unsigned is_origin_side : 1;

    /** Which hop in the circuit should we send padding to/from?
   *  1-indexed (ie: hop #1 is guard, #2 middle, #3 exit). */
    unsigned target_hopnum : 3;

} circuit_payment_data_t;

struct OR_request_st {
    uint8_t version;
    uint8_t message_type;
    uint8_t command;
    uint16_t nicknameLength;
    char* nickname;
    uint16_t messageLength;
    char* message;

};

struct OP_request_st {
    uint8_t version;
    uint8_t command;
    uint8_t message_type;
    uint16_t nicknameLength;
    char* nickname;
    uint16_t messageLength;
    char* message;

};

typedef struct OP_request_st OP_request_t;
typedef struct OR_request_st OR_request_t;


error_t circuit_payment_send_command_to_hop(
                            origin_circuit_t *circ,
                            uint8_t hopnum,
                            uint8_t relay_command,
                            const uint8_t *payload,
                            ssize_t payload_len);

node_t* circuit_payment_get_nth_node(origin_circuit_t *circ, int hop);

OR_request_t * payment_payload_new(void);
OP_request_t * payment_request_payload_new(void);
ssize_t
payment_request_parse_into(OP_request_t *obj, const uint8_t *input, const size_t len_in);
ssize_t
payment_parse_into(OR_request_t *obj, const uint8_t *input, const size_t len_in);

ssize_t
circuit_payment_negotiate_parse(OR_request_t **output, const uint8_t *input, const size_t len_in);
ssize_t
circuit_payment_request_negotiate_parse(OP_request_t **output, const uint8_t *input, const size_t len_in);

error_t circuit_payment_send_command_to_origin(circuit_t *circ, uint8_t relay_command, const uint8_t *payload, ssize_t payload_len);
static void
circuit_payment_negotiate_clear_1(OP_request_t *obj);
void
circuit_payment__free(OR_request_t *obj);
void
circuit_payment__free_1(OP_request_t *obj);
static void circuit_payment_negotiate_clear(OR_request_t *obj);
ssize_t circuit_payment_request_negotiate_encode(uint8_t *output, const size_t avail, const OR_request_t *obj);
ssize_t circuit_payment_negotiate_encode(uint8_t *output, const size_t avail, const OP_request_t *obj);

// public API

OP_request_t*
circuit_payment_request_handle_payment_request_negotiate(circuit_t *circ, cell_t *cell);
OR_request_t*
circuit_payment_handle_payment_negotiate(cell_t *cell);

error_t circuit_payment_send_OP(circuit_t *circ, uint8_t target_hopnum, OP_request_t* input);
error_t circuit_payment_send_OR(circuit_t *circ, OR_request_t* input);