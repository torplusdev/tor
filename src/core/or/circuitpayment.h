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

typedef struct circuit_payment_state_t {

    // The circuit for this machine
    struct circuit_t *circuit;

    unsigned is_origin_side : 1;

    /** Which hop in the circuit should we send padding to/from?
   *  1-indexed (ie: hop #1 is guard, #2 middle, #3 exit). */
    unsigned target_hopnum : 3;

} circuit_payment_data_t;


struct payment_payload_st {
    uint8_t version;
    uint8_t command;

    __u_char data[TRUNNEL_PAYMENT_LEN];

};

struct payment_request_payload_st {
    uint8_t version;
    uint8_t command;

    __uint32_t node_id;
    __u_char data[TRUNNEL_PAYMENT_LEN];

};

typedef struct payment_payload_st payment_payload_t;
typedef struct payment_request_payload_st payment_request_payload_t;


//public API
void circuit_send_send_payment_cell(circuit_payment_data_t *machine);


signed_error_t
circuit_payment_send(
                            origin_circuit_t *circ,
                            uint8_t target_hopnum,
                            uint8_t command);

signed_error_t circuit_payment_send_command_to_hop(
                            origin_circuit_t *circ,
                            uint8_t hopnum,
                            uint8_t relay_command,
                            const uint8_t *payload,
                            ssize_t payload_len);

node_t* circuit_payment_get_nth_node(origin_circuit_t *circ, int hop);

payment_payload_t * payment_payload_new(void);
payment_request_payload_t * payment_request_payload_new(void);
ssize_t
payment_request_parse_into(payment_request_payload_t *obj, const uint8_t *input, const size_t len_in);
ssize_t
payment_parse_into(payment_payload_t *obj, const uint8_t *input, const size_t len_in);

ssize_t
circuit_payment_negotiate_parse(circpad_negotiate_t **output, const uint8_t *input, const size_t len_in);
ssize_t
circuit_payment_request_negotiate_parse(payment_request_payload_t **output, const uint8_t *input, const size_t len_in);

payment_request_payload_t*
circuit_payment_request_handle_payment_request_negotiate(circuit_t *circ, cell_t *cell);
payment_payload_t*
circuit_payment_handle_payment_negotiate(circuit_t *circ, cell_t *cell);


ssize_t circuit_payment_request_negotiate_encode(uint8_t *output, const size_t avail, const payment_request_payload_t *obj);
ssize_t circuit_payment_negotiate_encode(uint8_t *output, const size_t avail, const payment_payload_t *obj);

signed_error_t circuit_payment_send(origin_circuit_t *circ, uint8_t target_hopnum, uint8_t command);
signed_error_t circuit_payment_request_send(origin_circuit_t *circ, uint8_t target_hopnum, uint8_t command);