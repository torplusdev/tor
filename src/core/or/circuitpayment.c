/* Copyright (c) 2017 The Tor Project, Inc. */
/* See LICENSE for licensing information */


//file circuitpayment.c
//brief Circuit-level payment implementation


#include <math.h>
#include "lib/math/fp.h"
#include "lib/math/prob_distr.h"
#include "core/or/or.h"
#include "core/or/circuitpadding.h"
#include "core/or/circuitpayment.h"
#include "core/or/circuitpadding_machines.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/mainloop/netstatus.h"
#include "core/or/relay.h"
#include "feature/stats/rephist.h"
#include "feature/nodelist/networkstatus.h"
#include "core/or/channel.h"
#include "lib/time/compat_time.h"
#include "lib/defs/time.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "core/or/crypt_path_st.h"
#include "core/or/circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/or_circuit_st.h"
#include "feature/nodelist/routerstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "core/or/cell_st.h"
#include "core/or/extend_info_st.h"
#include "core/crypto/relay_crypto.h"
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



signed_error_t circuit_payment_send(circuit_t *circ, uint8_t target_hopnum, uint8_t command)
{
    payment_payload_t type;
    cell_t cell;
    ssize_t len;

    if (!circuit_payment_get_nth_node(circ, target_hopnum)) {
        return 0;
    }

    memset(&cell, 0, sizeof(cell_t));
    memset(&type, 0, sizeof(payment_payload_t));


    cell.command = CELL_RELAY;

    type.command = command;
    type.version = 0;

    if ((len = circuit_payment_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE,
                                        &type)) < 0)
        return 0;

    return circuit_payment_send_command_to_hop(circ, target_hopnum,
                                       RELAY_COMMAND_PAYMENT,
                                       cell.payload, len);
}

signed_error_t circuit_payment_request_send(circuit_t *circ, uint8_t command)
{
    payment_request_payload_t type;
    cell_t cell;
    ssize_t len;

    if (CIRCUIT_IS_ORIGIN(circ)) {
        return 0;
    }

    memset(&cell, 0, sizeof(cell_t));
    memset(&type, 0, sizeof(payment_request_payload_t));


    cell.command = CELL_RELAY;

    type.command = command;
    type.version = 0;

    if ((len = circuit_payment_request_negotiate_encode(cell.payload, CELL_PAYLOAD_SIZE,
                                        &type)) < 0)
        return 0;

    return circuit_payment_send_command_to_origin(circ,
                                       RELAY_COMMAND_PAYMENT_REQUEST,
                                       cell.payload, len);
}

node_t* circuit_payment_get_nth_node(origin_circuit_t *circ, int hop) {
    crypt_path_t *iter = circuit_get_cpath_hop(circ, hop);

    if (!iter || iter->state != CPATH_STATE_OPEN)
        return NULL;

    return node_get_by_id(iter->extend_info->identity_digest);
}

signed_error_t circuit_payment_send_command_to_hop(origin_circuit_t *circ, uint8_t hopnum,uint8_t relay_command, const uint8_t *payload, ssize_t payload_len) {
    crypt_path_t *target_hop = circuit_get_cpath_hop(circ, hopnum);
    signed_error_t ret;

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

signed_error_t circuit_payment_send_command_to_origin(origin_circuit_t *circ, uint8_t relay_command, const uint8_t *payload, ssize_t payload_len) {
   signed_error_t ret;

/* Send the drop command to the second hop */
    ret = relay_send_command_from_edge(0, TO_CIRCUIT(circ), relay_command,
                                       (const char *) payload, payload_len,
                                       NULL);
    return ret;
}

payment_request_payload_t*
circuit_payment_request_handle_payment_request_negotiate(circuit_t *circ, cell_t *cell) {
    circpad_negotiate_t *negotiate;

    if (CIRCUIT_IS_ORIGIN(circ)) {
        log_fn(LOG_PROTOCOL_WARN, LD_CIRC,
               "Padding negotiate cell unsupported at origin (circuit %u)",
               TO_ORIGIN_CIRCUIT(circ)->global_identifier);
        return -1;
    }

    if (circuit_payment_request_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                                        CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_CIRC,
               "Received malformed PADDING_NEGOTIATE cell; dropping.");
        return -1;
    }

    return 0;
}
payment_payload_t*
circuit_payment_handle_payment_negotiate(circuit_t *circ, cell_t *cell){
    int retval = 0;
    circpad_negotiate_t *negotiate;

    if (circuit_payment_negotiate_parse(&negotiate, cell->payload+RELAY_HEADER_SIZE,
                                CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE) < 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_CIRC,
               "Received malformed PADDING_NEGOTIATE cell; dropping.");
        return -1;
    }

    return 0;
}



ssize_t
circuit_payment_negotiate_parse(circpad_negotiate_t **output, const uint8_t *input, const size_t len_in)
{
    ssize_t result;
    *output = payment_payload_new();
    if (NULL == *output)
        return -1;
    result = payment_parse_into(*output, input, len_in);
    if (result < 0) {
        circpad_negotiate_free(*output);
        *output = NULL;
    }
    return result;
}


ssize_t
circuit_payment_request_negotiate_parse(payment_request_payload_t **output, const uint8_t *input, const size_t len_in)
{
    ssize_t result;
    *output = payment_request_payload_new();
    if (NULL == *output)
        return -1;
    result = payment_request_parse_into(*output, input, len_in);
    if (result < 0) {
        circpad_negotiate_free(*output);
        *output = NULL;
    }
    return result;
}


payment_payload_t * payment_payload_new(void)
{
    payment_payload_t *val = trunnel_calloc(1, sizeof(payment_payload_t));
    if (NULL == val)
        return NULL;
    val->command = CELL_PAYMENT;
    return val;
}

payment_request_payload_t * payment_request_payload_new(void)
{
    payment_request_payload_t *val = trunnel_calloc(1, sizeof(payment_request_payload_t));
    if (NULL == val)
        return NULL;
    val->command = CELL_PAYMENT_REQUEST;
    return val;
}


ssize_t
payment_request_parse_into(payment_request_payload_t *obj, const uint8_t *input, const size_t len_in)
{
    const uint8_t *ptr = input;
    size_t remaining = len_in;
    ssize_t result = 0;
    (void)result;

    /* Parse u8 version IN [0] */
    CHECK_REMAINING(1, truncated);
    obj->version = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;
    if (! (obj->version == 0))
        goto fail;

    /* Parse u8 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(1, truncated);
    obj->command = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;
    if (! (obj->command == CELL_PAYMENT_REQUEST))
        goto fail;

    /* Parse u32 node_id */
    CHECK_REMAINING(4, truncated);
    obj->node_id = (trunnel_get_uint32(ptr));
    remaining -= 1; ptr += 1;

    /* Parse u8 data[TRUNNEL_PAYMENT_LEN] */
    CHECK_REMAINING(TRUNNEL_PAYMENT_LEN, fail);
    memcpy(obj->data, ptr, TRUNNEL_PAYMENT_LEN);
    remaining -= TRUNNEL_PAYMENT_LEN; ptr += TRUNNEL_PAYMENT_LEN;

    trunnel_assert(ptr + remaining == input + len_in);
    return len_in - remaining;

    truncated:
    return -2;
    fail:
    result = -1;
    return result;
}

ssize_t
payment_parse_into(payment_payload_t *obj, const uint8_t *input, const size_t len_in)
{
    const uint8_t *ptr = input;
    size_t remaining = len_in;
    ssize_t result = 0;
    (void)result;

    /* Parse u8 version IN [0] */
    CHECK_REMAINING(1, truncated);
    obj->version = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;
    if (! (obj->version == 0))
        goto fail;

    /* Parse u4 command IN [CELL_PAYMENT_REQUEST] */
    CHECK_REMAINING(1, truncated);
    obj->command = (trunnel_get_uint8(ptr));
    remaining -= 1; ptr += 1;
    if (! (obj->command == CELL_PAYMENT_REQUEST))
        goto fail;

    /* Parse u8 data[TRUNNEL_PAYMENT_LEN] */
    CHECK_REMAINING(TRUNNEL_PAYMENT_LEN, fail);
    memcpy(obj->data, ptr, TRUNNEL_PAYMENT_LEN);
    remaining -= TRUNNEL_PAYMENT_LEN; ptr += TRUNNEL_PAYMENT_LEN;

    trunnel_assert(ptr + remaining == input + len_in);
    return len_in - remaining;

    truncated:
    return -2;
    fail:
    result = -1;
    return result;
}


ssize_t circuit_payment_request_negotiate_encode(uint8_t *output, const size_t avail, const payment_request_payload_t *obj)
{
    ssize_t result = 0;
    size_t written = 0;
    uint8_t *ptr = output;
    const char *msg;
#ifdef TRUNNEL_CHECK_ENCODED_LEN
    const ssize_t encoded_len = circpad_negotiate_encoded_len(obj);
#endif

    if (NULL != (msg = circpad_negotiate_check(obj)))
        goto check_failed;

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

    /* Encode u32 machine_type */
    trunnel_assert(written <= avail);
    if (avail - written < 1)
        goto truncated;
    trunnel_set_uint32(ptr, (obj->node_id));
    written += 1; ptr += 1;

    /* Encode u4 data[TRUNNEL_PAYMENT_LEN] */
    trunnel_assert(written <= avail);
    if (avail - written < TRUNNEL_PAYMENT_LEN)
        goto truncated;
    memcpy(ptr, obj->data, TRUNNEL_PAYMENT_LEN);
    written += TRUNNEL_PAYMENT_LEN; ptr += TRUNNEL_PAYMENT_LEN;
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

ssize_t circuit_payment_negotiate_encode(uint8_t *output, const size_t avail, const payment_payload_t *obj)
{
    ssize_t result = 0;
    size_t written = 0;
    uint8_t *ptr = output;
    const char *msg;
#ifdef TRUNNEL_CHECK_ENCODED_LEN
    const ssize_t encoded_len = circpad_negotiate_encoded_len(obj);
#endif

    if (NULL != (msg = circpad_negotiate_check(obj)))
        goto check_failed;

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

    /* Encode u4 data[TRUNNEL_PAYMENT_LEN] */
    trunnel_assert(written <= avail);
    if (avail - written < TRUNNEL_PAYMENT_LEN)
        goto truncated;
    memcpy(ptr, obj->data, TRUNNEL_PAYMENT_LEN);
    written += TRUNNEL_PAYMENT_LEN; ptr += TRUNNEL_PAYMENT_LEN;
    trunnel_assert(ptr == output + written);

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


