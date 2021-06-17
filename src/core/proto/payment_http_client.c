#include "core/proto/payment_http_client.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <json-c/json.h>
#include <curl/curl.h>
#include <src/lib/malloc/malloc.h>
#include <src/lib/log/log.h>
#include <src/app/config/or_options_st.h>
#include <src/app/config/config.h>
#include <src/core/or/relay.h>
#include <src/core/mainloop/mainloop.h>
#include <pthread.h>

struct curl_fetch_st {
    char *payload;
    size_t size;
};

void ship_log(log_args_t* args)
{
    const or_options_t *options = get_options();
    if( !options->EnablePaymentLog )
        return;

    log_notice(LD_GENERAL,
        "Payments Log: NodeNickname='%s' RequestUrl='%s' RequestBody='%s' ResponseBody='%s'",
        options->Nickname ? options->Nickname : "(NULL)",
        args->url ? args->url : "(NULL)",
        args->requestBody ? args->requestBody : "(NULL)",
        args->responseBody ? args->responseBody : "(NULL)"
    );
}

char* tp_create_payment_info(char *url, create_payment_info_t* body)
{
    /* build post data */
    json_object*  json_request = json_object_new_object();
    json_object_object_add(json_request, "ServiceType", json_object_new_string(body->service_type));
    json_object_object_add(json_request, "CommodityType", json_object_new_string(body->commodity_type));
    json_object_object_add(json_request, "Amount", json_object_new_int(body->amount));

    const char* request_string = json_object_to_json_string(json_request);
    char *response = tp_http_post_request(url, request_string);
    log_args_t args;
    args.url= url;
    args.requestBody = request_string;
    args.responseBody = (response == NULL) ? "" : response;
    ship_log(&args);
    return response;
}

payment_response_t* tp_http_payment(char *url, process_payment_request_t* body, int hop_num) {
    json_object*  json_request = json_object_new_object();
    json_object *jarray = json_object_new_array();
    for (int i = 0; i < hop_num - 1; ++i) {
        json_object* obj = json_object_new_object();
        json_object_object_add(obj, "NodeId", json_object_new_string(body->routing_node[i].node_id));
        json_object_object_add(obj, "Address", json_object_new_string(body->routing_node[i].address));
        json_object_array_add(jarray,obj);
    }

    /* build post data */
    json_object_object_add(json_request, "CallbackUrl", json_object_new_string(body->call_back_url));
    json_object_object_add(json_request, "StatusCallbackUrl", json_object_new_string(body->status_call_back_url));
    json_object_object_add(json_request, "NodeId", json_object_new_string(body->node_id));
    json_object_object_add(json_request, "Route", jarray);
    json_object_object_add(json_request, "PaymentRequest", json_object_new_string(body->payment_request));

    const char* request_string = json_object_to_json_string(json_request);
    char* response = tp_http_post_request(url, request_string);
    log_args_t args;
    args.url= url;
    args.requestBody = request_string;
    args.responseBody = (response == NULL) ? "" : response;
    ship_log(&args);
    return NULL;
}

payment_response_t* tp_http_command(char *url, utility_command_t* body) {
    json_object*  json_request = json_object_new_object();
    /* build post data */
    json_object_object_add(json_request, "CommandType", json_object_new_int(body->command_type));
    json_object_object_add(json_request, "CommandBody", json_object_new_string(body->command_body));
    json_object_object_add(json_request, "CommandId", json_object_new_string(body->command_id));
    json_object_object_add(json_request, "CallbackUrl", json_object_new_string(body->callback_url));
    json_object_object_add(json_request, "NodeId", json_object_new_string(body->node_id));
    json_object_object_add(json_request, "SessionId", json_object_new_string(body->session_id));

    const char* request_string = json_object_to_json_string(json_request);
    char* response = tp_http_post_request(url, request_string);
    log_args_t args;
    args.url= url;
    args.requestBody = request_string;
    args.responseBody = (response == NULL) ? "" : response;
    ship_log(&args);
    return NULL;
}

payment_response_t* tp_http_response(char *url, utility_response_t* body) {
    json_object*  json_request = json_object_new_object();
    /* build post data */
    json_object_object_add(json_request, "ResponseBody", json_object_new_string(body->response_body));
    json_object_object_add(json_request, "NodeId", json_object_new_string(body->node_id));
    json_object_object_add(json_request, "CommandId", json_object_new_string(body->command_id));
    json_object_object_add(json_request, "SessionId", json_object_new_string(body->session_id));

    const char* request_string = json_object_to_json_string(json_request);
    char* response = tp_http_post_request(url, request_string);
    log_args_t args;
    args.url= url;
    args.requestBody = request_string;
    args.responseBody = (response == NULL) ? "" : response;
    ship_log(&args);
    return NULL;
}

/* callback for curl fetch */
static size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
        /* this isn't good */
        fprintf(stderr, "ERROR: Failed to expand buffer in curl_callback");
        /* free buffer */
        free(p->payload);
        /* return */
        return -1;
    }

    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

/* fetch and return url body via curl */
static CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
    CURLcode rcode;                   /* curl result code */

    /* init payload */
    fetch->payload = (char *) tor_calloc_(1, sizeof(fetch->payload));

    /* check payload */
    if (fetch->payload == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to allocate payload in curl_fetch_url");
        /* return error */
        return CURLE_FAILED_INIT;
    }

    /* init size */
    fetch->size = 0;

    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);

    /* set calback function */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) fetch);

    /* set default user agent */
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* set timeout */
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 5);

    /* enable location redirects */
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);

    /* set maximum allowed redirects */
    curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);

    /* fetch the url */
    rcode = curl_easy_perform(ch);

    /* return */
    return rcode;
}


char* tp_http_post_request(const char* url_input, const char* request_json)
{
    CURL *ch;                                               /* curl handle */
    CURLcode rcode;                                         /* curl result code */
   // json_object *json;                                      /* json post body */
    enum json_tokener_error jerr = json_tokener_success;    /* json parse error */
    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_slist *headers = NULL;                      /* http headers to send with request */
    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        return NULL;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, request_json);
    /* fetch page and capture return code */
    rcode = curl_fetch_url(ch, url_input, &curl_fetch);

    long http_code = 0;
    curl_easy_getinfo (ch, CURLINFO_RESPONSE_CODE, &http_code);

    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    /* free headers */
    curl_slist_free_all(headers);

    /* free json object */


    /* check return code */
    if (rcode != CURLE_OK) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to fetch url (%s) - curl said: %s",
                url_input, curl_easy_strerror(rcode));
        /* return error */

        return NULL;
    }

    /* check payload */
    if (curl_fetch.payload != NULL) {
        /* print result */
        //printf("url (%s) - curl said: %s:", url_input, rcode);
        /* parse return */
       // json = json_tokener_parse_verbose(cf->payload, &jerr);

        return curl_fetch.payload;
    } else {
        /* error */
        fprintf(stderr, "ERROR: Failed to populate payload");
        /* free payload */
        free(curl_fetch.payload);
        /* return */
        return NULL;
    }

    /* check error */
    if (jerr != json_tokener_success) {
        /* error */
        fprintf(stderr, "ERROR: Failed to parse json string");
        /* free json object */
        /* return */
        return NULL;
    }

    /* debugging */

    /* exit */
    return NULL;
}

json_object* tp_http_get_request(const char* url_input)
{
    CURL *ch;                                               /* curl handle */
    CURLcode rcode;                                         /* curl result code */
    // json_object *json;                                      /* json post body */
    enum json_tokener_error jerr = json_tokener_success;    /* json parse error */

    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */
    struct curl_slist *headers = NULL;                      /* http headers to send with request */

    /* url to test site */

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        return NULL;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);

    /* fetch page and capture return code */
    rcode = curl_fetch_url(ch, url_input, cf);

    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    /* free headers */
    curl_slist_free_all(headers);

    /* check return code */
    if (rcode != CURLE_OK) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to fetch url (%s) - curl said: %s",
                url_input, curl_easy_strerror(rcode));
        /* return error */

        return NULL;
    }

    /* check payload */
    if (cf->payload != NULL) {
        /* print result */
        printf("CURL Returned: \n%s\n", cf->payload);
        /* parse return */
        json_object* json = json_tokener_parse_verbose(cf->payload, &jerr);
        printf("Parsed JSON: %s\n", json_object_to_json_string(json));
        return json;
    } else {
        /* error */
        fprintf(stderr, "ERROR: Failed to populate payload");
        /* free payload */
        free(cf->payload);
        /* return */
        return NULL;
    }

    /* check error */
    if (jerr != json_tokener_success) {
        /* error */
        fprintf(stderr, "ERROR: Failed to parse json string");
        /* free json object */
        /* return */
        return NULL;
    }

    /* debugging */

    /* exit */
    return NULL;
}
