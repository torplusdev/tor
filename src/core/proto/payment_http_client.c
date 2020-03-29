#include "core/proto/payment_http_client.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <json-c/json.h>
#include <x86_64-linux-gnu/curl/curl.h>



struct curl_fetch_st {
    char *payload;
    size_t size;
};


//payment_creation_response_t* send_payment_request_creation(char *url, payment_creation_request_t* body) {
//    json_object*  json = json_object_new_object();
//
//    /* build post data */
//    json_object_object_add(json, "title", json_object_new_string(body->prm_1));
//    json_object_object_add(json, "body", json_object_new_string(body->prm_2));
//    json_object_object_add(json, "userId", json_object_new_int(133));
//
//    void* res = send_http_request(url, json);
//
//    struct payment_creation_response_t *p = (struct payment_creation_response_t *) res;   /* cast pointer to fetch struct */
//
//    return p;
//}
//
//utility_replay_command_response_t* send_utility_replay_command(char *url, utility_replay_command_request_t* body) {
//    json_object*  json = json_object_new_object();
//
//    /* build post data */
//    json_object_object_add(json, "title", json_object_new_string(body->prm_1));
//    json_object_object_add(json, "body", json_object_new_string(body->prm_2));
//    json_object_object_add(json, "userId", json_object_new_int(133));
//
//    void* res = send_http_request(url, json);
//
//    struct utility_replay_command_response_t *p = (struct utility_replay_command_response_t *) res;   /* cast pointer to fetch struct */
//
//    return p;
//}
//
//utility_process_command_response_t* send_process_command(char *url, utility_process_command_request_t* body){
//    json_object* json = json_object_new_object();
//
//    /* build post data */
//    json_object_object_add(json, "title", json_object_new_string(body->prm_1));
//    json_object_object_add(json, "body", json_object_new_string(body->prm_2));
//    json_object_object_add(json, "userId", json_object_new_int(133));
//
//    void* res = send_http_request(url, json);
//
//    struct utility_process_command_response_t *p = (struct utility_process_command_response_t *) res;   /* cast pointer to fetch struct */
//
//    return p;
//}
//
//payment_response_t* send_payment_request(char *url, payment_request_t* body) {
//    json_object* json = json_object_new_object();
//
//    /* build post data */
//    json_object_object_add(json, "title", json_object_new_string(body->prm_1));
//    json_object_object_add(json, "body", json_object_new_string(body->prm_2));
//    json_object_object_add(json, "userId", json_object_new_int(133));
//
//    void* res = send_http_request(url, json);
//
//    struct payment_response_t *p = (struct payment_response_t *) res;   /* cast pointer to fetch struct */
//
//    return p;
//}

/* callback for curl fetch */
size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
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
CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
    CURLcode rcode;                   /* curl result code */

    /* init payload */
    fetch->payload = (char *) calloc(1, sizeof(fetch->payload));

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



request_response_t* send_http_request(char* url_input, json_object* body) {
    CURL *ch;                                               /* curl handle */
    CURLcode rcode;                                         /* curl result code */

    json_object *json;                                      /* json post body */
    enum json_tokener_error jerr = json_tokener_success;    /* json parse error */

    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */
    struct curl_slist *headers = NULL;                      /* http headers to send with request */


    request_response_t* response;
    response = malloc(sizeof(request_response_t));
    response->error_code = 1;
    response->json_response = NULL;

    /* url to test site */
    char *url = "http://jsonplaceholder.typicode.com/posts/";

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        response->error_code = 1;
        return response;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* create json object for post */
   json = body;
//   json = json_object_new_object();
//
//    /* build post data */
//    json_object_object_add(json, "title", json_object_new_string(body->prm_1));
//    json_object_object_add(json, "body", json_object_new_string(body->prm_2));
//    json_object_object_add(json, "userId", json_object_new_int(133));

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

    /* fetch page and capture return code */
    rcode = curl_fetch_url(ch, url, cf);

    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    /* free headers */
    curl_slist_free_all(headers);

    /* free json object */
    json_object_put(json);

    /* check return code */
    if (rcode != CURLE_OK || cf->size < 1) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to fetch url (%s) - curl said: %s",
                url, curl_easy_strerror(rcode));
        /* return error */

        response->error_code = 2;
        return response;
    }

    /* check payload */
    if (cf->payload != NULL) {
        /* print result */
        printf("CURL Returned: \n%s\n", cf->payload);
        /* parse return */
        json = json_tokener_parse_verbose(cf->payload, &jerr);
        response->json_response = json;
        /* free payload */
        free(cf->payload);
    } else {
        /* error */
        fprintf(stderr, "ERROR: Failed to populate payload");
        /* free payload */
        free(cf->payload);
        /* return */
        response->error_code = 3;
        return response;
    }

    /* check error */
    if (jerr != json_tokener_success) {
        /* error */
        fprintf(stderr, "ERROR: Failed to parse json string");
        /* free json object */
        json_object_put(json);
        /* return */
        response->error_code = 4;
        return response;
    }

    /* debugging */
    printf("Parsed JSON: %s\n", json_object_to_json_string(json));
    /* exit */
    response->error_code = 0;
    return response;
}



