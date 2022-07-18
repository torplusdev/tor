#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include <string.h>
#include <stdio.h>

#include "microrestd.h"
#include "rest_lib.h"
#include "jsmn.h"
#include "tor_rest_service.h"
#include "route_generator.h"
#include <sstream>

using namespace std;
using namespace ufal::microrestd;


static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

tor_rest_service::tor_rest_service(int (* commandProcessingFunction)(tor_command* command),
		int (* commandProcessingReplayFunction)(tor_command_replay* command),
		int (*commandProcessingCompletedFunction)(payment_completed *command),
		void (*log_function)(const char *message),
		const char *app_version_string /*= NULL*/,
		int (*handler)(tor_http_api_request_t *) /* = nullptr*/
	)
{
	m_commandProcessor = commandProcessingFunction;
	m_commandProcessorReplay = commandProcessingReplayFunction;
    m_commandProcessingCompleted = commandProcessingCompletedFunction;
	m_log_handler = log_function;
	m_handler = handler;
	if(NULL != app_version_string)
		app_version = app_version_string;
}

void tor_rest_service::log(const char *message)
{
	if(m_log_handler)
		m_log_handler(message);
}

void tor_rest_service::req_log(rest_request& req)
{
	if(!m_log_handler)
		return;

	std::stringstream message;
	message << "===[ tor_rest_service::req_log ]=================================" << std::endl;
	message << "method: " << req.method << std::endl;
	message << "url: " << req.url << std::endl;
	message << "content_type: " << req.content_type << std::endl;
	message << "body_len: " << req.body.size() << std::endl;
	message << "body: " << req.body << std::endl;
	message << "=================================================================";
	std::string tmp = message.str();
	m_log_handler(tmp.c_str());
}

bool tor_rest_service::handle(rest_request& req)
{
	req_log(req);
	const int ConstMaxJsonTokens = 1280;
	jsmntok_t t[ConstMaxJsonTokens];
	jsmn_parser jsonParser;
    jsmn_init(&jsonParser);
    if (req.method != "HEAD" && req.method != "GET" && req.method != "POST") 
        return req.respond_method_not_allowed("HEAD, GET, POST");

    if (!req.url.empty()) {
		if (req.url.rfind("/api/command",0) == 0)
		{
	    	const char* jsonRequest = req.body.c_str();
	    	auto r = jsmn_parse(&jsonParser, jsonRequest, req.body.size(), t, sizeof(t) / sizeof(t[0]));

            if (r < 0)
	    		return req.respond_error("Couldn't parse json");

	    	std::string commandBody, commandId, commandType, nodeId, sessionId;
			for (int i = 1; i < r; i++) 
			{
				const jsmntok_t* pt = &t[i + 1];
				if (jsoneq(jsonRequest, &t[i], "CommandBody") == 0) {
					commandBody = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "CommandId") == 0)
				{
					commandId = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "CommandType") == 0)
				{
					commandType = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "NodeId") == 0)
				{
					nodeId =std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "SessionId") == 0)
				{
					sessionId = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
			}
	    	tor_command cmd;
			cmd.json_body = jsonRequest;
			cmd.commandBody = commandBody.c_str();
			cmd.commandId = commandId.c_str();
			cmd.commandType = commandType.c_str();
			cmd.nodeId = nodeId.c_str();
			cmd.sessionId = sessionId.c_str();

	    	int code = m_commandProcessor(&cmd);
	    	if (code < 0)
	    		return req.respond_error("Couldn't parse json or mandatory fields not present");

	    	return req.respond_201("application/json", "");
	    }
	    else if (req.url.rfind("/api/response",0) == 0)
		{
	    	const char* jsonRequest = req.body.c_str();
	    	auto r = jsmn_parse(&jsonParser, jsonRequest, req.body.size(), t, sizeof(t) / sizeof(t[0]));

	    	if (r < 0)
	    		return req.respond_error("Couldn't parse json");

	    	std::string commandResponse, commandId, nodeId, sessionId, commandType;
			for (int i = 1; i < r; i++)
			{
				const jsmntok_t* pt = &t[i + 1];
				if (jsoneq(jsonRequest, &t[i], "CommandResponse") == 0) {
					commandResponse = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "CommandId") == 0)
				{
					commandId = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "NodeId") == 0)
				{
					nodeId = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "SessionId") == 0)
				{
					sessionId = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "CommandType") == 0)
				{
					commandType = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
			}

	    	tor_command_replay cmd;
			cmd.json_body = jsonRequest;
			cmd.commandId = commandId.c_str();
			cmd.nodeId = nodeId.c_str();
			cmd.sessionId = sessionId.c_str();
			cmd.commandResponse = commandResponse.c_str();
			cmd.commandType = commandType.c_str();

	    	int code = m_commandProcessorReplay(&cmd);
	    	if (code < 0)
	    		return req.respond_error("Couldn't parse json or mandatory fields not present");

	    	return req.respond_201("application/json", "");
	    }
	    else if (req.url.rfind("/api/paymentComplete",0) == 0)
		{
	    	const char* jsonRequest = req.body.c_str();
	    	auto r = jsmn_parse(&jsonParser, jsonRequest, req.body.size(), t, sizeof(t) / sizeof(t[0]));

	    	if (r < 0)
	    		return req.respond_error("Couldn't parse json");

	    	std::string status, sessionId;
			for (int i = 1; i < r; i++)
			{
				const jsmntok_t* pt = &t[i + 1];
				if (jsoneq(jsonRequest, &t[i], "SessionId") == 0) {
					sessionId = std::string(jsonRequest + pt->start, pt->end - pt->start);
					i++;
				}
				else if (jsoneq(jsonRequest, &t[i], "Status") == 0) {
					status = std::string(jsonRequest + pt->start, pt->end - pt->start);;
					i++;
				}
			}

            payment_completed cmd;
			cmd.json_body = jsonRequest;
			cmd.sessionId = sessionId.c_str();
			cmd.status = (status.size() > 0) ? atoi(status.c_str()) : -1;

	    	int code = m_commandProcessingCompleted(&cmd);
	    	if (code < 0)
	    		return req.respond_error("Couldn't parse json or mandatory fields not present");

	    	return req.respond("application/json", "OK");
	    }
	    else if (req.url.rfind("/api/version",0) == 0) {

	    	return req.respond("text/plain", app_version);
		}
		else if (NULL != m_handler) {
			tor_http_api_request_t request;
			std::memset(&request, 0, sizeof(request));
			request.method = req.method.c_str();
			request.url = req.url.c_str();
			request.body = req.body.c_str();
			vector<tor_http_api_request_param_t> params;
			if(req.params.size()) {
				request.param_count = req.params.size();
				params.resize(request.param_count);
				request.params = params.data();
				size_t i = 0;
				for (auto& p : req.params) {
					request.params[i].name = p.first.c_str();
					request.params[i].value = p.second.c_str();
					i++;
				}
			}
			int rc =  m_handler(&request);
			switch (rc){
			case 0:
				if (request.answer_body) {
					return req.respond("application/json", request.answer_body);
				} else
				return req.respond("application/json", "{\"result\":\"success\"}");
			case -1:
				return req.respond("application/json", "{\"result\":\"wrong method\"}");
			case -2:
				return req.respond("application/json", "{\"result\":\"wrong url\"}");
			case -3:
				return req.respond("application/json", "{\"result\":\"wrong body\"}");
			case -4:
				return req.respond("application/json", "{\"result\":\"wrong json\"}");
			case -5:
				return req.respond("application/json", "{\"result\":\"wrong parameter\"}");
			case -6:
				return req.respond("application/json", "{\"result\":\"wrong empty/nil parameter\"}");
			case -7:
				return req.respond("application/json", "{\"result\":\"wrong parameter format\"}");
			default:
				return req.respond("application/json", "{\"result\":\"unknown answer\"}");
			}
			if(request.release && request.answer_body) {
				request.release(request.answer_body);
			}
		}
        else
        {
        	return req.respond_not_found();
        }
    }

    return req.respond_not_found();
}