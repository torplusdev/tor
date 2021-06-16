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

std::string* tor_rest_service::route2json(tor_route *route)
{
	json_builder json;

	json.object();
	if (nullptr != route->nodes && route->nodes_len >= 3) {
		json.key("node1").value(route->nodes[0].node_id);
		json.key("node2").value(route->nodes[1].node_id);
		json.key("node3").value(route->nodes[1].node_id);
	}
    json.finish();

	const auto str = json.current();
		
	return new string(str.str,str.len);
}

tor_rest_service::tor_rest_service(void (* routeFunction)(const char* targetNode, tor_route *route),
        int (* commandProcessingFunction)(tor_command* command),
		int (* commandProcessingReplayFunction)(tor_command_replay* command),
		int (*commandProcessingCompletedFunction)(payment_completed *command),
		const char *app_version_string /*= NULL*/)
{
	m_routeCreator = routeFunction;
	m_commandProcessor = commandProcessingFunction;
	m_commandProcessorReplay = commandProcessingReplayFunction;
    m_commandProcessingCompleted = commandProcessingCompletedFunction;
	if(NULL != app_version_string)
		app_version = app_version_string;
}

void tor_rest_service::dump_requests(const char *file_name_suffix, rest_request& req)
{
	if (1) // TODO: set flag from client code
		return;

	std::stringstream file_name;
	static int fn = 0;
	file_name << "~/dump/" << std::this_thread::get_id() << "-" << fn++ << "-" << file_name_suffix;
	// std::sprintf(file_name, "api_command.%i.log", fn++);
	std::ofstream ostrm(file_name.str(), std::ios::binary);
	if (ostrm.is_open())
	{
		ostrm << "method: " << req.method << std::endl;
		ostrm << "url: " << req.url << std::endl;
		ostrm << "content_type: " << req.content_type << std::endl;
		ostrm << "body_len: " << req.body.size() << std::endl;
		ostrm << "body: " << req.body << std::endl;
	}
	else {
		std::cout << req.body;
	}
}


bool tor_rest_service::handle(rest_request& req) 
{
	const int ConstMaxJsonTokens = 1280;
	jsmntok_t t[ConstMaxJsonTokens];
	jsmn_parser jsonParser;
    jsmn_init(&jsonParser);
    if (req.method != "HEAD" && req.method != "GET" && req.method != "POST") 
        return req.respond_method_not_allowed("HEAD, GET, POST");

    if (!req.url.empty()) {
		auto strRoutePrefix = string("/api/paymentRoute");
	    if (req.url.rfind(strRoutePrefix,0) == 0)
	    {
	    	auto index = strRoutePrefix.length();

	    	if (req.url[index] == '/')
                index++;
	    	
	    	auto nodeId = req.url.substr(index);

	    	if (nodeId.length() < 5)
				return req.respond_error("Node id is too short");

	    	auto firstSlash = nodeId.find("/");

	    	if (firstSlash != -1)
                nodeId = nodeId.substr(0,firstSlash);

	    	tor_route route;
	    	m_routeCreator(nodeId.c_str(),&route);
	    	auto str = route2json(&route);
	    	
	    	return req.respond("application/json", string_piece(str->c_str(),str->length()));  
		    
	    }
	    else if (req.url.rfind("/api/command",0) == 0)
		{
			dump_requests("api_command", req);
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
			dump_requests("api_response", req);
	    	const char* jsonRequest = req.body.c_str();
	    	auto r = jsmn_parse(&jsonParser, jsonRequest, req.body.size(), t, sizeof(t) / sizeof(t[0]));

	    	if (r < 0)
	    		return req.respond_error("Couldn't parse json");

	    	std::string commandResponse, commandId, nodeId, sessionId;
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
			}

	    	tor_command_replay cmd;
			cmd.json_body = jsonRequest;
			cmd.commandId = commandId.c_str();
			cmd.nodeId = nodeId.c_str();
			cmd.sessionId = sessionId.c_str();
			cmd.commandResponse = commandResponse.c_str();

	    	int code = m_commandProcessorReplay(&cmd);
	    	if (code < 0)
	    		return req.respond_error("Couldn't parse json or mandatory fields not present");

	    	return req.respond_201("application/json", "");
	    }
	    else if (req.url.rfind("/api/paymentComplete",0) == 0)
		{
			dump_requests("api_paymentComplete", req);
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
        else
        {
        	return req.respond_not_found();
        }
    }

    return req.respond_not_found();
}