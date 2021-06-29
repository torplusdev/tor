#include "rest_lib.h"
#define JSMN_HEADER
#include "jsmn.h"
#include "tor_rest_service.h"
#include <sstream>

extern "C" int runServer(
		int port,
		void (*routeFunction)(const char* targetNode, tor_route *route),
        int (*commandProcessingFunction)(tor_command* command),
		int (*commandProcessingReplayFunction)(tor_command_replay* command),
		int (*commandProcessingCompletedFunction)(payment_completed *command),
		void (*log_function)(const char *message),
		const char *appVersionString /*= NULL*/
	)
{	  
	int threads = 2;
	int connection_limit = 100;

	auto service = new tor_rest_service(
		routeFunction,
		commandProcessingFunction,
		commandProcessingReplayFunction,
		commandProcessingCompletedFunction,
		log_function,
		static_cast<const char *>(appVersionString));

	auto server = new rest_server();
	
	// server->set_log_file(&cerr);
	server->set_max_connections(connection_limit);
	server->set_threads(threads);
  
	if (!server->start(service, port)) {
		std::stringstream msg;
		msg << "Cannot start REST server on port: " << port;
		if (nullptr != log_function)
			log_function(msg.str().c_str());
		else
			cerr << msg.str() << std::endl;
		return -1;
	}
	return 0;
}
