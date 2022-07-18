#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "tor_rest/rest_lib.h"

int processCommand(tor_command* command)
{
	const char *nodeId = command->nodeId;
}

int processCommandReplay(tor_command_replay* command)
{
	const char *nodeId = command->nodeId;
}

int processPaymentCompete(payment_completed* command)
{
	const char *session_id = command->sessionId;
	int status = command->status;
}

int main(int argc, char* argv[]) {
	
	if (argc < 2)
	{
	printf("Usage: [port number]");
	return 1;
	}

	int port = atoi(argv[1]);
	runServer(port, processCommand, processCommandReplay, processPaymentCompete, NULL, NULL);
	getchar();

  return 0;
}
