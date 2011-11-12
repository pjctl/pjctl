/*
 * pjctl - network projector control utility
 *
 * Copyright (C) 2011  Benjamin Franzke <benjaminfranzke@googlemail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 1
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

enum pjlink_packet_offsets {
	PJLINK_HEADER = 0,
	PJLINK_CLASS = 1,
	PJLINK_COMMAND = 2,
	PJLINK_SEPERATOR = 6,
	PJLINK_PARAMETER = 7,
	PJLINK_TERMINATOR = 135 /* max or less */
};

enum pjctl_state {
	PJCTL_AWAIT_INITIAL,
	PJCTL_AWAIT_RESPONSE,
	PJCTL_FINISH
};

struct pjctl;

struct queue_command {
	char *command;
	void (*response_func)(struct pjctl *pjctl, struct queue_command *cmd,
			      char *op, char *param);
	char *prefix;
	struct queue_command *prev, *next;
};

struct pjctl {
	enum pjctl_state state;
	struct queue_command queue;
	int fd;
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

#define remove_from_list(elem) \
	do {						\
		(elem)->next->prev = (elem)->prev;	\
		(elem)->prev->next = (elem)->next;	\
	} while (0)

#define insert_at_head(list, elem)			\
	do {						\
		(elem)->prev = list;			\
		(elem)->next = (list)->next;		\
		(list)->next->prev = elem;		\
		(list)->next = elem;			\
	} while(0)


/* return value: -1 = error, 1 = ok, 0 = unknown */
static int
handle_pjlink_error(char *param)
{
	if (strcmp(param, "OK") == 0)
		return 1;

	if (strncmp(param, "ERR", 3) == 0) {
		if (strlen(param) < 4)
			/* not a valid error code, ignore */
			return 0;

		switch (param[3]) {
		case '1':
			printf("error: Undefined command.\n");
			break;
		case '2':
			printf("error: Out-of-parameter.\n");
			break;
		case '3':
			printf("error: Unavailable time.\n");
			break;
		case '4':
			printf("error: Projector failure.\n");
			break;
		default:
			return 0;
		}

		return -1;
	}

	return 0;
}

static int
send_next_cmd(struct pjctl *pjctl)
{
	ssize_t ret;
	struct queue_command *cmd;

	/* Are we're ready? */
	if (pjctl->queue.next == &pjctl->queue) {
		pjctl->state = PJCTL_FINISH;
		return 0;
	}

	cmd = pjctl->queue.prev;

	ret = send(pjctl->fd, cmd->command, strlen(cmd->command), 0);

	pjctl->state = PJCTL_AWAIT_RESPONSE;

	return 0;
}

static int
handle_setup(struct pjctl *pjctl, char *data, int len)
{
	if (data[PJLINK_PARAMETER] == '1') {
		fprintf(stderr,
			"error: pjlink encryption is not implemented.\n");
		return -1;
	}

	if (data[PJLINK_PARAMETER] != '0') {
		fprintf(stderr, "error: invalid setup message received.\n");
		return -1;
	}

	send_next_cmd(pjctl);

	return 0;
}

static int
handle_data(struct pjctl *pjctl, char *data, int len)
{
	struct queue_command *cmd;

	if (len < 8 || len > PJLINK_TERMINATOR) {
		fprintf(stderr, "error: invalid packet length: %d\n", len);
		return -1;
	}

	if (strncmp(data, "PJLINK ", 7) == 0) {
		if (pjctl->state != PJCTL_AWAIT_INITIAL) {
			fprintf(stderr, "error: got unexpected initial\n");
			return -1;
		}
		return handle_setup(pjctl, data, len);
	}

	if (pjctl->state != PJCTL_AWAIT_RESPONSE) {
		fprintf(stderr, "error: got unexpected response.\n");
		return -1;
	}

	if (data[PJLINK_HEADER] != '%') {
		fprintf(stderr, "invalid pjlink command received.\n");
		return -1;
	}

	if (data[PJLINK_CLASS] != '1') {
		fprintf(stderr, "unhandled pjlink class: %c\n", data[1]);
		return -1;
	}

	if (data[PJLINK_SEPERATOR] != '=') {
		fprintf(stderr, "incorrect seperator in pjlink command\n");
		return -1;
	}
	data[PJLINK_SEPERATOR] = '\0';

	cmd = pjctl->queue.prev;

	remove_from_list(cmd);

	cmd->response_func(pjctl, cmd, &data[PJLINK_COMMAND],
			   &data[PJLINK_PARAMETER]);

	free(cmd->command);
	free(cmd);

	send_next_cmd(pjctl);

	return 0;
}

static int
read_cb(struct pjctl *pjctl)
{
	char data[136];
	ssize_t ret;
	char *end;

	ret = recv(pjctl->fd, data, sizeof data, 0);
	if (ret <= 0) {
		exit(1);
	}

	end = memchr(data, 0x0d, ret);
	if (end == NULL) {
		fprintf(stderr, "invalid pjlink msg received\n");
		exit(1);
		return -1;
	}

	*end = '\0';
	if (handle_data(pjctl, data, (ptrdiff_t) (end - data)) < 0)
		return -1;

	return 0;
}

static void
power_response(struct pjctl *pjctl, struct queue_command *cmd,
	       char *op, char *param)
{
	int ret;

	fputs(cmd->prefix, stdout);
	free(cmd->prefix);

	ret = handle_pjlink_error(param);

	if (ret == 1)
		printf("OK\n");
	else if (ret == 0)
		printf("%s\n", param[0] == '1' ? "on" : "off" );
}

static int
power(struct pjctl *pjctl, char **argv, int argc)
{
	struct queue_command *cmd;
	int on;

	cmd = calloc(1, sizeof *cmd);
	if (!cmd)
		return -1;
	if (argc < 2) {
		return -1;
	}

	if (strcmp(argv[1], "on") == 0)
		on = 1;
	else if (strcmp(argv[1], "off") == 0)
		on = 0;
	else {
		fprintf(stderr, "invalid power parameter\n");
		return -1;
	}

	if (asprintf(&cmd->command, "%%1POWR %c\r", on ? '1' : '0') < 0)
		return -1;
	cmd->response_func = power_response;
	if (asprintf(&cmd->prefix, "power %s: ", argv[1]) < 0)
		return -1;

	insert_at_head(&pjctl->queue, cmd);

	return 0;
}

static void
source_response(struct pjctl *pjctl, struct queue_command *cmd,
		char *op, char *param)
{
	if (handle_pjlink_error(param) == 1)
		printf("OK\n");
}

static int
source(struct pjctl *pjctl, char **argv, int argc)
{
	struct queue_command *cmd;
	int type = 0, offset;
	int num;
	int i;
	const char *switches[] = { "rgb", "video", "digital", "storage", "net" };

	cmd = calloc(1, sizeof *cmd);
	if (!cmd)
		return -1;

	if (argc < 2) {
		fprintf(stderr, "missing parameter to source commands\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(switches); ++i) {
		offset = strlen(switches[i]);
		if (strncmp(argv[1], switches[i], offset) == 0) {
			type = i+1;
			break;
		}
	}

	if (type == 0) {
		fprintf(stderr, "incorrect source type given\n");
		return -1;
	}

	num = argv[1][offset];
	if (num < '1' || num > '9') {
		fprintf(stderr,
			"warning: missing source number, defaulting to 1\n");
		num = '1';
	}

	if (asprintf(&cmd->command, "%%1INPT %d%c\r", type, num) < 0)
		return -1;
	cmd->response_func = source_response;

	insert_at_head(&pjctl->queue, cmd);

	printf("source select %s%c: ", switches[type-1], num);

	return 0;
}

static void
avmute_response(struct pjctl *pjctl, struct queue_command *cmd,
		char *op, char *param)
{
	int ret;

	fputs(cmd->prefix, stdout);
	free(cmd->prefix);

	ret = handle_pjlink_error(param);

	if (ret == 1) {
		printf("OK\n");
	} else if (ret == 0) {
		if (strlen(param) != 2)
			return;
		switch (param[0]) {
		case '1':
			printf("video");
			break;
		case '2':
			printf("audio");
			break;
		case '3':
			printf("video & audio");
			break;
		}
		printf(" mute ");

		printf("%s\n", param[1] == '1' ? "on" : "off");
	}
}

static int
avmute(struct pjctl *pjctl, char **argv, int argc)
{
	struct queue_command *cmd;
	int type = -1;
	int i;
	int on;
	const char *targets[] = { "video", "audio", "av" };

	cmd = calloc(1, sizeof *cmd);
	if (!cmd)
		return -1;

	if (argc < 3) {
		fprintf(stderr, "missing parameter to source commands\n");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(targets); ++i) {
		int len = strlen(targets[i]);
		if (strncmp(argv[1], targets[i], len) == 0) {
			type = i+1;
			break;
		}
	}

	if (type == 0) {
		fprintf(stderr, "incorrect source type given\n");
		return -1;
	}

	if (strcmp(argv[2], "on") == 0)
		on = 1;
	else if (strcmp(argv[2], "off") == 0)
		on = 0;
	else {
		fprintf(stderr, "invalid mute parameter\n");
		return -1;
	}

	if (asprintf(&cmd->command, "%%1AVMT %d%d\r", type, on) < 0)
		return -1;
	cmd->response_func = avmute_response;
	if (asprintf(&cmd->prefix, "%s mute %s: ",
		     targets[type-1], argv[2]) < 0)
		return -1;
	insert_at_head(&pjctl->queue, cmd);

	return 0;
}

static void
name_response(struct pjctl *pjctl, struct queue_command *cmd,
	      char *op, char *param)
{
	if (!strlen(param))
		return;

	printf("name: ");
	if (handle_pjlink_error(param) < 0)
		return;

	printf("%s\n", param);
}

static void
manufactor_name_response(struct pjctl *pjctl, struct queue_command *cmd,
			 char *op, char *param)
{
	if (strlen(param))
		printf("manufactor name: %s\n", param);
}

static void
product_name_response(struct pjctl *pjctl, struct queue_command *cmd,
		      char *op, char *param)
{
	if (strlen(param))
		printf("product name: %s\n", param);
}

static void
info_response(struct pjctl *pjctl, struct queue_command *cmd,
	      char *op, char *param)
{
	if (strlen(param))
		printf("model info: %s\n", param);
}

static const char *
map_input_name(char sw)
{
	switch (sw) {
	case '1':
		return "rgb";
	case '2':
		return "video";
	case '3':
		return "digital";
	case '4':
		return "storage";
	case '5':
		return "net";
	default:
		return "unknown";
	}
}

static void
input_switch_response(struct pjctl *pjctl, struct queue_command *cmd,
		      char *op, char *param)
{
	if (!strlen(param))
		return;

	printf("current input: ");

	if (handle_pjlink_error(param) < 0)
		return;

	if (strlen(param) == 2)
		printf("%s%c\n",
			map_input_name(param[0]), param[1]);
	else
		printf("error: invalid response\n");
}

static void
input_list_response(struct pjctl *pjctl, struct queue_command *cmd,
		    char *op, char *param)
{
	int i;
	int len = strlen(param);

	if (len % 3 != 2)
		return;

	printf("available input sources:");

	for (i = 0; i < len; i+=3)
		printf(" %s%c", map_input_name(param[i]), param[i+1]);

	printf("\n");
}

static void
lamp_response(struct pjctl *pjctl, struct queue_command *cmd,
	      char *op, char *param)
{
	printf("lamp: %s\n", param);
}

static void
error_status_response(struct pjctl *pjctl, struct queue_command *cmd,
		      char *op, char *param)
{
	printf("error status: %s\n", param);
}

static void
class_response(struct pjctl *pjctl, struct queue_command *cmd,
	       char *op, char *param)
{
	printf("available classes: %s\n", param);
}

static int
status(struct pjctl *pjctl, char **argv, int argc)
{
	/* Note: incomplete commands stored here */
	static const struct queue_command cmds[] = {
		{ "NAME", name_response },
		{ "INF1", manufactor_name_response },
		{ "INF2", product_name_response },
		{ "INFO", info_response },
		{ "POWR", power_response, "power status: " },
		{ "INPT", input_switch_response },
		{ "INST", input_list_response },
		{ "AVMT", avmute_response, "avmute: " },
		{ "LAMP", lamp_response },
		{ "ERST", error_status_response },
		{ "CLSS", class_response }
	};
	struct queue_command *cmd;
	int i;

	for (i = 0; i < ARRAY_SIZE(cmds); ++i) {
		cmd = calloc(1, sizeof *cmd);
		if (!cmd)
			return -1;
		memcpy(cmd, &cmds[i], sizeof *cmd);
		if (asprintf(&cmd->command, "%%1%s ?\r", cmds[i].command) < 0)
			return -1;
		if (cmds[i].prefix)
			cmd->prefix = strdup(cmds[i].prefix);
		insert_at_head(&pjctl->queue, cmd);
	}

	return 0;
}

static struct pjctl_command {
	char *name;
	int (*func)(struct pjctl *pjctl, char **argv, int argc);
	char *help;
} commands[] = {
	{ "power", power, "<on|off>" },
	{ "source", source, "<rgb|video|digital|storage|net>[1-9]" },
	{ "mute", avmute, "<video|audio|av> <on|off>" },
	{ "status", status, ""},
};

static void
usage(struct pjctl *pjctl)
{
	int i;

	printf("usage: pjctl <hostname> command [args..]\n\n");
	printf("commands:\n");
	for (i = 0; i < ARRAY_SIZE(commands); ++i)
		printf("  %s %s\n", commands[i].name, commands[i].help);
}

int
main(int argc, char **argv)
{
	struct pjctl pjctl;
	char *host = argv[1];
	char *sport = "4352";
	struct addrinfo hints, *result, *rp;
	int s, i;

	memset(&pjctl, 0, sizeof pjctl);
	pjctl.queue.next = pjctl.queue.prev = &pjctl.queue;

	if (argc <= 2) {
		usage(&pjctl);
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(commands); ++i) {
		if (strcmp(argv[2], commands[i].name) == 0) {
			if (commands[i].func(&pjctl, &argv[2], argc-2) < 0)
				return 1;
		}
	}

	/* Nothing got into queue? User gave invalid command. */
	if (pjctl.queue.next == &pjctl.queue) {
		fprintf(stderr, "error: invalid command\n");
		usage(&pjctl);
		return 1;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	s = getaddrinfo(host, sport, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo :%s\n", gai_strerror(s));
		return 1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		pjctl.fd = socket(rp->ai_family, rp->ai_socktype,
				  rp->ai_protocol);
		if (pjctl.fd == -1)
			continue;

		if (connect(pjctl.fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;

		close(pjctl.fd);
	}
	freeaddrinfo(result);
	if (rp == NULL) {
		fprintf(stderr, "Failed to connect: %m\n");
		return 1;
	}

	pjctl.state = PJCTL_AWAIT_INITIAL;

	while (pjctl.state != PJCTL_FINISH) {
		if (read_cb(&pjctl) < 0)
			return 1;
	}
	
	close(pjctl.fd);

	return 0;
}
