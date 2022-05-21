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

#define _POSIX_C_SOURCE 200112L
#define _BSD_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <netdb.h>

#ifndef NO_CRYPTO
#include <openssl/evp.h>
#endif

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
	PJCTL_AWAIT_RESPONSE_OR_AUTH_ERR,
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

	char *password;
#ifndef NO_CRYPTO
	int need_hash;
	char hash[32+1]; /* 0-terminated hex as ascii encoded 16 byte hash */
#endif
};

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))

#define MIN(a,b) ((a)<(b) ? (a) : (b))

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

#ifndef NO_CRYPTO
static int
calculate_hash(struct pjctl *pjctl, const char *salt)
{

	EVP_MD_CTX *mdctx = NULL;
	uint8_t md[EVP_MAX_MD_SIZE];
	unsigned md_size;
	int r;

	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		/* This function just calls OPENSSL_zalloc, so failure
		 * here is almost certainly a failed allocation. */
		return -ENOMEM;
	}
	r = EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
	if (r == 0) {
		EVP_MD_CTX_free(mdctx);
		return -EIO;
	}

	r = EVP_DigestUpdate(mdctx, salt, strlen(salt));
	if (r == 0) {
		EVP_MD_CTX_free(mdctx);
		return -EIO;
	}

	r = EVP_DigestUpdate(mdctx, pjctl->password, strlen(pjctl->password));
	if (r == 0) {
		EVP_MD_CTX_free(mdctx);
		return -EIO;
	}

	r = EVP_DigestFinal_ex(mdctx, md, &md_size);
	if (r == 0) {
		EVP_MD_CTX_free(mdctx);
		return -EIO;
	}

	EVP_MD_CTX_free(mdctx);

	snprintf(pjctl->hash, sizeof(pjctl->hash),
		 "%02x%02x%02x%02x%02x%02x%02x%02x"
		 "%02x%02x%02x%02x%02x%02x%02x%02x",
		 md[ 0], md[ 1], md[ 2], md[ 3],
		 md[ 4], md[ 5], md[ 6], md[ 7],
		 md[ 8], md[ 9], md[10], md[11],
		 md[12], md[13], md[14], md[15]);
	pjctl->need_hash = 1;

	return 0;
}
#endif

static int
send_next_cmd(struct pjctl *pjctl)
{
	struct queue_command *cmd;
	struct msghdr msg;
	struct iovec iov[2];

	/* Are we're ready? */
	if (pjctl->queue.next == &pjctl->queue) {
		pjctl->state = PJCTL_FINISH;
		return 0;
	}

	pjctl->state = PJCTL_AWAIT_RESPONSE;

	memset(&msg, 0, sizeof msg);
	msg.msg_iov = iov;

#ifndef NO_CRYPTO
	if (pjctl->need_hash) {
		pjctl->state = PJCTL_AWAIT_RESPONSE_OR_AUTH_ERR;

		iov[msg.msg_iovlen].iov_base = pjctl->hash;
		iov[msg.msg_iovlen].iov_len = 32;
		msg.msg_iovlen++;
	}
#endif

	cmd = pjctl->queue.prev;
	iov[msg.msg_iovlen].iov_base = cmd->command;
	iov[msg.msg_iovlen].iov_len = strlen(cmd->command);
	msg.msg_iovlen++;

	if (sendmsg(pjctl->fd, &msg, 0) < 0) {
		fprintf(stderr, "sendmsg failed: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int
handle_setup(struct pjctl *pjctl, char *data, int len)
{
	switch (data[PJLINK_PARAMETER]) {
#ifndef NO_CRYPTO
	case '1':
		if (pjctl->password == NULL) {
			fprintf(stderr,
				"Authentication required, password needed\n");
			return -1;
		}
		if (strlen(&data[PJLINK_PARAMETER]) < 3)
			goto err;
		if (calculate_hash(pjctl, &data[PJLINK_PARAMETER+2]) != 0) {
			fprintf(stderr,
				"Failed to calculate md5sum\n");
			return -1;
		}
		break;
#endif
	case '0':
		/* No authentication */
		break;
	case 'E':
		if (strcmp(&data[PJLINK_PARAMETER], "ERRA") == 0) {
			fprintf(stderr, "Authentication failed.\n");
			return -1;
		}
		/* FALLTHROUGH */
	default:
		goto err;
	}

	send_next_cmd(pjctl);

	return 0;
err:
	fprintf(stderr, "error: invalid setup message received.\n");
	return -1;
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
		switch (pjctl->state) {
		case PJCTL_AWAIT_INITIAL:
		case PJCTL_AWAIT_RESPONSE_OR_AUTH_ERR:
			break;
		default:
			fprintf(stderr, "error: got unexpected initial\n");
			return -1;
		}
		return handle_setup(pjctl, data, len);
	}

	switch (pjctl->state) {
	case PJCTL_AWAIT_RESPONSE:
	case PJCTL_AWAIT_RESPONSE_OR_AUTH_ERR:
		break;
	default:
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
	char *lamp_end, *lamp_on, *lamp_time = param;
	int i, len = strlen(param);

	printf("lamp: ");
	if (handle_pjlink_error(param) < 0)
		return;

	for (i = 0; len; ++i) {
		lamp_end = memchr(lamp_time, ' ', MIN(len, 5));
		if (lamp_end == NULL)
			goto invalid;

		*lamp_end = '\0';
		len -= lamp_end - lamp_time;
		if (len < 2)
			goto invalid;

		switch (*(lamp_end + 1)) {
		case '1':
			lamp_on = "on";
			break;
		case '0':
			lamp_on = "off";
			break;
		default:
			goto invalid;
		}

		printf("lamp%d:%s cumulative lighting time: %s; ",
		       i, lamp_on, lamp_time);

		lamp_time = lamp_end + 2;
		len -= 2;
		if (strlen(lamp_time)) {
			if (lamp_time[0] != ' ')
				goto invalid;
			lamp_time++;
			len--;
		}
	}

	printf("\n");
	return;

invalid:
	printf("invalid message body: %s\n", param);
}

static void
error_status_response(struct pjctl *pjctl, struct queue_command *cmd,
		      char *op, char *param)
{
	int i;
	int none = 1;
	const char *flags[] = {
		"fan", "lamp", "temperature", "cover", "filter", "other"
	};

	printf("errors: ");
	if (handle_pjlink_error(param) < 0)
		return;

	if (strlen(param) != 6) {
		fprintf(stderr, "invalid message received\n");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(flags); ++i) {
		switch (param[i]) {
		case '2':
			printf("%s:error ", flags[i]);
			none = 0;
			break;
		case '1':
			printf("%s:warning ", flags[i]);
			none = 0;
			break;
		case '0':
			break;
		default:
			fprintf(stderr, "invalid message received\n");
			return;
		}
	}
	if (none)
		fputs("none", stdout);
	fputs("\n", stdout);
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

	printf("usage: pjctl [-p password] <hostname> command [args..]\n\n");
	printf("commands:\n");
	for (i = 0; i < ARRAY_SIZE(commands); ++i)
		printf("  %s %s\n", commands[i].name, commands[i].help);
}

int
main(int argc, char **argv)
{
	struct pjctl pjctl;
	char *host;
	char *sport = "4352";
	struct addrinfo hints, *result, *rp;
	int s, i, c;

	memset(&pjctl, 0, sizeof pjctl);
	pjctl.queue.next = pjctl.queue.prev = &pjctl.queue;

	while ((c = getopt(argc, argv, "p:")) != -1) {
		switch (c) {
		case 'p':
			pjctl.password = optarg;
			break;
		default:
			return 1;
		}
	}

	if (argc < optind+2) {
		usage(&pjctl);
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(commands); ++i) {
		if (strcmp(argv[optind+1], commands[i].name) == 0) {
			if (commands[i].func(&pjctl, &argv[optind+1],
					     argc-optind-1) < 0)
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

	host = argv[optind];
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
		fprintf(stderr, "Failed to connect: %s\n", strerror(errno));
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
