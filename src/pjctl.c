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

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <gio/gio.h>

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
	PJCTL_AWAIT_RESPONSE
};

struct pjctl {
	enum pjctl_state state;
	GList *queue;

	GMainLoop *loop;

	GSocketClient *sc;
	GSocketConnection *con;
	GPollableInputStream *in;
	GOutputStream *out;
};

struct queue_command {
	char *command;
	void (*response_func)(struct pjctl *pjctl, char *cmd, char *param);
};

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
			g_printerr("error: Undefined command.\n");
			break;
		case '2':
			g_printerr("error: Out-of-parameter.\n");
			break;
		case '3':
			g_printerr("error: Unavailable time.\n");
			break;
		case '4':
			g_printerr("error: Projector failure.\n");
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
	GError *error = NULL; 
	gssize ret;
	struct queue_command *cmd;

	/* Are we're ready? */
	if (g_list_length(pjctl->queue) == 0) {
		g_main_loop_quit(pjctl->loop);
		return 0;
	}

	cmd = g_list_nth_data(pjctl->queue, 0);

	ret = g_output_stream_write(pjctl->out, cmd->command,
				    strlen(cmd->command), NULL, &error);
	if (ret == -1) {
		g_printerr("error: write failed: %s\n",
			   error ? error->message : "unknown reason");
		g_main_loop_quit(pjctl->loop);
		return -1;
	}

	pjctl->state = PJCTL_AWAIT_RESPONSE;
	
	return 0;
}

static int
handle_setup(struct pjctl *pjctl, char *data, int len)
{
	if (data[PJLINK_PARAMETER] == '1') {
		g_printerr("error: pjlink encryption is not implemented.\n");
		goto quit;
	}

	if (data[PJLINK_PARAMETER] != '0') {
		g_printerr("error: invalid setup message received.\n");
		goto quit;
	}

	send_next_cmd(pjctl);

	return 0;
quit:
	g_main_loop_quit(pjctl->loop);

	return -1;
}

static int
handle_data(struct pjctl *pjctl, char *data, int len)
{
	struct queue_command *cmd;

	if (len < 8 || len > PJLINK_TERMINATOR) {
		g_printerr("error: invalid packet length: %d\n", len);
		goto quit;
	}

	if (strncmp(data, "PJLINK ", 7) == 0) {
		if (pjctl->state != PJCTL_AWAIT_INITIAL) {
			g_printerr("error: got unexpected initial\n");
			goto quit;
		}
		return handle_setup(pjctl, data, len);
	}

	if (pjctl->state != PJCTL_AWAIT_RESPONSE) {
		g_printerr("error: got unexpected response.\n");
		goto quit;
	}

	if (data[PJLINK_HEADER] != '%') {
		g_printerr("invalid pjlink command received.\n");
		goto quit;
	}

	if (data[PJLINK_CLASS] != '1') {
		g_printerr("unhandled pjlink class: %c\n", data[1]);
		goto quit;
	}

	if (data[PJLINK_SEPERATOR] != '=') {
		g_printerr("incorrect seperator in pjlink command\n");
		goto quit;
	}
	data[PJLINK_SEPERATOR] = '\0';

	cmd = g_list_nth_data(pjctl->queue, 0);

	pjctl->queue = g_list_remove(pjctl->queue, cmd);

	cmd->response_func(pjctl, &data[PJLINK_COMMAND],
			   &data[PJLINK_PARAMETER]);

	g_free(cmd->command);
	g_free(cmd);

	send_next_cmd(pjctl);

	return 0;

quit:
	g_main_loop_quit(pjctl->loop);

	return -1;
}

static gboolean
read_cb(GObject *pollable_stream, gpointer userdata)
{
	struct pjctl *pjctl = userdata;
	gssize ret;
	char data[136];
	char *end;
	GError *error = NULL;

	do {
		ret = g_pollable_input_stream_read_nonblocking(pjctl->in,
							       data,
							       sizeof data,
							       NULL, &error);

		if (ret <= 0) {
			if (g_error_matches(error, G_IO_ERROR,
					    G_IO_ERROR_WOULD_BLOCK))
				break;


			if (ret == 0 && error == NULL) {
				g_main_loop_quit(pjctl->loop);
				break;
			}

			g_printerr("read failed: %ld: %d %s\n", ret,
				   error ? error->code : -1,
				   error ? error->message: "unknown");

			break;
		}

		end = memchr(data, 0x0d, ret);
		if (end == NULL) {
			g_printerr("invalid pjlink msg received\n");
			g_main_loop_quit(pjctl->loop);
			return 0;
		}

		*end = '\0';
		if (handle_data(pjctl, data, (ptrdiff_t) (end - data)) < 0)
			break;
	} while (g_pollable_input_stream_is_readable(pjctl->in));

	return TRUE;
}

static void
power_response(struct pjctl *pjctl, char *cmd, char *param)
{
	int ret = handle_pjlink_error(param);

	if (ret == 1)
		g_print("OK\n");
	if (ret == 0)
		g_print("power status: %s\n", param[0] == '1' ? "on" : "off" );
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
		g_printerr("invalid power parameter\n");
		return -1;
	}

	cmd->command = g_strdup_printf("%%1POWR %c\r", on ? '1' : '0');
	cmd->response_func = power_response;

	pjctl->queue = g_list_append(pjctl->queue, cmd);

	g_print("power %s: ", argv[1]);

	return 0;
}

static void
source_response(struct pjctl *pjctl, char *cmd, char *param)
{
	if (handle_pjlink_error(param) == 1)
		g_print("OK\n");
}

static int
source(struct pjctl *pjctl, char **argv, int argc)
{
	struct queue_command *cmd;
	int type = 0, offset;
	int num;
	int i;
	char *switches[] = {
		"rgb",
		"video",
		"digital",
		"storage",
		"network"
	};

	cmd = calloc(1, sizeof *cmd);
	if (!cmd)
		return -1;

	if (argc < 2) {
		g_printerr("missing parameter to source commands\n");
		return -1;
	}

	for (i = 0; i < G_N_ELEMENTS(switches); ++i) {
		offset = strlen(switches[i]);
		if (strncmp(argv[1], switches[i], offset) == 0) {
			type = i+1;
			break;
		}
	}

	if (type == 0) {
		g_printerr("incorrect source type given\n");
		return -1;
	}

	num = argv[1][offset];
	if (num < '1' || num > '9') {
		g_printerr("warning: missing source number, defaulting to 1\n");
		num = '1';
	}

	cmd->command = g_strdup_printf("%%1INPT %d%c\r", type, num);
	cmd->response_func = source_response;

	pjctl->queue = g_list_append(pjctl->queue, cmd);

	g_print("source select %s%c: ", switches[type-1], num);

	return 0;
}

static void
avmute_response(struct pjctl *pjctl, char *cmd, char *param)
{
	int ret;

	ret = handle_pjlink_error(param);

	if (ret == 1) {
		g_print("OK\n");
	} else if (ret == 0) {
		g_print("avmute: %c%c\n", param[0], param[1]);
	}
}

static int
avmute(struct pjctl *pjctl, char **argv, int argc)
{
	struct queue_command *cmd;
	int type = -1;
	int i;
	int on;
	const char *targets[] = {
		"video",
		"audio",
		"av"
	};

	cmd = calloc(1, sizeof *cmd);
	if (!cmd)
		return -1;

	if (argc < 3) {
		g_printerr("missing parameter to source commands\n");
		return -1;
	}

	for (i = 0; i < G_N_ELEMENTS(targets); ++i) {
		int len = strlen(targets[i]);
		if (strncmp(argv[1], targets[i], len) == 0) {
			type = i+1;
			break;
		}
	}

	if (type == 0) {
		g_printerr("incorrect source type given\n");
		return -1;
	}
		
	if (strcmp(argv[2], "on") == 0)
		on = 1;
	else if (strcmp(argv[2], "off") == 0)
		on = 0;
	else {
		g_printerr("invalid mute parameter\n");
		return -1;
	}

	cmd->command = g_strdup_printf("%%1AVMT %d%d\r", type, on);
	cmd->response_func = avmute_response;

	pjctl->queue = g_list_append(pjctl->queue, cmd);

	g_print("%s mute %s: ", targets[type-1], argv[2]);

	return 0;
}

static void
name_response(struct pjctl *pjctl, char *cmd, char *param)
{
	if (!strlen(param))
		return;

	g_print("name: ");
	if (handle_pjlink_error(param) < 0)
		return;

	g_print("%s\n", param);
}

static void
manufactor_name_response(struct pjctl *pjctl, char *cmd, char *param)
{
	if (strlen(param))
		g_print("manufactor name: %s\n", param);
}

static void
product_name_response(struct pjctl *pjctl, char *cmd, char *param)
{
	if (strlen(param))
		g_print("product name: %s\n", param);
}

static void
info_response(struct pjctl *pjctl, char *cmd, char *param)
{
	if (strlen(param))
		g_print("model info: %s\n", param);
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
		return "network";
	default:
		return "unknown";
	}
}

static void
input_switch_response(struct pjctl *pjctl, char *cmd, char *param)
{
	if (!strlen(param))
		return;

	g_print("current input: ");

	if (handle_pjlink_error(param) < 0)
		return;

	if (strlen(param) == 2)
		g_print("%s%c\n",
		       map_input_name(param[0]), param[1]);
	else
		g_print("error: invalid response\n");
}

static void
input_list_response(struct pjctl *pjctl, char *cmd, char *param)
{
	int i;
	int len = strlen(param);

	if (len % 3 != 2)
		return;

	g_print("available input sources:");

	for (i = 0; i < len; i+=3)
		g_print(" %s%c", map_input_name(param[i]), param[i+1]);

	g_print("\n");
}

static void
lamp_response(struct pjctl *pjctl, char *cmd, char *param)
{
	g_print("lamp response: %s\n", param);
}

static void
error_status_response(struct pjctl *pjctl, char *cmd, char *param)
{
	g_print("error status response: %s\n", param);
}

static void
class_response(struct pjctl *pjctl, char *cmd, char *param)
{
	g_print("class response: %s\n", param);
}

static int
status(struct pjctl *pjctl, char **argv, int argc)
{
	struct queue_command cmd;

	cmd.command = g_strdup("%1NAME ?\r");
	cmd.response_func = name_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1INF1 ?\r");
	cmd.response_func = manufactor_name_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1INF2 ?\r");
	cmd.response_func = product_name_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1INFO ?\r");
	cmd.response_func = info_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1POWR ?\r");
	cmd.response_func = power_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1INPT ?\r");
	cmd.response_func = input_switch_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1INST ?\r");
	cmd.response_func = input_list_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1AVMT ?\r");
	cmd.response_func = avmute_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1LAMP ?\r");
	cmd.response_func = lamp_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1ERST ?\r");
	cmd.response_func = error_status_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	cmd.command = g_strdup("%1CLSS ?\r");
	cmd.response_func = class_response;
	pjctl->queue = g_list_append(pjctl->queue, g_memdup(&cmd, sizeof cmd));

	return 0;
}

static struct pjctl_command {
	char *name;
	int (*func)(struct pjctl *pjctl, char **argv, int argc);
	char *help;
} commands[] = {
	{ "power", power, "<on|off>" },
	{ "source", source, "<rgb|video|digital|storage|network>[1-9]" },
	{ "mute", avmute, "<video|audio|av> <on|off>" },
	{ "status", status, ""},
};

static void
print_commands(struct pjctl *pjctl)
{
	int i;

	g_print("Commands:\n");
	for (i = 0; i < G_N_ELEMENTS(commands); ++i)
		g_print("  %s %s\n", commands[i].name, commands[i].help);
}

int
main(int argc, char **argv)
{
	struct pjctl pjctl;
	char *host = argv[1];
	int port = 4352;
	GError *error = NULL;
	int i;
	GSource *src;
	guint src_id;

	memset(&pjctl, 0, sizeof pjctl);

	g_type_init();

	if (argc <= 2) {
		print_commands(&pjctl);
		return 1;
	}
	
	for (i = 0; i < G_N_ELEMENTS(commands); ++i) {
		if (strcmp(argv[2], commands[i].name) == 0) {
			if (commands[i].func(&pjctl, &argv[2], argc-2) < 0)
				return 1;
		}
	}
	
	/* Nothing got into queue? User gave invalid command. */
	if (g_list_length(pjctl.queue) == 0) {
		g_printerr("error: invalid command\n");
		print_commands(&pjctl);
		return 1;
	}

	pjctl.loop = g_main_loop_new(NULL, FALSE);

	pjctl.sc = g_socket_client_new();
	g_socket_client_set_family(pjctl.sc, G_SOCKET_FAMILY_IPV4);
	g_socket_client_set_protocol(pjctl.sc, G_SOCKET_PROTOCOL_TCP);
	g_socket_client_set_socket_type(pjctl.sc, G_SOCKET_TYPE_STREAM);

	pjctl.con = g_socket_client_connect_to_host(pjctl.sc, host, port,
						    NULL, &error);
	if (error) {
		g_printerr("failed to connect: %s\n", error->message);
		return 1;
	}

	g_object_get(G_OBJECT(pjctl.con),
		     "input-stream", &pjctl.in,
		     "output-stream", &pjctl.out, NULL);

	if (!G_IS_POLLABLE_INPUT_STREAM(pjctl.in) ||
	    !g_pollable_input_stream_can_poll(pjctl.in)) {
		g_printerr("Error: GSocketConnection is not pollable\n");
		return 1;
	}

	src = g_pollable_input_stream_create_source(pjctl.in, NULL);
	g_source_set_callback(src, (GSourceFunc) read_cb, &pjctl, NULL);
	src_id = g_source_attach(src, NULL);
	g_source_unref(src);

	pjctl.state = PJCTL_AWAIT_INITIAL;

	g_main_loop_run(pjctl.loop);

	g_source_remove(src_id);
	g_object_unref(pjctl.in);
	g_object_unref(pjctl.out);
	g_object_unref(pjctl.con);
	g_object_unref(pjctl.sc);
	g_main_loop_unref(pjctl.loop);

	return 0;
}
