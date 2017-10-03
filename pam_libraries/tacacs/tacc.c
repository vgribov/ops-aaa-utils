/* tacc.c  TACACS+ PAP authentication client
 *
 * Copyright (C) 2016-2017 Hewlett Packard Enterprise Development LP.
 * Copyright 1997-98 by Pawel Krawczyk <kravietz@ceti.com.pl>
 * Portions copyright (c) 1989 Carnegie Mellon University.
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 */

#include <stdio.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <utmp.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <ctype.h>
#include <openssl/rand.h>
#include "tacplus.h"
#include "libtac.h"
#include "libtac/support.h"
#include "nl-utils.h"

/* Prompt displayed when asking for password */
#define PASSWORD_PROMPT "Password: "

/* if defined, given command will be run after
 * successful authentication and proper wtmp
 * entries will be made
 */
#define DEFAULT_COMMAND "/usr/sbin/pppd -detach"

/* message that will be displayed to user
 * before starting COMMAND
 */
#define COMMAND_MESSAGE "Starting PPP\n"

/* timeout for reading password from user (seconds) */
#define GETPASS_TIMEOUT 60

/* end of CONFIGURABLE PARAMETERS */

/* prototypes */
void sighandler(int sig);
void showusage(char *argv0);
unsigned long getservername(char *serv);
void showusage(char *progname);
void authenticate(const struct addrinfo *tac_server, const char *tac_secret,
		const char *user, const char *pass, const char *tty,
		const char *remote_addr,
                struct addrinfo *source_address);
void timeout_handler(int signum);

#define USE_SYSTEM	1

/* globals */
//int tac_encryption = 1;
typedef unsigned char flag;
flag quiet = 0;
char *user = NULL; /* global, because of signal handler */

/* command line options */
static struct option long_options[] =
		{
		/* operation */
		{ "authenticate", no_argument, NULL, 'T' }, { "authorize", no_argument,
				NULL, 'R' }, { "account", no_argument, NULL, 'A' }, { "cmd_author",
				no_argument, NULL, 'C' }, { "get_priv",
                                no_argument, NULL, 'G' }, {"help", no_argument, NULL, 'h' },

		/* data */
		{ "username", required_argument, NULL, 'u' }, { "remote",
				required_argument, NULL, 'r' }, { "password", required_argument,
				NULL, 'p' }, { "server", required_argument, NULL, 's' }, {
				"secret", required_argument, NULL, 'k' }, { "command",
				required_argument, NULL, 'c' }, { "exec", required_argument,
				NULL, 'c' }, { "service", required_argument, NULL, 'S' }, {
				"protocol", required_argument, NULL, 'P' },  { "remote",
				required_argument, NULL, 'r' }, { "login", required_argument,
				NULL, 'L' }, { "dstn_namespace", required_argument,
                                NULL, 'f' }, { "source_ip", required_argument,
                                NULL, 'g' },

		/* modifiers */
		{ "quiet", no_argument, NULL, 'q' },
				{ "silent", no_argument, NULL, 'q' }, { "no-wtmp", no_argument,
						NULL, 'w' }, { "no-encrypt", no_argument, NULL, 'n' }, {
						0, 0, 0, 0 } };

/* command line letters */
char *opt_string = "TRACGhu:p:s:k:c:qr:wnS:P:L:e:f:g";

int main(int argc, char **argv) {
	char *pass = NULL;
	char tty[10];
	char *command = NULL;
	char *remote_addr = NULL;
	char *service = NULL;
	char *protocol = NULL;
	struct addrinfo *tac_server;
	char *tac_server_name = NULL;
	char *tac_secret = NULL;
	int tac_fd;
	short int task_id = 0;
	char buf[40];
	int ret;
        int cmd_author_status;
        int priv_lvl_status;

	char *tac_dstn_namespace = NULL;
	char *tac_source_ip = NULL;
	struct addrinfo *source_address = NULL;

#ifndef USE_SYSTEM
	pid_t pid;
#endif
	struct areply arep;

	/* options */
	flag do_author = 0;
	flag do_command_author = 0;
	flag do_authen = 0;
	flag do_account = 0;
	flag login_mode = 0;
        flag get_privilege_level = 0;

	/* check argc */
	if (argc < 2) {
		showusage(argv[0]);
		exit(EXIT_ERR);
	}

	/* check for login mode */
	if (argc == 2 && isalpha(*argv[1])) {
		user = argv[1];
		do_author = do_authen = do_account = 1;
		command = DEFAULT_COMMAND;
		login_mode = 1;
	} else {
		int c;
		int opt_index;

		while ((c = getopt_long(argc, argv, opt_string, long_options,
				&opt_index)) != EOF) {
			switch (c) {
			case 'T':
				do_authen = 1;
				break;
			case 'R':
				do_author = 1;
				break;
			case 'A':
				do_account = 1;
				break;
			case 'C':
				do_command_author = 1;
				break;
			case 'G':
				get_privilege_level = 1;
				break;
			case 'h':
				showusage(argv[0]);
			case 'u':
				user = optarg;
				break;
			case 'r':
				remote_addr = optarg;
				break;
			case 'L':
				// tac_login is a global variable initialized in libtac
				bzero(tac_login, sizeof(tac_login));
				strncpy(tac_login, optarg, sizeof(tac_login) - 1);
				break;
			case 'p':
				pass = optarg;
				break;
			case 's':
				tac_server_name = optarg;
				break;
			case 'k':
				tac_secret = optarg;
				break;
			case 'c':
				command = optarg;
				break;
			case 'S':
				service = optarg;
				break;
			case 'P':
				protocol = optarg;
				break;
			case 'q':
				quiet = 1;
				break;
			case 'n':
				tac_encryption = 0;
				break;
                        case 'f':
                                tac_dstn_namespace = optarg;
                                break;
                        case 'g':
                                tac_source_ip = optarg;
                                break;
			}
		}
	}

	/* check available information and set to defaults if needed */
	if (do_authen + do_command_author + do_author + do_account == 0) {
		printf("error: one of -TRAVh options is required\n");
		exit(EXIT_ERR);
	}

	if (user == NULL) {
		printf("error: username is required.\n");
		exit(EXIT_ERR);
	}

	if (remote_addr == NULL) {
		printf("error: remote address is required.\n");
		exit(EXIT_ERR);
	}

	if (service == NULL) {
		printf("error: service is required.\n");
		exit(EXIT_ERR);
	}

	/*if (protocol == NULL) {
		printf("error: protocol is required.\n");
		exit(EXIT_ERR);
	}*/

	if (tac_server_name == NULL) {
		printf("error: server name is required.\n");
		exit(EXIT_ERR);
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(tac_server_name, "tacacs", &hints, &tac_server);
	if (ret != 0) {
		printf("error: resolving name %s: %s", tac_server_name,
				gai_strerror(ret));
		exit(EXIT_ERR);
	}

	if (tac_secret == NULL) {
		printf("error: server secret is required.\n");
		exit(EXIT_ERR);
	}

	if (pass == NULL) {
		signal(SIGALRM, timeout_handler);
		alarm(GETPASS_TIMEOUT);
		pass = getpass(PASSWORD_PROMPT);
		alarm(0);
		signal(SIGALRM, SIG_DFL);
		if (!strlen(pass))
			exit(EXIT_ERR);
	}

	strcpy(tty, "mytty");

	/* open syslog before any TACACS+ calls */
	openlog("tacc", LOG_CONS | LOG_PID, LOG_AUTHPRIV);


        /* switch to destination namespace */
        syslog(LOG_DEBUG, "tac_dstn_namespace = %s,"
            " source_ip = %s, dst ns len = %d",
            tac_dstn_namespace, tac_source_ip,
            (tac_dstn_namespace ? ((int) strlen(tac_dstn_namespace)) : 0));
        nl_setns_with_name(tac_dstn_namespace);

        /* set the source ip address for the tacacs packets */
        set_source_ip(tac_source_ip, &source_address);

	if (do_authen)
		authenticate(tac_server, tac_secret, user, pass, tty, remote_addr,
		     source_address);

	if (get_privilege_level) {
		priv_lvl_status = get_priv_level(tac_server, tac_secret, user,
							tty, remote_addr, quiet);
                exit(priv_lvl_status);
	}

	if (do_author) {
                if (!do_command_author && protocol == NULL) {
                    printf("error: protocol is required for authorization\n");
                    exit(EXIT_ERR);
                }

                if (do_command_author && command == NULL) {
                    printf("error: command is required for authorization\n");
                    exit(EXIT_ERR);
                }
                cmd_author_status = tac_cmd_author(tac_server_name,
                                                   tac_secret,
                                                   user,
                                                   tty,
                                                   remote_addr,
                                                   service,
                                                   protocol,
                                                   command,
                                                   TACC_CONN_TIMEOUT,
                                                   quiet,
                                                   NULL,
                                                   NULL,
                                                   NULL);
                exit(cmd_author_status);
        }

	/* we no longer need the password in our address space */
	bzero(pass, strlen(pass));
	pass = NULL;

	if (do_account) {
		/* start accounting */
		struct tac_attrib *attr = NULL;
		sprintf(buf, "%lu", time(0));
		tac_add_attrib(&attr, "start_time", buf);
		RAND_bytes((unsigned char *) &task_id, sizeof(task_id));
		sprintf(buf, "%hi", task_id);
		tac_add_attrib(&attr, "task_id", buf);
		tac_add_attrib(&attr, "service", service);
		tac_add_attrib(&attr, "protocol", protocol);

		tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
		if (tac_fd < 0) {
			if (!quiet)
				printf("Error connecting to TACACS+ server: %m\n");
			exit(EXIT_ERR);
		}

		tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, user, tty, remote_addr,
				attr);

		ret = tac_acct_read(tac_fd, &arep);
		if (ret == 0) {
			if (!quiet)
				printf("Accounting: START failed: %s\n", arep.msg);
			syslog(LOG_INFO, "TACACS+ accounting start failed: %s", arep.msg);
		} else if (!login_mode && !quiet)
			printf("Accounting: START OK\n");

		close(tac_fd);

		tac_free_attrib(&attr);

	}

	/* log in local utmp */
#ifdef HAVE_LOGWTMP
	if (log_wtmp)
		logwtmp(tty, user, "dialup");
#endif

	if (command != NULL) {
		int ret;

		syslog(LOG_DEBUG, "starting %s for %s", command, user);

		signal(SIGHUP, SIG_IGN);
		signal(SIGTERM, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);

#ifdef COMMAND_MESSAGE
		printf(COMMAND_MESSAGE);
#endif

#if USE_SYSTEM
		ret = system(command);
		if (ret < 0)
			syslog(LOG_WARNING, "command failed: %m");
		else
			syslog(LOG_NOTICE, "command exit code %u", ret);
#else
		pid=fork();

		if(pid == 0) {
			/* child */

			execl(DEFAULT_COMMAND, DEFAULT_COMMAND, ARGS, NULL);
			syslog(LOG_ERR, "execl() failed: %m");
			_exit(EXIT_FAIL);
		}

		if(pid < 0) {
			/* error */
			syslog(LOG_ERR, "fork failed: %m");
			exit(EXIT_FAIL);
		}

		if(pid > 0) {
			/* parent */
			int st, r;

			r=wait(&st);
		}
#endif
	}

	if (do_account) {
		/* stop accounting */
		struct tac_attrib *attr = NULL;
		sprintf(buf, "%lu", time(0));
		tac_add_attrib(&attr, "stop_time", buf);
		sprintf(buf, "%hi", task_id);
		tac_add_attrib(&attr, "task_id", buf);

		tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
		if (tac_fd < 0) {
			if (!quiet)
				printf("Error connecting to TACACS+ server: %m\n");
			exit(EXIT_ERR);
		}

		tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, user, tty, remote_addr,
				attr);
		ret = tac_acct_read(tac_fd, &arep);
		if (ret == 0) {
			if (!quiet)
				printf("Accounting: STOP failed: %s", arep.msg);
			syslog(LOG_INFO, "TACACS+ accounting stop failed: %s\n", arep.msg);
		} else if (!login_mode && !quiet)
			printf("Accounting: STOP OK\n");

		close(tac_fd);

		tac_free_attrib(&attr);
	}

	/* logout from utmp */
#ifdef HAVE_LOGWTMP
	if (log_wtmp)
		logwtmp(tty, "", "");
#endif
	nl_setns_oobm();
	exit(EXIT_OK);
}

void sighandler(int sig) {
	TACDEBUG((LOG_DEBUG, "caught signal %d", sig));
}

void authenticate(const struct addrinfo *tac_server, const char *tac_secret,
		const char *user, const char *pass, const char *tty,
		const char *remote_addr,
		struct addrinfo *source_address) {
	int tac_fd;
	int ret;
	struct areply arep;

	tac_fd = tac_connect_single(tac_server, tac_secret, source_address, 60);

	if (tac_fd < 0) {
		if (!quiet)
			printf("Error connecting to TACACS+ server: %m\n");
		exit(EXIT_ERR);
	}

	/* start authentication */

	if (tac_authen_send(tac_fd, user, pass, tty, remote_addr,
			TAC_PLUS_AUTHEN_LOGIN) < 0) {
		if (!quiet)
			printf("Error sending query to TACACS+ server\n");
		exit(EXIT_ERR);
	}

	ret = tac_authen_read(tac_fd, &arep);

	if (ret != TAC_PLUS_AUTHEN_STATUS_PASS) {
		if (!quiet)
			printf("Authentication FAILED: %s\n", arep.msg);
		syslog(LOG_ERR, "authentication failed for %s: %s", user, arep.msg);
		exit(EXIT_FAIL);
	}

	if (!quiet)
		printf("Authentication OK\n");
	syslog(LOG_INFO, "authentication OK for %s", user);

	close(tac_fd);
}

void showusage(char *progname) {
	char *a;

	a = rindex(progname, '/');
	progname = (a == NULL) ? progname : ++a;

	printf("%s -- simple TACACS+ client and login\n",
			progname);
	printf("Copyright 1997-2016 by Pawel Krawczyk <pawel.krawczyk@hush.com>\n");
	printf("Usage: %s option [option, ...]\n\n", progname);
	printf(" Action:\n");
	printf(
			"  -T, --authenticate  perform authentication with username and password\n");
	printf(
			"  -R, --authorize     perform authorization for requested service\n");
	printf("  -A, --account       account session beginning and end\n");
	printf("  -G, --get_priv      get privilege level for the user\n");
	printf("  -h, --help          display this help and exit\n");
	printf(" Data:\n");
	printf("  -u, --username      remote user name\n");
	printf("  -p, --password      remote user password\n");
	printf("  -s, --server        server IP address or FQDN\n");
	printf("  -r, --remote        remote client's IP address\n");
	printf("  -S, --service       requested service (e.g. ppp)\n");
	printf("  -P, --protocol      requested protocl (e.g. ip)\n");
	printf("  -L, --login         TACACS+ login mode (e.g. chap, login)\n");
	printf("  -k, --secret        server encryption key\n");
	printf("  -c, --command       command to execute after successful AAA\n");
	printf("       --exec         alias for --command\n\n");
	printf(" Modifiers:\n");
	printf(
			"  -q, --quiet         don't display messages to screen (but still\n");
	printf("      --silent        report them via syslog(3))\n");
	printf("  -w, --no-wtmp       don't write records to wtmp(5)\n");
	printf(
			"  -n, --no-encrypt    don't encrypt AAA packets sent to servers\n\n");
	printf("Example usage:\n\n");
	printf(
			"  tacc -TRA -u test1 -p test1 -s localhost -r 1.1.1.1 -k test1 -S ppp -P ip\n");

	exit(EXIT_ERR);
}

unsigned long getservername(char *serv) {
	struct in_addr addr;
	struct hostent *h;

	if (inet_aton(serv, &addr) == 0) {
		if ((h = gethostbyname(serv)) == NULL) {
			herror("gethostbyname");
		} else {
			bcopy(h->h_addr, (char *)&addr, sizeof(struct in_addr));
			return(addr.s_addr);
		}
	} else
	return(addr.s_addr);

	return (-1);
}

void timeout_handler(int signum) {
	syslog(LOG_ERR, "timeout reading password from user %s", user);

}
