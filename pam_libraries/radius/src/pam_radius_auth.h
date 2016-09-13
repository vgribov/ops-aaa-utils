#ifndef PAM_RADIUS_H
#define PAM_RADIUS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <utmp.h>
#include <time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "radius.h"
#include <openssl/md5.h>

/* Defaults for the prompt option */
#define MAXPROMPT 33               /* max prompt length, including '\0' */
#define DEFAULT_PROMPT "Password"  /* default prompt, without the ': '  */

#define PAP            "pap"
#define LOGIN          "login="
#define SERVER         "server="
#define SECRET         "secret="
#define TIMEOUT        "timeout="
#define BYPASS_ACCT    "bypass_acct"
#define BYPASS_SESSION "bypass_session"

#define RADIUS_DEFAULT_UDP_PORT 1812

/*************************************************************************
 * Additional RADIUS definitions
 *************************************************************************/

/* Per-attribute structure */
typedef struct attribute_t {
	unsigned char attribute;
	unsigned char length;
	unsigned char data[1];
} attribute_t;

typedef struct radius_server_t {
	struct radius_server_t *next;
	struct in_addr ip;
	uint16_t port;
	char *hostname;
} radius_server_t;

typedef struct radius_conf_t {
	radius_server_t *server;
	int retries;
	int localifdown;
	char *client_id;
	int accounting_bug;
	int force_prompt;
	int max_challenge;
	int sockfd;
	int debug;
	char prompt[MAXPROMPT];
	int use_chap;
} radius_conf_t;


/*************************************************************************
 * Platform specific defines
 *************************************************************************/

#ifndef CONST
#  if defined(__sun) || defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__)
/*
 *  On older versions of Solaris, you may have to change this to:
 *  #define CONST
 */
#    define CONST const
#  else
#    define CONST
#  endif
#endif

#ifndef PAM_EXTERN
#  ifdef __sun
#    define PAM_EXTERN extern
#  else
#    define PAM_EXTERN
#  endif
#endif


/*************************************************************************
 * Useful macros and defines
 *************************************************************************/

#define _pam_forget(X) if (X) {memset(X, 0, strlen(X));free(X);X = NULL;}
#ifndef _pam_drop
#define _pam_drop(X) if (X) {free(X);X = NULL;}
#endif

#define PAM_DEBUG_ARG          1
#define PAM_SKIP_PASSWD        2
#define PAM_USE_FIRST_PASS     4
#define PAM_TRY_FIRST_PASS     8
#define PAM_RUSER_ARG          16
#define PAM_RAD_BYPASS_ACCT    32  /* bypass accounting */
#define PAM_RAD_BYPASS_SESSION 64  /* bypass session */

/* Module defines */
#ifndef BUFFER_SIZE
#define BUFFER_SIZE      1024
#endif /* BUFFER_SIZE */
#define MAXPWNAM 253    /* maximum user name length. Server dependent,
                         * this is the default value
                         */
#define MAXPASS 128     /* max password length. Again, depends on server
                         * compiled in. This is the default.
                         */
#ifndef CONF_FILE       /* the configuration file holding the server secret */
#define CONF_FILE       "/etc/pam.d/common-auth-access"
#endif /* CONF_FILE */

#ifndef FALSE
#define FALSE 0
#undef TRUE
#define TRUE !FALSE
#endif

#endif /* PAM_RADIUS_H */
