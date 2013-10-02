
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <event2/event.h>

#define MAX_BUFFER_SIZE (64u*1024u)
#define MAX_STRING_BUFFER_SIZE (64u*1024u) /* env keys and values */

#define CONST_STR_LEN(x) (x), sizeof(x) - 1
#define GSTR_LEN(x) (x) ? (x)->str : "", (x) ? (x)->len : 0
#define UNUSED(x) ((void)(x))

#ifdef __GNUC__
#define ATTR_WARN_UNUSED_RESULT \
	__attribute__((warn_unused_result))
#define ATTR_FORMAT(fmt, args) \
	__attribute__(( format(printf, fmt, args) ))
#else
#define ATTR_WARN_UNUSED_RESULT 
#define ATTR_FORMAT(fmt, args) 
#endif

#define ERROR(...) printerr(__LINE__, __VA_ARGS__)

#ifdef NDEBUG
# define DEBUG(...) do { } while (0)
#else
# define DEBUG(...) printerr(__LINE__, "DEBUG: " __VA_ARGS__)
#endif

#define PACKAGE_DESC PACKAGE_NAME " v" PACKAGE_VERSION " - SCGI application to run normal cgi applications"

/* force asserts to be enabled */
#undef NDEBUG
#include <assert.h>

/****************************************************************************
 *                         logging                                          *
 ***************************************************************************/

static void printerr(unsigned int line, const char *fmt, ...) ATTR_FORMAT(2, 3);
static void printerr(unsigned int line, const char *fmt, ...) {
	va_list ap;

	fprintf(stderr, "scgi-cgi.c:%u:", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

/****************************************************************************
 *                         STRING BUFFER                                    *
 ***************************************************************************/

typedef struct string_buffer string_buffer;
struct string_buffer {
	/* always 0-terminated string (unless data == NULL), but don't count terminating 0 in `used' */
	unsigned char *data;
	unsigned int used, size;
};

static void string_buffer_init(string_buffer *buf);
static void string_buffer_clear(string_buffer *buf);
static unsigned char* string_buffer_extract(string_buffer *buf) ATTR_WARN_UNUSED_RESULT; /* resets buffer, returns string. free string with free() */
static int string_buffer_reserve(string_buffer *buf, unsigned int len) ATTR_WARN_UNUSED_RESULT;
static int string_buffer_append(string_buffer *buf, const unsigned char *data, unsigned int len) ATTR_WARN_UNUSED_RESULT;
static int string_buffer_append_char(string_buffer *buf, unsigned char c) ATTR_WARN_UNUSED_RESULT;
static int string_buffer_equal(string_buffer *buf, const char *data, unsigned int len);

#define STRING_BUFFER_EQUAL(buf, str) string_buffer_equal(buf, str, sizeof(str) - 1)


static void string_buffer_init(string_buffer *buf) {
	buf->data = NULL;
	buf->used = buf->size = 0;
}

static void string_buffer_clear(string_buffer *buf) {
	if (NULL != buf->data) free(buf->data);
	buf->data = NULL;
	buf->used = buf->size = 0;
}

static unsigned char* string_buffer_extract(string_buffer *buf) {
	unsigned char *str = buf->data;
	string_buffer_init(buf);
	return str;
}

static int string_buffer_reserve(string_buffer *buf, unsigned int len) {
	assert(buf->used <= buf->size);
	assert(buf->size <= MAX_STRING_BUFFER_SIZE);

	if (1 > UINT_MAX - len || len + 1 > MAX_STRING_BUFFER_SIZE - buf->used) {
		DEBUG("string buffer: overflow");
		return 0;
	}
	unsigned int newlen = buf->used + len;
	if (newlen + 1 > buf->size) {
		unsigned int need_size = newlen + 1;
		unsigned int want_size = (need_size + 127) & ~127; /* round up to next multiple of 128 */
		unsigned char *newdata;

		if (want_size < need_size) want_size = need_size; /* overflow handling */
		newdata = (unsigned char*) realloc(buf->data, want_size);
		if (NULL == newdata) {
			DEBUG("string buffer: realloc failed");
			return 0;
		}

		buf->data = newdata;
		buf->size = want_size;
	}

	return 1;
}

static int string_buffer_append(string_buffer *buf, const unsigned char *data, unsigned int len) {
	if (!string_buffer_reserve(buf, len)) return 0;

	if (len > 0) memcpy(buf->data + buf->used, data, len);
	buf->used += len;
	buf->data[buf->used] = '\0';

	return 1;
}

static int string_buffer_append_char(string_buffer *buf, unsigned char c) {
	if (!string_buffer_reserve(buf, 1)) return 0;

	buf->data[buf->used++] = c;
	buf->data[buf->used] = '\0';

	return 1;
}

static int string_buffer_equal(string_buffer *buf, const char *data, unsigned int len) {
	if (buf->used != len) return 0;
	if (0 == len) return 1;
	return 0 == memcmp(buf->data, data, len);
}


/****************************************************************************
 *                         SCGI PARSER                                      *
 ***************************************************************************/

typedef enum scgi_req_parser_state {
	SCGI_REQ_PARSER_HEADER_LEN,
	SCGI_REQ_PARSER_HEADER_ENV_KEY,
	SCGI_REQ_PARSER_HEADER_ENV_VALUE,
	SCGI_REQ_PARSER_HEADER_DONE,
	SCGI_REQ_PARSER_HEADER_ERROR
} scgi_req_parser_state;

typedef struct scgi_req_parser scgi_req_parser;
struct scgi_req_parser {
	scgi_req_parser_state state;
	unsigned int header_length, is_scgi;
	unsigned long long content_length;

	unsigned char **environ; /* list terminated by NULL entry */
	unsigned int environ_used, environ_size;

	string_buffer key_value;
	unsigned int key_length;
};

static int key_value_has_key(scgi_req_parser *parser, char *key, unsigned int keylen);
static void scgi_parser_init(scgi_req_parser *parser);
static void scgi_parser_clear(scgi_req_parser *parser);
static void scgi_parser_clear_environment(scgi_req_parser *parser);
static int scgi_parser_environ_reserve(scgi_req_parser *parser);
static int scgi_parser_environ_append(scgi_req_parser *parser, unsigned char *kvstr, int keylength);
static int scgi_parser_environ_copy(scgi_req_parser *parser, const char *key, unsigned int keylength);
static const char* scgi_parser_environ_get(scgi_req_parser *parser, const char *key, unsigned int keylength);
static int scgi_parse(scgi_req_parser *parser, unsigned char *data, int len) ATTR_WARN_UNUSED_RESULT;


static int key_value_has_key(scgi_req_parser *parser, char *key, unsigned int keylen) {
	if (parser->key_length != keylen) return 0;
	return 0 == memcmp(parser->key_value.data, key, keylen);
}

#define KEY_VALUE_HAS_KEY(parser, key) key_value_has_key(parser, key, sizeof(key) - 1)


static void scgi_parser_init(scgi_req_parser *parser) {
	parser->state = SCGI_REQ_PARSER_HEADER_LEN;
	parser->header_length = parser->content_length = parser->is_scgi = 0;

	parser->environ = NULL;
	parser->environ_used = parser->environ_size = 0;

	string_buffer_init(&parser->key_value);
	parser->key_length = 0;
}

static void scgi_parser_clear(scgi_req_parser *parser) {
	unsigned int i;

	for (i = 0; i < parser->environ_used; ++i) {
		free(parser->environ[i]);
	}
	free(parser->environ);

	string_buffer_clear(&parser->key_value);

	parser->state = SCGI_REQ_PARSER_HEADER_LEN;
	parser->header_length = parser->content_length = parser->is_scgi = 0;

	parser->environ = NULL;
	parser->environ_used = parser->environ_size = 0;

	parser->key_length = 0;
}

static void scgi_parser_clear_environment(scgi_req_parser *parser) {
	unsigned int i;

	for (i = 0; i < parser->environ_used; ++i) {
		free(parser->environ[i]);
	}
	free(parser->environ);

	parser->environ = NULL;
	parser->environ_used = parser->environ_size = 0;
}

static int scgi_parser_environ_reserve(scgi_req_parser *parser) {
	if (2 > UINT_MAX/sizeof(unsigned char*) - parser->environ_used) {
		DEBUG("scgi environment: entries overflow");
		return 0; /* overflow: can't append */
	}
	if (parser->environ_used + 2 > parser->environ_size) {
		unsigned int need_size = sizeof(unsigned char*) * (parser->environ_used + 2);
		unsigned int want_size = (need_size + 1024) & ~1023; /* round up to next multiple of 1023 (for 8-byte pointers: 128 entries) */
		unsigned char **newdata;

		if (want_size < need_size) want_size = need_size; /* overflow handling */
		newdata = (unsigned char**) realloc(parser->environ, want_size);
		if (NULL == newdata) {
			DEBUG("scgi environment: realloc failed");
			return 0; /* ENOMEM */
		}

		parser->environ = newdata;
		parser->environ_size = want_size / sizeof(unsigned char*);
	}

	return 1;
}

/* kvstr: "KEY=VALUE", keylength = strlen("KEY")
 * return values: 0: not appended: key already exists (not overwriting), or some other error; 1: appended
 * kvstr is free()d if it wasn't appended.
 */
static int scgi_parser_environ_append(scgi_req_parser *parser, unsigned char *kvstr, int keylength) {
	unsigned int i;

	for (i = 0; i < parser->environ_used; ++i) {
		const char *e = (const char*) parser->environ[i];
		if (0 == strncmp(e, (const char *) kvstr, keylength + 1)) {
			DEBUG("scgi req header: duplicate key for entry '%s', already have '%s'", kvstr, e);
			goto fail; /* found */
		}
	}
	if (!scgi_parser_environ_reserve(parser)) goto fail;

	parser->environ[parser->environ_used++] = kvstr;
	parser->environ[parser->environ_used] = NULL;

	return 1;

fail:
	free(kvstr);
	return 0;
}

static int scgi_parser_environ_copy(scgi_req_parser *parser, const char *key, unsigned int keylength) {
	const char *val = getenv(key);
	unsigned int vallen;
	unsigned char *kvstr;
	unsigned int i;

	if (NULL == val) return 1;

	vallen = strlen(val);
	kvstr = malloc(keylength + 2 + vallen);
	if (NULL == kvstr) return 0;

	memcpy(kvstr, key, keylength);
	kvstr[keylength] = '=';
	memcpy(kvstr + keylength + 1, val, vallen + 1);

	for (i = 0; i < parser->environ_used; ++i) {
		const char *e = (const char*) parser->environ[i];
		if (0 == strncmp(e, (const char *) kvstr, keylength + 1)) {
			/* found. overwrite: */
			free(parser->environ[i]);
			parser->environ[i] = kvstr;
		}
	}

	if (!scgi_parser_environ_reserve(parser)) {
		free(kvstr);
		return 0;
	}

	parser->environ[parser->environ_used++] = kvstr;
	parser->environ[parser->environ_used] = NULL;

	return 1;
}

static const char* scgi_parser_environ_get(scgi_req_parser *parser, const char *key, unsigned int keylength) {
	unsigned int i;

	for (i = 0; i < parser->environ_used; ++i) {
		const char *e = (const char*) parser->environ[i];
		if (0 == strncmp(e, (const char *) key, keylength) && '=' == e[keylength]) {
			return (const char*) e + keylength + 1;
		}
	}

	return NULL;
}

/* return values:
 *   -2: error
 *   -1: need more data for header
 * l>=0: trailing l bytes of data are request body data; header finished.
 */
static int scgi_parse(scgi_req_parser *parser, unsigned char *data, int len) {
	assert(len > 0);

	for (; len > 0; ++data, --len) {
		unsigned char c = *data;

		switch (parser->state) {
		case SCGI_REQ_PARSER_HEADER_LEN:
			{
				unsigned int digit;

				if (c == ':') {
					/* require at least 'CONTENT_LENGTH=0;SCGI=1;' in header ('=' and ';' encoded as '\0') */
					if (parser->header_length < 24) {
						DEBUG("scgi req header too small: %u", parser->header_length);
						goto fail;
					}
					parser->state = SCGI_REQ_PARSER_HEADER_ENV_KEY;
					break;
				}

				if (c < '0' || c > '9') {
					DEBUG("scgi req header: expected digit or ':' in header length, got '%c'", c);
					goto fail;
				}
				if (0 == parser->header_length && c == '0') {
					/* extra leading zeroes are prohibited; zero header length is not permitted either:
					 * require CONTENT_LENGTH and SCGI vars
					 * => starting 0 digit is never allowed
					 */
					DEBUG("scgi req header: header length starting with 0");
					goto fail;
				}

				digit = c - '0';
				if (parser->header_length > UINT_MAX / 10 - digit) {
					DEBUG("scgi req header: header length overflow");
					goto fail; /* overflow */
				}
				parser->header_length = 10*parser->header_length + digit;
			}
			break;
		case SCGI_REQ_PARSER_HEADER_ENV_KEY:
			if (0 == parser->header_length) {
				if (',' != c) {
					DEBUG("scgi req header: require ',' before request body, got '%c'", c);
					goto fail; /* after header require a ',' */
				}
				if (0 != parser->key_value.used) {
					DEBUG("scgi req header: headers ended with partial key '%s'", parser->key_value.data);
					goto fail; /* partial header on headers end */
				}
				if (!parser->is_scgi) {
					DEBUG("scgi req header: missing SCGI=1");
					goto fail; /* is_scgi is only set after CONTENT_LENGTH (always first header) is parsed, and then SCGI=1 was found */
				}
				parser->state = SCGI_REQ_PARSER_HEADER_DONE;
				return len - 1;
			}
			--parser->header_length;

			if (0 != c) {
				if ('=' == c) {
					DEBUG("scgi req header: key must not include '='");
					goto fail; /* '=' can't be allowed in keys */
				}
				if (!string_buffer_append_char(&parser->key_value, c)) goto fail;
				break;
			}

			/* key end */
			parser->key_length = parser->key_value.used;
			if (!string_buffer_append_char(&parser->key_value, '=')) goto fail;
			parser->state = SCGI_REQ_PARSER_HEADER_ENV_VALUE;
			break;
		case SCGI_REQ_PARSER_HEADER_ENV_VALUE:
			if (0 == parser->header_length) {
				DEBUG("scgi req header: headers ended with partial value '%s'", parser->key_value.data);
				goto fail; /* partial header on headers end */
			}
			--parser->header_length;

			if (0 != c) {
				int vallen = 1;
				while (vallen < len && 0 != data[vallen]) ++vallen;
				if (!string_buffer_append(&parser->key_value, data, vallen)) goto fail;
				data += (vallen - 1);
				len -= (vallen - 1);
				parser->header_length -= (vallen - 1);
				break;
			}

			/* value end */

			if (0 == parser->environ_used) {
				long long clen;
				char *endptr = NULL, *startptr = (char*) parser->key_value.data + parser->key_length + 1;

				if (!KEY_VALUE_HAS_KEY(parser, "CONTENT_LENGTH")) {
					DEBUG("scgi req header: first header isn't CONTENT_LENGTH: '%s'", parser->key_value.data);
					goto fail; /* first entry must be CONTENT_LENGTH */
				}
				if (parser->key_value.used == parser->key_length + 1) {
					DEBUG("scgi req header: CONTENT_LENGTH is empty");
					goto fail; /* empty CONTENT_LENGTH */
				}

				errno = 0;
				clen = strtoll(startptr, &endptr, 10);
				if (0 != errno) {
					DEBUG("scgi req header: parsing '%s' failed: %s", parser->key_value.data, strerror(errno));
					goto fail;
				}
				if (endptr != (char*) parser->key_value.data + parser->key_value.used) {
					DEBUG("scgi req header: parsing '%s' failed: contained more than number", parser->key_value.data);
					goto fail; /* number didn't cover complete value */
				}
				if (clen < 0) {
					DEBUG("scgi req header: parsing '%s' failed: negative length", parser->key_value.data);
					goto fail; /* number didn't cover complete value */
				}
				parser->content_length = (unsigned long long) clen;
			} else if (KEY_VALUE_HAS_KEY(parser, "SCGI")) {
				if (STRING_BUFFER_EQUAL(&parser->key_value, "SCGI=1")) {
					parser->is_scgi = 1;
				} else {
					DEBUG("scgi req header: SCGI is not 1: '%s'", parser->key_value.data);
					goto fail; /* SCGI must be 1 */
				}
			}
			if (!scgi_parser_environ_append(parser, string_buffer_extract(&parser->key_value), parser->key_length)) goto fail; /* duplicate key / ENOMEM */
			parser->key_length = 0;
			parser->state = SCGI_REQ_PARSER_HEADER_ENV_KEY;

			break;
		case SCGI_REQ_PARSER_HEADER_DONE:
			return len;
		case SCGI_REQ_PARSER_HEADER_ERROR:
			goto fail;
		}
	}
	return -1;

fail:
	parser->state = SCGI_REQ_PARSER_HEADER_ERROR;
	return -2;
}

/****************************************************************************
 *                         SCGI RING BUFFERS                                *
 ***************************************************************************/

/* ring buffer */
typedef struct scgi_cgi_buffer scgi_cgi_buffer;
struct scgi_cgi_buffer {
	unsigned int pos, len;
	unsigned char data[MAX_BUFFER_SIZE];
};

static void scgi_buffer_input_location(scgi_cgi_buffer *buf, unsigned char **location, ssize_t *location_size);
static void scgi_buffer_fill(scgi_cgi_buffer *buf, ssize_t n);
static void scgi_buffer_output_location(scgi_cgi_buffer *buf, unsigned char **location, ssize_t *location_size);
static void scgi_buffer_drain(scgi_cgi_buffer *buf, ssize_t n);
static int scgi_buffer_is_input_open(scgi_cgi_buffer *buf);
static void scgi_buffer_set(scgi_cgi_buffer *buf, const char *data, ssize_t len);

#define SCGI_BUFFER_SET(buf, str) scgi_buffer_set(buf, str, sizeof(str)-1)

static void scgi_buffer_input_location(scgi_cgi_buffer *buf, unsigned char **location, ssize_t *location_size) {
	if (buf->pos +  buf->len >= MAX_BUFFER_SIZE) {
		*location = buf->data + (buf->pos +  buf->len - MAX_BUFFER_SIZE);
		*location_size = MAX_BUFFER_SIZE - buf->len;
	} else {
		*location = buf->data + (buf->pos +  buf->len);
		*location_size = MAX_BUFFER_SIZE - (buf->pos +  buf->len);
	}
}

static void scgi_buffer_fill(scgi_cgi_buffer *buf, ssize_t n) {
	assert(n >= 0 && (unsigned int) n <= MAX_BUFFER_SIZE - buf->len);
	buf->len += n;
}

static void scgi_buffer_output_location(scgi_cgi_buffer *buf, unsigned char **location, ssize_t *location_size) {
	*location = buf->data + buf->pos;
	if (buf->pos +  buf->len >= MAX_BUFFER_SIZE) {
		*location_size = MAX_BUFFER_SIZE - buf->pos;
	} else {
		*location_size = buf->len;
	}
}

static void scgi_buffer_drain(scgi_cgi_buffer *buf, ssize_t n) {
	assert(n >= 0 && (unsigned int) n <= buf->len);
	buf->pos = (buf->pos + n) % MAX_BUFFER_SIZE;
	buf->len -= n;
	if (0 == buf->len) buf->pos = 0;
}

static int scgi_buffer_is_input_open(scgi_cgi_buffer *buf) {
	return buf->len < MAX_BUFFER_SIZE;
}

static void scgi_buffer_set(scgi_cgi_buffer *buf, const char *data, ssize_t len) {
	assert(len >= 0 && len <= MAX_BUFFER_SIZE);
	memcpy(buf->data, data, len);
	buf->pos = 0;
	buf->len = len;
}

/****************************************************************************
 *                         SCGI CHILD + SERVER                              *
 ***************************************************************************/

typedef struct scgi_cgi_server scgi_cgi_server;
typedef struct scgi_cgi_child scgi_cgi_child;

struct scgi_cgi_server {
	struct event_base *base;
	struct event *listen_watcher;

	struct event
		*sig_w_CHLD,
		*sig_w_INT,
		*sig_w_TERM,
		*sig_w_HUP;

	const char *binary;

	unsigned int children_used, children_size;
	scgi_cgi_child **children;
};

struct scgi_cgi_child {
	unsigned int ndx;
	scgi_cgi_server *srv;

	struct event *sock_in_watcher, *sock_out_watcher;
	scgi_req_parser req_parser;

	pid_t pid;

	int child_stdout, child_stdin;
	struct event *pipe_in_watcher, *pipe_out_watcher;

	scgi_cgi_buffer request_buf;
	scgi_cgi_buffer response_buf;
};

static void fd_init(int fd);
static void _my_event_free_with_fd(struct event **event);
static void _my_event_free(struct event **event);
#define MY_EVENT_FREE_WITH_FD(event) _my_event_free_with_fd(&(event))
#define MY_EVENT_FREE(event) _my_event_free(&(event))

static scgi_cgi_child* scgi_cgi_child_create(scgi_cgi_server *srv, int fd);
static void scgi_cgi_child_free(scgi_cgi_child *cld);
static void scgi_cgi_child_check_done(scgi_cgi_child *cld);
static void scgi_cgi_child_exec(scgi_cgi_child *cld);
static void scgi_cgi_child_start(scgi_cgi_child *cld);
static void scgi_cgi_close_socket(scgi_cgi_child *cld);
static void scgi_cgi_child_sock_in_cb(evutil_socket_t fd, short what, void *arg);
static void scgi_cgi_child_sock_out_cb(evutil_socket_t fd, short what, void *arg);
static void scgi_cgi_child_pipe_in_cb(evutil_socket_t fd, short what, void *arg);
static void scgi_cgi_child_pipe_out_cb(evutil_socket_t fd, short what, void *arg);

static scgi_cgi_server* scgi_cgi_server_create(int fd, const char *binary, unsigned int maxconns);
static void scgi_cgi_server_free(scgi_cgi_server* srv);
static void scgi_cgi_server_child_finished(scgi_cgi_server *srv, scgi_cgi_child *cld);
static void scgi_cgi_server_accept(evutil_socket_t fd, short what, void *arg);
static void sigint_cb(evutil_socket_t fd, short what, void *arg);
static void sigchld_cb(evutil_socket_t fd, short what, void *arg);


/****************************************************************************
 *                         SCGI utils implementation                        *
 ***************************************************************************/

static void fd_init(int fd) {
#ifdef _WIN32
	int i = 1;
#endif
#ifdef FD_CLOEXEC
	/* close fd on exec (cgi) */
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
#ifdef O_NONBLOCK
	fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);
#elif defined _WIN32
	ioctlsocket(fd, FIONBIO, &i);
#endif
}

static void _my_event_free_with_fd(struct event **event) {
	int fd;
	if (NULL == *event) return;
	fd = event_get_fd(*event);
	event_free(*event);
	*event = NULL;
	if (-1 != fd) close(fd);
}

static void _my_event_free(struct event **event) {
	if (NULL == *event) return;
	event_free(*event);
	*event = NULL;
}

/****************************************************************************
 *                         SCGI CHILD implementation                        *
 ***************************************************************************/


static scgi_cgi_child* scgi_cgi_child_create(scgi_cgi_server *srv, int fd) {
	struct event_base *base = srv->base;
	scgi_cgi_child *cld;
	int pipe_stdout[2], pipe_stdin[2];
	if (-1 == pipe(pipe_stdout)) {
		ERROR("couldn't create pipe: %s", strerror(errno));
		return NULL;
	}
	if (-1 == pipe(pipe_stdin)) {
		ERROR("couldn't create pipe: %s", strerror(errno));
		close(pipe_stdout[0]); close(pipe_stdout[1]); return NULL;
	}

	cld = calloc(1, sizeof(scgi_cgi_child));
	if (NULL == cld) {
		ERROR("couldn't alloc: %s", strerror(errno));
		close(pipe_stdout[0]); close(pipe_stdout[1]); close(pipe_stdin[0]); close(pipe_stdin[1]); return NULL;
	}

	cld->srv = srv;
	cld->pid = -1;
	cld->child_stdin = pipe_stdin[0];
	cld->child_stdout = pipe_stdout[1];

	scgi_parser_init(&cld->req_parser);

	cld->sock_in_watcher = event_new(base, fd, EV_READ | EV_PERSIST, scgi_cgi_child_sock_in_cb, cld);
	cld->sock_out_watcher = event_new(base, fd, EV_WRITE | EV_PERSIST, scgi_cgi_child_sock_out_cb, cld);
	fd_init(pipe_stdin[1]);
	cld->pipe_out_watcher = event_new(base, pipe_stdin[1], EV_WRITE | EV_PERSIST, scgi_cgi_child_pipe_out_cb, cld);
	fd_init(pipe_stdout[0]);
	cld->pipe_in_watcher = event_new(base, pipe_stdout[0], EV_READ | EV_PERSIST, scgi_cgi_child_pipe_in_cb, cld);

	if (NULL == cld->sock_in_watcher || NULL == cld->sock_out_watcher || NULL == cld->pipe_in_watcher || NULL == cld->pipe_out_watcher) {
		ERROR("couldn't alloc: %s", strerror(errno));
		if (NULL == cld->pipe_in_watcher) close(pipe_stdin[1]);
		if (NULL == cld->pipe_out_watcher) close(pipe_stdout[0]);
		scgi_cgi_child_free(cld);
		return NULL;
	}

	/* start handling */
	event_add(cld->sock_in_watcher, NULL);

	return cld;
}

static void scgi_cgi_child_free(scgi_cgi_child *cld) {
	/* shared fd */
	if (NULL != cld->sock_in_watcher) {
		MY_EVENT_FREE(cld->sock_out_watcher);
		MY_EVENT_FREE_WITH_FD(cld->sock_in_watcher);
	} else {
		MY_EVENT_FREE_WITH_FD(cld->sock_out_watcher);
	}

	MY_EVENT_FREE_WITH_FD(cld->pipe_in_watcher);
	MY_EVENT_FREE_WITH_FD(cld->pipe_out_watcher);

	if (-1 != cld->child_stdin) {
		close(cld->child_stdin);
		cld->child_stdin = -1;
	}
	if (-1 != cld->child_stdout) {
		close(cld->child_stdout);
		cld->child_stdout = -1;
	}

	scgi_parser_clear(&cld->req_parser);

	if (-1 != cld->pid) {
		kill(cld->pid, SIGTERM);
		cld->pid = -1;
	}

	free(cld);
}

static void scgi_cgi_child_check_done(scgi_cgi_child *cld) {
	if (-1 == cld->pid && NULL == cld->sock_out_watcher) {
		MY_EVENT_FREE_WITH_FD(cld->sock_in_watcher);
		MY_EVENT_FREE_WITH_FD(cld->pipe_in_watcher);
		MY_EVENT_FREE_WITH_FD(cld->pipe_out_watcher);
	}

	if (-1 != cld->pid || NULL != cld->sock_out_watcher || NULL != cld->sock_in_watcher || NULL != cld->pipe_in_watcher || NULL != cld->pipe_out_watcher) return;

	scgi_cgi_server_child_finished(cld->srv, cld);
}

static const char http_503_message[] =
	"Status: 503 Service Unavailable\r\n"
	"Content-Length: 0\r\n"
	"\r\n"
	;

static void scgi_cgi_child_exec(scgi_cgi_child *cld) {
	char **newenv;
	const char *path = cld->srv->binary;
	char * args[] = { NULL, NULL };

	if (cld->child_stdin != 0) {
		dup2(cld->child_stdin, 0);
		close(cld->child_stdin);
	}
	if (cld->child_stdout != 1) {
		dup2(cld->child_stdout, 1);
		close(cld->child_stdout);
	}
#ifdef FD_CLOEXEC
	/* UNDO close fd on exec (cgi) */
	fcntl(0, F_SETFD, 0);
	fcntl(1, F_SETFD, 0);
#endif

	if (NULL == path) path = scgi_parser_environ_get(&cld->req_parser, CONST_STR_LEN("INTERPRETER"));
	if (NULL == path) path = scgi_parser_environ_get(&cld->req_parser, CONST_STR_LEN("SCRIPT_FILENAME"));
	args[0] = (char*) path;

	/* try changing the directory. don't care about memleaks, execve() coming soon :) */
	{
		char *dir = strdup(path), *sep;
		if (NULL == (sep = strrchr(dir, '/'))) {
			chdir("/");
		} else {
			*sep = '\0';
			chdir(dir);
		}
	}

	scgi_parser_environ_copy(&cld->req_parser, CONST_STR_LEN("PATH"));
	newenv = (char**) cld->req_parser.environ;

	execve(path, args, newenv);

	fprintf(stderr, "couldn't execve '%s': %s\n", path, strerror(errno));

	write(1, http_503_message, sizeof(http_503_message));
	exit(-1);
}

static void scgi_cgi_child_start(scgi_cgi_child *cld) {
	cld->pid = fork();
	switch (cld->pid) {
	case 0:
		/* child process */
		scgi_cgi_child_exec(cld);
		break;
	case -1:
		/* error */
		fprintf(stderr, "couldn't fork: %s\n", strerror(errno));

		SCGI_BUFFER_SET(&cld->response_buf, http_503_message);
		if (NULL != cld->sock_out_watcher) event_add(cld->sock_out_watcher, NULL);

		/* don't need those anymore */
		scgi_parser_clear_environment(&cld->req_parser);
		close(cld->child_stdout); cld->child_stdout = -1;
		close(cld->child_stdin); cld->child_stdin = -1;

		/* close pipe stuff */
		MY_EVENT_FREE_WITH_FD(cld->pipe_in_watcher);
		MY_EVENT_FREE_WITH_FD(cld->pipe_out_watcher);

		break;
	default:
		/* don't need those anymore */
		scgi_parser_clear_environment(&cld->req_parser);
		close(cld->child_stdout); cld->child_stdout = -1;
		close(cld->child_stdin); cld->child_stdin = -1;

		/* start reading */
		event_add(cld->pipe_in_watcher, NULL);
		break;
	}
}

static void scgi_cgi_close_socket(scgi_cgi_child *cld) {
	cld->response_buf.pos = cld->response_buf.len = 0;
	/* shared fd */
	if (NULL != cld->sock_in_watcher) {
		MY_EVENT_FREE(cld->sock_out_watcher);
		MY_EVENT_FREE_WITH_FD(cld->sock_in_watcher);
	} else {
		MY_EVENT_FREE_WITH_FD(cld->sock_out_watcher);
	}
	if (NULL != cld->pipe_out_watcher) event_add(cld->pipe_out_watcher, NULL);
	if (NULL != cld->pipe_in_watcher) event_add(cld->pipe_in_watcher, NULL);

	scgi_cgi_child_check_done(cld);
}

static void scgi_cgi_child_sock_in_cb(evutil_socket_t fd, short what, void *arg) {
	scgi_cgi_child *cld = (scgi_cgi_child*) arg;
	UNUSED(what);
	assert(NULL != cld->sock_in_watcher);

	for (;;) {
		unsigned char *buf;
		ssize_t r;

		scgi_buffer_input_location(&cld->request_buf, &buf, &r);
		if (0 == r) { /* buffer is full */
			event_del(cld->sock_in_watcher);
			break;
		}
		r = read(fd, buf, r);
		if (0 == r) { /* eof */
			/* shared fd */
			if (NULL == cld->sock_out_watcher) {
				MY_EVENT_FREE_WITH_FD(cld->sock_in_watcher);
			} else {
				MY_EVENT_FREE(cld->sock_in_watcher);
			}
			break;
		} else if (0 > r) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
#if EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
				break; /* try again later */
			default:
				goto close_sock;
			}
			break;
		} else {
			if (SCGI_REQ_PARSER_HEADER_DONE != cld->req_parser.state) {
				ssize_t result;
				assert(0 == cld->request_buf.len);
				result = scgi_parse(&cld->req_parser, buf, r);
				DEBUG("scgi req parse result: %i", (int) result);
				if (result >= 0) {
					assert(SCGI_REQ_PARSER_HEADER_DONE == cld->req_parser.state);
					if (result > 0) {
						cld->request_buf.pos = r - result;
						cld->request_buf.len = result;
					}
					scgi_cgi_child_start(cld);
				} else if (result < -1) {
					goto close_sock;
				}
			} else if (NULL != cld->pipe_out_watcher) {
				scgi_buffer_fill(&cld->request_buf, r);
			} else {
				goto close_sock;
			}
		}
	}

	if (cld->request_buf.len > cld->req_parser.content_length) {
		cld->request_buf.len = cld->req_parser.content_length;
		goto close_sock;
	}

	if (NULL == cld->sock_in_watcher || 0 < cld->request_buf.len || 0 == cld->req_parser.content_length) {
		if (NULL != cld->pipe_out_watcher) event_add(cld->pipe_out_watcher, NULL);
	}

	scgi_cgi_child_check_done(cld);
	return;

close_sock:
	scgi_cgi_close_socket(cld);
}

static void scgi_cgi_child_sock_out_cb(evutil_socket_t fd, short what, void *arg) {
	scgi_cgi_child *cld = (scgi_cgi_child*) arg;
	UNUSED(what);
	assert(NULL != cld->sock_out_watcher);

	for (;;) {
		unsigned char *buf;
		ssize_t r;

		scgi_buffer_output_location(&cld->response_buf, &buf, &r);
		if (0 == r) { /* buffer empty */
			event_del(cld->sock_out_watcher);
			break;
		}
		r = write(fd, buf, r);
		if (0 >= r) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
#if EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
				break; /* try again later */
			default:
				goto close_sock;
			}
			break;
		}
		scgi_buffer_drain(&cld->response_buf, r);
	}

	if (0 == cld->response_buf.len && NULL == cld->pipe_in_watcher) {
		shutdown(fd, SHUT_RDWR);
		goto close_sock;
	} else if (NULL != cld->pipe_in_watcher && scgi_buffer_is_input_open(&cld->response_buf)) {
		event_add(cld->pipe_in_watcher, NULL);
	}

	scgi_cgi_child_check_done(cld);
	return;

close_sock:
	scgi_cgi_close_socket(cld);
}

static void scgi_cgi_child_pipe_in_cb(evutil_socket_t fd, short what, void *arg) {
	scgi_cgi_child *cld = (scgi_cgi_child*) arg;
	UNUSED(what);
	assert(NULL != cld->pipe_in_watcher);

	for (;;) {
		unsigned char *buf;
		ssize_t r;

		scgi_buffer_input_location(&cld->response_buf, &buf, &r);
		if (0 == r) { /* buffer full */
			event_del(cld->pipe_in_watcher);
			break;
		}
		r = read(fd, buf, r);
		if (0 == r) { /* eof */
			MY_EVENT_FREE_WITH_FD(cld->pipe_in_watcher);
			break;
		} else if (0 > r) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
#if EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
				break; /* try again later */
			default:
				MY_EVENT_FREE_WITH_FD(cld->pipe_in_watcher);
				break;
			}
			break;
		} else {
			if (NULL != cld->sock_out_watcher) {
				scgi_buffer_fill(&cld->response_buf, r);
			}
		}
	}

	if (NULL == cld->pipe_in_watcher || cld->response_buf.len > 0) {
		if (NULL != cld->sock_out_watcher) event_add(cld->sock_out_watcher, NULL);
	}

	scgi_cgi_child_check_done(cld);
}

static void scgi_cgi_child_pipe_out_cb(evutil_socket_t fd, short what, void *arg) {
	scgi_cgi_child *cld = (scgi_cgi_child*) arg;
	UNUSED(what);
	assert(NULL != cld->pipe_out_watcher);

	for (;;) {
		unsigned char *buf;
		ssize_t r;

		scgi_buffer_output_location(&cld->request_buf, &buf, &r);
		assert(cld->req_parser.content_length >= (size_t) r);

		if (0 == r) { /* buffer empty */
			event_del(cld->pipe_out_watcher);
			break;
		}
		r = write(fd, buf, r);
		if (0 >= r) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
#if EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
				break; /* try again later */
			default:
				goto close_pipe;
			}
			break;
		}
		cld->req_parser.content_length -= r;
		scgi_buffer_drain(&cld->request_buf, r);
	}

	if (0 == cld->req_parser.content_length || (0 == cld->request_buf.len && NULL == cld->sock_in_watcher)) {
		goto close_pipe;
	} else if (NULL != cld->sock_in_watcher && scgi_buffer_is_input_open(&cld->request_buf)) {
		event_add(cld->sock_in_watcher, NULL);
	}

	scgi_cgi_child_check_done(cld);
	return;

close_pipe:
	MY_EVENT_FREE_WITH_FD(cld->pipe_out_watcher);
	cld->request_buf.pos = cld->request_buf.len = 0;
	if (NULL != cld->sock_in_watcher) event_add(cld->sock_in_watcher, NULL);

	scgi_cgi_child_check_done(cld);
}

/****************************************************************************
 *                         SCGI SERVER implementation                       *
 ***************************************************************************/

#define CATCH_SIGNAL(cb, n) do { \
	srv->sig_w_##n = event_new(srv->base, SIG##n, EV_SIGNAL|EV_PERSIST, cb, srv); \
	assert(NULL != srv->sig_w_##n); \
	event_add(srv->sig_w_##n, NULL); \
} while (0)

#define UNCATCH_SIGNAL(n) MY_EVENT_FREE(srv->sig_w_##n)

static scgi_cgi_server* scgi_cgi_server_create(int fd, const char *binary, unsigned int maxconns) {
	scgi_cgi_server* srv = calloc(1, sizeof(scgi_cgi_server));

	srv->children = (scgi_cgi_child**) calloc(maxconns, sizeof(scgi_cgi_child*));
	assert(NULL != srv->children);
	srv->children_used = 0;
	srv->children_size = maxconns;

	srv->binary = binary;

	srv->base = event_base_new();
	fd_init(fd);
	srv->listen_watcher = event_new(srv->base, fd, EV_READ | EV_PERSIST, scgi_cgi_server_accept, srv);
	event_add(srv->listen_watcher, NULL);

	CATCH_SIGNAL(sigint_cb, INT);
	CATCH_SIGNAL(sigint_cb, TERM);
	CATCH_SIGNAL(sigint_cb, HUP);
	CATCH_SIGNAL(sigchld_cb, CHLD);

	return srv;
}

static void scgi_cgi_server_free(scgi_cgi_server* srv) {
	while (srv->children_used > 0) {
		scgi_cgi_server_child_finished(srv, srv->children[0]);
	}

	MY_EVENT_FREE_WITH_FD(srv->listen_watcher);

	UNCATCH_SIGNAL(INT);
	UNCATCH_SIGNAL(TERM);
	UNCATCH_SIGNAL(HUP);
	UNCATCH_SIGNAL(CHLD);

	free(srv->children);
	srv->children = NULL;
	srv->children_size = 0;
	free(srv);
}

static void scgi_cgi_server_child_finished(scgi_cgi_server *srv, scgi_cgi_child *cld) {
	unsigned int ndx = cld->ndx;
	assert(srv->children[ndx] == cld);
	assert(ndx < srv->children_used);

	DEBUG("Child %i finished", ndx);

	--srv->children_used;
	if (ndx != srv->children_used) {
		srv->children[ndx] = srv->children[srv->children_used];
		srv->children[ndx]->ndx = ndx;
	}
	srv->children[srv->children_used] = NULL;

	scgi_cgi_child_free(cld);

	if (NULL == srv->listen_watcher && 0 == srv->children_used) UNCATCH_SIGNAL(CHLD); /* shutdown */
	if (NULL != srv->listen_watcher) event_add(srv->listen_watcher, NULL);
}

static void scgi_cgi_server_accept(evutil_socket_t fd, short what, void *arg) {
	scgi_cgi_server *srv = (scgi_cgi_server*) arg;
	int confd;
	UNUSED(what);

	if (srv->children_used == srv->children_size) {
		event_del(srv->listen_watcher);
		return;
	}

	while (srv->children_used < srv->children_size) {
		if (-1 != (confd = accept(fd, NULL, NULL))) {
			scgi_cgi_child *cld;

			fd_init(confd);
			cld = scgi_cgi_child_create(srv, confd);
			if (NULL == cld) {
				if (0 == srv->children_used) {
					ERROR("no children running, and child creation failed. abort.");
					exit(-2);
				}
				ERROR("child creation failed, disable listening temporarily until next child finishes");
				close(confd);
				event_del(srv->listen_watcher);
				return;
			}
			srv->children[srv->children_used++] = cld;
		} else {
			break;
		}
	}
}

static void sigint_cb(evutil_socket_t fd, short what, void *arg) {
	scgi_cgi_server *srv = (scgi_cgi_server*) arg;
	UNUSED(fd);
	UNUSED(what);

	UNCATCH_SIGNAL(INT);
	UNCATCH_SIGNAL(TERM);
	UNCATCH_SIGNAL(HUP);

	MY_EVENT_FREE_WITH_FD(srv->listen_watcher);

	if (0 == srv->children_used) UNCATCH_SIGNAL(CHLD);

	fprintf(stderr, "Got signal, shutdown (%i children remaining)\n", srv->children_used);
}

static void sigchld_cb(evutil_socket_t fd, short what, void *arg) {
	scgi_cgi_server *srv = (scgi_cgi_server*) arg;
	pid_t pid;
	int status;
	UNUSED(fd);
	UNUSED(what);

	while (srv->children_used > 0) {
		if (-1 != (pid = waitpid(-1, &status, WNOHANG))) {
			unsigned int i;
			for (i = 0; i < srv->children_used; ++i) {
				scgi_cgi_child *cld = srv->children[i];
				if (cld->pid == pid) {
					DEBUG("child %i terminated with status %i", i, status);
					cld->pid = -1;
					scgi_cgi_child_check_done(cld);
					break;
				}
			}
		} else {
			break;
		}
	}
}

static void show_help() {
	fprintf(stderr, PACKAGE_DESC "\n");
	fprintf(stderr,
		"Usage: scgi-cgi [-b binary] [-c maxconns] [-h] [-v] -- [binary]\n"
		"Options:\n"
		"  -b binary     the executable to call instead of INTERPRETER\n"
		"                or SCRIPT_FILENAME from SCGI environment (default: none)\n"
		"  -c maxconns   how many connections to accept at the same time (default: 16)\n"
		"  -v            show version\n"
		"  -h            show this help\n"
	);
}

int main (int argc, char **argv) {
	scgi_cgi_server *srv;
	const char *binary = NULL;
	unsigned int maxconn = 16;
	int o;

	while(-1 != (o = getopt(argc, argv, "b:c:hv"))) {
		switch(o) {
		case 'b':
			binary = optarg;
			break;
		case 'c':
			maxconn = atoi(optarg);
			break;
		case 'v':
			fprintf(stderr, PACKAGE_DESC "\n");
			return 0;
		case 'h':
			show_help();
			return 0;
		default:
			show_help();
			return -1;
		}
	}

	if (optind < argc && argv[optind] && NULL == binary) binary = argv[optind];

	srv = scgi_cgi_server_create(0, binary, maxconn);
	event_base_loop(srv->base, 0);
	scgi_cgi_server_free(srv);
	return 0;
}
