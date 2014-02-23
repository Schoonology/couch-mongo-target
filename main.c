#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include <http_parser.h>
#include <uv.h>
#include <mongo.h>

void uv_check(int rc) {
  if (rc >= 0) {
    return;
  }

  uv_err_t err = uv_last_error(uv_default_loop());
  printf("%s UV Error: %s\n", uv_err_name(err), uv_strerror(err));
  exit(1);
}

uv_buf_t alloc_cb(uv_handle_t* handle, size_t size) {
  printf("In alloc_cb.\n");
  return uv_buf_init((char *)malloc(size), size);
}

void close_cb(uv_handle_t *handle) {
  printf("Closed.\n");
}

void write_cb(uv_write_t *req, int status) {
  assert(req);
  uv_check(status);
  uv_close((uv_handle_t *)req->data, close_cb);
}

typedef struct {
  uv_tcp_t *socket;
  http_parser_settings *settings;
} cm_server;

typedef struct {
  cm_server *server;
  uv_tcp_t *socket;
  http_parser *parser;
} cm_conn_baton;

int on_message_begin_cb(http_parser *parser) {
  printf("In on_message_begin.\n");
  return 0;
}

int on_headers_complete_cb(http_parser *parser) {
  printf("In on_headers_complete.\n");
  return 0;
}

int on_message_complete_cb(http_parser *parser) {
  printf("In on_message_complete.\n");
  cm_conn_baton *baton = (cm_conn_baton *)parser->data;

  uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
  assert(req);
  req->data = baton->socket;
  uv_buf_t response[] = {{ .base = "Response.", .len = 9 }};
  uv_write(req, (uv_stream_t *)baton->socket, response, 1, write_cb);
  return 0;
}

int on_url_cb(http_parser *parser, const char *data, size_t length) {
  char *_data = (char *)malloc(length);
  assert(_data);
  strncpy(_data, data, length);
  printf("In on_url: %s\n", _data);
  return 0;
}

int on_status_cb(http_parser *parser, const char *data, size_t length) {
  char *_data = (char *)malloc(length);
  assert(_data);
  strncpy(_data, data, length);
  printf("In on_status: %s\n", _data);
  return 0;
}

int on_header_field_cb(http_parser *parser, const char *data, size_t length) {
  char *_data = (char *)malloc(length);
  assert(_data);
  strncpy(_data, data, length);
  printf("In on_header_field: %s\n", _data);
  return 0;
}

int on_header_value_cb(http_parser *parser, const char *data, size_t length) {
  char *_data = (char *)malloc(length);
  assert(_data);
  strncpy(_data, data, length);
  printf("In on_header_value: %s\n", _data);
  return 0;
}

int on_body_cb(http_parser *parser, const char *data, size_t length) {
  char *_data = (char *)malloc(length);
  assert(_data);
  strncpy(_data, data, length);
  printf("In on_body: %s\n", _data);
  return 0;
}

cm_server *cm_server_new() {
  cm_server *self = malloc(sizeof(cm_server));
  assert(self);

  uv_tcp_t *socket = malloc(sizeof(uv_tcp_t));
  assert(socket);
  self->socket = socket;
  self->socket->data = self;
  uv_check(uv_tcp_init(uv_default_loop(), self->socket));
  uv_check(uv_tcp_nodelay(self->socket, 0));

  // TOOD(schoon) - This is wrong. I need one parser per request with the
  // settings used to establish the proper callbacks for handling.
  // TODO(schoon) - Break into good H form for maintainability. Now is the time.
  http_parser_settings *settings = malloc(sizeof(http_parser_settings));
  assert(settings);
  self->settings = settings;

  settings->on_message_begin = on_message_begin_cb;
  settings->on_url = on_url_cb;
  settings->on_status = on_status_cb;
  settings->on_header_field = on_header_field_cb;
  settings->on_header_value = on_header_value_cb;
  settings->on_headers_complete = on_headers_complete_cb;
  settings->on_body = on_body_cb;
  settings->on_message_complete = on_message_complete_cb;

  return self;
}

void cm_server_destroy(cm_server **_self) {
  cm_server *self = *_self;
  if (self) {
    uv_close((uv_handle_t*)self->socket, NULL);

    free(self->socket);
    free(self->settings);
    free(self);
    *_self = NULL;
  }
}

void cm_server_connection_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf) {
  printf("In read_cb.\n");
  uv_check(nread);

  printf("Buffer: %s\n", buf.base);

  cm_conn_baton *baton = (cm_conn_baton *)stream->data;
  size_t parsed = 0;

  parsed = http_parser_execute(baton->parser, baton->server->settings, buf.base, nread == -1 ? 0 : nread);

  if (baton->parser->upgrade) {
    printf("Upgrade requested.\n");
  } else if (nread != -1 && parsed != nread) {
    fprintf(stderr, "Error parsing data: %s\n", http_errno_description(HTTP_PARSER_ERRNO(baton->parser)));
  }
}

void cm_server_connection_cb(uv_stream_t *socket, int status) {
  uv_check(status);

  uv_tcp_t *client = malloc(sizeof(uv_tcp_t));
  assert(client);
  uv_check(uv_tcp_init(uv_default_loop(), client));
  uv_check(uv_accept(socket, (uv_stream_t*)client));

  http_parser *parser;
  parser = malloc(sizeof(http_parser));
  assert(parser);
  http_parser_init(parser, HTTP_REQUEST);

  cm_conn_baton *baton = malloc(sizeof(cm_conn_baton));
  assert(baton);
  baton->parser = parser;
  baton->socket = client;
  baton->server = (cm_server *)socket->data;

  parser->data = baton;
  client->data = baton;

  uv_check(uv_read_start((uv_stream_t*)client, alloc_cb, cm_server_connection_read_cb));
}

void cm_server_listen(cm_server *self, const char *ip, int port) {
  assert(self);

  printf("Listening at %s:%d...\n", ip, port);

  struct sockaddr_in addr;
  addr = uv_ip4_addr(ip, port);
  uv_check(uv_tcp_bind(self->socket, addr));
  uv_check(uv_listen((uv_stream_t*)self->socket, 128, cm_server_connection_cb));
}

int main(int argc, char const *argv[])
{
  printf("Starting...\n");

  cm_server *server = cm_server_new();
  cm_server_listen(server, "0.0.0.0", 8080);

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  /* code */
  return 0;
}
