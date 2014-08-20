#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/md5.h>
#include <stdio.h>

typedef struct {
    ngx_str_t	filename;
} ngx_http_md5_loc_conf_t;

static void *ngx_http_md5_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_md5_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_md5_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_md5_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_md5_commands[] = {
    {
        ngx_string("md5_sum"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_md5_set,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_md5_loc_conf_t, filename),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_md5_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_md5_create_loc_conf,
    ngx_http_md5_merge_loc_conf
};

ngx_module_t ngx_http_md5_module = {
    NGX_MODULE_V1,
    &ngx_http_md5_module_ctx,
    ngx_http_md5_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_md5_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_md5_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_md5_handler(ngx_http_request_t *r) {
    FILE *fp;
    MD5_CTX	ctx;
    char	*path;
    char buffer[8196];
    unsigned char result[16];
    size_t	rc, i;
    int		j = 0;
    char	*output;
    ngx_http_md5_loc_conf_t	*md5_conf;
    md5_conf = ngx_http_get_module_loc_conf(r, ngx_http_md5_module);

    path = (char *) md5_conf->filename.data;

    MD5_Init(&ctx);

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    while (! feof(fp)) {
        rc = fread(buffer, sizeof(char), 8196, fp);
        MD5_Update(&ctx, buffer, rc);
    }
    fclose(fp);


    MD5_Final(result, &ctx);

    output = ngx_palloc(r->pool, 32);

    for (i = 0; i < 16; i++) {
        j += sprintf(output + j, "%02x", result[i]);
    }
    output[32] = '\0';


    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 32;
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    ngx_http_send_header(r);

    ngx_buf_t	*b;
    ngx_chain_t	out;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = (u_char *) output;
    b->last = (u_char *) output + 32;

    b->memory = 1;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static void *
ngx_http_md5_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_md5_loc_conf_t	*conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_md5_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->filename.data = NULL;
    conf->filename.len = 0;
    return conf;
}

static char *
ngx_http_md5_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_md5_loc_conf_t	*prev = parent;
    ngx_http_md5_loc_conf_t	*conf = child;

    ngx_conf_merge_str_value(conf->filename, prev->filename, "");
    return NGX_CONF_OK;
}
