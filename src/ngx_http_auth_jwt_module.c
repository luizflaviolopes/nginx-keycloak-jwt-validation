#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <jwt.h>
#include <jansson.h>
#include <curl/curl.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#define NGX_JWT_VALIDATION_OFF       0
#define NGX_JWT_VALIDATION_JWKS      1
#define NGX_JWT_VALIDATION_SESSION   2

#define NGX_JWT_NOT_AUTHENTICATED    0
#define NGX_JWT_AUTHENTICATED        1

typedef struct {
  ngx_int_t jwt_validation_flag;    // Function of "auth_jwt": off -> 0 | jwks -> 1 | session -> 2
  ngx_int_t  acct_num_var_index;
} ngx_http_auth_jwt_loc_conf_t;

struct MemoryStruct {
  char *memory;
  size_t size;
};

typedef struct jwk_key {
    unsigned char * n;
    int nLen;
    unsigned char * e;
    int eLen;
} jwk_key;

typedef struct {
    ngx_int_t     status;
    u_char     *acctNum;
} ngx_http_auth_jwt_ctx_t;


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static ngx_int_t auth_jwt_get_token(u_char **token, ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf);
static u_char * auth_jwt_safe_string(ngx_pool_t *pool, u_char *src, size_t len);
static char * combineStrings(ngx_pool_t *pool, char * textA, char *textB);
static ngx_int_t validation_jwt_jwks(ngx_http_request_t  *r, char * plain_jwt);
static ngx_int_t validation_jwt_session(ngx_http_request_t  *r, char * plain_jwt);
static void PerformHttpRequest(ngx_pool_t *pool, ngx_log_t *log, char **response, char * url, char * auth_token);
static int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
static char * ParseAndGetJsonString(ngx_log_t *log, char* content, char *prop);
static json_t *ParseAndGetJsonObject(ngx_log_t *log, char* content, char *prop);
static int GetCorrectKey(ngx_http_request_t *r, jwk_key *key, json_t *keysArray);
static char * base64uri_decode(char *str);
static int Base64decode(char *bufplain, const char *bufcoded);
static int Base64decode_len(const char *bufcoded);
static int UpdateRequest(ngx_http_request_t  *r, char * acctNum);
static int ProcessAcctNumUriRequest(ngx_http_request_t  *r, char * acctNum);
static void ProcessAcctNumBodyRequest(ngx_http_request_t  *r);
static void RewriteRequestFromFile(ngx_file_t *dst,ngx_file_t *src, u_char *acctNum, ngx_log_t *log, ngx_pool_t *pool );

// Configuration functions
static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static void * ngx_http_auth_jwt_create_conf(ngx_conf_t *cf);
static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_conf_set_jwt_validation_flag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static char * combineStrings(ngx_pool_t *pool, char * textA, char *textB)
{
    size_t size = strlen(textA) + strlen(textB);
    char *completeString = ngx_pcalloc(pool, size + 1);
    completeString[0] = '\0';
    strcat(completeString,textA);
    strcat(completeString,textB);

    return completeString;
    
}

static u_char * auth_jwt_safe_string(ngx_pool_t *pool, u_char *src, size_t len)
{
  u_char  *dst;

  dst = ngx_pcalloc(pool, len + 1);
  if (dst == NULL)
  {
    return NULL;
  }

  ngx_memcpy(dst, src, len);

  dst[len] = '\0';

  return dst;
}

static ngx_command_t ngx_http_auth_jwt_commands[] = {

  // auth_jwt $ off | jwks | session;
  { ngx_string("auth_jwt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_jwt_validation_flag,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_validation_flag),
    NULL },

  ngx_null_command
};


static char * ngx_conf_set_jwt_validation_flag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
  ngx_http_auth_jwt_loc_conf_t *ajcf = conf;

  ngx_int_t *flag = &ajcf->jwt_validation_flag;

  if (*flag != NGX_CONF_UNSET)
  {
    return "is duplicate";
  }

  const ngx_str_t *value = cf->args->elts;

  const ngx_str_t var = value[1];

  if (var.len == 0)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: Invalid value");
    return NGX_CONF_ERROR;
  }

  // Check if enabled, if not: return conf.
  if (var.len == 3 && ngx_strncmp(var.data, "off", 3) == 0)
  {
    *flag = NGX_JWT_VALIDATION_OFF;
  }
  // If enabled and "jwks" method
  else if (var.len == 4 && ngx_strncmp(var.data, "jwks", 2) == 0)
  {
    *flag = NGX_JWT_VALIDATION_JWKS;
  }
  // If enabled and "session" method
  else if (var.len == 7 && ngx_strncmp(var.data, "session", 2) == 0)
  {
    *flag = NGX_JWT_VALIDATION_SESSION;
  }
  else
  {
    *flag = NGX_CONF_UNSET;
  }

  return NGX_CONF_OK;
}



static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
  NULL, /* preconfiguration */
  ngx_http_auth_jwt_init,      /* postconfiguration */

  NULL,                        /* create main configuration */
  NULL,                        /* init main configuration */

  NULL,                        /* create server configuration */
  NULL,                        /* merge server configuration */

  ngx_http_auth_jwt_create_conf,             /* create location configuration */
  ngx_http_auth_jwt_merge_conf               /* merge location configuration */
};

ngx_module_t ngx_http_auth_jwt_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_jwt_module_ctx,     /* module context */
  ngx_http_auth_jwt_commands,        /* module directives */
  NGX_HTTP_MODULE,                   /* module type */
  NULL,                              /* init master */
  NULL,                              /* init module */
  NULL,                              /* init process */
  NULL,                              /* init thread */
  NULL,                              /* exit thread */
  NULL,                              /* exit process */
  NULL,                              /* exit master */
  NGX_MODULE_V1_PADDING
};



static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL)
  {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_jwt_handler;

  return NGX_OK;
}

static void * ngx_http_auth_jwt_create_conf(ngx_conf_t *cf)
{
  ngx_http_auth_jwt_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_jwt_loc_conf_t));
  if (conf == NULL)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "JWT: conf==NULL");
    return NULL;
  }

  // Initialize variables
  conf->jwt_validation_flag = NGX_CONF_UNSET;
  

  return conf;
}


static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_jwt_loc_conf_t *prev = parent;
  ngx_http_auth_jwt_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->jwt_validation_flag, prev->jwt_validation_flag, 0);

  return NGX_CONF_OK;
}


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: STARTING...");

  // ngx_str_t newuri = ngx_string("acctNum=260001-1221680325&company=paragonmeds&customerId=99999");
  // r->args = newuri;

  // return NGX_OK;
    
    const ngx_http_auth_jwt_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

    // ngx_http_variable_value_t  *v = ngx_http_get_indexed_variable(r,conf->acct_num_var_index);
    // ngx_http_auth_jwt_vars_t * data = (ngx_http_auth_jwt_vars_t *)v->data;

    // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: var data = %d", data->authenticated);
    // if(r->uri.len > 0)
    // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: uri requested = %s", r->uri.data);
    // if(r->args.len > 0)
    // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: args requested = %s", r->args.data);

    // if(data->authenticated > 0)
    // {
    //   ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: ending the request");
    //   return NGX_OK;
    // }
  
    u_char *jwt_data;


  // Pass through if "auth_jwt" is unset
  if (conf->jwt_validation_flag == NGX_CONF_UNSET)
  {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: flag is unset");
    return NGX_DECLINED;

  }

  // Pass through if "auth_jwt" is "off"
  if (conf->jwt_validation_flag == NGX_JWT_VALIDATION_OFF)
  {

    return UpdateRequest(r,"123-4-0006");
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: flag is off");
    return NGX_DECLINED;

  }


  if (auth_jwt_get_token(&jwt_data, r, conf) != NGX_OK)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to find a jwt");
    return NGX_HTTP_UNAUTHORIZED;
  }

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: Got authorization token");

  if(conf->jwt_validation_flag == NGX_JWT_VALIDATION_JWKS)
  {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: flag is jwks");
    
    
    ngx_int_t validation_result = validation_jwt_jwks(r, (char *)jwt_data);

    if(validation_result != NGX_OK)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: invalid token");
      return NGX_HTTP_UNAUTHORIZED;
    }
  }

  if(conf->jwt_validation_flag == NGX_JWT_VALIDATION_SESSION)
  {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: flag is session");

    ngx_int_t validation_session_result = validation_jwt_session(r, (char *)jwt_data);

    if(validation_session_result != NGX_OK)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: invalid token");
      return NGX_HTTP_UNAUTHORIZED;
    }
  }

  return NGX_OK;

}

static ngx_int_t auth_jwt_get_token(u_char **token, ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf)
{
  static const ngx_str_t bearer = ngx_string("Bearer ");

    if (r->headers_in.authorization == NULL)
    {
      return NGX_DECLINED;
    }

    ngx_str_t header = r->headers_in.authorization->value;

    // If the "Authorization" header value is less than "Bearer X" length, there is no reason to continue.
    if (header.len < bearer.len + 1)
    {
     ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Invalid Authorization length");
     return NGX_DECLINED;
    }
    // If the "Authorization" header does not starts with "Bearer ", return NULL.
    if (ngx_strncmp(header.data, bearer.data, bearer.len) != 0)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Invalid authorization header content");
      return NGX_DECLINED;
    }

    *token = auth_jwt_safe_string(r->pool, header.data + bearer.len, (size_t) header.len - bearer.len);


  if (token == NULL)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "Could not allocate memory.");
    return NGX_ERROR;
  }

  return NGX_OK;
}

static ngx_int_t validation_jwt_jwks(ngx_http_request_t  *r, char * plain_jwt) {

    curl_global_init(CURL_GLOBAL_DEFAULT);

    jwt_t *jwt = NULL;
    char *opidcf_url_end = "/.well-known/openid-configuration";

    jwt_decode(&jwt, plain_jwt, NULL,0);
    const char *opidcf_base_url = jwt_get_grant(jwt, "iss");
    if(opidcf_base_url == NULL)
    {
      return NGX_DECLINED;
    }

    char *opidcf_url = combineStrings(r->pool,(char *)opidcf_base_url, opidcf_url_end);
    
    char * opidcf_resp;
    PerformHttpRequest(r->pool,r->connection->log, &opidcf_resp,(char*)opidcf_url, NULL);
    
    char *jwks_uri = ParseAndGetJsonString(r->connection->log, opidcf_resp,"jwks_uri");
    if(jwks_uri == NULL)
    {
      return NGX_DECLINED;
    }

    char * jks_resp;
    PerformHttpRequest(r->pool,r->connection->log,&jks_resp,jwks_uri, NULL);

    json_t * keys = ParseAndGetJsonObject(r->connection->log, jks_resp, "keys");
    if(keys == NULL)
    {
      return NGX_DECLINED;
    }

    struct jwk_key key;
            key.e = ngx_alloc(1, r->connection->log);
            key.n = ngx_alloc(1, r->connection->log);
            key.eLen = 0;
            key.nLen = 0;

    GetCorrectKey(r, &key, keys);

    BIGNUM* modul = BN_bin2bn(key.n, key.nLen, NULL);
    BIGNUM* expon = BN_bin2bn(key.e, key.eLen, NULL);

    RSA * rr = RSA_new();
    EVP_PKEY * pRsaKey = EVP_PKEY_new();

    RSA_set0_key(rr, modul, expon, NULL);

    EVP_PKEY_assign_RSA(pRsaKey, rr);
    // unsigned char * ss[1024];
    unsigned char *desc = ngx_calloc(1024, r->connection->log);

    unsigned char * strPubKey;

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rr);
    BIO_read(bio, desc, 1024);
    strPubKey = desc;
    BIO_free(bio);
    RSA_free(rr);

    jwt_t *new_jwt;

    if(jwt_decode(&new_jwt, plain_jwt,strPubKey ,strlen((char *)strPubKey)))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error: error to decode jwt");
        return NGX_HTTP_UNAUTHORIZED;
    }

    free(key.e);
    free(key.n);
    free(keys);
    curl_global_cleanup();

    // jwt_decode succeded and allocated an jwt object.
    // We register jwt_free as a function to be called on pool cleanup.
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL)
    {
      jwt_free(new_jwt);
      return NGX_ERROR;
    }
    cln->handler = (ngx_pool_cleanup_pt)jwt_free;
    cln->data = new_jwt;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: processed public key");

    jwt_alg_t alg = jwt_get_alg(new_jwt);
    const char* alg_val =  jwt_alg_str(alg);
    if(alg_val == NULL || alg_val == JWT_ALG_NONE)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "invalid algorithm : ");
      return NGX_HTTP_UNAUTHORIZED;
    }
    
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: algorithm: %s",(char *)alg_val);

    time_t exp = (time_t)jwt_get_grant_int(jwt, "exp");
    if (exp != -1 && exp < time(NULL))
    {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "JWT: the jwt has expired [exp=%ld]", (long)exp);
      return NGX_HTTP_UNAUTHORIZED;
    }

    return NGX_OK;
}


static ngx_int_t validation_jwt_session(ngx_http_request_t  *r, char * plain_jwt) {

  curl_global_init(CURL_GLOBAL_DEFAULT);

    jwt_t *jwt = NULL;
    char *opidcf_url_end = "/protocol/openid-connect/userinfo";


    jwt_decode(&jwt, plain_jwt, NULL,0);
    const char *opidcf_base_url = jwt_get_grant(jwt, "iss");
    if(opidcf_base_url == NULL)
    {
      return NGX_DECLINED;
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: step 1" );

    char *opidcf_url = combineStrings(r->pool,(char *)opidcf_base_url, opidcf_url_end);
    
    char * opidcf_resp;
    PerformHttpRequest(r->pool,r->connection->log, &opidcf_resp,(char*)opidcf_url, plain_jwt);
    
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: step 2" );
    char *acctNum = ParseAndGetJsonString(r->connection->log, opidcf_resp,"acctNum");
    if(acctNum == NULL)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: Could not find a valid session");
      return NGX_HTTP_UNAUTHORIZED;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: session is valid. acctNum: %s",acctNum );

    return UpdateRequest(r,acctNum);

    return NGX_OK;

}

static void PerformHttpRequest(ngx_pool_t *pool, ngx_log_t *log, char **response, char * url, char * auth_token)
{
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = ngx_alloc(1, log);
    chunk.size = 0;

    CURL *curl = curl_easy_init();
    if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "charset: utf-8");

    if(auth_token != NULL)
    {
        char * auth_header = combineStrings(pool, "Authorization: Bearer ",auth_token);
        headers = curl_slist_append(headers, auth_header);
        ngx_pfree(pool, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK){
          ngx_log_error(NGX_LOG_ERR, log, 0, "JWT: curl_easy_perform() failed: %s",(char *)curl_easy_strerror(res));
    }

    curl_easy_reset(curl);
    curl_easy_cleanup(curl);

    }
    else
    {
      ngx_log_error(NGX_LOG_ERR, log, 0, "curl does not exist\n");
    }

    *response = ngx_pcalloc(pool,chunk.size);
    strcpy(*response, chunk.memory);

}

static int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

static char * ParseAndGetJsonString(ngx_log_t *log, char* content, char *prop)
{
    json_t *root;
    json_error_t error;

    root = json_loads(content, 0, &error);

    if(!root)
    {
      ngx_log_error(NGX_LOG_ERR, log, 0, "error: content is not an object");
      json_decref(root);
      return NULL;
    }

    json_t *propValue = json_object_get(root, prop);
    if(!json_is_string(propValue))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0, "error: property is not a string");
        json_decref(root);
        json_decref(propValue);
        return NULL;
    }

    char *jsonStrVal = strdup(json_string_value(propValue));
    json_decref(root);
    json_decref(propValue);

    return jsonStrVal;

}

static json_t *ParseAndGetJsonObject(ngx_log_t *log, char* content, char *prop)
{
    json_t *root;
    json_error_t error;


    root = json_loads(content, 0, &error);

    if(!root)
    {
      ngx_log_error(NGX_LOG_ERR, log, 0, "error: content is not an object");
      json_decref(root);
      return NULL;
    }

    json_t *propValue = json_object_get(root, prop);
    if(!json_is_object(propValue) && !json_is_array(propValue))
    {
      ngx_log_error(NGX_LOG_ERR, log, 0, "error: property is not valid");

      json_decref(root);
      json_decref(propValue);
      return NULL;
    }
    
    json_t *resp = json_deep_copy(propValue);
    json_decref(root);
    return resp;
}

static int GetCorrectKey(ngx_http_request_t *r, jwk_key *key, json_t *keysArray)
{

    if(!json_is_array(keysArray))
    {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error: keys value is not an array");
      return 0;
    }

    long unsigned int i;
    json_t * data;

    for(i = 0; i < json_array_size(keysArray); i++)
    {
        data = json_array_get(keysArray, i);
        if(!json_is_object(data))
        {
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error: data %d is not an object");
          json_decref(data);
          return 0;
        }

        json_t *use = json_object_get(data,"use");
        if(!json_is_string(use))
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error: property use is not a string");
            json_decref(data);
            return 0;
        }

        const char * useString = json_string_value(use);
        if(strcmp(useString,"sig") == 0)
        {
            json_t *n = json_object_get(data,"n");
            if(!json_is_string(n))
            {
              ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error: property N is not a string");
              json_decref(data);
              return 0;
            }

            json_t *e = json_object_get(data,"e");
            if(!json_is_string(n))
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error: property E is not a string");
                json_decref(data);
                return 0;
            }

            char *nStr = base64uri_decode(strdup(json_string_value(n)));
            char *eStr = base64uri_decode(strdup(json_string_value(e)));

            char * plainn = ngx_alloc(Base64decode_len(nStr), r->connection->log);
            char * plaine = ngx_alloc(Base64decode_len(eStr)+1, r->connection->log);

            int elen = Base64decode(plaine,eStr);
            int nlen = Base64decode(plainn,nStr);

            free(nStr);
            free(eStr);

            unsigned char buf[nlen]; 

            memcpy(buf,plainn,nlen);

            key->e = ngx_alloc(elen,r->connection->log);
            key->n = ngx_alloc(nlen, r->connection->log);

            memcpy(key->e,plaine,elen);
            memcpy(key->n,plainn,nlen);

            key->eLen = elen;
            key->nLen = nlen;


            free(n);
            free(use);
            json_decref(data);

            return 1;

        }
        
        free(use);
        json_decref(data);
    }

    return 0;
}


static char * base64uri_decode(char *str)
{
	int len = (int)strlen(str);
  int rest = len % 4;
  char new[len+rest];  
	int i;

	for (i = 0; i < len; i++) {
		switch (str[i]) {
		case '-':
			new[i] = '+';
			break;
		case '_':
			new[i] = '/';
			break;
		default:
			new[i] = str[i];
		}
	}

  long unsigned int t;
	for (t =i; t < strlen(new); t++)
  {
      new[t] = '=';
  }

    new[t] = '\0';

    char * toRet = malloc(len+rest+1);
    strcpy(toRet,new);

    return toRet;
}

static int Base64decode(char *bufplain, const char *bufcoded)
{

    const unsigned char pr2six[256] =
    {
        /* ASCII table */
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
    };

    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static int Base64decode_len(const char *bufcoded)
{

    const unsigned char pr2six[256] =
    {
        /* ASCII table */
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
    };

    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}


static int UpdateRequest(ngx_http_request_t  *r, char * acctNum){
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: again...");
  // check method
  if(r->method == NGX_HTTP_GET)
  {
  // if get request
    return ProcessAcctNumUriRequest(r, acctNum);

  }
  else
  {
  // if post request

    ngx_http_auth_jwt_ctx_t       *ctx;       
    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);

    if (ctx) {
        return ctx->status;
    }
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_jwt_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->status = NGX_DONE;
    
    u_char *newacct = ngx_pcalloc(r->pool, ngx_strlen(acctNum)+1);
    ngx_memcpy(newacct,acctNum,ngx_strlen(acctNum));
    ctx->acctNum = newacct;

    ngx_http_set_ctx(r, ctx, ngx_http_auth_jwt_module);

    ngx_int_t rc;
    rc = ngx_http_read_client_request_body(r, ProcessAcctNumBodyRequest);


    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: RC= %O",rc);


    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;

   
  }

}

static int ProcessAcctNumUriRequest(ngx_http_request_t  *r, char * acctNum){

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: start processing... ");
  

  u_char * path;

  char * query_string_start = strstr((char *)r->uri.data, "?");
  if(query_string_start != NULL) //has queryString
  {
    int path_len = query_string_start - (char *)r->uri.data;
    path = ngx_pcalloc(r->pool,path_len+1);
    ngx_memcpy(path, (char *)r->uri.data, path_len);
  }
  else
  {
    path = ngx_pcalloc(r->pool,r->uri.len+1);
    ngx_memcpy(path, (char *)r->uri.data, r->uri.len);
  }

  u_char * query_string;

  if(r->args.len > 0) //if has args
  {
      // setting acctNum arg to inject
      char accnum_arg[8+strlen(acctNum)+1];
      ngx_memcpy(accnum_arg, "acctNum=", 8);
      ngx_memcpy((accnum_arg+8), acctNum, strlen(acctNum)+1);
      int accnum_arg_len = strlen(accnum_arg);

      char * accnum_pos = ngx_strstr((char *)r->args.data, "acctNum=");
      if(accnum_pos == NULL) // check if does not exist acctNum
      { 
          //does not exist and need to be appended to the end

          int qs_len = r->args.len + accnum_arg_len+1;
          query_string = ngx_pcalloc(r->pool,qs_len+1);
          ngx_memcpy(query_string,r->args.data,r->args.len);
          *(query_string+r->args.len) = '&';
          ngx_memcpy((query_string+r->args.len+1),accnum_arg,accnum_arg_len);
      }
      else
      {
        // acctNum exist and needs to be replaced to assure it has the correct value

        int fstpt_len = accnum_pos - (char *)r->args.data;
        char fstpt_part[fstpt_len+1];
        ngx_memcpy(fstpt_part, (char *)r->args.data, fstpt_len);

        u_char * accnum_end_pos = NULL;
        size_t i;
        for(i = fstpt_len; i <= (r->args.len); i++) {

          if(*(r->args.data+i) == '&' )
          {
            accnum_end_pos = r->args.data + i;
            break;
          }
        }
        if(accnum_end_pos == NULL)
        {
          accnum_end_pos = r->args.data + r->args.len;
        }
        
        
        int lstpt_len = r->args.len - (accnum_end_pos - r->args.data);
        char lstpt_part[lstpt_len+1];
        ngx_memcpy(lstpt_part, (char *)accnum_end_pos, lstpt_len);

        query_string = ngx_pcalloc(r->pool,fstpt_len+accnum_arg_len+lstpt_len+1);
        ngx_memcpy(query_string,fstpt_part,fstpt_len);
        ngx_memcpy((query_string+fstpt_len),accnum_arg,accnum_arg_len);
        ngx_memcpy((query_string+fstpt_len+accnum_arg_len),lstpt_part,lstpt_len);
        
      }
  }
  else
  {
    query_string = NULL;
  }

  // ngx_str_t  uri;
  ngx_str_t  args;

    // uri.data = path;
    // uri.len = ngx_strlen(path);

  //set args
  if(query_string != NULL)
  {
    args.data = query_string;
    args.len = ngx_strlen(query_string);
  }
  else
  {
    ngx_str_null(&args);
  }

  // const ngx_http_auth_jwt_loc_conf_t *conf;
  // conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

  // ngx_http_variable_value_t  *v = ngx_http_get_indexed_variable(r,conf->acct_num_var_index);
  // ngx_http_auth_jwt_vars_t * data = (ngx_http_auth_jwt_vars_t *)v->data;

  // data->authenticated = NGX_JWT_AUTHENTICATED;

  // (void) ngx_http_internal_redirect(r, &uri, &args);

  
  r->args = args;

  // ngx_http_finalize_request(r, NGX_DONE);

  return NGX_OK;


}

static void ProcessAcctNumBodyRequest(ngx_http_request_t  *r){
  
  ngx_http_auth_jwt_ctx_t  *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_auth_jwt_module);
    

  // // ngx_chain_t  *in;
  // // u_char * p;
  // // u_char * n = (u_char*)"a";
  // // off_t p;

  // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: starting body processing ");

  // // const ngx_http_auth_jwt_loc_conf_t *conf;
  // // conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);
  // // ngx_http_variable_value_t  *v = ngx_http_get_indexed_variable(r,conf->acct_num_var_index);
  // // ngx_http_auth_jwt_vars_t * data = (ngx_http_auth_jwt_vars_t *)v->data;

  // // int len = 0;
  // // int buffers_len = 0;
  


  // if(r->request_body->bufs->buf->in_file)
  // {
  //   ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: in_File = true");

  //   // int len = r->request_body->bufs->buf->file_last - r->request_body->bufs->buf->file_pos;

  //       size_t ret;
  //       size_t offset = r->request_body->temp_file->file.offset - 100;
  //       int p;
  //       int chunk_len = 4096;
  //       unsigned char frst_chunk[chunk_len];
  //       // unsigned char scnd_chunk[chunk_len];
  //       // unsigned char all_chunk[chunk_len*2];

  //       ret = ngx_read_file(&r->request_body->temp_file->file, frst_chunk, chunk_len, offset);
  //       offset = offset + ret;

  //       for (p = 0; p < 100; p++) {
  //           ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
  //                          "catch body in:%O:%c", r->request_body->temp_file->file.offset+p, frst_chunk[p]);

  //       }

      if(r->request_body->bufs->buf->in_file)
      {
        ngx_temp_file_t *tf;
        ngx_buf_t    *b;
        ngx_chain_t * cl;

        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = r->request_body->temp_file->path;
        tf->pool = r->pool;
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        ngx_create_temp_file(&tf->file, tf->path, tf->pool, tf->persistent, tf->clean, tf->access);

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: scr length = %O",r->request_body->temp_file->file.offset );

        RewriteRequestFromFile(&tf->file,&r->request_body->temp_file->file,ctx->acctNum,r->connection->log, r->pool);

        r->request_body->temp_file = tf;

        cl = ngx_chain_get_free_buf(r->pool, &r->request_body->free);
        if (cl == NULL) {
            ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }

        b = cl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->in_file = 1;
        b->file_last = r->request_body->temp_file->file.offset;
        b->file = &r->request_body->temp_file->file;

        r->request_body->bufs = cl;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: dst length = %O",r->request_body->temp_file->file.offset );
        
        r->headers_in.content_length_n = r->request_body->temp_file->file.offset;
      }
      else
      {


        ngx_chain_t  *in;
        ngx_buf_t    *frst_buf;

        

        //invalidate any acctNum property
        for (in = r->request_body->bufs; in; in = in->next) {
        
          u_char * accnum_pos = ngx_strnstr(in->buf->pos, "\"acctNum\"",in->buf->end- in->buf->start);
          while(accnum_pos != NULL)
          {
            int startPos;
            startPos = accnum_pos - in->buf->pos;

            //replace property key
            int p;
            for(p = 1; p < 8; p++ )
            {
              *(in->buf->pos+startPos+p) = 'x';
            }

            accnum_pos = ngx_strnstr(in->buf->pos, "\"acctNum\"",in->buf->end- in->buf->start);

          }
        }

        frst_buf = r->request_body->bufs->buf;
        int frst_buf_len = frst_buf->end-frst_buf->start;

        int beggining_len = 14+ngx_strlen(ctx->acctNum);
        unsigned char *beggining = ngx_pcalloc(r->pool,beggining_len);
        memcpy(beggining,"{\"acctNum\":\"",12);
        memcpy(beggining+12,ctx->acctNum,ngx_strlen(ctx->acctNum));
        *(beggining+beggining_len-2) = '\"';
        *(beggining+beggining_len-1) = ',';

        int new_buf_Len = frst_buf_len+beggining_len-1;
        unsigned char * new_buf = ngx_pcalloc(r->pool,new_buf_Len );
        ngx_memcpy(new_buf,beggining,beggining_len);
        ngx_memcpy(new_buf + beggining_len,frst_buf->start+1,frst_buf_len-1);

        frst_buf->start = new_buf;
        frst_buf->end = new_buf+new_buf_Len;
        frst_buf->pos = new_buf;
        frst_buf->last = new_buf+new_buf_Len;

        r->headers_in.content_length_n = r->headers_in.content_length_n+beggining_len-1;

      }


  // ngx_int_t     rc;
  // ngx_buf_t    *b;
  // 
  // off_t         len;

  // // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: start finishing");
  // // len = 0;

  // // for (in = r->request_body->bufs; in; in = in->next) {
  // //       len += ngx_buf_size(in->buf);
  // //   }

  // //   b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);
  // //   if (b == NULL) {
  // //       ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
  // //       return;
  // //   }
  // //   out.buf = b;
  // //   out.next = NULL;

  // //   b->last = ngx_sprintf(b->pos, "%O", len);
  // //   b->last_buf = (r == r->main) ? 1: 0;
  // //   b->last_in_chain = 1;

  // //   r->headers_out.status = NGX_HTTP_OK;
  // //   r->headers_out.content_length_n = b->last - b->pos;

  // // rc = ngx_http_send_header(r);
  // // rc = ngx_http_output_filter(r, &out);
  // // ngx_http_finalize_request(r, rc);












  // // for (in = r->request_body->bufs; in; in = in->next) {
  // //       ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: body reading -> %02x",in->buf->pos);
  // //       buffers_len++;
  // //       p = in->buf->pos;
  // //       // n = p;
  // //       for (p = in->buf->pos; p < in->buf->last; p++) {
  // //           len++;
  // //           ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
  // //                          "catch body in:%02Xd:%c", *p, *p);

  // //       }


  // //       // inbuf = in->buf->pos;
  // //   }
  // // }

  //   // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
  //   //                        "buffers in chain -> %d", buffers_len);
  //   // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
  //   //                        "body len -> %d", len);

  //   ngx_str_t randomstr = ngx_string("{\"asd\":\"bleble\"}");
  //   u_char *bodytogo = ngx_pcalloc(r->pool,randomstr.len+1);
  //   ngx_memcpy(bodytogo,randomstr.data,randomstr.len);


  //   ngx_buf_t *b;
  //   b = ngx_create_temp_buf(r->pool,randomstr.len);

  //   b->last = (u_char*)ngx_cpymem(b->pos, randomstr.data, randomstr.len);

  //   r->request_body->bufs[0].buf = b;
  //   r->headers_in.content_length_n = randomstr.len;

  // char *abav = ParseAndGetJsonString(r->connection->log, (char*)inbuf,"abav");

  // json_error_t error;
  // json_t *root =  json_loads((char *)inbuf, 0, &error);
  // json_t* newabav = json_object_get(root,"abav");
  // const char * res = json_string_value(newabav);

  // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: abav parsed -> %s",res);
  // json_t *acctNumP = json_string((char *)data->acctNum.data);
  // json_object_set(root,"acctNum",acctNumP);
  // u_char *rep = (u_char*)json_dumps(root,0);
  // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: json representation =  %s ", rep);


  // // ngx_int_t     rc;
  // ngx_buf_t    *b;
  // // ngx_chain_t   out;

  // b = ngx_create_temp_buf(r->pool, NGX_OFF_T_LEN);
  //   if (b == NULL) {
  //       ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
  //       return;
  //   }
  // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: working 1");

  //   u_char * test = (u_char *)"{\"test\":\"blabla\"}";
  //   ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: json test = %s", test);

  //   b->last_buf = (r == r->main) ? 1: 0;
  //   b->last_in_chain = 1;
  //   b->pos = test;
  //   b->last = test + ngx_strlen(test);

  //   ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: working 2 ");

  //   // rc = ngx_http_send_header(r);

  //   // out.buf = b;
  //   // out.next = NULL;

  //   r->request_body->bufs->buf = b;


  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "JWT: FINALIZING ");

  

  ctx->status = NGX_OK;


  r->write_event_handler = ngx_http_core_run_phases;
  ngx_http_core_run_phases(r);

  return;

}


void RewriteRequestFromFile(ngx_file_t *dst,ngx_file_t *src, u_char * acctNum, ngx_log_t *log, ngx_pool_t *pool ){

        size_t ret;
        size_t scr_offset = 1;
        size_t dst_offset = 0;
        int chunk_len = 4096;
        unsigned char * frst_chunk = ngx_pcalloc(pool, chunk_len);
        int frst_c_len = 0;
        unsigned char * lst_chunk = ngx_pcalloc(pool, chunk_len);
        int lst_c_len = 0;
        unsigned char *cbn_chunk = ngx_pcalloc(pool,1);
        int cbn_c_length = 0;

        int beggining_len = 14+ngx_strlen(acctNum);
        unsigned char *beggining = ngx_pcalloc(pool,beggining_len);
        memcpy(beggining,"{\"acctNum\":\"",12);
        memcpy(beggining+12,acctNum,ngx_strlen(acctNum));
        *(beggining+beggining_len-2) = '\"';
        *(beggining+beggining_len-1) = ',';

        ngx_write_file(dst,beggining,beggining_len,dst_offset);
        dst_offset = dst_offset + beggining_len;


        ret = ngx_read_file(src, frst_chunk, chunk_len, scr_offset);
        scr_offset = scr_offset + ret;
        frst_c_len = ret;
        

        for(;;)
        {
          //get new data chunk
          ret = ngx_read_file(src, lst_chunk, chunk_len, scr_offset);
          scr_offset = scr_offset + ret;
          lst_c_len = ret;

          ngx_pfree(pool,cbn_chunk);
          cbn_c_length = frst_c_len+ lst_c_len;
          cbn_chunk = ngx_pcalloc(pool, cbn_c_length);
          ngx_memcpy(cbn_chunk,frst_chunk,frst_c_len);
          ngx_memcpy(cbn_chunk + frst_c_len,lst_chunk,lst_c_len);

          
          if(ret <= 0)
          {
            break;
          }
          
            

          char * accnum_pos = ngx_strstr(cbn_chunk, "\"acctNum\"");
          while(accnum_pos != NULL)
          {
            int startPos;
            startPos = accnum_pos - (char *)cbn_chunk;
            ngx_log_error(NGX_LOG_DEBUG,log, 0, "JWT: found acctNum at offset %O",scr_offset-(frst_c_len+lst_c_len)+startPos);

            //replace property key
            int p;
            for(p = 1; p < 8; p++ )
            {
              *(cbn_chunk+startPos+p) = 'x';
            }


            ngx_memcpy(frst_chunk,cbn_chunk,frst_c_len);
            ngx_memcpy(lst_chunk,cbn_chunk + frst_c_len,lst_c_len);

            accnum_pos = ngx_strstr(cbn_chunk, "\"acctNum\"");

          }


          ngx_write_file(dst,frst_chunk,frst_c_len,dst_offset);
          dst_offset = dst_offset + frst_c_len;
          
          ngx_memcpy(frst_chunk,lst_chunk,lst_c_len);
          frst_c_len = lst_c_len;


        }

        ngx_write_file(dst,frst_chunk,frst_c_len,dst_offset);
        dst_offset = dst_offset + frst_c_len;

        ngx_memcpy(frst_chunk,lst_chunk,lst_c_len);
        frst_c_len = lst_c_len;

        ngx_write_file(dst,lst_chunk,lst_c_len,dst_offset);
        dst_offset = dst_offset + lst_c_len;

        return;


}







