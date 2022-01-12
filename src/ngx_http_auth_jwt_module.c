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



typedef struct {
  ngx_int_t jwt_on_off_flag;         // Function of "auth_jwt": on -> 1 | off -> 0
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


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r);
static ngx_int_t auth_jwt_get_token(u_char **token, ngx_http_request_t *r, const ngx_http_auth_jwt_loc_conf_t *conf);
static u_char * auth_jwt_safe_string(ngx_pool_t *pool, u_char *src, size_t len);
static char * combineStrings(ngx_pool_t *pool, char * textA, char *textB);
static ngx_int_t validate_jwt(ngx_http_request_t  *r, char * plain_jwt);
static void PerformHttpRequest(ngx_pool_t *pool, ngx_log_t *log, char **response, char * url);
static int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
static char * ParseAndGetJsonString(ngx_log_t *log, char* content, char *prop);
static json_t *ParseAndGetJsonObject(ngx_log_t *log, char* content, char *prop);
static int GetCorrectKey(ngx_http_request_t *r, jwk_key *key, json_t *keysArray);
static char * base64uri_decode(char *str);
static int Base64decode(char *bufplain, const char *bufcoded);
static int Base64decode_len(const char *bufcoded);


// Configuration functions
static ngx_int_t ngx_http_auth_jwt_init(ngx_conf_t *cf);
static void * ngx_http_auth_jwt_create_conf(ngx_conf_t *cf);
static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child);

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

  // auth_jwt $ off | on;
  { ngx_string("auth_jwt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_auth_jwt_loc_conf_t, jwt_on_off_flag),
    NULL },

  ngx_null_command
};

static ngx_http_module_t ngx_http_auth_jwt_module_ctx = {
  NULL,                        /* preconfiguration */
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
  conf->jwt_on_off_flag = NGX_CONF_UNSET;

  return conf;
}


static char * ngx_http_auth_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_jwt_loc_conf_t *prev = parent;
  ngx_http_auth_jwt_loc_conf_t *conf = child;

  ngx_conf_merge_value(conf->jwt_on_off_flag, prev->jwt_on_off_flag, 0);

  return NGX_CONF_OK;
}


static ngx_int_t ngx_http_auth_jwt_handler(ngx_http_request_t *r)
{
  const ngx_http_auth_jwt_loc_conf_t *conf;
  u_char *jwt_data;

  conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_jwt_module);

  // Pass through if "auth_jwt" is "off"
  if (conf->jwt_on_off_flag == 0)
  {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "test flag is off");
        return NGX_DECLINED;

  }
  
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "test flag is on");


  if (auth_jwt_get_token(&jwt_data, r, conf) != NGX_OK)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: failed to find a jwt");
    return NGX_HTTP_UNAUTHORIZED;
  }

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "test got token");

  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, combineStrings(r->pool,"test ",(char *)jwt_data ));

  ngx_int_t validation_result = validate_jwt(r, (char *)jwt_data);

  if(validation_result != NGX_OK)
  {
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "JWT: invalid token");
    return NGX_HTTP_UNAUTHORIZED;
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

static ngx_int_t validate_jwt(ngx_http_request_t  *r, char * plain_jwt) {

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
    PerformHttpRequest(r->pool,r->connection->log, &opidcf_resp,(char*)opidcf_url);
    
    char *jwks_uri = ParseAndGetJsonString(r->connection->log, opidcf_resp,"jwks_uri");
    if(jwks_uri == NULL)
    {
      return NGX_DECLINED;
    }

    char * jks_resp;
    PerformHttpRequest(r->pool,r->connection->log,&jks_resp,jwks_uri);

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

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, combineStrings(r->pool,"test pubkey : ",(char *)strPubKey));

    jwt_alg_t alg = jwt_get_alg(new_jwt);
    const char* alg_val =  jwt_alg_str(alg);
    if(alg_val == NULL || alg_val == JWT_ALG_NONE)
    {
      ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "invalid algorithm : ");
      return NGX_HTTP_UNAUTHORIZED;
    }
    
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, combineStrings(r->pool,"test pubkey : ",(char *)alg_val));

    time_t exp = (time_t)jwt_get_grant_int(jwt, "exp");
    if (exp != -1 && exp < time(NULL))
    {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "test JWT: the jwt has expired [exp=%ld]", (long)exp);
      return NGX_HTTP_UNAUTHORIZED;
    }

    return NGX_OK;
}

static void PerformHttpRequest(ngx_pool_t *pool, ngx_log_t *log, char **response, char * url)
{
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = ngx_alloc(1, log);
    chunk.size = 0;

    CURL *curl = curl_easy_init();
    if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    struct curl_slist *headers = NULL;
    curl_slist_append(headers, "Accept: application/json");
    curl_slist_append(headers, "charset: utf-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK){
          ngx_log_error(NGX_LOG_ERR, log, 0, combineStrings(pool,"test curl_easy_perform() failed: ",(char *)curl_easy_strerror(res)));
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

            /* target buffer should be large enough */
            char str[nlen*2];

            unsigned char * pin = buf;
            const char * hex = "0123456789ABCDEF";
            char * pout = str;
            long unsigned int i = 0;
            for(; i < sizeof(buf)-1; ++i){
                *pout++ = hex[(*pin>>4)&0xF];
                *pout++ = hex[(*pin++)&0xF];
            }
            *pout++ = hex[(*pin>>4)&0xF];
            *pout++ = hex[(*pin)&0xF];
            *pout = 0;

            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, combineStrings(r->pool,"test key N : ",str));

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




