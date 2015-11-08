#include <openssl/applink.c> 
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 

/*
* SSL Socket Implementation Using OpenSSL
*/


void initialize_SSL()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void destroy_SSL()
{
    ERR_free_strings();
    EVP_cleanup();
}

void shutdown_SSL()
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int sockfd, newsockfd;
SSL_CTX *sslctx;
SSL *cSSL;

initialize_SSL();

sockfd = socket(AF_INET, SOCK_STREAM, 0);
