#include <stdio.h>
#include <WinSock2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <stdlib.h>

#pragma warning(disable:4996) 

#define ON   1
#define OFF  0

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

int main(){
	int err;
	SOCKET socket_descriptor;
	WSADATA wsa_data;
	int sd;
	struct sockaddr_in sa;

	SSL_CTX* ctx;
	SSL* ssl;
	X509* server_cert;
	char* str;
	char buf[4096];
	SSL_METHOD* meth;
	short int s_port = 443;

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	// Check certificate file
	if (SSL_CTX_use_certificate_file(ctx,"client.crt", SSL_FILETYPE_PEM) <= 0) {    
		ERR_print_errors_fp(stderr);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
	}
	

	//CHK_SSL(err);
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data)) {
		printf("WSAStartup Error..");
	}

	/* Create a socket and connect to server using normal socket calls. */
	socket_descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_descriptor == INVALID_SOCKET)
	{
		printf(" [Err] Socket create failed. reason : %d\n", WSAGetLastError());
		return 1;
	}
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");      
	sa.sin_port = htons(s_port);              

	if (connect(socket_descriptor, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
		printf("[Err] Server Connection failed..\n");
	}

	/* Now we have TCP connection. Start SSL negotiation. */
	ssl = SSL_new(ctx);  
	SSL_set_fd(ssl, socket_descriptor);
	err = SSL_connect(ssl); 

	/* Following two steps are optional and not required for data exchange to be successful. */

	/* Get the Cipher – opt */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* Get server’s certificate (note: beware of dynamic allocation) – opt */
	server_cert = SSL_get_peer_certificate(ssl);
	printf("Server certificate : %s\n", server_cert);

	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	printf("t subject : %s\n", str);
	OPENSSL_free(str);

	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	printf("t issuer : %s\n", str);
	OPENSSL_free(str);

	/* We could do all sorts of certificate verification stuff here before deallocating the certificate */
	X509_free(server_cert);

	err = SSL_write(ssl, "GET  \  HTTP\1.1\r\nHost: test.com\r\n\n", strlen("GET  \  HTTP\1.1\r\nHost: test.com\r\n\n"));

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	buf[err] = '\0';
	printf("Got %d chars : %s\n", err, buf);
	SSL_shutdown(ssl);  
	close(socket_descriptor);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}