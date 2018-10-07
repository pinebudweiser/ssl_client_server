#include <stdio.h>
#include <WinSock2.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <stdlib.h>

#define RSA_SERVER_CERT     "server.crt"
#define RSA_SERVER_KEY      "server.key"
#define RSA_SERVER_CA_CERT	"server_ca.crt"
#define RSA_SERVER_CA_PATH  "sys$common:[syshlp.examples.ssl]"

#define ON   1
#define OFF  0

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

void main()
{
	SOCKET  socket_descriptor;
	SOCKET  client_descriptor;
	WSADATA wsa_data;
	struct sockaddr_in tcp_server;
	struct sockaddr_in client_request;
	size_t client_len;
	char    *str;
	char     buf[4096];
	int     err;
	int     verify_client = ON; /* To verify a client certificate, set ON */

	SSL_CTX* ctx;
	SSL* ssl;
	SSL_METHOD* meth;
	X509* client_cert = NULL;

	short int       s_port = 443;
	/*----------------------------------------------------------------*/
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

	/* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
	meth = SSLv23_method();

	/* Create a SSL_CTX structure */
	ctx = SSL_CTX_new(meth);

	if (!ctx) {

		ERR_print_errors_fp(stderr);

		exit(1);

	}

	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {

		ERR_print_errors_fp(stderr);

		exit(1);

	}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx)) {

		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(1);
	}

	if (verify_client == ON)
	{
		/* Load the RSA CA certificate into the SSL_CTX structure */
		if (!SSL_CTX_load_verify_locations(ctx, RSA_SERVER_CA_CERT, NULL)) {

			ERR_print_errors_fp(stderr);
			exit(1);
		}

		/* Set to require peer (client) certificate verification */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

		/* Set the verification depth to 1 */
		SSL_CTX_set_verify_depth(ctx, 1);

	}
	/* ----------------------------------------------- */
	/* Set up a TCP socket */

	if (WSAStartup(MAKEWORD(2, 2), &wsa_data)) {
		printf("WSAStartup Error..");
	}

	socket_descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (socket_descriptor == INVALID_SOCKET) {
		printf(" [Err] Socket create failed. reason : %d\n", WSAGetLastError());
		return 1;
	}
	/* Initialize */
	tcp_server.sin_family = AF_INET;
	tcp_server.sin_addr.s_addr = INADDR_ANY;
	tcp_server.sin_port = htons(s_port);

	if (bind(socket_descriptor, (struct sockaddr*)&tcp_server, sizeof(tcp_server)) != 0){
		printf(" [Err] Bind Error. reason : %d\n", WSAGetLastError());
		return 1;
	}


	/* Wait for an incoming TCP connection. */
	if (listen(socket_descriptor, 10) != 0) {
		printf("[Err] listen error. reason : %d\n", WSAGetLastError());
		return 1;
	}

	client_len = sizeof(client_request);

	/* Socket for a TCP/IP connection is created */
	client_descriptor = accept(socket_descriptor, (struct sockaddr*)&client_request, &client_len);

	//close(listen_sock);

	if (client_descriptor != -1) {
		printf("Connection from %lx, port %x\n", client_request.sin_addr.s_addr,
			client_request.sin_port);
	}

	/* ----------------------------------------------- */
	/* TCP connection is ready. */
	/* A SSL structure is created */
	ssl = SSL_new(ctx);

	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	SSL_set_fd(ssl, client_descriptor);

	/* Perform SSL Handshake on the SSL server */
	err = SSL_accept(ssl);

	/* Informational output (optional) */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	if (verify_client == ON)
	{
		/* Get the client's certificate (optional) */
		client_cert = SSL_get_peer_certificate(ssl);
		if (client_cert != NULL)
		{
			printf("Client certificate:\n");
			str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
			printf("\t subject: %s\n", str);
			OPENSSL_free(str);
			str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
			printf("\t issuer: %s\n", str);
			OPENSSL_free(str);
			X509_free(client_cert);
		}

		else
			printf("The SSL client does not have certificate.\n");
	}

	/*------- DATA EXCHANGE - Receive message and send reply. -------*/
	/* Receive data from the SSL client */
	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	buf[err] = '\0';

	printf("Received %d chars: %s\n", err, buf);

	/* Send data to the SSL client */
	err = SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\nHello",
		strlen("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\nHello")+1);

	/*--------------- SSL closure ---------------*/
	/* Shutdown this side (server) of the connection. */

	//err = SSL_shutdown(ssl);


	/* Terminate communication on a socket */
	//err = close(client_descriptor);


	/* Free the SSL structure */
	//SSL_free(ssl);

	/* Free the SSL_CTX structure */
	//SSL_CTX_free(ctx);
}