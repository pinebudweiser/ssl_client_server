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

#define RSA_SERVER_CERT     "server.crt"
#define RSA_SERVER_KEY      "server.key"

#define RSA_SERVER_CA_CERT	"server_ca.crt"
#define RSA_SERVER_CA_PATH  "sys$common:[syshlp.examples.ssl]"
#define OPENSSL_NO_SSL3_METHOD TRUE

#define ON   1
#define OFF  0

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

int main(void)
{
	int err;
	SOCKET socket_descriptor;
	WSADATA wsa_data;
	int sd;
	struct sockaddr_in sa;

	/* SSL 관련 정보를 관리할 구조체를 선언한다. */
	SSL_CTX   *ctx;
	SSL     *ssl;
	X509    *server_cert;
	char    *str;
	char    buf[4096];
	SSL_METHOD    *meth;
	short int       s_port = 443;

	/* 암호화 통신을 위한 초기화 작업을 수행한다. */
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	/* 사용하게 되는 인증서 파일을 설정한다. – opt*/
	if (SSL_CTX_use_certificate_file(ctx,"client.crt", SSL_FILETYPE_PEM) <= 0) {    // 인증서를 파일로 부터 로딩할때 사용함.
		ERR_print_errors_fp(stderr);
		//exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		//exit(4);
	}

	/* 개인 키가 사용 가능한 것인지 확인한다. – opt */
	
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		//exit(5);
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
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");        // Server IP Address
	sa.sin_port = htons(s_port);                // Server Port Number

	if (connect(socket_descriptor, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
		printf("[Err] Server Connection failed..\n");
	}


	/* Now we have TCP connection. Start SSL negotiation. */
	ssl = SSL_new(ctx);  // 세션을 위한 자원을 할당받는다.

	SSL_set_fd(ssl, socket_descriptor);
	err = SSL_connect(ssl); // 기존의 connect() 함수 대신 사용하여 서버로 접속한다.

	/* Following two steps are optional and not required for data exchange to be successful. */

	/* Get the Cipher – opt */
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));

	/* Get server’s certificate (note: beware of dynamic allocation) – opt */
	/* 서버의 인증서를 받는다. */
	server_cert = SSL_get_peer_certificate(ssl);
	printf("Server certificate : %s\n", server_cert);

	/* 인증서의 이름을 출력한다. */
	str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
	printf("t subject : %s\n", str);
	OPENSSL_free(str);

	/* 인증서의 issuer를 출력한다. */
	str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
	printf("t issuer : %s\n", str);
	OPENSSL_free(str);

	/* We could do all sorts of certificate verification stuff here before deallocating the certificate */
	X509_free(server_cert);

	/* 서버와 데이터를 송수신 한다. */
	err = SSL_write(ssl, "GET  \  HTTP\1.1\r\nHost: test.com\r\n\n", strlen("GET  \  HTTP\1.1\r\nHost: test.com\r\n\n")+1);

	err = SSL_read(ssl, buf, sizeof(buf) - 1);
	buf[err] = '\0';
	printf("Got %d chars : %s\n", err, buf);
	//SSL_shutdown(ssl);    // SSL로 연결된 접속을 해지한다.
	//close(socket_descriptor);
	//SSL_free(ssl);
	//SSL_CTX_free(ctx);

	return 0;
}