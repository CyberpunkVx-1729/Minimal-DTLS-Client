#include "SSL_manager.h"

DTLS_CLIENT::DTLS_CLIENT()
{
#ifdef WIN32
	int err = WSAStartup(this->wVersionRequested, &this->wsaData);
	if (err != 0)
	{
		if (this->verbose)
			printf("WSAStartup failed with error: %d, WSAE#%d\n", err, WSAGetLastError());

		perror("WSAStartup()");
		exit(EXIT_FAILURE);
	}
#endif

	memset((void*)&this->remote_addr, 0, sizeof(struct sockaddr_in));
	memset((void*)&this->local_addr, 0, sizeof(struct sockaddr_in));

	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
}

DTLS_CLIENT::~DTLS_CLIENT()
{
	SSL_shutdown(ssl);

#ifdef WIN32
	closesocket(this->sock);
#else
	close(this->sock);
#endif

	WSACleanup();
}


void DTLS_CLIENT::setup_server(const char* server_ip_address, unsigned short server_port, bool verbosity)
{
	//Setup Server Address & port
	memset((char*)this->server_ip_addr, 0, sizeof(char));
	strcpy(this->server_ip_addr, server_ip_address);
	this->server_port = server_port;

	//Verbosity
	this->verbose = verbosity;

	//Create Socket
	this->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (this->sock < 0)
	{
		if (this->verbose)
		{
			printf("NET: Unable to create socket,  WSAE#%d\n",  WSAGetLastError());
		}

		perror("socket()");
		exit(EXIT_FAILURE + 1);
	}

	//Setup local address
	this->local_addr.sin_family = AF_INET;
	this->local_addr.sin_port = htons(0);
	this->local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	//Setup Server address
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(this->server_port);
	remote_addr.sin_addr.s_addr = inet_addr(this->server_ip_addr);

	//Bind Socket to local address
	if (bind(this->sock, (const struct sockaddr*)&this->local_addr, sizeof(struct sockaddr_in)))
	{
		if (this->verbose)
		{
			printf("NET: Unable to bind socket,  WSAE#%d\n", WSAGetLastError());
		}

		perror("bind()");
		exit(EXIT_FAILURE + 2);
	}
}

void DTLS_CLIENT::setup_dtls()
{
	OPENSSL_init();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	//Create new Context
	ctx = SSL_CTX_new(DTLSv1_client_method());
	if (ctx == nullptr)
	{
		if (this->verbose)
		{
			printf("SSL: Unable to create Context\n");
		}
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 3);
	}

	//Load certificate File
	if (!SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM))
	{
		printf("SSL: No Certificate found!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 4);
	}

	//Load private Key File
	if (!SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM))
	{
		printf("SSL: No Private Key found!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 5);
	}

	//Check Private Key
	if (!SSL_CTX_check_private_key(ctx))
	{
		printf("SSL: Invalid Private Key found!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 6);
	}

	//Set Context Settings
	SSL_CTX_set_verify_depth(ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);

	//Create a SSL Object
	ssl = SSL_new(ctx);
	if(ssl == nullptr)
	{
		printf("SSL:Unable to create an SSL Object!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 7);
	}

	//Create a BIO
	bio = BIO_new_dgram(sock, BIO_CLOSE);
	if (bio == nullptr)
	{
		printf("SSL:Unable to create a BIO Object!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 8);
	}

	//Set BIO settings
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);
	SSL_set_bio(ssl, bio, bio);

	//Set Timeout
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	//SOCKET Connect
	if (connect(sock, (struct sockaddr*)&remote_addr, sizeof(struct sockaddr_in)))
	{
		printf("NET: Unable to connect to SERVER,  WSAE#%d\n", WSAGetLastError());
		perror("connect():");
	}
}

void DTLS_CLIENT::Connect()
{
	//SSL Connect
	int retval = SSL_connect(ssl);
	if (retval <= 0) {
		switch (SSL_get_error(ssl, retval))
		{
		case SSL_ERROR_ZERO_RETURN:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
			break;
		case SSL_ERROR_WANT_READ:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_WANT_READ\n");
			break;
		case SSL_ERROR_WANT_WRITE:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
			break;
		case SSL_ERROR_WANT_CONNECT:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
			break;
		case SSL_ERROR_WANT_ACCEPT:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
			break;
		case SSL_ERROR_SYSCALL:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_SYSCALL\n");
			break;
		case SSL_ERROR_SSL:
			fprintf(stderr, "SSL: SSL_connect failed with SSL_ERROR_SSL\n");
			break;
		default:
			fprintf(stderr, "SSL: SSL_connect failed with unknown error\n");
			break;
		}
		exit(EXIT_FAILURE + 9);
	}


	if (verbose)
	{
		printf("NET: Connected successfully to [%s::%d]\n", this->server_ip_addr, this->server_port);
		this->__print_server_cert();
	}
}

bool DTLS_CLIENT::Communicate()
{
	//Communicate
	{
		//Send
		char buf[200] = {0};
		int length = sizeof("Hello from Client");
		int len = SSL_write(ssl, "Hello from Client", length);

		//Receive
		len = SSL_read(ssl, buf, sizeof(buf));
		printf("read %d bytes [%s]\n", (int)len, buf);
	}

	return false;
}

void DTLS_CLIENT::__print_server_cert()
{
	if (!this->verbose)
		return;

	printf("------------------------------------------------------------\n");
	X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
		1, XN_FLAG_MULTILINE);
	printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	printf("\n------------------------------------------------------------\n\n");
}
