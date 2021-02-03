
/*
 * Copyright (C) 2020 - 2021 Laidouni Habib, cyberpunkVx@gmail.com
 *				 2020 - 2021 DECIMA Technologies			
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once
#ifndef DTLS_CLIENT_H
#define DTLS_CLIENT_H

#pragma comment (lib, "crypt32")
#pragma comment (lib, "ws2_32.lib")

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/*	Net/Socket dependencies*/
#ifdef WIN32			//Win32 Dependencies
#include <winsock2.h>
#include <Ws2tcpip.h>
#else					//Linux/BSD Dependencies
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#endif

/*	OpenSSL dependencies*/
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

class DTLS_CLIENT
{
public:
	DTLS_CLIENT();
	~DTLS_CLIENT();

	virtual void setup_server(const char* server_ip_address, unsigned short server_port, bool verbosity);
	virtual void setup_dtls();
	virtual void Connect();
	virtual bool Communicate();

public:
	bool verbose = false;							//Flag VERBOSE
	char server_ip_addr[INET_ADDRSTRLEN] = { 0 };	//Server Ip Address
	unsigned short server_port = 0;

private:
#if WIN32
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	SOCKET sock = INVALID_SOCKET;
#else
	int sock = NULL;
#endif

	struct sockaddr_in remote_addr, local_addr;
	struct timeval timeout;

	SSL_CTX* ctx = nullptr;
	SSL* ssl = nullptr;
	BIO* bio = nullptr;

	void __print_server_cert();
};
#endif DTLS_CLIENT_H