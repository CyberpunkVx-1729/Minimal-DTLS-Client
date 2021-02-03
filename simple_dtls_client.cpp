#include <iostream>
#include "SSL_manager.h"

int main()
{
    DTLS_CLIENT dtls_client;
    dtls_client.setup_server("144.91.109.147", 20000, true);
    dtls_client.setup_dtls();
    dtls_client.Connect();
    dtls_client.Communicate();


    std::cout << "Finished ! " << std::endl;
}
