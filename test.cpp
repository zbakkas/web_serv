#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[4096];

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        std::cerr << "Socket creation failed." << std::endl;
        return 1;
    }

    // Define server address
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed." << std::endl;
        close(server_fd);
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed." << std::endl;
        close(server_fd);
        return 1;
    }

    std::cout << "Server is running on port " << PORT << "..." << std::endl;

    while (true) {
        // Accept a new connection
        client_fd = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (client_fd < 0) {
            std::cerr << "Connection failed." << std::endl;
            continue;
        }

        // Read HTTP request
        std::memset(buffer, 0, sizeof(buffer));
        read(client_fd, buffer, sizeof(buffer));
        std::cout << "Received request:\n" << buffer << std::endl;

        // Extract data from GET or POST
        std::string request(buffer);
        size_t pos;
        std::string data;

        if (request.find("GET") == 0 && (pos = request.find("?")) != std::string::npos) {
            // Extract data from query string
            size_t end_pos = request.find(" ", pos);
            data = request.substr(pos + 1, end_pos - pos - 1);
            std::cout << "Extracted GET data: " << data << std::endl;
        } else if (request.find("POST") == 0) {
            // Extract data from request body
            pos = request.find("\r\n\r\n");
            if (pos != std::string::npos) {
                data = request.substr(pos + 4);
                std::cout << "Extracted POST data: " << data << std::endl;
            }
        }

        // Respond to the client
        const char* response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<!DOCTYPE html>"
            "<html><head><title>Response</title></head>"
            "<body><h1>Data Received!</h1></body></html>";

        send(client_fd, response, std::strlen(response), 0);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
