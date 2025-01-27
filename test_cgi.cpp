#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fstream>

#define PORT 8080





void handle_cgi(const std::string& path, const std::string& query_string, const std::string& request_body, int client_fd) {
    int cgi_input[2], cgi_output[2];

    // Create pipes for communication with the CGI script
    if (pipe(cgi_input) < 0 || pipe(cgi_output) < 0) {
        std::cerr << "Pipe creation failed." << std::endl;
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Fork failed." << std::endl;
        return;
    }

    if (pid == 0) {
        // Child process: Run the CGI script
        dup2(cgi_output[1], STDOUT_FILENO); // Redirect CGI output to pipe
        dup2(cgi_input[0], STDIN_FILENO);  // Redirect CGI input from pipe
        close(cgi_input[1]);
        close(cgi_output[0]);

        // Set CGI environment variables
        setenv("REQUEST_METHOD", "GET", 1);
        setenv("QUERY_STRING", query_string.c_str(), 1); // Ensure QUERY_STRING is set
        setenv("CONTENT_LENGTH", std::to_string(request_body.length()).c_str(), 1);

        // Debugging: Print all environment variables
        std::cout << "Environment Variables:" << std::endl;
        char** envp = environ;
        while (*envp) {
            std::cout << *envp << std::endl;
            envp++;
        }

        std::cout << "Executing CGI script: " << path << std::endl;  // Debugging line
        
        // Execute the CGI script (PHP)
        // execl("/usr/bin/php-cgi", "/usr/bin/php-cgi", path.c_str(), NULL);
        execl("/usr/bin/php", "/usr/bin/php", path.c_str(), NULL);
        exit(1); // Only reached if execl fails
    } else {
        // Parent process: Send data to CGI and read output
        close(cgi_input[0]);
        close(cgi_output[1]);

        if (!request_body.empty()) {
            write(cgi_input[1], request_body.c_str(), request_body.length());
        }
        close(cgi_input[1]);

        char buffer[1024];
        int bytes_read;
        std::string response;

        while ((bytes_read = read(cgi_output[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            response += buffer;
        }
        close(cgi_output[0]);

        // Send CGI output as HTTP response
        std::string http_response = "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: text/html\r\n"
                                    "Connection: close\r\n\r\n" +
                                    response;

        send(client_fd, http_response.c_str(), http_response.length(), 0);
        waitpid(pid, NULL, 0); // Wait for CGI process to terminate
    }
}




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
        std::string request(buffer);

        // Parse HTTP request
        std::string method = request.substr(0, request.find(' '));
        std::string uri = request.substr(request.find(' ') + 1, request.find(' ', request.find(' ') + 1) - request.find(' ') - 1);

        std::string path = "." + uri; // Serve files relative to the current directory
        std::string query_string;

        // Split URI and query string if present
        size_t pos = uri.find('?');
        if (pos != std::string::npos) {
            path = "." + uri.substr(0, pos);
            query_string = uri.substr(pos + 1);
        }

        std::cout << "Request path: " << path << std::endl;  // Debugging line

        // Check if the file has a .php extension
        if (path.find(".php") != std::string::npos) {
            std::cout << "Found .php file, executing CGI..." << std::endl;  // Debugging line
            std::string request_body;

            if (method == "POST") {
                // Extract the request body for POST method
                size_t body_pos = request.find("\r\n\r\n");
                if (body_pos != std::string::npos) {
                    request_body = request.substr(body_pos + 4);
                }
            }

            handle_cgi(path, query_string, request_body, client_fd);
        } else {
            // Handle non-CGI requests (e.g., static files)
            std::ifstream file(path.c_str());
            if (file) {
                std::string response = "HTTP/1.1 200 OK\r\n"
                                       "Content-Type: text/html\r\n"
                                       "Connection: close\r\n\r\n";

                std::string line;
                while (std::getline(file, line)) {
                    response += line + "\n";
                }
                send(client_fd, response.c_str(), response.length(), 0);
            } else {
                std::string not_found = "HTTP/1.1 404 Not Found\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Connection: close\r\n\r\n"
                                        "<h1>404 Not Found</h1>";
                send(client_fd, not_found.c_str(), not_found.length(), 0);
            }
        }

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
