#include <iostream>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <map>

#define PORT 8080
#define BUFFER_SIZE 1024

// Map file extensions to their corresponding interpreters
std::map<std::string, std::string> interpreters = {
    {".php", "/usr/bin/php"},
    {".py", "/usr/bin/python3"},
    {".sh", "/bin/bash"}
};

// Function to execute a CGI script
std::string execute_cgi(const std::string& script_path, const std::string& interpreter, const std::string& method, const std::string& query_string, const std::string& post_data) {
    int pipefd[2];
    pipe(pipefd); // Create a pipe for communication with the child process

    pid_t pid = fork(); // Fork a child process
    if (pid == 0) { // Child process
        // Set environment variables for CGI
        setenv("REQUEST_METHOD", method.c_str(), 1);
        setenv("QUERY_STRING", query_string.c_str(), 1);
        setenv("CONTENT_LENGTH", std::to_string(post_data.length()).c_str(), 1);

        // Redirect stdout to the pipe
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        // Execute the CGI script using the appropriate interpreter
        if (execl(interpreter.c_str(), interpreter.c_str(), script_path.c_str(), NULL) == -1) {
            perror("execl failed");
            exit(1);
        }
    } else if (pid > 0) { // Parent process
        close(pipefd[1]); // Close the write end of the pipe

        // Read the output from the child process
        char buffer[BUFFER_SIZE];
        std::string output;
        ssize_t bytes_read;
        while ((bytes_read = read(pipefd[0], buffer, BUFFER_SIZE - 1)) > 0) {
            buffer[bytes_read] = '\0';
            output += buffer;
        }
        close(pipefd[0]);

        // Wait for the child process to finish
        waitpid(pid, NULL, 0);
        return output;
    } else {
        std::cerr << "Fork failed" << std::endl;
        return "";
    }
}

// Function to parse the HTTP request
void parse_request(const std::string& request, std::string& method, std::string& path, std::string& query_string, std::string& post_data) {
    size_t method_end = request.find(' ');
    method = request.substr(0, method_end);

    size_t path_start = method_end + 1;
    size_t path_end = request.find(' ', path_start);
    std::string full_path = request.substr(path_start, path_end - path_start);

    size_t query_start = full_path.find('?');
    if (query_start != std::string::npos) {
        path = full_path.substr(0, query_start);
        query_string = full_path.substr(query_start + 1);
    } else {
        path = full_path;
        query_string = "";
    }

    if (method == "POST") {
        size_t header_end = request.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            post_data = request.substr(header_end + 4);
        }
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Socket failed" << std::endl;
        return -1;
    }

    // Bind socket
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        return -1;
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed" << std::endl;
        return -1;
    }

    std::cout << "Server is listening on port " << PORT << std::endl;

    while (true) {
        // Accept a new connection
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        // Read the HTTP request
        ssize_t bytes_read = read(new_socket, buffer, BUFFER_SIZE - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            std::string request(buffer);

            // Parse the request
            std::string method, path, query_string, post_data;
            parse_request(request, method, path, query_string, post_data);

            std::cout << "Request received: " << request << std::endl;
            std::cout << "Method: " << method << ", Path: " << path << ", Query: " << query_string << std::endl;

            // Check if the file is a CGI script
            size_t dot_pos = path.find_last_of('.');
            if (dot_pos != std::string::npos) {
                std::string extension = path.substr(dot_pos);
                if (interpreters.find(extension) != interpreters.end()) {
                    std::string interpreter = interpreters[extension];
                    std::string cgi_output = execute_cgi("." + path, interpreter, method, query_string, post_data);

                    // Send the CGI output as the HTTP response
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + std::to_string(cgi_output.length()) + "\r\n\r\n" + cgi_output;
                    send(new_socket, response.c_str(), response.length(), 0);
                } else {
                    // Unsupported file extension
                    std::string response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n404 Not Found";
                    send(new_socket, response.c_str(), response.length(), 0);
                }
            } else {
                // Handle non-CGI files (e.g., serve static files)
                std::string response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n404 Not Found";
                send(new_socket, response.c_str(), response.length(), 0);
            }
        }

        // Close the socket
        close(new_socket);
    }

    // Close the server socket
    close(server_fd);
    return 0;
}