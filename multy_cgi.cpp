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
#include <fstream>
#include <sstream>
#include <sys/stat.h> // For mkdir
#include <limits.h>
#define PORT 8080
#define BUFFER_SIZE 1024
#define UPLOAD_DIR "./uploads"

// Map file extensions to their corresponding interpreters
std::map<std::string, std::string> interpreters = {
    {".php", "/usr/bin/php-cgi"},
    {".py", "/usr/bin/python3"},
    {".sh", "/bin/bash"}
};

// Function to read a file and return its content
std::string read_file(const std::string& file_path) {
    std::ifstream file(file_path.c_str(), std::ios::in | std::ios::binary);
    if (!file) {
        return "";
    }

    std::ostringstream content;
    content << file.rdbuf();
    return content.str();
}



std::string execute_cgi(const std::string& script_path, const std::string& interpreter, const std::string& method, const std::string& query_string, const std::string& post_data) {
    std::cout << "Executing CGI script: " << script_path << std::endl;

    // Get the absolute path of the script
    char abs_path[PATH_MAX];
    if (realpath(script_path.c_str(), abs_path) == NULL) {
        std::cerr << "Error resolving absolute path for: " << script_path << std::endl;
        return "";
    }
    std::cout << "Absolute path: " << abs_path << std::endl;

    int pipefd[2];
    pipe(pipefd); // Create a pipe for communication with the child process

    pid_t pid = fork(); // Fork a child process
    if (pid == 0) { // Child process
        // Set environment variables for CGI
        setenv("REQUEST_METHOD", method.c_str(), 1);
        setenv("QUERY_STRING", query_string.c_str(), 1);
        setenv("CONTENT_LENGTH", std::to_string(post_data.length()).c_str(), 1);
        setenv("CONTENT_TYPE", "application/x-www-form-urlencoded", 1);
        setenv("REDIRECT_STATUS", "200", 1); // Required for PHP-CGI
        setenv("SCRIPT_FILENAME", abs_path, 1); // Add this line

        // Redirect stdin to read POST data
        if (method == "POST") {
            int input_pipe[2];
            pipe(input_pipe);
            write(input_pipe[1], post_data.c_str(), post_data.length());
            close(input_pipe[1]);
            dup2(input_pipe[0], STDIN_FILENO);
            close(input_pipe[0]);
        }

        // Redirect stdout to the pipe
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        // Change to the script's directory
        std::string dir = script_path.substr(0, script_path.find_last_of('/'));
        if (!dir.empty()) {
            std::cout << "Changing working directory to: " << dir << std::endl;
            chdir(dir.c_str());
        }

        // Execute the CGI script using the appropriate interpreter
        std::cout << "Executing: " << interpreter << " " << abs_path << std::endl;
        if (execl(interpreter.c_str(), interpreter.c_str(), abs_path, NULL) == -1) {
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

        // Parse the CGI output to extract the response body
        size_t header_end = output.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            // Extract the body (everything after the headers)
            std::string body = output.substr(header_end + 4);
            return body;
        } else {
            // If no headers are found, return the entire output
            return output;
        }
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

    // Create uploads directory if it doesn't exist
    mkdir(UPLOAD_DIR, 0777);

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

            std::cout << "Request received: " << method << " " << path << std::endl;

            // Handle file uploads
            if (path == "/upload" && method == "POST") {
                std::ofstream out_file(std::string(UPLOAD_DIR) + "/uploaded_file", std::ios::binary);
                out_file.write(post_data.c_str(), post_data.size());
                out_file.close();

                std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nFile uploaded";
                send(new_socket, response.c_str(), response.length(), 0);
                close(new_socket);
                continue;
            }

            // Check if the file is a CGI script
            size_t dot_pos = path.find_last_of('.');
            if (dot_pos != std::string::npos) 
            {
                std::string extension = path.substr(dot_pos);
                // std::cout<< "\n\n"<< "extension"<<extension<<"\n\n";
                if (interpreters.find(extension) != interpreters.end()) 
                {
                    // Handle CGI scripts
                    std::string interpreter = interpreters[extension];
                    std::string script_path = "." + path;

                    // std::cout<< "\n\n"<< "interpreter"<<interpreter<<"\n\n";

                    // std::cout<< "\n\n"<< "script_path"<<script_path<<"\n\n";

                    std::string cgi_output = execute_cgi(script_path, interpreter, method, query_string, post_data) ;

                        // std::cout<< "\n\n"<< "cgi_output"<<cgi_output<<"\n\n";

                    // Send the CGI output as the HTTP response
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + std::to_string(cgi_output.length()) + "\r\n\r\n" + cgi_output;
                    
                    // std::cout<< "\n\n"<< "response "<<response<<"\n\n";

                    send(new_socket, response.c_str(), response.length(), 0);
                } else {
                    // Handle static files
                    std::string file_path = "." + path;
                    std::string file_content = read_file(file_path);

                    if (!file_content.empty()) {
                        // Determine the MIME type based on the file extension
                        std::string content_type = "text/plain";
                        if (extension == ".html") {
                            content_type = "text/html";
                        } else if (extension == ".css") {
                            content_type = "text/css";
                        } else if (extension == ".js") {
                            content_type = "application/javascript";
                        }

                        // Send the file content as the HTTP response
                        std::string response = "HTTP/1.1 200 OK\r\nContent-Type: " + content_type + "\r\nContent-Length: " + std::to_string(file_content.length()) + "\r\n\r\n" + file_content;
                        send(new_socket, response.c_str(), response.length(), 0);
                    } else {
                        // File not found
                        std::string response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n404 Not Found";
                        send(new_socket, response.c_str(), response.length(), 0);
                    }
                }
            } else {
                // Handle non-CGI files (e.g., serve static files)
                std::string file_path = "." + path;
                std::string file_content = read_file(file_path);

                if (!file_content.empty()) {
                    // Send the file content as the HTTP response
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(file_content.length()) + "\r\n\r\n" + file_content;
                    send(new_socket, response.c_str(), response.length(), 0);
                } else {
                    // File not found
                    std::string response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\n404 Not Found";
                    send(new_socket, response.c_str(), response.length(), 0);
                }
            }
        }

        // Close the socket
        close(new_socket);
    }

    // Close the server socket
    close(server_fd);
    return 0;
}