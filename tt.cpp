#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fstream>
#include <sstream>
#include <vector>

#define PORT 8080
#define BUFFER_SIZE 1024
#define UPLOAD_DIR "./uploads"

// Function to handle CGI execution
std::string execute_cgi(const std::string& script_path, const std::string& method, const std::string& query, const std::string& body) {
    int pipefd[2];
    pipe(pipefd);

    pid_t pid = fork();
    if (pid == 0) { // Child process
        dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe
        close(pipefd[0]);

        // Set environment variables for CGI
        setenv("REQUEST_METHOD", method.c_str(), 1);
        setenv("QUERY_STRING", query.c_str(), 1);
        setenv("CONTENT_LENGTH", std::to_string(body.size()).c_str(), 1);
        setenv("REDIRECT_STATUS", "200", 1); // Add this line

        // Change to the script's directory
        std::string dir = script_path.substr(0, script_path.find_last_of('/'));
        chdir(dir.c_str());

        // Execute the CGI script
        execlp("php-cgi", "php-cgi", script_path.c_str(), NULL);
        exit(1);
    } else { // Parent process
        close(pipefd[1]);

        // Read the output from the CGI script
        char buffer[BUFFER_SIZE];
        std::string output;
        ssize_t bytes_read;
        while ((bytes_read = read(pipefd[0], buffer, BUFFER_SIZE)) > 0) {
            output.append(buffer, bytes_read);
        }
        close(pipefd[0]);

        waitpid(pid, NULL, 0); // Wait for the child process to finish
        return output;
    }
}

// Function to handle client requests
void handle_client(int client_socket) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = read(client_socket, buffer, BUFFER_SIZE);
    if (bytes_read < 0) {
        std::cerr << "Error reading from socket" << std::endl;
        return;
    }

    std::string request(buffer, bytes_read);
    std::istringstream request_stream(request);
    std::string method, path, protocol;
    request_stream >> method >> path >> protocol;

    std::string query, body;
    if (method == "GET") {
        size_t query_pos = path.find('?');
        if (query_pos != std::string::npos) {
            query = path.substr(query_pos + 1);
            path = path.substr(0, query_pos);
        }
    } else if (method == "POST") {
        size_t body_pos = request.find("\r\n\r\n");
        if (body_pos != std::string::npos) {
            body = request.substr(body_pos + 4);
        }
    }

    // Handle file uploads
    if (path == "/upload" && method == "POST") {
        std::ofstream out_file(std::string(UPLOAD_DIR) + "/uploaded_file", std::ios::binary);
        out_file.write(body.c_str(), body.size());
        out_file.close();

        std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nFile uploaded";
        write(client_socket, response.c_str(), response.size());
        close(client_socket);
        return;
    }

    // Handle CGI execution
    if (path.find(".php") != std::string::npos) {
        std::string cgi_output = execute_cgi("." + path, method, query, body);

        std::string response = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(cgi_output.size()) + "\r\n\r\n" + cgi_output;
        write(client_socket, response.c_str(), response.size());
    } else {
        std::string response = "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\n404 Not Found";
        write(client_socket, response.c_str(), response.size());
    }

    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    // Bind socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Error binding socket" << std::endl;
        return 1;
    }

    // Listen for connections
    if (listen(server_socket, 10) < 0) {
        std::cerr << "Error listening on socket" << std::endl;
        return 1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    // Accept connections
    while (true) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }

        handle_client(client_socket);
    }

    close(server_socket);
    return 0;
}