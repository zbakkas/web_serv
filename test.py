#!/usr/bin/python3
import os, cgi

print("Content-Type: text/html\n")
print("<h1>Python CGI Script</h1>")
print("<p>Request Method:", os.getenv("REQUEST_METHOD"), "</p>")

if os.getenv("REQUEST_METHOD") == "GET":
    form = cgi.FieldStorage()
    print("<p>Name:", form.getvalue("name", "Unknown"), "</p>")
