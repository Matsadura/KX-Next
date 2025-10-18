#pragma once

#include <string>

/**
 * HttpClient - Simple HTTP client using libcurl for GET requests.
 */
class HttpClient
{
public:
    HttpClient();

    struct Response {
        std::string body;
        long http_code;
    };

    Response GET(const std::string& url);

private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);

    static bool curl_initialized;
};
