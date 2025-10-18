#include "http_client.h"
#include <curl/curl.h>
#include <string>
#include <iostream>

bool HttpClient::curl_initialized = false;

/**
 * HttpClient - Constructor that initializes libcurl if not already done.
 */
HttpClient::HttpClient()
{
    if (!curl_initialized)
    {
        curl_global_init(CURL_GLOBAL_ALL);
        curl_initialized = true;
    }
}

/**
 * WriteCallback - Callback function for libcurl to write response data.
 * @contents: Pointer to the data received from the server
 * @size: Size of each data element
 * @nmemb: Number of elements
 * @userp: Pointer to user-defined data (response body)
 * Returns: Number of bytes processed
 */
size_t HttpClient::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    std::string* response_body = static_cast<std::string*>(userp);
    response_body->append(static_cast<char*>(contents), size * nmemb);
    return (size * nmemb);
}

/**
 * HttpClient::GET - Performs an HTTP GET request.
 * @url: The URL to send the request to.
 * Returns: A Response object containing the HTTP response code and body.
 */
HttpClient::Response HttpClient::GET(const std::string& url)
{
    CURL* curl;
    CURLcode res;
    Response response;

    curl = curl_easy_init();
    if (curl)
    {
        std::string response_body;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "KX-Trainer-Free/1.0");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        else
        {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.http_code);
            response.body = response_body;
        }

        curl_easy_cleanup(curl);
    }
    return (response);
}
