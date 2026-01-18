#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/json.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
namespace json = boost::json;
using tcp = boost::asio::ip::tcp;

class WebSocketClient {
public:
    WebSocketClient(const std::string& host, const std::string& port);
    void connect(std::string target);
    void send(const std::string& message);
    std::string receive();
    void close();
    
private:
std::string host_;
std::string port_;
tcp::resolver resolver_{ioc_};
net::io_context ioc_;
ssl::context ctx_{ssl::context::sslv23_client};
websocket::stream<beast::ssl_stream<tcp::socket>> ws_{ioc_, ctx_};
};