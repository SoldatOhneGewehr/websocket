#include "Websocket.hpp"

WebSocketClient::WebSocketClient(const std::string& host, const std::string& port)
    : host_(host)
    , port_(port)
    , resolver_(ioc_)
    , ws_(ioc_, ctx_) 
    { }

void WebSocketClient::connect(std::string target) {
    auto const results = resolver_.resolve(host_, port_);
    net::connect(beast::get_lowest_layer(ws_), results);

    if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(), host_.c_str()))
        throw beast::system_error(beast::error_code(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()));

    ws_.next_layer().handshake(ssl::stream_base::client);
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::request_type& req) {
            req.set(http::field::user_agent, "BoostBeastClient");
        }));

    ws_.handshake(host_, target);
};

std::string WebSocketClient::receive() {
    beast::flat_buffer buffer;
    ws_.read(buffer);
    return beast::buffers_to_string(buffer.data());
}

void WebSocketClient::send(const std::string& message) {
    ws_.write(net::buffer(std::string(message)));
}

void WebSocketClient::close() {
    ws_.close(websocket::close_code::normal);
}
