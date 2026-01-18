#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstring>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

class BinanceSBEWebSocket {
private:
    std::string api_key_;
    std::string private_key_pem_;
    net::io_context ioc_;
    ssl::context ctx_;
    tcp::resolver resolver_;
    websocket::stream<beast::ssl_stream<tcp::socket>> ws_;

    // Convert bytes to hex string
    std::string to_hex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; ++i) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    // Get current timestamp in milliseconds
    long long get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        );
        return ms.count();
    }

    // Sign message using Ed25519
    std::string sign_ed25519(const std::string& message) {
        BIO* bio = BIO_new_mem_buf(private_key_pem_.c_str(), -1);
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!pkey) {
            throw std::runtime_error("Failed to read private key");
        }

        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create MD context");
        }

        if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize signing");
        }

        size_t sig_len = 0;
        if (EVP_DigestSign(md_ctx, nullptr, &sig_len, 
                          reinterpret_cast<const unsigned char*>(message.c_str()), 
                          message.length()) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to get signature length");
        }

        std::vector<unsigned char> signature(sig_len);
        if (EVP_DigestSign(md_ctx, signature.data(), &sig_len,
                          reinterpret_cast<const unsigned char*>(message.c_str()),
                          message.length()) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to sign message");
        }

        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);

        return to_hex(signature.data(), sig_len);
    }

    // Create authentication payload
    std::string create_auth_payload() {
        long long timestamp = get_timestamp();
        std::string payload = "timestamp=" + std::to_string(timestamp);
        std::string signature = sign_ed25519(payload);
        
        return R"({"method":"session.logon","id":1,"params":{"apiKey":")" + 
               api_key_ + R"(","signature":")" + signature + 
               R"(","timestamp":)" + std::to_string(timestamp) + "}}";
    }

public:
    BinanceSBEWebSocket(const std::string& api_key, const std::string& private_key_pem)
        : api_key_(api_key)
        , private_key_pem_(private_key_pem)
        , ctx_(ssl::context::tlsv12_client)
        , resolver_(ioc_)
        , ws_(ioc_, ctx_) {
        
        // Load default root certificates
        ctx_.set_default_verify_paths();
        ctx_.set_verify_mode(ssl::verify_peer);
    }

    void connect(const std::string& host, const std::string& port, const std::string& path) {
        try {
            // Resolve hostname
            auto const results = resolver_.resolve(host, port);
            
            // Connect to the IP address
            auto ep = net::connect(get_lowest_layer(ws_), results);
            
            // Set SNI Hostname
            if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(), host.c_str())) {
                throw beast::system_error(
                    beast::error_code(
                        static_cast<int>(::ERR_get_error()),
                        net::error::get_ssl_category()
                    ),
                    "Failed to set SNI Hostname"
                );
            }
            
            // Perform SSL handshake
            ws_.next_layer().handshake(ssl::stream_base::client);
            
            // Set WebSocket handshake decorator for User-Agent
            ws_.set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(http::field::user_agent, "BinanceSBEClient/1.0");
                }
            ));
            
            // Perform WebSocket handshake
            ws_.handshake(host, path);
            
            std::cout << "Connected to " << host << path << std::endl;
            
            // Authenticate
            authenticate();
            
        } catch (std::exception const& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            throw;
        }
    }

    void authenticate() {
        try {
            std::string auth_msg = create_auth_payload();
            std::cout << "Sending authentication: " << auth_msg << std::endl;
            
            ws_.write(net::buffer(auth_msg));
            
            // Read authentication response
            beast::flat_buffer buffer;
            ws_.read(buffer);
            
            std::cout << "Auth response received (" << buffer.size() << " bytes)" << std::endl;
            std::cout << beast::make_printable(buffer.data()) << std::endl;
            
        } catch (std::exception const& e) {
            std::cerr << "Authentication error: " << e.what() << std::endl;
            throw;
        }
    }

    void subscribe(const std::string& subscription_msg) {
        try {
            ws_.write(net::buffer(subscription_msg));
            std::cout << "Subscription sent: " << subscription_msg << std::endl;
        } catch (std::exception const& e) {
            std::cerr << "Subscription error: " << e.what() << std::endl;
            throw;
        }
    }

    void read_messages() {
        try {
            while (true) {
                beast::flat_buffer buffer;
                ws_.read(buffer);
                
                std::cout << "Received binary message (" << buffer.size() << " bytes)" << std::endl;
                
                // The binary SBE data is in buffer.data()
                // You can process it here or pass it to an SBE decoder
                // For now, just print the size
            }
        } catch (beast::system_error const& se) {
            if (se.code() != websocket::error::closed) {
                std::cerr << "Error: " << se.code().message() << std::endl;
            }
        } catch (std::exception const& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }
    }

    void close() {
        try {
            ws_.close(websocket::close_code::normal);
        } catch (std::exception const& e) {
            std::cerr << "Close error: " << e.what() << std::endl;
        }
    }

    ~BinanceSBEWebSocket() {
        close();
    }
};

int main() {
    try {
        // Replace with your actual API key and private key
        std::string api_key = "YOUR_API_KEY";
        
        // Your Ed25519 private key in PEM format
        std::string private_key_pem = R"(-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----)";

        // Binance WebSocket endpoint
        std::string host = "ws-api.binance.com";
        std::string port = "443";
        std::string path = "/ws-api/v3";

        BinanceSBEWebSocket client(api_key, private_key_pem);
        
        // Connect and authenticate
        client.connect(host, port, path);
        
        // Example: Subscribe to a stream (adjust as needed for SBE)
        // std::string subscribe_msg = R"({"method":"subscribe","params":["btcusdt@trade"],"id":2})";
        // client.subscribe(subscribe_msg);
        
        // Read incoming messages
        client.read_messages();
        
    } catch (std::exception const& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}