#include "Websocket.hpp"
#include "JsonParser.hpp"
int main()
{
    WebSocketClient client("stream.binance.com", "443");

    client.connect("/ws");

    client.send(R"({
  "method": "SUBSCRIBE",
        "params": [
            "btcusdt@miniTicker"
        ],
        "id": 1
    })");

    JsonParser parser;

    while (true)
    {
        parser.parse(client.receive());
    }
    client.close();

    return 0;
}
