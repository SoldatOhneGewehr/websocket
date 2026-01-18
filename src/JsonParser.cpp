#include "JsonParser.hpp"

#include <boost/json.hpp>
#include <iostream>

bool JsonParser::parse(const std::string& jsonString) {
    parseInternal(jsonString);
    return true;
}

void JsonParser::parseInternal(const std::string& jsonString) {
    boost::json::value jv = boost::json::parse(jsonString);
    if(jv.is_object())
    {
        auto& obj = jv.get_object();
        if(obj.contains("o"))
        {
            std::string price = obj["o"].as_string().c_str();
            std::cout << "Price: " << price << std::endl;
        }
    }
}
