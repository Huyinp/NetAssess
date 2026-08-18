#include "protocol_classifier.h"

#include <iostream>
#include <string_view>

namespace {

int failures = 0;

void PrintValue(std::ostream& stream, ApplicationProtocol value) {
    stream << static_cast<int>(value);
}

void PrintValue(std::ostream& stream, std::wstring_view value) {
    for (const wchar_t character : value) {
        stream << (character < 128 ? static_cast<char>(character) : '?');
    }
}

#define CHECK_EQ(actual, expected)                                                   \
    do {                                                                             \
        const auto actual_value = (actual);                                          \
        const auto expected_value = (expected);                                      \
        if (actual_value != expected_value) {                                        \
            std::cerr << __FILE__ << ':' << __LINE__ << ": actual=";                \
            PrintValue(std::cerr, actual_value);                                     \
            std::cerr << ", expected=";                                             \
            PrintValue(std::cerr, expected_value);                                   \
            std::cerr << '\\n';                                                      \
            ++failures;                                                               \
        }                                                                            \
    } while (false)

}  // namespace

int main() {
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Send, 50000, 443),
             ApplicationProtocol::HttpsTls);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Udp,
                                      TrafficDirection::Send, 50000, 443),
             ApplicationProtocol::Quic);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Udp,
                                      TrafficDirection::Receive, 53, 50000),
             ApplicationProtocol::Dns);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Send, 50000, 49152),
             ApplicationProtocol::Other);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Send, 22, 443),
             ApplicationProtocol::HttpsTls);
    CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                      TrafficDirection::Receive, 22, 443),
             ApplicationProtocol::Ssh);
    CHECK_EQ(ApplicationProtocolName(ApplicationProtocol::HttpsTls),
             L"HTTPS/TLS锛堢鍙ｆ帹鏂級");
    CHECK_EQ(ApplicationProtocolName(ApplicationProtocol::Other), L"鍏朵粬");

    return failures == 0 ? 0 : 1;
}
