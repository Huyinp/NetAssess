#pragma once

#include "traffic_types.h"

#include <cstdint>
#include <string_view>

ApplicationProtocol InferApplicationProtocol(TransportProtocol transport_protocol,
                                             TrafficDirection direction,
                                             uint16_t source_port,
                                             uint16_t destination_port);

std::wstring_view ApplicationProtocolName(ApplicationProtocol protocol);
