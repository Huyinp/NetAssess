#pragma once

#include "traffic_types.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

struct FieldLayout {
    std::size_t offset{};
    std::size_t width{};
};

struct EventLayout {
    FieldLayout pid;
    FieldLayout size;
    FieldLayout source_address;
    FieldLayout destination_address;
    FieldLayout source_port;
    FieldLayout destination_port;
    TrafficDirection direction{};
    TransportProtocol transport{};
    IpAddressFamily address_family{};
};

struct DecodedNetworkEvent {
    std::uint32_t pid{};
    TrafficDirection direction{};
    TransportProtocol transport{};
    IpAddress source_address{};
    IpAddress destination_address{};
    std::uint16_t source_port{};
    std::uint16_t destination_port{};
    std::uint64_t bytes{};
};

std::optional<DecodedNetworkEvent> DecodePayload(
    const EventLayout& layout, std::span<const std::byte> payload);

class EtwDecoder {
public:
    using SchemaLoader = std::function<std::optional<EventLayout>(const EVENT_RECORD&)>;

    EtwDecoder();
    explicit EtwDecoder(SchemaLoader schema_loader);

    std::optional<DecodedNetworkEvent> Decode(const EVENT_RECORD& record);
    std::uint64_t parse_failures() const noexcept;
    std::size_t cached_layout_count() const noexcept;

private:
    struct SchemaKey {
        GUID provider{};
        std::uint8_t opcode{};
        std::uint8_t version{};
        std::uint16_t header_width_flags{};
    };

    struct SchemaKeyLess {
        bool operator()(const SchemaKey& left, const SchemaKey& right) const noexcept;
    };

    SchemaLoader schema_loader_;
    std::map<SchemaKey, std::optional<EventLayout>, SchemaKeyLess> layouts_;
    std::atomic_uint64_t parse_failures_{};
};
