#include "etw_decoder.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <limits>
#include <tuple>
#include <utility>
#include <vector>

#include <tdh.h>

namespace {

constexpr GUID kTcpIpProvider{0x9a280ac0, 0xc8e0, 0x11d1,
                              {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
constexpr GUID kUdpIpProvider{0xbf3a50c5, 0xa9c9, 0x4988,
                              {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};
constexpr std::uint8_t kSendIpv6 = EVENT_TRACE_TYPE_SEND + 16;
constexpr std::uint8_t kReceiveIpv6 = EVENT_TRACE_TYPE_RECEIVE + 16;

bool EqualGuid(const GUID& left, const GUID& right) {
    return left.Data1 == right.Data1 && left.Data2 == right.Data2 && left.Data3 == right.Data3 &&
           std::equal(std::begin(left.Data4), std::end(left.Data4), std::begin(right.Data4));
}

std::optional<std::pair<TrafficDirection, TransportProtocol>> Classify(
    const EVENT_RECORD& record) {
    TransportProtocol transport;
    if (EqualGuid(record.EventHeader.ProviderId, kTcpIpProvider)) {
        transport = TransportProtocol::Tcp;
    } else if (EqualGuid(record.EventHeader.ProviderId, kUdpIpProvider)) {
        transport = TransportProtocol::Udp;
    } else {
        return std::nullopt;
    }

    switch (record.EventHeader.EventDescriptor.Opcode) {
    case EVENT_TRACE_TYPE_SEND:
    case kSendIpv6:
        return std::pair{TrafficDirection::Send, transport};
    case EVENT_TRACE_TYPE_RECEIVE:
    case kReceiveIpv6:
        return std::pair{TrafficDirection::Receive, transport};
    default:
        return std::nullopt;
    }
}

std::optional<std::size_t> FixedElementWidth(const EVENT_PROPERTY_INFO& property,
                                             std::uint16_t header_flags) {
    if ((property.Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount |
                           PropertyWBEMXmlFragment | PropertyHasCustomSchema)) != 0) {
        return std::nullopt;
    }

    switch (property.nonStructType.InType) {
    case TDH_INTYPE_INT8:
    case TDH_INTYPE_UINT8:
    case TDH_INTYPE_ANSICHAR:
        return 1;
    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16:
    case TDH_INTYPE_UNICODECHAR:
        return 2;
    case TDH_INTYPE_INT32:
    case TDH_INTYPE_UINT32:
    case TDH_INTYPE_FLOAT:
    case TDH_INTYPE_BOOLEAN:
    case TDH_INTYPE_HEXINT32:
        return 4;
    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
    case TDH_INTYPE_DOUBLE:
    case TDH_INTYPE_FILETIME:
    case TDH_INTYPE_HEXINT64:
        return 8;
    case TDH_INTYPE_GUID:
    case TDH_INTYPE_SYSTEMTIME:
        return 16;
    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_SIZET:
        if (header_flags == EVENT_HEADER_FLAG_32_BIT_HEADER) {
            return 4;
        }
        if (header_flags == EVENT_HEADER_FLAG_64_BIT_HEADER) {
            return 8;
        }
        return std::nullopt;
    case TDH_INTYPE_BINARY:
        if (property.length != 0) {
            return property.length;
        }
        if (property.nonStructType.OutType == TDH_OUTTYPE_IPV6) {
            return 16;
        }
        return std::nullopt;
    default:
        return std::nullopt;
    }
}

std::optional<std::size_t> FixedPropertyWidth(const EVENT_PROPERTY_INFO& property,
                                              std::uint16_t header_flags) {
    const auto element_width = FixedElementWidth(property, header_flags);
    if (!element_width || property.count == 0 ||
        *element_width > std::numeric_limits<std::size_t>::max() / property.count) {
        return std::nullopt;
    }
    return *element_width * property.count;
}

const wchar_t* PropertyName(const TRACE_EVENT_INFO& information, std::size_t buffer_size,
                            const EVENT_PROPERTY_INFO& property) {
    if (property.NameOffset == 0 || property.NameOffset >= buffer_size ||
        property.NameOffset % alignof(wchar_t) != 0) {
        return nullptr;
    }

    const auto* name = reinterpret_cast<const wchar_t*>(
        reinterpret_cast<const std::byte*>(&information) + property.NameOffset);
    const std::size_t available_characters = (buffer_size - property.NameOffset) / sizeof(wchar_t);
    return std::wmemchr(name, L'\0', available_characters) ? name : nullptr;
}

bool SetField(FieldLayout& field, std::size_t offset, std::size_t width) {
    if (field.width != 0) {
        return false;
    }
    field = {offset, width};
    return true;
}

std::optional<EventLayout> LoadEventLayout(const EVENT_RECORD& record) {
    const auto classification = Classify(record);
    if (!classification) {
        return std::nullopt;
    }

    ULONG buffer_size = 0;
    auto* mutable_record = const_cast<EVENT_RECORD*>(&record);
    if (TdhGetEventInformation(mutable_record, 0, nullptr, nullptr, &buffer_size) !=
            ERROR_INSUFFICIENT_BUFFER ||
        buffer_size < offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray)) {
        return std::nullopt;
    }

    std::vector<std::byte> buffer(buffer_size);
    auto* information = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    if (TdhGetEventInformation(mutable_record, 0, nullptr, information, &buffer_size) !=
        ERROR_SUCCESS) {
        return std::nullopt;
    }

    constexpr std::size_t property_array_offset =
        offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray);
    if (buffer_size > buffer.size() || buffer_size < property_array_offset ||
        information->TopLevelPropertyCount > information->PropertyCount ||
        information->TopLevelPropertyCount >
            (buffer_size - property_array_offset) / sizeof(EVENT_PROPERTY_INFO)) {
        return std::nullopt;
    }

    EventLayout layout;
    layout.direction = classification->first;
    layout.transport = classification->second;
    std::size_t offset = 0;
    const std::uint16_t header_flags = record.EventHeader.Flags &
                                       (EVENT_HEADER_FLAG_32_BIT_HEADER |
                                        EVENT_HEADER_FLAG_64_BIT_HEADER);
    for (ULONG index = 0; index < information->TopLevelPropertyCount; ++index) {
        const auto& property = information->EventPropertyInfoArray[index];
        const auto width = FixedPropertyWidth(property, header_flags);
        const wchar_t* name = PropertyName(*information, buffer_size, property);
        if (!width || !name || offset > std::numeric_limits<std::size_t>::max() - *width) {
            return std::nullopt;
        }

        bool accepted = true;
        if (_wcsicmp(name, L"PID") == 0) {
            accepted = SetField(layout.pid, offset, *width);
        } else if (_wcsicmp(name, L"size") == 0) {
            accepted = SetField(layout.size, offset, *width);
        } else if (_wcsicmp(name, L"sport") == 0) {
            accepted = SetField(layout.source_port, offset, *width);
        } else if (_wcsicmp(name, L"dport") == 0) {
            accepted = SetField(layout.destination_port, offset, *width);
        }
        if (!accepted) {
            return std::nullopt;
        }
        offset += *width;
    }

    if (layout.pid.width != 4 || layout.size.width != 4 || layout.source_port.width != 2 ||
        layout.destination_port.width != 2) {
        return std::nullopt;
    }
    return layout;
}

bool Contains(std::span<const std::byte> payload, const FieldLayout& field) {
    return field.offset <= payload.size() && field.width <= payload.size() - field.offset;
}

std::optional<std::uint32_t> ReadLittleEndian32(std::span<const std::byte> payload,
                                               const FieldLayout& field) {
    if (field.width != sizeof(std::uint32_t) || !Contains(payload, field)) {
        return std::nullopt;
    }

    std::uint32_t value = 0;
    for (std::size_t index = 0; index < field.width; ++index) {
        value |= std::to_integer<std::uint32_t>(payload[field.offset + index]) << (index * 8);
    }
    return value;
}

std::optional<std::uint16_t> ReadNetworkOrder16(std::span<const std::byte> payload,
                                               const FieldLayout& field) {
    if (field.width != sizeof(std::uint16_t) || !Contains(payload, field)) {
        return std::nullopt;
    }

    return static_cast<std::uint16_t>(
        (std::to_integer<std::uint16_t>(payload[field.offset]) << 8) |
        std::to_integer<std::uint16_t>(payload[field.offset + 1]));
}

}  // namespace

std::optional<DecodedNetworkEvent> DecodePayload(const EventLayout& layout,
                                                 std::span<const std::byte> payload) {
    if (payload.empty()) {
        return std::nullopt;
    }

    const auto pid = ReadLittleEndian32(payload, layout.pid);
    const auto size = ReadLittleEndian32(payload, layout.size);
    const auto source_port = ReadNetworkOrder16(payload, layout.source_port);
    const auto destination_port = ReadNetworkOrder16(payload, layout.destination_port);
    if (!pid || !size || !source_port || !destination_port) {
        return std::nullopt;
    }

    return DecodedNetworkEvent{*pid, layout.direction, layout.transport, *source_port,
                               *destination_port, *size};
}

bool EtwDecoder::SchemaKeyLess::operator()(const SchemaKey& left,
                                           const SchemaKey& right) const noexcept {
    const auto left_prefix = std::tie(left.provider.Data1, left.provider.Data2, left.provider.Data3);
    const auto right_prefix =
        std::tie(right.provider.Data1, right.provider.Data2, right.provider.Data3);
    if (left_prefix != right_prefix) {
        return left_prefix < right_prefix;
    }
    const int data4_order = std::memcmp(left.provider.Data4, right.provider.Data4,
                                       sizeof(left.provider.Data4));
    if (data4_order != 0) {
        return data4_order < 0;
    }
    return std::tie(left.opcode, left.version, left.header_width_flags) <
           std::tie(right.opcode, right.version, right.header_width_flags);
}

EtwDecoder::EtwDecoder() : EtwDecoder(LoadEventLayout) {}

EtwDecoder::EtwDecoder(SchemaLoader schema_loader)
    : schema_loader_(schema_loader ? std::move(schema_loader) : LoadEventLayout) {}

std::optional<DecodedNetworkEvent> EtwDecoder::Decode(const EVENT_RECORD& record) {
    const SchemaKey key{record.EventHeader.ProviderId,
                        record.EventHeader.EventDescriptor.Opcode,
                        record.EventHeader.EventDescriptor.Version,
                        static_cast<std::uint16_t>(
                            record.EventHeader.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER |
                                                        EVENT_HEADER_FLAG_64_BIT_HEADER))};
    auto [layout, inserted] = layouts_.try_emplace(key);
    if (inserted) {
        layout->second = schema_loader_(record);
    }

    if (!layout->second || record.UserData == nullptr || record.UserDataLength == 0) {
        parse_failures_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    const auto payload = std::span{static_cast<const std::byte*>(record.UserData),
                                   static_cast<std::size_t>(record.UserDataLength)};
    auto decoded = DecodePayload(*layout->second, payload);
    if (!decoded) {
        parse_failures_.fetch_add(1, std::memory_order_relaxed);
    }
    return decoded;
}

std::uint64_t EtwDecoder::parse_failures() const noexcept {
    return parse_failures_.load(std::memory_order_relaxed);
}

std::size_t EtwDecoder::cached_layout_count() const noexcept {
    return layouts_.size();
}
