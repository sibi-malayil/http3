# Transport Parameter Exchange Implementation

## Overview

Transport parameter exchange is a critical part of the QUIC connection establishment process, as specified in RFC 9000 Section 7. This document describes the implementation of transport parameter negotiation in our HTTP/3 library.

## Key Components

### 1. Transport Parameters Structure (`src/quic/transport.rs`)

The `TransportParameters` struct contains all the parameters defined in RFC 9000 Section 18:

- `max_idle_timeout` - Maximum idle timeout in milliseconds
- `initial_max_data` - Initial flow control limit for connection-level data
- `initial_max_stream_data_*` - Initial flow control limits for streams
- `initial_max_streams_*` - Maximum number of streams that can be opened
- `ack_delay_exponent` - Exponent used to decode ACK Delay field
- `max_ack_delay` - Maximum time in milliseconds by which endpoint will delay acknowledgments
- `disable_active_migration` - Whether connection migration is disabled
- `active_connection_id_limit` - Maximum number of connection IDs from peer
- And more...

### 2. Parameter Encoding/Decoding

Transport parameters are encoded as TLS extensions during the handshake:

```rust
pub fn encode(&self) -> Result<Bytes> {
    // Encode each parameter as ID-Length-Value
    // Following RFC 9000 Section 18
}

pub fn decode(data: Bytes) -> Result<Self> {
    // Parse parameters from TLS extension data
}
```

### 3. Integration with Connection State

#### Connection Structure Updates (`src/quic/connection.rs`)

Added fields to track transport parameters:
- `peer_transport_params: Option<TransportParameters>` - Parameters received from peer

#### Processing Flow

1. **During Initialization**: Local transport parameters are set in the crypto manager
2. **During Handshake**: Transport parameters are exchanged via TLS extensions
3. **After Handshake**: Peer parameters are extracted and applied to connection state

### 4. Flow Control Integration

The `FlowControlLimits` structure is initialized from transport parameters:

```rust
pub fn new(transport_params: &TransportParameters) -> Self {
    Self {
        max_data: transport_params.initial_max_data.unwrap_or(0),
        max_streams_bidi: transport_params.initial_max_streams_bidi.unwrap_or(0),
        // ... other limits
    }
}
```

### 5. Recovery Manager Integration

ACK delay parameters are applied to the recovery manager:

```rust
self.recovery.set_ack_delay_exponent(exponent);
self.recovery.set_max_ack_delay(max_delay);
```

## Implementation Details

### Parameter Validation

Transport parameters are validated according to RFC 9000 requirements:
- ACK delay exponent must not exceed 20
- Max ACK delay must be less than 2^14 milliseconds
- Active connection ID limit must be at least 2

### Idle Timeout Negotiation

The effective idle timeout is the minimum of local and peer values:

```rust
let min_timeout = local_timeout.min(peer_timeout);
```

### Error Handling

Invalid transport parameters result in connection termination with appropriate error codes.

## Testing

Comprehensive tests verify:
1. Parameter encoding/decoding round trips
2. Flow control initialization from parameters
3. Parameter validation rules
4. Integration with connection establishment

## RFC Compliance

This implementation complies with:
- RFC 9000 Section 7 (Transport Parameter Negotiation)
- RFC 9000 Section 18 (Transport Parameter Definitions)
- RFC 9001 (TLS integration for parameter exchange)

## Future Work

- Implement connection migration using preferred address parameter
- Add support for additional extension parameters
- Optimize parameter encoding for minimal overhead