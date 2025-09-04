#!/bin/bash

# Fix the most critical warnings in the HTTP/3 implementation

echo "Fixing critical warnings in HTTP/3 implementation..."

# Fix unused variables by prefixing with underscore
find src -name "*.rs" -type f -exec sed -i \
    -e 's/conn_type)/\_conn_type)/g' \
    -e 's/let recv_keys/let _recv_keys/g' \
    -e 's/let old_rtt_var/let _old_rtt_var/g' \
    -e 's/for (idx,/for (_idx,/g' \
    -e 's/let first_byte/let _first_byte/g' \
    -e 's/packet_type: PacketType,/_packet_type: PacketType,/g' \
    -e 's/key_change: rustls/_key_change: rustls/g' \
    -e 's/label: &\[u8\]/_label: \&[u8]/g' \
    -e 's/context: &\[u8\]/_context: \&[u8]/g' \
    -e 's/length: usize/_length: usize/g' \
    -e 's/packet_data: Bytes/_packet_data: Bytes/g' \
    -e 's/pn: u64/_pn: u64/g' \
    -e 's/now: Instant/_now: Instant/g' \
    -e 's/max_bytes: usize/_max_bytes: usize/g' \
    -e 's/stream_id: u64,/_stream_id: u64,/g' \
    -e 's/referenced_indices: &mut Vec/_referenced_indices: \&mut Vec/g' \
    -e 's/let base = stats/_base = stats/g' \
    -e 's/let server_key/_server_key/g' \
    -e 's/let mut conn = quic/let conn = quic/g' \
    -e 's/let mut current = \*/let current = \*/g' \
    -e 's/let mut scheduler = self/let scheduler = self/g' \
    -e 's/let mut remaining_bytes = available/let remaining_bytes = available/g' \
    -e 's/let mut queue_remaining/let queue_remaining/g' \
    -e 's/let quantum = self/_quantum = self/g' \
    -e 's/headers: &\[HeaderField\]/_headers: \&[HeaderField]/g' \
    -e 's/encoder: &Encoder/_encoder: \&Encoder/g' \
    -e 's/let ack = decoder/let _ack = decoder/g' {} \;

# Remove unused imports
echo "Removing unused imports..."
find src -name "*.rs" -type f -exec sed -i \
    -e '/^use.*EventKind.*$/d' \
    -e '/^use.*Error.*Result.*Http3ErrorCode.*$/s/, Error/, Result/g' \
    -e '/^use.*Http3FrameType.*GoawayFrame.*$/s/, Http3FrameType//g' \
    -e '/^use.*Http3FrameType.*GoawayFrame.*$/s/, GoawayFrame//g' \
    -e '/^use.*quic::stream::StreamId.*$/d' \
    -e '/^use.*ring::aead::chacha20_poly1305_openssh.*$/d' \
    -e '/^use.*tokio::sync::Mutex.*$/d' {} \;

# Fix the unused assignment in stream_multiplexer
sed -i 's/let mut scheduled = Vec::new();$/let scheduled;/g' src/http3/stream_multiplexer.rs

# Add #[must_use] attributes to important constructors
echo "Adding #[must_use] attributes..."
for file in src/whathappened/output.rs src/whathappened/span.rs; do
    if [ -f "$file" ]; then
        sed -i 's/pub fn new(/\#[must_use]\n    pub fn new(/g' "$file"
        sed -i 's/pub fn with_color(/\#[must_use]\n    pub fn with_color(/g' "$file"
        sed -i 's/pub fn path(/\#[must_use]\n    pub fn path(/g' "$file"
        sed -i 's/pub fn enter(/\#[must_use]\n    pub fn enter(/g' "$file"
        sed -i 's/pub fn level(/\#[must_use]\n    pub fn level(/g' "$file"
    fi
done

# Fix format string interpolation
echo "Fixing format string interpolation..."
find src -name "*.rs" -type f -exec sed -i \
    -e 's/writeln!(io::stderr(), "{}", formatted)/writeln!(io::stderr(), "{formatted}")/g' \
    -e 's/writeln!(io::stdout(), "{}", formatted)/writeln!(io::stdout(), "{formatted}")/g' \
    -e 's/writeln!(file, "{}", formatted)/writeln!(file, "{formatted}")/g' \
    -e 's/eprintln!("{}", info)/eprintln!("{info}")/g' \
    -e 's/format!("context_{}", i)/format!("context_{i}")/g' \
    -e 's/format!("source_{}", depth)/format!("source_{depth}")/g' \
    -e 's/write!(f, ": {}", ctx)/write!(f, ": {ctx}")/g' \
    -e 's/write!(f, "\\n    {}: {}", depth, err)/write!(f, "\\n    {depth}: {err}")/g' \
    -e 's/eprintln!("Handler error: {}", e)/eprintln!("Handler error: {e}")/g' \
    -e 's/eprintln!("Output error: {}", e)/eprintln!("Output error: {e}")/g' \
    -e 's/format!("→ {}", name)/format!("→ {name}")/g' {} \;

echo "Critical warnings fixed!"
echo "Run 'cargo build' to verify the fixes."