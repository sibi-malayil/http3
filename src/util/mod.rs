/// Variable-length integer encoding/decoding
pub mod varint;
/// Buffer utilities and extensions
pub mod buffer;
/// Time and duration utilities
pub mod time;

pub use varint::{VarInt, VarIntBoundsExceeded};
pub use buffer::{BufExt, BufMutExt};
pub use time::{Instant, Duration};