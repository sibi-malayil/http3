use std::ops::{Add, Sub, AddAssign, SubAssign};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A point in time
pub struct Instant {
    inner: std::time::Instant,
}

impl Instant {
    #[inline]
    /// Get the current instant
    pub fn now() -> Self {
        Self {
            inner: std::time::Instant::now(),
        }
    }

    #[inline]
    /// Get the duration elapsed since an earlier instant
    pub fn duration_since(&self, earlier: Self) -> Duration {
        Duration {
            inner: self.inner.duration_since(earlier.inner),
        }
    }

    #[inline]
    /// Get the duration elapsed since this instant
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        Duration {
            inner: self.inner.elapsed(),
        }
    }

    #[inline]
    /// Add a duration to this instant with overflow checking
    #[must_use]
    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.inner.checked_add(duration.inner).map(|inner| Self { inner })
    }

    #[inline]
    /// Subtract a duration from this instant with overflow checking
    #[must_use]
    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
        self.inner.checked_sub(duration.inner).map(|inner| Self { inner })
    }

    #[inline]
    /// Add a duration to this instant, saturating at the numeric bounds
    #[must_use]
    pub fn saturating_add(&self, duration: Duration) -> Self {
        Self {
            inner: self.inner.checked_add(duration.inner).unwrap_or(self.inner),
        }
    }

    #[inline]
    /// Subtract a duration from this instant, saturating at the numeric bounds
    #[must_use]
    pub fn saturating_sub(&self, duration: Duration) -> Self {
        Self {
            inner: self.inner.checked_sub(duration.inner).unwrap_or(self.inner),
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    #[inline]
    fn add(self, other: Duration) -> Instant {
        Instant {
            inner: self.inner + other.inner,
        }
    }
}

impl AddAssign<Duration> for Instant {
    #[inline]
    fn add_assign(&mut self, other: Duration) {
        self.inner += other.inner;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    #[inline]
    fn sub(self, other: Duration) -> Instant {
        Instant {
            inner: self.inner - other.inner,
        }
    }
}

impl SubAssign<Duration> for Instant {
    #[inline]
    fn sub_assign(&mut self, other: Duration) {
        self.inner -= other.inner;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    #[inline]
    fn sub(self, other: Instant) -> Duration {
        Duration {
            inner: self.inner - other.inner,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A duration of time
pub struct Duration {
    inner: std::time::Duration,
}

impl Duration {
    /// Zero duration constant
    pub const ZERO: Duration = Duration {
        inner: std::time::Duration::ZERO,
    };

    /// Maximum duration constant
    pub const MAX: Duration = Duration {
        inner: std::time::Duration::MAX,
    };

    #[inline]
    /// Create a new duration from seconds and nanoseconds
    pub const fn new(secs: u64, nanos: u32) -> Duration {
        Duration {
            inner: std::time::Duration::new(secs, nanos),
        }
    }

    #[inline]
    /// Create a duration from seconds
    pub const fn from_secs(secs: u64) -> Duration {
        Duration {
            inner: std::time::Duration::from_secs(secs),
        }
    }

    #[inline]
    /// Create a duration from milliseconds
    pub const fn from_millis(millis: u64) -> Duration {
        Duration {
            inner: std::time::Duration::from_millis(millis),
        }
    }

    #[inline]
    /// Create a duration from microseconds
    pub const fn from_micros(micros: u64) -> Duration {
        Duration {
            inner: std::time::Duration::from_micros(micros),
        }
    }

    #[inline]
    /// Create a duration from nanoseconds
    pub const fn from_nanos(nanos: u64) -> Duration {
        Duration {
            inner: std::time::Duration::from_nanos(nanos),
        }
    }

    #[inline]
    /// Check if this duration is zero
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }

    #[inline]
    /// Get the number of whole seconds in this duration
    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.inner.as_secs()
    }

    #[inline]
    /// Get the total number of milliseconds in this duration
    #[must_use]
    pub const fn as_millis(&self) -> u128 {
        self.inner.as_millis()
    }

    #[inline]
    /// Get the total number of microseconds in this duration
    pub const fn as_micros(&self) -> u128 {
        self.inner.as_micros()
    }

    #[inline]
    /// Get the total number of nanoseconds in this duration
    pub const fn as_nanos(&self) -> u128 {
        self.inner.as_nanos()
    }

    #[inline]
    /// Multiply this duration by a floating point number
    pub fn mul_f64(self, rhs: f64) -> Duration {
        Duration {
            inner: self.inner.mul_f64(rhs),
        }
    }

    #[inline]
    /// Divide this duration by a floating point number
    pub fn div_f64(self, rhs: f64) -> Duration {
        Duration {
            inner: self.inner.div_f64(rhs),
        }
    }

    #[inline]
    /// Add another duration with overflow checking
    pub fn checked_add(self, rhs: Duration) -> Option<Duration> {
        self.inner.checked_add(rhs.inner).map(|inner| Duration { inner })
    }

    #[inline]
    /// Subtract another duration with overflow checking
    pub fn checked_sub(self, rhs: Duration) -> Option<Duration> {
        self.inner.checked_sub(rhs.inner).map(|inner| Duration { inner })
    }

    #[inline]
    /// Add another duration, saturating at the numeric bounds
    pub fn saturating_add(self, rhs: Duration) -> Duration {
        Duration {
            inner: self.inner.saturating_add(rhs.inner),
        }
    }

    #[inline]
    /// Subtract another duration, saturating at the numeric bounds
    pub fn saturating_sub(self, rhs: Duration) -> Duration {
        Duration {
            inner: self.inner.saturating_sub(rhs.inner),
        }
    }

    #[inline]
    /// Multiply this duration by a u32, saturating at the numeric bounds
    pub fn saturating_mul(self, rhs: u32) -> Duration {
        Duration {
            inner: self.inner.saturating_mul(rhs),
        }
    }

    #[inline]
    /// Divide this duration by a u32 with overflow checking
    pub fn checked_div(self, rhs: u32) -> Option<Duration> {
        self.inner.checked_div(rhs).map(|inner| Duration { inner })
    }

    #[inline]
    /// Get the total duration as a floating point number of seconds
    pub fn as_secs_f64(self) -> f64 {
        self.inner.as_secs_f64()
    }

    #[inline]
    /// Create a duration from a floating point number of seconds
    pub fn from_secs_f64(secs: f64) -> Duration {
        Duration {
            inner: std::time::Duration::from_secs_f64(secs),
        }
    }
}

impl Add for Duration {
    type Output = Duration;

    #[inline]
    fn add(self, rhs: Duration) -> Duration {
        Duration {
            inner: self.inner + rhs.inner,
        }
    }
}

impl AddAssign for Duration {
    #[inline]
    fn add_assign(&mut self, rhs: Duration) {
        self.inner += rhs.inner;
    }
}

impl Sub for Duration {
    type Output = Duration;

    #[inline]
    fn sub(self, rhs: Duration) -> Duration {
        Duration {
            inner: self.inner - rhs.inner,
        }
    }
}

impl SubAssign for Duration {
    #[inline]
    fn sub_assign(&mut self, rhs: Duration) {
        self.inner -= rhs.inner;
    }
}

impl From<std::time::Duration> for Duration {
    #[inline]
    fn from(duration: std::time::Duration) -> Self {
        Duration { inner: duration }
    }
}

impl From<Duration> for std::time::Duration {
    #[inline]
    fn from(duration: Duration) -> Self {
        duration.inner
    }
}

impl From<std::time::Instant> for Instant {
    #[inline]
    fn from(instant: std::time::Instant) -> Self {
        Instant { inner: instant }
    }
}

impl From<Instant> for std::time::Instant {
    #[inline]
    fn from(instant: Instant) -> Self {
        instant.inner
    }
}

use std::ops::{Mul, Div};

impl Mul<u32> for Duration {
    type Output = Duration;

    #[inline]
    fn mul(self, rhs: u32) -> Duration {
        Duration {
            inner: self.inner * rhs,
        }
    }
}

impl Mul<Duration> for u32 {
    type Output = Duration;

    #[inline]
    fn mul(self, rhs: Duration) -> Duration {
        Duration {
            inner: rhs.inner * self,
        }
    }
}

impl Div<u32> for Duration {
    type Output = Duration;

    #[inline]
    fn div(self, rhs: u32) -> Duration {
        Duration {
            inner: self.inner / rhs,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A timeout with an optional deadline
pub struct Timeout {
    /// Optional deadline for the timeout
    deadline: Option<Instant>,
}

impl Timeout {
    /// Create a timeout with no deadline (never expires)
    pub const fn none() -> Self {
        Self { deadline: None }
    }

    /// Create a timeout that expires after the given duration
    pub fn after(duration: Duration) -> Self {
        Self {
            deadline: Some(Instant::now() + duration),
        }
    }

    /// Create a timeout that expires at the given instant
    pub fn at(instant: Instant) -> Self {
        Self {
            deadline: Some(instant),
        }
    }

    /// Check if this timeout has expired
    pub fn is_expired(&self) -> bool {
        match self.deadline {
            Some(deadline) => Instant::now() >= deadline,
            None => false,
        }
    }

    /// Get the remaining duration until timeout
    pub fn remaining(&self) -> Option<Duration> {
        match self.deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now < deadline {
                    Some(deadline - now)
                } else {
                    Some(Duration::ZERO)
                }
            }
            None => None,
        }
    }

    /// Get the deadline instant if any
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

impl Default for Timeout {
    fn default() -> Self {
        Self::none()
    }
}