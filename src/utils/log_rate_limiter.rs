use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct RateLimitDecision {
    pub should_emit: bool,
    pub suppressed_since_last_emit: u64,
}

#[derive(Debug, Clone)]
struct LimiterState {
    last_emit: Instant,
    suppressed: u64,
}

#[derive(Debug, Clone)]
pub struct LogRateLimiter {
    window: Duration,
    states: HashMap<String, LimiterState>,
}

impl LogRateLimiter {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            states: HashMap::new(),
        }
    }

    pub fn should_emit(&mut self, key: &str) -> RateLimitDecision {
        let now = Instant::now();

        match self.states.get_mut(key) {
            None => {
                self.states.insert(
                    key.to_string(),
                    LimiterState {
                        last_emit: now,
                        suppressed: 0,
                    },
                );
                RateLimitDecision {
                    should_emit: true,
                    suppressed_since_last_emit: 0,
                }
            }
            Some(state) => {
                if now.duration_since(state.last_emit) >= self.window {
                    let suppressed = state.suppressed;
                    state.last_emit = now;
                    state.suppressed = 0;
                    RateLimitDecision {
                        should_emit: true,
                        suppressed_since_last_emit: suppressed,
                    }
                } else {
                    state.suppressed = state.suppressed.saturating_add(1);
                    RateLimitDecision {
                        should_emit: false,
                        suppressed_since_last_emit: 0,
                    }
                }
            }
        }
    }
}
