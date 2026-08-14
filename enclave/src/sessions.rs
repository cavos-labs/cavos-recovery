//! Short-lived channel keys, held between `OpenSession` and `RunJob`.
//!
//! This is the only state a long-lived enclave keeps, and it is deliberately
//! tiny: one ephemeral P-256 key per in-flight session, dropped as soon as the
//! session's single job runs.
//!
//! An alternative was to hold no state at all and derive each channel key from
//! a long-lived enclave secret and the session id. That was rejected: it costs
//! forward secrecy, since one leak of the seed would retroactively open every
//! channel ever opened. Keeping real ephemeral keys and forgetting them quickly
//! is both simpler to reason about and stronger.
//!
//! Two limits keep the untrusted parent from growing this map without bound:
//! entries expire, and the map is capped. Both matter — the parent can call
//! `OpenSession` as often as it likes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::crypto::ChannelKey;

/// How long an opened session may sit before its job arrives. The browser opens
/// a session and posts its job in the same user action, so this only has to
/// cover a slow network, not a slow human.
const SESSION_TTL: Duration = Duration::from_secs(120);

/// Ceiling on concurrent open sessions. Reaching it means either a burst far
/// beyond real traffic or an abusive parent; either way, refusing to open more
/// is better than growing until the enclave is killed for memory.
const MAX_SESSIONS: usize = 4_096;

struct Session {
    channel: ChannelKey,
    opened_at: Instant,
}

pub struct SessionStore {
    sessions: HashMap<String, Session>,
}

/// Why a session could not be opened or claimed.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The map is full. The caller should retry later.
    AtCapacity,
    /// No such session, or it expired, or its job already ran.
    Unknown,
}

impl SessionStore {
    pub fn new() -> Self {
        Self { sessions: HashMap::new() }
    }

    /// Open a session and return its channel public key.
    ///
    /// Re-opening an existing session id replaces its key. That is intentional:
    /// a browser that retries `OpenSession` after a dropped response must get a
    /// working channel, and the old key was never used for anything.
    pub fn open(&mut self, session_id: &str, now: Instant) -> Result<Vec<u8>, SessionError> {
        self.expire(now);
        if !self.sessions.contains_key(session_id) && self.sessions.len() >= MAX_SESSIONS {
            return Err(SessionError::AtCapacity);
        }
        let channel = ChannelKey::generate();
        let public = channel.public_key().to_vec();
        self.sessions
            .insert(session_id.to_owned(), Session { channel, opened_at: now });
        Ok(public)
    }

    /// Take a session's channel key, removing it.
    ///
    /// Removal is what makes a session single-use: a replayed `RunJob` finds
    /// nothing, so the same encrypted credential cannot be run twice even if
    /// the parent stored a copy.
    pub fn claim(&mut self, session_id: &str, now: Instant) -> Result<ChannelKey, SessionError> {
        self.expire(now);
        match self.sessions.remove(session_id) {
            Some(session) => Ok(session.channel),
            None => Err(SessionError::Unknown),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    fn expire(&mut self, now: Instant) {
        self.sessions
            .retain(|_, session| now.duration_since(session.opened_at) < SESSION_TTL);
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_claims_once() {
        let mut store = SessionStore::new();
        let now = Instant::now();

        let public = store.open("session-a", now).unwrap();
        assert_eq!(public.len(), 65, "uncompressed SEC1 P-256 key");
        assert_eq!(store.len(), 1);

        assert!(store.claim("session-a", now).is_ok());
        assert_eq!(store.len(), 0, "claiming removes the session");
        // `ChannelKey` deliberately does not implement `Debug` — it holds a
        // secret — so these assert by pattern rather than by `unwrap_err`.
        assert!(
            matches!(store.claim("session-a", now), Err(SessionError::Unknown)),
            "a replayed job finds nothing"
        );
    }

    #[test]
    fn unknown_sessions_are_rejected() {
        let mut store = SessionStore::new();
        assert!(matches!(
            store.claim("never-opened", Instant::now()),
            Err(SessionError::Unknown)
        ));
    }

    #[test]
    fn sessions_expire() {
        let mut store = SessionStore::new();
        let opened = Instant::now();
        store.open("session-a", opened).unwrap();

        let later = opened + SESSION_TTL + Duration::from_secs(1);
        assert!(matches!(
            store.claim("session-a", later),
            Err(SessionError::Unknown)
        ));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn reopening_replaces_the_channel_key() {
        let mut store = SessionStore::new();
        let now = Instant::now();

        let first = store.open("session-a", now).unwrap();
        let second = store.open("session-a", now).unwrap();
        assert_ne!(first, second, "a retry gets a fresh key");
        assert_eq!(store.len(), 1, "and does not leak an entry");
    }

    #[test]
    fn refuses_to_grow_past_the_cap() {
        let mut store = SessionStore::new();
        let now = Instant::now();
        for index in 0..MAX_SESSIONS {
            store.open(&format!("session-{index}"), now).unwrap();
        }
        assert_eq!(
            store.open("one-too-many", now).unwrap_err(),
            SessionError::AtCapacity
        );
        // An existing session may still be re-opened while at capacity, so a
        // retry does not fail just because the map happens to be full.
        assert!(store.open("session-0", now).is_ok());
    }

    #[test]
    fn expiry_frees_capacity() {
        let mut store = SessionStore::new();
        let opened = Instant::now();
        for index in 0..MAX_SESSIONS {
            store.open(&format!("session-{index}"), opened).unwrap();
        }
        let later = opened + SESSION_TTL + Duration::from_secs(1);
        assert!(store.open("fresh", later).is_ok());
        assert_eq!(store.len(), 1, "the expired entries are gone");
    }
}
