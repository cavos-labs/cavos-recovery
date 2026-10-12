//! One-time email codes, held between `SendCode` and `VerifyEmail`.
//!
//! Like `sessions`, this is bounded memory the untrusted parent cannot grow
//! without limit: entries expire and the map is capped.
//!
//! An address has at most one live code. Asking for another inside the cooldown
//! is refused, and that includes an address whose code was used up by wrong
//! guesses: an exhausted entry stays until it expires, so guessing cannot be
//! used to reset the cooldown.
//!
//! The store never talks to the network. The caller reserves an entry, sends
//! the mail without holding the lock, and removes the entry if sending failed.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const CODE_LEN: usize = 9;
const CODE_ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const CODE_TTL: Duration = Duration::from_secs(5 * 60);
const RESEND_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_ATTEMPTS: u8 = 3;
const MAX_CODES: usize = 4_096;

struct Entry {
    code: Zeroizing<String>,
    app_id: String,
    attempts_left: u8,
    sent_at: Instant,
    expires_at: Instant,
}

pub struct CodeStore {
    entries: HashMap<String, Entry>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CodeError {
    /// A code was reserved for this address less than a minute ago.
    Cooldown,
    /// The map is full.
    AtCapacity,
}

/// A fresh code: nine characters of the bech32 alphabet, five random bits each.
pub fn generate_code() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; CODE_LEN]);
    OsRng.fill_bytes(bytes.as_mut_slice());
    Zeroizing::new(
        bytes
            .iter()
            .map(|byte| CODE_ALPHABET[(byte & 31) as usize] as char)
            .collect(),
    )
}

/// ASCII-lowercase, with whitespace and `-` removed.
pub fn normalize_code(code: &str) -> Zeroizing<String> {
    Zeroizing::new(
        code.chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect(),
    )
}

impl CodeStore {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Record `code` for `email`, replacing an earlier one once the cooldown
    /// has passed.
    pub fn reserve(
        &mut self,
        email: &str,
        app_id: &str,
        code: Zeroizing<String>,
        now: Instant,
    ) -> Result<(), CodeError> {
        self.expire(now);
        match self.entries.get(email) {
            Some(entry) if now.duration_since(entry.sent_at) < RESEND_COOLDOWN => {
                return Err(CodeError::Cooldown);
            }
            Some(_) => {}
            None if self.entries.len() >= MAX_CODES => return Err(CodeError::AtCapacity),
            None => {}
        }
        self.entries.insert(
            email.to_owned(),
            Entry {
                code,
                app_id: app_id.to_owned(),
                attempts_left: MAX_ATTEMPTS,
                sent_at: now,
                expires_at: now + CODE_TTL,
            },
        );
        Ok(())
    }

    /// Forget a reservation whose mail was never sent, so the user may retry.
    pub fn release(&mut self, email: &str) {
        self.entries.remove(email);
    }

    /// Check a guess. A correct one consumes the entry and returns the app it
    /// was issued for; a wrong one costs an attempt.
    pub fn verify(&mut self, email: &str, guess: &str, now: Instant) -> Option<String> {
        self.expire(now);
        let entry = self.entries.get_mut(email)?;
        if entry.attempts_left == 0 {
            return None;
        }
        let guess = normalize_code(guess);
        if bool::from(entry.code.as_bytes().ct_eq(guess.as_bytes())) {
            return self.entries.remove(email).map(|entry| entry.app_id);
        }
        entry.attempts_left -= 1;
        None
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entry| now < entry.expires_at);
    }
}

impl Default for CodeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";

    fn code(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    #[test]
    fn generated_codes_use_the_alphabet() {
        for _ in 0..200 {
            let generated = generate_code();
            assert_eq!(generated.len(), CODE_LEN);
            assert!(generated.bytes().all(|byte| CODE_ALPHABET.contains(&byte)));
        }
        assert_ne!(*generate_code(), *generate_code());
    }

    #[test]
    fn every_symbol_is_reachable() {
        let mut seen = [false; 32];
        for _ in 0..200 {
            for byte in generate_code().bytes() {
                seen[CODE_ALPHABET.iter().position(|c| *c == byte).unwrap()] = true;
            }
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn normalization_ignores_case_whitespace_and_dashes() {
        assert_eq!(*normalize_code(" QPZ-ry9 x8g\n"), "qpzry9x8g");
    }

    #[test]
    fn a_correct_guess_returns_the_app_and_consumes_the_code() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        store.reserve("a@b.co", APP, code("qpzry9x8g"), now).unwrap();
        assert_eq!(store.verify("a@b.co", "QPZ-RY9X8G", now).as_deref(), Some(APP));
        assert_eq!(store.len(), 0);
        assert_eq!(store.verify("a@b.co", "qpzry9x8g", now), None);
    }

    #[test]
    fn unknown_addresses_are_rejected() {
        let mut store = CodeStore::new();
        assert_eq!(store.verify("nobody@b.co", "qpzry9x8g", Instant::now()), None);
    }

    #[test]
    fn three_wrong_guesses_exhaust_the_code_even_for_the_right_one() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        store.reserve("a@b.co", APP, code("qpzry9x8g"), now).unwrap();
        for _ in 0..3 {
            assert_eq!(store.verify("a@b.co", "00000000g", now), None);
        }
        assert_eq!(store.verify("a@b.co", "qpzry9x8g", now), None);
        assert_eq!(store.len(), 1, "an exhausted entry stays until it expires");
    }

    #[test]
    fn a_wrong_guess_leaves_the_code_usable() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        store.reserve("a@b.co", APP, code("qpzry9x8g"), now).unwrap();
        assert_eq!(store.verify("a@b.co", "wrong", now), None);
        assert_eq!(store.verify("a@b.co", "qpzry9x8g", now).as_deref(), Some(APP));
    }

    #[test]
    fn codes_expire() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        store.reserve("a@b.co", APP, code("qpzry9x8g"), now).unwrap();
        let later = now + CODE_TTL;
        assert_eq!(store.verify("a@b.co", "qpzry9x8g", later), None);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn a_new_code_waits_out_the_cooldown_then_replaces_the_old_one() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        store.reserve("a@b.co", APP, code("qpzry9x8g"), now).unwrap();
        assert_eq!(
            store.reserve("a@b.co", APP, code("2222222222"), now + Duration::from_secs(59)),
            Err(CodeError::Cooldown)
        );
        let later = now + RESEND_COOLDOWN;
        store.reserve("a@b.co", APP, code("2222222222"), later).unwrap();
        assert_eq!(store.verify("a@b.co", "qpzry9x8g", later), None);
        assert_eq!(store.verify("a@b.co", "2222222222", later).as_deref(), Some(APP));
    }

    #[test]
    fn exhausting_a_code_does_not_skip_the_cooldown() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        store.reserve("a@b.co", APP, code("qpzry9x8g"), now).unwrap();
        for _ in 0..3 {
            store.verify("a@b.co", "wrong", now);
        }
        assert_eq!(
            store.reserve("a@b.co", APP, code("2222222222"), now),
            Err(CodeError::Cooldown)
        );
    }

    #[test]
    fn a_failed_send_can_be_retried_at_once() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        store.reserve("a@b.co", APP, code("qpzry9x8g"), now).unwrap();
        store.release("a@b.co");
        assert!(store.reserve("a@b.co", APP, code("2222222222"), now).is_ok());
    }

    #[test]
    fn refuses_to_grow_past_the_cap_but_allows_replacing() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        for index in 0..MAX_CODES {
            store.reserve(&format!("u{index}@b.co"), APP, code("qpzry9x8g"), now).unwrap();
        }
        assert_eq!(
            store.reserve("extra@b.co", APP, code("qpzry9x8g"), now),
            Err(CodeError::AtCapacity)
        );
        assert!(store
            .reserve("u0@b.co", APP, code("qpzry9x8g"), now + RESEND_COOLDOWN)
            .is_ok());
    }

    #[test]
    fn expiry_frees_capacity() {
        let mut store = CodeStore::new();
        let now = Instant::now();
        for index in 0..MAX_CODES {
            store.reserve(&format!("u{index}@b.co"), APP, code("qpzry9x8g"), now).unwrap();
        }
        assert!(store.reserve("fresh@b.co", APP, code("qpzry9x8g"), now + CODE_TTL).is_ok());
        assert_eq!(store.len(), 1);
    }
}
