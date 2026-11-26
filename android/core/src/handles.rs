//! The `jlong` handles `nativeCreate` gives Kotlin.
//!
//! A handle is a key into a table, not a pointer: a stale, repeated or
//! forged handle (say a `nativeDestroy` racing another call if Kotlin's
//! locking ever slips) finds nothing instead of touching freed memory, and
//! a call in flight keeps its object alive through its own `Arc`. Handles
//! start at 1 (0 means "no core" to Kotlin) and are never reused. Pure so it
//! is tested on the host.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

pub struct Handles<T> {
    inner: Mutex<Inner<T>>,
}

struct Inner<T> {
    next: i64,
    live: BTreeMap<i64, Arc<T>>,
}

impl<T> Handles<T> {
    pub const fn new() -> Self {
        Handles {
            inner: Mutex::new(Inner {
                next: 1,
                live: BTreeMap::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Store `value`; returns its new, never-zero handle.
    pub fn insert(&self, value: T) -> i64 {
        let mut g = self.lock();
        let h = g.next;
        g.next += 1;
        g.live.insert(h, Arc::new(value));
        h
    }

    /// The object behind a live handle.
    pub fn get(&self, handle: i64) -> Option<Arc<T>> {
        self.lock().live.get(&handle).cloned()
    }

    /// Take the object out; later `get`/`remove` calls with `handle` find
    /// nothing.
    pub fn remove(&self, handle: i64) -> Option<Arc<T>> {
        self.lock().live.remove(&handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_nonzero_unique_and_die_once() {
        let t = Handles::new();
        let a = t.insert("a");
        let b = t.insert("b");
        assert!(a != 0 && b != 0 && a != b);
        assert_eq!(t.get(0), None);
        assert_eq!(t.get(a).as_deref(), Some(&"a"));
        assert_eq!(t.remove(a).as_deref(), Some(&"a"));
        // A destroyed (or repeated) handle is never valid again.
        assert_eq!(t.get(a), None);
        assert_eq!(t.remove(a), None);
        assert_eq!(t.get(b).as_deref(), Some(&"b"));
        let c = t.insert("c");
        assert!(c != a && c != b, "handles are never reused");
        assert_eq!(t.get(-1), None);
    }

    #[test]
    fn a_call_in_flight_keeps_its_object() {
        let t = Handles::new();
        let h = t.insert(String::from("core"));
        let held = t.get(h).unwrap();
        drop(t.remove(h));
        assert_eq!(*held, "core");
    }
}
