//! Allocation-count checks (own test binary: it installs a global allocator).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use mirror_protocol::codec::encode_into;
use mirror_protocol::{Message, VideoFrame};

/// Counts only allocations of at least 64 KiB, so test-harness noise on
/// other threads cannot disturb the count.
struct Counting;
static BIG_ALLOCS: AtomicUsize = AtomicUsize::new(0);
/// The counter is global: tests that read it must not run concurrently.
static SERIAL: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() >= 64 * 1024 {
            BIG_ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn encoding_a_video_frame_does_not_copy_the_payload() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let msg = Message::VideoFrame(VideoFrame {
        pts_us: 1,
        flags: 0,
        data: vec![7; 1 << 20],
    });
    let mut out = Vec::with_capacity(2 << 20);
    let before = BIG_ALLOCS.load(Ordering::Relaxed);
    encode_into(&msg, &mut out);
    assert_eq!(BIG_ALLOCS.load(Ordering::Relaxed) - before, 0);
    assert_eq!(out.len(), 16 + (1 << 20));
}

#[test]
fn sealing_a_video_frame_allocates_the_record_once() {
    use mirror_protocol::secure::{Sealer, SecretKey};
    // The tag is reserved up front: appending it must not reallocate (and
    // copy) the whole record. Matters for frames larger than the sender's
    // retained write buffer, which start from a smaller capacity each time.
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let msg = Message::VideoFrame(VideoFrame {
        pts_us: 1,
        flags: 0,
        data: vec![7; 1 << 20],
    });
    let mut sealer = Sealer::new(
        &SecretKey::from_bytes([1; 32]),
        mirror_protocol::MAX_PAYLOAD,
    );
    for start_cap in [0, 64 * 1024] {
        let mut out = Vec::with_capacity(start_cap);
        let before = BIG_ALLOCS.load(Ordering::Relaxed);
        sealer.seal_message(&msg, &mut out).unwrap();
        let allocs = BIG_ALLOCS.load(Ordering::Relaxed) - before;
        assert_eq!(allocs, 1, "start capacity {start_cap}");
        assert_eq!(out.len(), 4 + 16 + (1 << 20) + 16);
    }
}

#[test]
fn iterating_nals_does_not_allocate() {
    use mirror_protocol::annexb::{nal_type, nals};
    // 10 000 tiny NALs: a collected Vec<Range> would be 160 KB.
    let au: Vec<u8> = (0..10_000).flat_map(|_| [0, 0, 1, 0x41, 7]).collect();
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let before = BIG_ALLOCS.load(Ordering::Relaxed);
    let n = nals(&au).filter(|n| nal_type(n) == Some(1)).count();
    assert_eq!(BIG_ALLOCS.load(Ordering::Relaxed) - before, 0);
    assert_eq!(n, 10_000);
}
