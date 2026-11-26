package dev.local.androidmirror.control

/**
 * Text and key input waiting for the text thread, in arrival order. Adjacent text is merged
 * (one commit or ACTION_SET_TEXT instead of one per character, each a cross-process call), and
 * the queue is bounded so a target app that blocks every call cannot grow it without limit:
 * input beyond [maxOps] entries or [maxChars] characters is dropped, except that an empty queue
 * always takes one op (one TEXT message is bounded by the protocol). Merging stops at
 * [maxMergeChars] per op so one IME commit stays well under the binder limit (ACTION_SET_TEXT
 * carries the whole field, so the injector caps that separately: see [fitsSetText]).
 * Dropping is sticky until the queue drains empty, so a gap is never followed by more queued
 * text or keys; and a key arriving within [keyQuietNanos] of the last drop is refused too, so a
 * human pressing Enter right after a truncated paste can't submit a field with a hole in it.
 * Thread-safe.
 */
internal class InputQueue(
    private val maxOps: Int,
    private val maxChars: Int,
    private val maxMergeChars: Int = MAX_MERGE_CHARS,
    private val keyQuietNanos: Long = KEY_QUIET_NANOS,
    private val now: () -> Long = System::nanoTime,
) {
    sealed interface Op {
        data class Text(val text: String) : Op
        data class Key(val key: Int) : Op
    }

    enum class Offer {
        /** Queued, and no drain is pending: schedule one. */
        DRAIN,

        /** Queued for the drain already pending. */
        QUEUED,

        /** Dropped: the queue is full (the target is not keeping up), or it was since it was last empty. */
        DROPPED,

        /** Dropped: earlier input reached no field ([noteDrop]); this would land after the hole. */
        DROPPED_AFTER_LOSS,
    }

    private val ops = ArrayDeque<Op>()
    private var chars = 0
    private var draining = false
    private var dropping = false
    private var lastDropAt: Long? = null

    /** Why input is being dropped: [Offer.DROPPED] or [Offer.DROPPED_AFTER_LOSS]. */
    private var dropCause = Offer.DROPPED

    @Synchronized
    fun offer(op: Op): Offer {
        val last = ops.lastOrNull()
        val addChars = (op as? Op.Text)?.text?.length ?: 0
        val merge = op is Op.Text && last is Op.Text && last.text.length + addChars <= maxMergeChars
        if (dropping) return drop()
        if (op is Op.Key && lastDropAt?.let { now() - it < keyQuietNanos } == true) return dropCause
        if (ops.isNotEmpty() && (chars + addChars > maxChars || (!merge && ops.size >= maxOps))) {
            dropping = true
            dropCause = Offer.DROPPED
            return drop()
        }
        if (merge) ops[ops.lastIndex] = Op.Text((last as Op.Text).text + (op as Op.Text).text) else ops.addLast(op)
        chars += addChars
        if (draining) return Offer.QUEUED
        draining = true
        return Offer.DRAIN
    }

    /** The next op, or null when empty (the drain then ends: the next offer schedules a new one). */
    @Synchronized
    fun poll(): Op? {
        val op = ops.removeFirstOrNull()
        if (op == null) {
            draining = false
            dropping = false
        } else if (op is Op.Text) chars -= op.text.length
        return op
    }

    /**
     * The injector could not deliver an op (no focused field): everything queued after it would
     * land after a hole, so discard it, and refuse a key right after (an Enter) like any drop.
     */
    @Synchronized
    fun noteDrop() {
        ops.clear()
        chars = 0
        dropping = true // input arriving before this drain ends belongs after the hole too
        dropCause = Offer.DROPPED_AFTER_LOSS
        lastDropAt = now()
    }

    private fun drop(): Offer {
        lastDropAt = now()
        return dropCause
    }

    @Synchronized
    fun clear() {
        ops.clear()
        chars = 0
        dropping = false
        lastDropAt = null
    }

    companion object {
        /** Covers a whole Mac paste (`MAX_PASTE_BYTES` = 1 MiB; UTF-16 units ≤ UTF-8 bytes): ≤ 2 MB. */
        const val MAX_CHARS = 1024 * 1024

        /** One TEXT message (64 KiB): 128 KB of UTF-16, well below the ~512 KB one-way binder buffer. */
        const val MAX_MERGE_CHARS = 64 * 1024

        /** Keys arriving this soon after a drop are refused (a human Enter after a truncated paste). */
        const val KEY_QUIET_NANOS = 1_000_000_000L
    }
}
