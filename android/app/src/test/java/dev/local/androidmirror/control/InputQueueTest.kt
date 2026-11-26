package dev.local.androidmirror.control

import dev.local.androidmirror.control.InputQueue.Offer
import dev.local.androidmirror.control.InputQueue.Op
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InputQueueTest {
    private fun InputQueue.drain(): List<Op> = generateSequence { poll() }.toList()

    @Test
    fun firstOfferSchedulesOneDrainAndLaterOffersJoinIt() {
        val q = InputQueue(maxOps = 8, maxChars = 100)
        assertEquals(Offer.DRAIN, q.offer(Op.Key(1)))
        assertEquals(Offer.QUEUED, q.offer(Op.Text("a")))
        assertEquals(listOf(Op.Key(1), Op.Text("a")), q.drain())
        // The drain saw the queue empty, so the next offer must schedule a new one.
        assertEquals(Offer.DRAIN, q.offer(Op.Text("b")))
    }

    @Test
    fun adjacentTextIsCoalescedButKeysKeepTheirPlace() {
        val q = InputQueue(maxOps = 8, maxChars = 100)
        listOf(Op.Text("a"), Op.Text("b"), Op.Key(1), Op.Text("c"), Op.Text("d")).forEach { q.offer(it) }
        assertEquals(listOf(Op.Text("ab"), Op.Key(1), Op.Text("cd")), q.drain())
    }

    @Test
    fun aStuckTargetCannotGrowTheQueueWithoutBound() {
        val q = InputQueue(maxOps = 2, maxChars = 3)
        q.offer(Op.Key(1))
        q.offer(Op.Text("ab"))
        assertEquals(Offer.DROPPED, q.offer(Op.Text("cd"))) // 4 chars > 3
        assertEquals(listOf(Op.Key(1), Op.Text("ab")), q.drain())
        // Room again once drained.
        assertEquals(Offer.DRAIN, q.offer(Op.Text("xyz")))
    }

    @Test
    fun theOpCountIsBounded() {
        val q = InputQueue(maxOps = 2, maxChars = 100)
        q.offer(Op.Key(1))
        q.offer(Op.Key(2))
        assertEquals(Offer.DROPPED, q.offer(Op.Key(3)))
    }

    @Test
    fun anEmptyQueueTakesOneOpLargerThanTheCharBudget() {
        // A single TEXT message (≤ 64 KiB by protocol) must never be lost just for its size.
        val q = InputQueue(maxOps = 2, maxChars = 3)
        val paste = "x".repeat(10)
        assertEquals(Offer.DRAIN, q.offer(Op.Text(paste)))
        assertEquals(Offer.DROPPED, q.offer(Op.Text("y")))
        assertEquals(listOf(Op.Text(paste)), q.drain())
    }

    @Test
    fun afterADropEverythingIsDroppedUntilTheQueueDrainsEmpty() {
        var t = 0L
        val q = InputQueue(maxOps = 8, maxChars = 3, now = { t })
        q.offer(Op.Text("abc"))
        assertEquals(Offer.DROPPED, q.offer(Op.Text("de")))
        // Would fit the budget, but following a hole it must not run: no Enter after a gap.
        assertEquals(Offer.DROPPED, q.offer(Op.Key(2)))
        assertEquals(Offer.DROPPED, q.offer(Op.Text("f")))
        assertEquals(Op.Text("abc"), q.poll())
        assertEquals(Offer.DROPPED, q.offer(Op.Key(2))) // still sticky until the drain sees empty
        assertNull(q.poll())
        t += InputQueue.KEY_QUIET_NANOS
        assertEquals(Offer.DRAIN, q.offer(Op.Key(2)))
    }

    @Test
    fun aWholeMacPasteFitsTheProductionBudget() {
        // The Mac sends up to 1 MiB as 16 TEXT messages of 64 KiB, back to back, while the text
        // thread may still be busy with the first: none of it may be dropped.
        val q = InputQueue(maxOps = 256, maxChars = InputQueue.MAX_CHARS)
        val chunk = "x".repeat(64 * 1024)
        repeat(16) { assertNotEquals("chunk $it", Offer.DROPPED, q.offer(Op.Text(chunk))) }
        val ops = q.drain()
        assertEquals(16 * 64 * 1024, ops.sumOf { (it as Op.Text).text.length })
        // Merging is capped per op, so no single commit carries the whole paste over binder.
        assertTrue(ops.all { (it as Op.Text).text.length <= InputQueue.MAX_MERGE_CHARS })
    }

    @Test
    fun aKeyRightAfterADropIsRefusedEvenOnceTheBacklogIsTyped() {
        var t = 0L
        val q = InputQueue(maxOps = 8, maxChars = 3, now = { t })
        q.offer(Op.Text("abc"))
        assertEquals(Offer.DROPPED, q.offer(Op.Text("de"))) // truncated paste
        assertEquals(Op.Text("abc"), q.poll())
        assertNull(q.poll()) // backlog typed: sticky ends
        t += InputQueue.KEY_QUIET_NANOS / 2
        assertEquals(Offer.DROPPED, q.offer(Op.Key(2))) // the user's Enter half a second later
        assertEquals(Offer.DRAIN, q.offer(Op.Text("f"))) // typing itself goes on
        q.poll()
        t += InputQueue.KEY_QUIET_NANOS
        assertNull(q.poll())
        assertEquals(Offer.DRAIN, q.offer(Op.Key(2)))
    }

    @Test
    fun clearEndsDropping() {
        val q = InputQueue(maxOps = 1, maxChars = 100)
        q.offer(Op.Key(1))
        assertEquals(Offer.DROPPED, q.offer(Op.Key(2)))
        q.clear()
        assertEquals(Offer.QUEUED, q.offer(Op.Key(3))) // the drain already scheduled takes it
    }

    @Test
    fun clearDropsPendingInput() {
        val q = InputQueue(maxOps = 8, maxChars = 100)
        q.offer(Op.Text("secret"))
        q.clear()
        assertNull(q.poll())
        assertEquals(Offer.DRAIN, q.offer(Op.Text("x")))
    }

    @Test
    fun anUndeliveredOpFencesTheRestOfTheBacklogAndTheNextKey() {
        var t = 0L
        val q = InputQueue(maxOps = 8, maxChars = 100, now = { t })
        q.offer(Op.Text("a"))
        q.offer(Op.Text("b"))
        assertEquals(Op.Text("ab"), q.poll())
        q.offer(Op.Key(2)) // Enter queued behind the text
        q.noteDrop() // "ab" found no focused field
        assertNull(q.poll()) // the queued Enter must not run after the hole
        // Nor one arriving right after; named as a loss, not as a target that can't keep up.
        assertEquals(Offer.DROPPED_AFTER_LOSS, q.offer(Op.Key(2)))
        t += InputQueue.KEY_QUIET_NANOS
        assertEquals(Offer.DRAIN, q.offer(Op.Key(2)))
    }

    @Test
    fun aFullQueueAfterAnEarlierLossIsNamedAsBusy() {
        var t = 0L
        val q = InputQueue(maxOps = 1, maxChars = 100, now = { t })
        q.offer(Op.Text("a"))
        q.noteDrop()
        assertNull(q.poll())
        t += InputQueue.KEY_QUIET_NANOS
        q.offer(Op.Key(1))
        assertEquals(Offer.DROPPED, q.offer(Op.Key(1))) // full: the cause is the backlog now
        assertEquals(Offer.DROPPED, q.offer(Op.Key(1)))
    }

    @Test
    fun mergingStopsExactlyAtTheCap() {
        val q = InputQueue(maxOps = 8, maxChars = 100, maxMergeChars = 4)
        q.offer(Op.Text("abc"))
        q.offer(Op.Text("d")) // 4: merges
        q.offer(Op.Text("e")) // 5: new op
        assertEquals(listOf(Op.Text("abcd"), Op.Text("e")), q.drain())
    }

    @Test
    fun setTextIsOnlyUsedForFieldsThatFitTheBinderBuffer() {
        assertTrue(fitsSetText(MAX_SET_TEXT_CHARS - 1, 1))
        assertFalse(fitsSetText(MAX_SET_TEXT_CHARS, 1))
        assertFalse(fitsSetText(Int.MAX_VALUE, Int.MAX_VALUE))
    }

    @Test
    fun afterAnUndeliveredOpLateArrivalsOfTheSameBacklogAreDropped() {
        val q = InputQueue(maxOps = 8, maxChars = 100)
        q.offer(Op.Text("a"))
        assertEquals(Op.Text("a"), q.poll()) // drain in progress
        q.noteDrop() // "a" reached no field
        assertEquals(Offer.DROPPED_AFTER_LOSS, q.offer(Op.Text("b"))) // rest of the paste, mid-drain
        assertNull(q.poll()) // drain ends
        assertEquals(Offer.DRAIN, q.offer(Op.Text("c"))) // new typing works again
    }

    @Test
    fun theNodePathStopsBeforeAFieldGetsTooLargeToRead() {
        assertTrue(fitsNodeField(MAX_NODE_FIELD_CHARS - 1, 1))
        assertFalse(fitsNodeField(MAX_NODE_FIELD_CHARS, 1))
        assertTrue(MAX_SET_TEXT_CHARS <= MAX_NODE_FIELD_CHARS)
    }
}
