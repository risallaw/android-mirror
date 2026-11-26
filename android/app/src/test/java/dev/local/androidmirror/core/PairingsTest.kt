package dev.local.androidmirror.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingsTest {
    private val other = PairedMac("other", "Other Mac", 1L)

    @Test fun removedAndGoneIsSuccess() = assertTrue(removeSucceeded(true, "mac", listOf(other)))

    @Test fun aFailedSaveIsReportedEvenThoughTheListNoLongerShowsTheMac() {
        // Running core: dropped from memory, then the save failed -> false, list without it.
        assertFalse(removeSucceeded(false, "mac", listOf(other)))
    }

    @Test fun stillListedIsAFailure() {
        assertFalse(removeSucceeded(true, "mac", listOf(other, PairedMac("mac", "Mac", 1L))))
        assertFalse(removeSucceeded(false, "mac", listOf(PairedMac("mac", "Mac", 1L))))
    }

    @Test fun anUnreadableListLeavesItToTheRevokeResult() {
        assertTrue(removeSucceeded(true, "mac", null))
        assertFalse(removeSucceeded(false, "mac", null))
    }
}
