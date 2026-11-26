package dev.local.androidmirror.service

import dev.local.androidmirror.core.CoreCallbacks.Companion.STATE_CONNECTING
import dev.local.androidmirror.core.CoreCallbacks.Companion.STATE_DISCONNECTED
import dev.local.androidmirror.core.CoreCallbacks.Companion.STATE_STREAMING
import dev.local.androidmirror.core.PairedMac
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MirrorStatusTest {
    private val base = MirrorStatus(phase = Phase.WAITING, ip = "192.168.1.2", port = 47800, pin = "123456")

    @Test
    fun notificationIgnoresWhatItDoesNotShow() {
        val changed = base.copy(
            pin = "654321",
            paired = listOf(PairedMac("id", "Mac", 1L)),
            pairingMessage = "Wrong PIN",
            error = "core error",
        )
        assertEquals(base.notificationFields(), changed.notificationFields())
        assertEquals("", changed.notificationFields().pin)
    }

    @Test
    fun notificationTracksWhatItShows() {
        val n = base.notificationFields()
        assertNotEquals(n, base.copy(phase = Phase.STREAMING).notificationFields())
        assertNotEquals(n, base.copy(ip = "10.0.0.2").notificationFields())
        assertNotEquals(n, base.copy(port = 1).notificationFields())
        assertNotEquals(n, base.copy(clientName = "Mac").notificationFields())
        assertNotEquals(n, base.copy(streamInfo = "1x1").notificationFields())
    }

    @Test
    fun thePinStaysOutOfToString() {
        assertFalse(base.toString().contains("123456"))
        assertTrue(base.toString().contains("<redacted>"))
    }

    @Test
    fun anUnreadableStoreIsNotAnEmptyList() {
        val s = base.withPaired(null)
        assertNull(s.paired)
        assertTrue(s.pairedUnreadable)
        val ok = s.withPaired(emptyList())
        assertEquals(emptyList<PairedMac>(), ok.paired)
        assertFalse(ok.pairedUnreadable)
    }
}

class ClientStateTest {
    private val waiting = MirrorStatus(phase = Phase.WAITING, ip = "192.168.1.2", port = 1, error = "old")

    @Test
    fun aClientConnectsStreamsAndLeaves() {
        val (connecting, t1) = applyClientState(waiting, 0, STATE_CONNECTING, 7, "MacBook")
        assertEquals(Phase.CONNECTING, connecting.phase)
        assertEquals("MacBook", connecting.clientName)
        assertNull(connecting.error)
        assertEquals(7L, t1)
        val (streaming, t2) = applyClientState(connecting, t1, STATE_STREAMING, 7, "MacBook")
        assertEquals(Phase.STREAMING, streaming.phase)
        val (left, t3) = applyClientState(streaming.copy(streamInfo = "1x1"), t2, STATE_DISCONNECTED, 7, null)
        assertEquals(Phase.WAITING, left.phase)
        assertNull(left.clientName)
        assertNull(left.streamInfo)
        assertEquals(0L, t3)
    }

    @Test
    fun aReplacedSessionCannotMoveTheStatus() {
        val (s, t) = applyClientState(waiting, 0, STATE_CONNECTING, 8, "New")
        assertEquals(s to t, applyClientState(s, t, STATE_DISCONNECTED, 7, null))
        assertEquals(s to t, applyClientState(s, t, STATE_STREAMING, 7, "Old"))
    }

    @Test
    fun aBlankNameShowsAsNoName() {
        assertNull(applyClientState(waiting, 0, STATE_CONNECTING, 1, "  ").first.clientName)
        assertNull(applyClientState(waiting, 0, STATE_CONNECTING, 1, "").first.clientName)
    }
}

class PeerTextTest {
    @Test fun plainTextIsKept() = assertEquals("MacBook Pro", peerText("MacBook Pro"))

    @Test fun controlAndBidiCharactersAreEscaped() {
        assertEquals("a\\u000aINFO fake", peerText("a\nINFO fake"))
        assertEquals("x\\u202egnp.exe", peerText("x\u202Egnp.exe"))
    }

    @Test fun longTextIsTruncated() {
        val t = peerText("a".repeat(100))!!
        assertEquals("a".repeat(64) + "…", t)
        assertEquals("a".repeat(64), peerText("a".repeat(64)))
    }

    @Test fun nullStaysNull() = assertNull(peerText(null))
}

class SessionGateTest {
    private val gate = SessionGate<String>()

    @Test
    fun aSecondShutdownCannotReplaceTheFirstOnesResult() {
        assertEquals(SessionGate.Start.NOW, gate.start("consent"))
        assertTrue(gate.beginShutdown()) // a failed start shuts down with ERROR...
        assertFalse(gate.beginShutdown())
        assertNull(gate.shutdownDone())
        // ...then the system's "projection stopped" report, or onDestroy, arrives.
        assertFalse(gate.beginShutdown())
    }

    @Test
    fun aStartWhileStoppingRunsWhenTheStopFinishes() {
        gate.start("first")
        gate.beginShutdown()
        assertEquals(SessionGate.Start.AFTER_STOP, gate.start("second"))
        assertEquals(SessionGate.Start.AFTER_STOP, gate.start("third")) // the newest consent wins
        assertEquals("third", gate.shutdownDone())
        assertFalse(gate.active)
        assertEquals(SessionGate.Start.NOW, gate.start("third"))
    }

    @Test
    fun aStartWhileRunningIsIgnored() {
        gate.start("first")
        assertEquals(SessionGate.Start.RUNNING, gate.start("second"))
        gate.beginShutdown()
        assertNull(gate.shutdownDone())
    }

    @Test
    fun nothingToShutDownWhenIdle() = assertFalse(gate.beginShutdown())

    /** A Mac can connect (and pair) before the service learns the core is up. */
    @Test
    fun coreEventsAreLiveFromTheStartUntilStop() {
        assertFalse(gate.eventsLive)
        gate.start("consent")
        assertTrue(gate.eventsLive)
        gate.beginShutdown()
        assertFalse(gate.eventsLive)
        gate.start("next") // deferred: the old session's events are still not live
        assertFalse(gate.eventsLive)
        gate.shutdownDone()
        assertFalse(gate.eventsLive)
    }
}

class NotificationActionTest {
    @Test
    fun stopIsOfferedUntilTheSessionIsStopping() {
        for (p in Phase.entries) assertEquals(p.name, p != Phase.STOPPING, offersStop(p))
    }
}

class NewPinOrderingTest {
    private val core = Any()

    @Test
    fun aResultAppliesOnlyToTheSessionAndCoreItWasAskedFor() {
        assertTrue(newPinResultApplies(startedGen = 2, gen = 2, live = true, startedCore = core, core = core))
        assertFalse(newPinResultApplies(2, 3, true, core, core)) // a newer session started
        assertFalse(newPinResultApplies(2, 2, false, core, core)) // stopping
        assertFalse(newPinResultApplies(2, 2, true, core, Any())) // another core
        assertFalse(newPinResultApplies(2, 2, true, core, null)) // shut down
    }

    /**
     * The server can rotate the PIN again (a lockout) between the New PIN call returning and its
     * result reaching the main thread; the PIN shown is the one the core holds now.
     */
    @Test
    fun theLiveCorePinIsShownNotTheReturnedOne() =
        assertEquals("333333", newPinToShow(applies = true, returned = "222222") { "333333" })

    @Test
    fun aStaleOrFailedResultShowsNoPin() {
        assertNull(newPinToShow(applies = false, returned = "222222") { error("not read") })
        assertNull(newPinToShow(applies = true, returned = null) { error("not read") })
    }

    /** A failure counted before a New PIN already applied (a smaller count) is stale: that New PIN cleared it. */
    @Test
    fun aPairingFailureFromBeforeANewPinIsNotShown() =
        assertFalse(pairingFailureApplies(live = true, resets = 1, pinResets = 2))

    /** No New PIN since (both 0 in a fresh session), or one counted against the new PIN: shown. */
    @Test
    fun aCurrentPairingFailureIsShown() {
        assertTrue(pairingFailureApplies(live = true, resets = 0, pinResets = 0))
        assertTrue(pairingFailureApplies(live = true, resets = 2, pinResets = 2))
        // The New PIN result not applied yet: its failures must not be dropped later either.
        assertTrue(pairingFailureApplies(live = true, resets = 3, pinResets = 2))
    }

    @Test
    fun aPairingFailureFromAnEndedSessionIsNotShown() =
        assertFalse(pairingFailureApplies(live = false, resets = 1, pinResets = 1))

    /**
     * The race the counts close: a failure counted before New PIN reaches the main thread after
     * the New PIN result. Either order ends with no stale message; a real post-reset one stays.
     */
    @Test
    fun aStaleFailureNeverOutlivesTheNewPinInEitherOrder() {
        val start = MirrorStatus(phase = Phase.WAITING, pin = "111111", newPinPending = true)
        fun failed(s: MirrorStatus, resets: Long) =
            if (pairingFailureApplies(true, resets, s.pinResets)) s.copy(pairingMessage = "Wrong PIN", pairingMessageResets = resets) else s
        // Failure (count 0) first, then the New PIN (count 1): the New PIN clears it.
        assertNull(withNewPin(failed(start, 0), "222222", 1).pairingMessage)
        // New PIN first: the failure is dropped.
        assertNull(failed(withNewPin(start, "222222", 1), 0).pairingMessage)
        // A failure against the new PIN is kept in both orders.
        assertEquals("Wrong PIN", withNewPin(failed(start, 1), "222222", 1).pairingMessage)
        assertEquals("Wrong PIN", failed(withNewPin(start, "222222", 1), 1).pairingMessage)
    }
}

class CoalescedTest {
    @Test
    fun aBurstOfRequestsRunsOnceAndALaterOneRunsAgain() {
        val posted = mutableListOf<Runnable>()
        var runs = 0
        val c = Coalesced({ posted += it }) { runs++ }
        repeat(5) { c.request() }
        assertEquals(1, posted.size)
        posted.removeAt(0).run()
        assertEquals(1, runs)
        c.request()
        assertEquals(1, posted.size)
    }

    @Test
    fun aRequestMadeWhileTheTaskRunsGetsARunOfItsOwn() {
        val posted = mutableListOf<Runnable>()
        lateinit var c: Coalesced
        var first = true
        c = Coalesced({ posted += it }) {
            if (first) {
                first = false
                c.request()
            }
        }
        c.request()
        posted.removeAt(0).run()
        assertEquals(1, posted.size)
    }
}

class SessionStateTest {
    private val starting = MirrorStatus(phase = Phase.STARTING, paired = emptyList())

    @Test
    fun theCoreComingUpMakesAStartingSessionWait() {
        val s = coreReady(starting, "192.168.1.2", 47800, "123456")
        assertEquals(MirrorStatus(phase = Phase.WAITING, ip = "192.168.1.2", port = 47800, pin = "123456", paired = emptyList()), s)
    }

    @Test
    fun aMacThatConnectedBeforeTheCoreWasReportedUpStaysShown() {
        val (connecting, _) = applyClientState(starting, 0, STATE_CONNECTING, 3, "MacBook")
        val s = coreReady(connecting.copy(pairingMessage = "Wrong PIN"), "10.0.0.2", 47800, "123456")
        assertEquals(Phase.CONNECTING, s.phase)
        assertEquals("MacBook", s.clientName)
        assertEquals("Wrong PIN", s.pairingMessage)
        assertEquals("10.0.0.2:47800", s.address)
        val streaming = coreReady(connecting.copy(phase = Phase.STREAMING), null, 1, "")
        assertEquals(Phase.STREAMING, streaming.phase)
    }

    @Test
    fun stoppingDropsThePinAndIsNotRunning() {
        val live = MirrorStatus(phase = Phase.WAITING, ip = "192.168.1.2", port = 1, pin = "123456", paired = emptyList())
        val s = stoppingStatus(live)
        assertEquals(Phase.STOPPING, s.phase)
        assertEquals("", s.pin)
        assertFalse(s.showPin)
        assertNull(s.address)
        assertFalse(s.running)
        assertEquals(emptyList<PairedMac>(), s.paired)
    }

    @Test
    fun runningCoversExactlyTheLivePhases() {
        val live = setOf(Phase.STARTING, Phase.WAITING, Phase.CONNECTING, Phase.STREAMING)
        for (p in Phase.entries) assertEquals(p.name, p in live, MirrorStatus(phase = p).running)
    }

    @Test
    fun aNewPinReplacesTheOldAndClearsTheLockoutMessage() {
        val locked = MirrorStatus(phase = Phase.WAITING, pin = "111111", pairingMessage = "Locked for 5 minutes", newPinPending = true)
        val s = withNewPin(locked, "222222", resets = 1)
        assertEquals("222222", s.pin)
        assertEquals(1L, s.pinResets)
        assertNull(s.pairingMessage)
        assertFalse(s.newPinPending)
        assertTrue(s.showPin)
    }

    @Test
    fun aNewPinFromAClosedCoreOnlyEndsThePendingState() {
        val pending = MirrorStatus(phase = Phase.WAITING, pin = "111111", pairingMessage = "Wrong PIN", newPinPending = true)
        assertEquals(pending.copy(newPinPending = false), withNewPin(pending, null, resets = 1))
    }

    /** A failure counted after the New PIN is against the new PIN: wiping it would hide a lockout. */
    @Test
    fun aNewPinKeepsAMessageCountedAfterIt() {
        val locked = MirrorStatus(phase = Phase.WAITING, pin = "111111", pairingMessage = "Locked", pairingMessageResets = 2, newPinPending = true)
        val s = withNewPin(locked, "222222", resets = 2)
        assertEquals("222222", s.pin)
        assertEquals("Locked", s.pairingMessage)
        assertFalse(s.newPinPending)
        assertNull(withNewPin(locked.copy(pairingMessageResets = 1), "222222", resets = 2).pairingMessage)
    }

    /** The applied count never goes back (a later failure must still be compared against the newest New PIN). */
    @Test
    fun theAppliedNewPinCountNeverDecreases() =
        assertEquals(3L, withNewPin(MirrorStatus(pinResets = 3), "222222", resets = 2).pinResets)
}

class LockoutPartsTest {
    @Test fun underAMinuteIsSecondsRoundedUp() {
        assertEquals(Triple(0L, 0L, 1L), lockoutParts(1))
        assertEquals(Triple(0L, 0L, 30L), lockoutParts(30_000))
        assertEquals(Triple(0L, 0L, 59L), lockoutParts(59_000))
    }

    @Test fun minutesAreRoundedUp() {
        assertEquals(Triple(0L, 1L, 0L), lockoutParts(60_000))
        assertEquals(Triple(0L, 2L, 0L), lockoutParts(60_001))
        assertEquals(Triple(0L, 5L, 0L), lockoutParts(300_000))
    }

    @Test fun hoursAndMinutes() {
        assertEquals(Triple(1L, 0L, 0L), lockoutParts(3_600_000))
        assertEquals(Triple(1L, 30L, 0L), lockoutParts(5_400_000))
        assertEquals(Triple(24L, 0L, 0L), lockoutParts(86_400_000))
    }

    @Test fun nothingNegative() = assertEquals(Triple(0L, 0L, 0L), lockoutParts(-5))
}

class PeerTextSurrogateTest {
    private val face = "😀" // one code point, two chars

    @Test fun aPairIsNeverSplitAtTheLimit() {
        val t = peerText("a".repeat(63) + face)!!
        assertEquals("a".repeat(63) + "…", t)
        assertFalse(t.any { Character.isSurrogate(it) })
    }

    @Test fun aPairThatFitsIsKept() = assertEquals("a".repeat(62) + face, peerText("a".repeat(62) + face))

    @Test fun aLoneSurrogateIsEscaped() {
        assertEquals("x\\ud83d", peerText("x\uD83D"))
        assertEquals("\\ude00y", peerText("\uDE00y"))
    }

    /** Braced, so "\\u{e0001}" cannot be read as "\\ue000" followed by "1". */
    @Test fun supplementaryFormatCharactersAreEscaped() = assertEquals("a\\u{e0001}1", peerText("a\uDB40\uDC011"))

    @Test fun anEscapeNeverOverrunsTheLimit() {
        assertEquals("a".repeat(60) + "…", peerText("a".repeat(60) + "\n"))
        assertEquals("a".repeat(58) + "\\u000a", peerText("a".repeat(58) + "\n"))
        assertEquals("a".repeat(56) + "…", peerText("a".repeat(56) + "\uDB40\uDC01"))
        assertEquals("a".repeat(55) + "\\u{e0001}", peerText("a".repeat(55) + "\uDB40\uDC01"))
    }
}
