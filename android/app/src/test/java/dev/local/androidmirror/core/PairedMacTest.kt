package dev.local.androidmirror.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairedMacTest {
    @Test fun nameIsShown() = assertEquals("MacBook", PairedMac("id-1", "MacBook", 1L).displayName)

    @Test fun blankNameFallsBackToTheId() {
        assertEquals("id-1", PairedMac("id-1", "", 1L).displayName)
        assertEquals("id-1", PairedMac("id-1", "  ", 1L).displayName)
    }

    @Test fun aMissingOrBogusDateIsNotShownAs1970() {
        assertNull(PairedMac("id", "Mac", 0L).pairedAt)
        assertNull(PairedMac("id", "Mac", 1_700_000L).pairedAt) // seconds, or garbage
        assertEquals(1_764_000_000_000L, PairedMac("id", "Mac", 1_764_000_000_000L).pairedAt)
    }
}

class ParsePairedTest {
    @Test fun aListIsParsed() = assertEquals(
        listOf(PairedMac("a", "Mac A", 1_764_000_000_000L), PairedMac("b", "", 0L)),
        parsePaired("""[{"clientId":"a","clientName":"Mac A","pairedAtMs":1764000000000},{"clientId":"b"}]"""),
    )

    @Test fun aNullNameIsNoNameNotTheWordNull() {
        val mac = parsePaired("""[{"clientId":"a","clientName":null}]""")!!.single()
        assertEquals("", mac.clientName)
        assertEquals("a", mac.displayName)
    }

    @Test fun emptyIsEmpty() = assertEquals(emptyList<PairedMac>(), parsePaired("[]"))

    @Test fun anUnreadableStoreIsNotAnEmptyList() {
        assertNull(parsePaired(null))
        assertNull(parsePaired(""))
        assertNull(parsePaired("{"))
        assertNull(parsePaired("""[{"clientName":"no id"}]"""))
    }
}

class PairedMacNameTest {
    @Test fun aNameIsMadeSafeToShow() {
        assertEquals("x\\u202egnp.exe", PairedMac("id", "x‮gnp.exe", 1L).displayName)
        assertEquals("a".repeat(64) + "…", PairedMac("id", "a".repeat(100), 1L).displayName)
    }

    @Test fun anIdShownInsteadIsMadeSafeToo() =
        assertEquals("id\\u000aINFO", PairedMac("id\nINFO", "", 1L).displayName)
}
