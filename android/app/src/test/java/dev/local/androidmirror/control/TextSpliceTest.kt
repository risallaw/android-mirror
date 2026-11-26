package dev.local.androidmirror.control

import com.ibm.icu.text.BreakIterator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ICU rules Android's java.text.BreakIterator uses on a device. The host JDK only knows emoji
 * ZWJ sequences and flags from 20 on, so the tests use ICU4J rather than depend on the build JDK.
 */
private object IcuGraphemes : Graphemes {
    override fun preceding(text: String, offset: Int): Int = BreakIterator.getCharacterInstance().run {
        setText(text)
        preceding(offset).let { if (it == BreakIterator.DONE) 0 else it }
    }

    override fun following(text: String, offset: Int): Int = BreakIterator.getCharacterInstance().run {
        setText(text)
        following(offset).let { if (it == BreakIterator.DONE) text.length else it }
    }
}

private fun splice(current: String, selStart: Int, selEnd: Int, insert: String, backspace: Int, delete: Int) =
    splice(current, selStart, selEnd, insert, backspace, delete, IcuGraphemes)

class TextSpliceTest {
    private fun bs(t: String, at: Int = t.length) = splice(t, at, at, "", 1, 0)

    @Test fun backspaceAscii() = assertEquals(SpliceResult("ab", 2), bs("abc"))

    @Test fun backspaceZwjEmoji() {
        val family = "👨‍👩‍👧" // man ZWJ woman ZWJ girl
        assertEquals(SpliceResult("a", 1), bs("a$family"))
    }

    @Test fun backspaceFlag() {
        val flag = "🇯🇵" // JP
        assertEquals(SpliceResult("x", 1), bs("x$flag"))
    }

    @Test fun backspaceCombiningMark() = assertEquals(SpliceResult("a", 1), bs("aé"))

    @Test fun backspaceMidText() = assertEquals(SpliceResult("ac", 1), splice("abc", 2, 2, "", 1, 0))

    @Test fun deleteForwardEmojiSequence() {
        val family = "👨‍👩‍👧"
        assertEquals(SpliceResult("ab", 1), splice("a${family}b", 1, 1, "", 0, 1))
    }

    @Test fun backspaceAtStartAndDeleteAtEndAreNoOps() {
        assertNull(bs("abc", 0))
        assertNull(splice("abc", 3, 3, "", 0, 1))
    }

    @Test fun selectionReplaced() = assertEquals(SpliceResult("aXc", 2), splice("abc", 1, 2, "X", 0, 0))

    @Test fun reversedSelection() = assertEquals(SpliceResult("aXc", 2), splice("abc", 2, 1, "X", 0, 0))

    @Test fun noSelectionAppends() = assertEquals(SpliceResult("abcd", 4), splice("abc", -1, -1, "d", 0, 0))

    @Test fun insertAtCaret() = assertEquals(SpliceResult("a😀bc", 3), splice("abc", 1, 1, "😀", 0, 0))

    @Test fun platformGraphemesKeepSurrogatePairsWhole() {
        // What every JDK handles; the device's ICU covers the rest (see IcuGraphemes).
        assertEquals(SpliceResult("a", 1), splice("a😀", 3, 3, "", 1, 0, PlatformGraphemes))
        assertEquals(SpliceResult("ab", 1), splice("a😀b", 1, 1, "", 0, 1, PlatformGraphemes))
    }
}

/** Password fields expose only masked text, so edits are computed from what is known about the field. */
class PasswordSpliceTest {
    private fun edit(known: String?, length: Int, s: Int, e: Int, insert: String, bs: Int = 0, del: Int = 0) =
        passwordBase(known, length, s, e)?.let { splice(it, s, e, insert, bs, del) }

    @Test fun emptyFieldIsSetDirectly() = assertEquals(SpliceResult("p", 1), edit(null, 0, 0, 0, "p"))

    @Test fun emptyFieldWithoutSelectionIsSetDirectly() = assertEquals(SpliceResult("p", 1), edit(null, 0, -1, -1, "p"))

    @Test fun fullySelectedFieldIsReplacedWithoutReadingIt() =
        assertEquals(SpliceResult("new", 3), edit(null, 4, 0, 4, "new"))

    @Test fun reversedFullSelectionIsReplaced() = assertEquals(SpliceResult("x", 1), edit(null, 2, 2, 0, "x"))

    @Test fun backspaceOnFullSelectionEmptiesIt() = assertEquals(SpliceResult("", 0), edit(null, 4, 0, 4, "", bs = 1))

    @Test fun whatWeTypedIsAppendedTo() = assertEquals(SpliceResult("pw1", 3), edit("pw", 2, 2, 2, "1"))

    @Test fun whatWeTypedIsAppendedToWithoutSelection() = assertEquals(SpliceResult("pw1", 3), edit("pw", 2, -1, -1, "1"))

    @Test fun backspaceOnWhatWeTyped() = assertEquals(SpliceResult("p", 1), edit("pw", 2, 2, 2, "", bs = 1))

    @Test fun unknownContentIsNotGuessed() {
        assertNull(passwordBase(null, 3, 3, 3)) // someone else typed it
        assertNull(passwordBase("pw", 3, 3, 3)) // it changed since we set it
        assertNull(passwordBase(null, 3, 0, 2)) // partial selection
        assertNull(passwordBase(null, 3, -1, -1))
    }

    @Test fun aFieldThatHidesItsLengthIsNotTakenForEmpty() {
        assertNull(passwordBase(null, null, 0, 0)) // no text reported at all
        assertNull(passwordBase("pw", null, 2, 2))
        assertNull(passwordBase(null, 0, 5, 5)) // "empty", yet the caret is at 5
    }
}

class PasswordMemoryTest {
    private val field = "field"
    private val mem = PasswordMemory<String>()

    @Test fun ourOwnSetTextEchoKeepsWhatWeKnow() {
        mem.remember(field, "pw", previousLength = 0)
        mem.onTextChanged(fromIndex = 0, removed = 0, added = 2)
        assertEquals("pw", mem.base(field, 2, 2, 2))
    }

    @Test fun anEditOnThePhoneOfTheSameLengthIsNotSplicedInto() {
        mem.remember(field, "pw", previousLength = 0)
        mem.onTextChanged(0, 0, 2) // our echo
        mem.onTextChanged(1, 1, 0) // the user deleted "w" on the phone...
        mem.onTextChanged(1, 0, 1) // ...and typed another character: still 2 long
        assertNull(mem.base(field, 2, 2, 2))
    }

    @Test fun anEditBeforeOurEchoArrivesIsNotTakenForIt() {
        mem.remember(field, "pw", previousLength = 0)
        mem.onTextChanged(1, 1, 1) // the user replaced a character before our echo came in
        assertNull(mem.base(field, 2, 2, 2))
    }

    @Test fun echoesOfBackToBackSetsAreMatchedInOrder() {
        mem.remember(field, "p", 0)
        mem.remember(field, "pw", 1)
        mem.onTextChanged(0, 0, 1)
        mem.onTextChanged(0, 1, 2)
        assertEquals("pw", mem.base(field, 2, 2, 2))
    }

    @Test fun anotherFieldIsUnknown() {
        mem.remember(field, "pw", 0)
        assertNull(mem.base("other", 2, 2, 2))
    }

    @Test fun forgetIsFinal() {
        mem.remember(field, "pw", 0)
        mem.forget()
        assertNull(mem.base(field, 2, 2, 2))
        mem.onTextChanged(0, 0, 2) // a late echo brings nothing back
        assertNull(mem.base(field, 2, 2, 2))
    }
}

class PasswordMemorySubscriptionTest {
    private var unsubscribed = 0
    private val mem = PasswordMemory<String>(onForget = { unsubscribed++ })

    @Test fun holdsTextOnlyBetweenRememberAndForget() {
        assertFalse(mem.holdsText)
        mem.remember("f", "pw", 0)
        assertTrue(mem.holdsText)
        mem.forget()
        assertFalse(mem.holdsText)
    }

    @Test fun forgettingWhatItKnewUnsubscribesOnce() {
        mem.remember("f", "pw", 0)
        mem.forget()
        mem.forget()
        assertEquals(1, unsubscribed)
    }

    @Test fun anUnmatchedChangeUnsubscribes() {
        mem.remember("f", "pw", 0)
        mem.onTextChanged(1, 1, 1)
        assertEquals(1, unsubscribed)
        assertFalse(mem.holdsText)
    }

    @Test fun ourEchoKeepsTheSubscription() {
        mem.remember("f", "pw", 0)
        mem.onTextChanged(0, 0, 2)
        assertEquals(0, unsubscribed)
    }

    @Test fun withoutTheSubscriptionNothingIsRemembered() {
        mem.remember("f", "pw", 0, watching = false)
        assertFalse(mem.holdsText)
        assertNull(mem.base("f", 2, 2, 2))
    }

    @Test fun losingTheSubscriptionForgetsWhatItKnew() {
        mem.remember("f", "p", 0)
        mem.remember("f", "pw", 1, watching = false) // the echo of this set could be missed
        assertFalse(mem.holdsText)
        assertNull(mem.base("f", 2, 2, 2))
        assertEquals(1, unsubscribed)
    }

    @Test fun moreSetsThanEchoesItCanTrackForgetsWhatItKnew() {
        var text = ""
        repeat(17) {
            val before = text.length
            text += "x"
            mem.remember("f", text, before)
        }
        // An expected echo was dropped: the next event could not be told apart from a phone edit.
        assertFalse(mem.holdsText)
        assertNull(mem.base("f", 17, 17, 17))
        assertEquals(1, unsubscribed)
    }

    @Test fun asManySetsAsEchoesItCanTrackAreKept() {
        var text = ""
        repeat(16) {
            val before = text.length
            text += "x"
            mem.remember("f", text, before)
        }
        for (n in 0 until 16) mem.onTextChanged(0, n, n + 1)
        assertEquals(text, mem.base("f", 16, 16, 16))
    }

    @Test fun forgettingNothingDoesNotUnsubscribe() {
        mem.forget()
        assertEquals(0, unsubscribed)
    }
}

class KeyEditsTextTest {
    @Test fun onlyKeysThatChangeTextLeaveAHole() {
        assertEquals(listOf(1, 7), (0..9).filter { keyEditsText(it) })
    }
}
