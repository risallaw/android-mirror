package dev.local.androidmirror.control

import java.text.BreakIterator

/** Result of [splice]: the new text and where the caret goes. */
data class SpliceResult(val text: String, val caret: Int)

/** Grapheme-cluster (user-perceived character) boundaries. */
interface Graphemes {
    /** The last boundary before [offset] (0 if none). */
    fun preceding(text: String, offset: Int): Int

    /** The first boundary after [offset] (the text length if none). */
    fun following(text: String, offset: Int): Int
}

/**
 * Android's java.text.BreakIterator is ICU-backed and knows emoji ZWJ sequences and flags. (Host JDKs
 * before 20 do not, which is why the unit tests pass a full ICU4J implementation instead.)
 */
object PlatformGraphemes : Graphemes {
    override fun preceding(text: String, offset: Int): Int =
        BreakIterator.getCharacterInstance().run {
            setText(text)
            preceding(offset).let { if (it == BreakIterator.DONE) 0 else it }
        }

    override fun following(text: String, offset: Int): Int =
        BreakIterator.getCharacterInstance().run {
            setText(text)
            following(offset).let { if (it == BreakIterator.DONE) text.length else it }
        }
}

/**
 * Replace the selection [selStart]..[selEnd] (or, when it is empty, [backspace] / [delete] grapheme
 * clusters before / after the caret) with [insert]. Negative selection means "append at the end".
 * Returns null when there is nothing to do.
 */
fun splice(
    current: String,
    selStart: Int,
    selEnd: Int,
    insert: String,
    backspace: Int,
    delete: Int,
    graphemes: Graphemes = PlatformGraphemes,
): SpliceResult? {
    var start = if (selStart < 0 || selEnd < 0) current.length else minOf(selStart, selEnd)
    var end = if (selStart < 0 || selEnd < 0) current.length else maxOf(selStart, selEnd)
    start = start.coerceIn(0, current.length)
    end = end.coerceIn(0, current.length)
    if (start == end) {
        if (backspace > 0 && start > 0) start = graphemes.preceding(current, start)
        if (delete > 0 && end < current.length) end = graphemes.following(current, end)
    }
    if (start == end && insert.isEmpty()) return null
    return SpliceResult(current.substring(0, start) + insert + current.substring(end), start + insert.length)
}

/**
 * What a password field holds, as far as it can be known without reading it (its node text is
 * masked; only its [length] is real, and null when the node reports no text at all): "" when
 * empty, [known] (what we last set on this field) while the length still matches it, or, when the
 * whole field is selected, a placeholder of that length (every character is replaced, so the
 * content does not matter). Null when unknown. A reported length of 0 with the caret past 0 is
 * not trusted as empty: that field hides even its length, and setting it would wipe its content.
 */
fun passwordBase(known: String?, length: Int?, selStart: Int, selEnd: Int): String? = when {
    length == null -> null
    length == 0 -> "".takeIf { maxOf(selStart, selEnd) <= 0 }
    known != null && known.length == length -> known
    minOf(selStart, selEnd) == 0 && maxOf(selStart, selEnd) == length -> "\u2022".repeat(length)
    else -> null
}

/**
 * What we last set on a password field (whose node text is masked), so the next edit can be spliced
 * into it; see [passwordBase]. Forgotten as soon as the field changes in any way other than the
 * echo of our own ACTION_SET_TEXT: an edit made on the phone can keep the length (one character
 * deleted, one typed), and splicing into the stale copy would then overwrite it. Text thread only.
 */
internal class PasswordMemory<N : Any>(private val onForget: () -> Unit = {}) {
    private var node: N? = null
    private var text: String? = null

    /** Whether it knows a field's text (and so needs that field's text-change events). */
    val holdsText: Boolean get() = text != null

    /** Text-changed events our own SET_TEXT calls will cause, as (removed, added), oldest first. */
    private val echoes = ArrayDeque<Pair<Int, Int>>()

    /**
     * Our ACTION_SET_TEXT replaced [previousLength] chars of [on] with [newText]. Unless [watching]
     * (text-change events are subscribed to), an edit on the phone could go unseen: then nothing is
     * known. So too when more echoes are pending than it tracks: one would go unmatched.
     */
    fun remember(on: N, newText: String, previousLength: Int, watching: Boolean = true) {
        if (on != node) echoes.clear()
        if (!watching || echoes.size >= MAX_ECHOES) {
            forget()
            return
        }
        node = on
        text = newText
        echoes.addLast(previousLength to newText.length)
    }

    /** Calls `onForget` when it knew a text. */
    fun forget() {
        val held = text != null
        node = null
        text = null
        echoes.clear()
        if (held) onForget()
    }

    /**
     * A password field's text changed (TYPE_VIEW_TEXT_CHANGED). A whole-text replace matching the
     * next expected echo is ours; anything else (or an event we cannot match) makes it unknown.
     */
    fun onTextChanged(fromIndex: Int, removed: Int, added: Int) {
        if (text == null) return
        val echo = echoes.removeFirstOrNull()
        if (echo == null || fromIndex != 0 || echo != (removed to added)) forget()
    }

    /** See [passwordBase]. */
    fun base(on: N, length: Int?, selStart: Int, selEnd: Int): String? =
        passwordBase(text.takeIf { on == node }, length, selStart, selEnd)

    private companion object {
        const val MAX_ECHOES = 16
    }
}

/**
 * ACTION_SET_TEXT sends the whole field (and refresh() fetches it) over one-way binder calls,
 * whose buffer is ~512 KB; past this many chars a large field would fail silently, so the node
 * path pastes instead.
 */
internal const val MAX_SET_TEXT_CHARS = 100_000

internal fun fitsSetText(currentLength: Int, insertLength: Int): Boolean =
    currentLength.toLong() + insertLength <= MAX_SET_TEXT_CHARS

/**
 * Upper bound for a field typed into on the node path: findFocus()/refresh() return the whole
 * node text over a one-way binder callback (~512 KB buffer, UTF-16), which fails beyond ~250 K.
 */
internal const val MAX_NODE_FIELD_CHARS = 150_000

internal fun fitsNodeField(currentLength: Int, insertLength: Int): Boolean =
    currentLength.toLong() + insertLength <= MAX_NODE_FIELD_CHARS
