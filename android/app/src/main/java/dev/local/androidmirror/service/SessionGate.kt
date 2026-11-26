package dev.local.androidmirror.service

/**
 * When [MirrorService] may start and stop its one session. A session is active from its start until
 * its shutdown has finished; a second shutdown (a system "projection stopped" report arriving after
 * a failed start already shut down, or after the service was destroyed) is a no-op, so it cannot
 * replace an ERROR with IDLE. A start [R]equest arriving while a shutdown runs carries a
 * single-use screen-capture consent: it is kept and run once the shutdown finishes, not dropped.
 * Main thread only.
 */
internal class SessionGate<R : Any> {
    enum class Start {
        /** Start it now. */
        NOW,

        /** A session is already running: ignore. */
        RUNNING,

        /** Kept until the shutdown in progress finishes ([shutdownDone] returns it). */
        AFTER_STOP,
    }

    var active = false
        private set
    var stopping = false
        private set
    private var pending: R? = null

    /**
     * Whether core events belong to the session on screen: from its start (a Mac can connect
     * before the service learns the core is up) until Stop.
     */
    val eventsLive: Boolean get() = active && !stopping

    fun start(request: R): Start = when {
        stopping -> {
            pending = request // a newer consent supersedes an older one
            Start.AFTER_STOP
        }
        active -> Start.RUNNING
        else -> {
            active = true
            Start.NOW
        }
    }

    /** True if a shutdown should run now: a session is active and none is being shut down. */
    fun beginShutdown(): Boolean {
        if (!active || stopping) return false
        stopping = true
        return true
    }

    /** The shutdown finished: the start request that arrived meanwhile, to run next, if any. */
    fun shutdownDone(): R? {
        active = false
        stopping = false
        return pending.also { pending = null }
    }
}
