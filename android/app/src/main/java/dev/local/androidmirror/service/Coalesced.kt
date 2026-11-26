package dev.local.androidmirror.service

/**
 * Runs [task] once per burst of [request]s: the first request [post]s it, and requests made
 * while it is queued ride on that run. One thread only (the main thread).
 */
internal class Coalesced(private val post: (Runnable) -> Unit, private val task: () -> Unit) {
    private var queued = false

    fun request() {
        if (queued) return
        queued = true
        post(
            Runnable {
                // Cleared first: a request made while [task] runs gets a run of its own.
                queued = false
                task()
            },
        )
    }
}
