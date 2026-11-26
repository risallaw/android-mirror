package dev.local.androidmirror.core

/**
 * Serializes access to the pairing store file. A running core caches the store and writes its
 * cached copy back, so the file may be edited directly (handle-free) only while no core owns it;
 * while one does, edits must go through it (which also disconnects a revoked Mac). A core owns
 * the store from a successful [start] until its [close] returns. Thread-safe; [use] blocks a
 * concurrent [start] (and vice versa) for as long as the other runs.
 */
internal class StoreGuard<C : Any> {
    private val lock = Any()
    private var owner: C? = null

    fun start(core: C, start: () -> Boolean): Boolean = synchronized(lock) {
        start().also { if (it) owner = core }
    }

    fun close(core: C, close: () -> Unit) = synchronized(lock) {
        try {
            close()
        } finally {
            if (owner === core) owner = null
        }
    }

    fun <R> use(idle: () -> R, running: (C) -> R): R = synchronized(lock) {
        val o = owner
        if (o != null) running(o) else idle()
    }
}
