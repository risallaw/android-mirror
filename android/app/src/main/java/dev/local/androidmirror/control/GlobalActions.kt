package dev.local.androidmirror.control

import android.accessibilityservice.AccessibilityService
import android.media.AudioManager
import android.util.Log

/** System-wide actions requested by the Mac (codes mirror `CoreCallbacks.onGlobalAction`). */
class GlobalActions(private val service: AccessibilityService) {
    fun perform(action: Int) {
        val ok = try {
            dispatch(action)
        } catch (e: RuntimeException) {
            // E.g. a SecurityException from the audio service (Do Not Disturb); on the main thread
            // an escaping exception would kill the process.
            Log.w(TAG, "global action $action failed: $e")
            return
        }
        if (!ok) Log.w(TAG, "global action $action not performed")
    }

    private fun dispatch(action: Int): Boolean =
        when (action) {
            1 -> service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            2 -> service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
            3 -> service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_RECENTS)
            4 -> service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_NOTIFICATIONS)
            5 -> service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_QUICK_SETTINGS)
            6 -> service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_LOCK_SCREEN)
            7 -> adjustVolume(AudioManager.ADJUST_RAISE)
            8 -> adjustVolume(AudioManager.ADJUST_LOWER)
            else -> false
        }

    private fun adjustVolume(direction: Int): Boolean {
        val am = service.getSystemService(AudioManager::class.java) ?: return false
        am.adjustSuggestedStreamVolume(direction, AudioManager.USE_DEFAULT_STREAM_TYPE, AudioManager.FLAG_SHOW_UI)
        return true
    }

    private companion object {
        const val TAG = "GlobalActions"
    }
}
