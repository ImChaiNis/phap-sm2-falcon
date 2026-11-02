package com.example.v2v0614.business

import android.content.SharedPreferences
import com.example.v2v0614.protocol.CryptoProvider
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.Callable
import java.util.concurrent.Executors

/** Runs with an Android API interface jar; does not need AndroidKeyStore or a phone. */
class AndroidPersistenceTest {
    private val owner = "01".repeat(16)
    private val nonce = "02".repeat(32)
    private val digest = "03".repeat(32)
    private fun preferences() = MemoryPreferences().also { it.data["owner"] = owner; it.data["bootstrap"] = nonce }
    private fun store(prefs: MemoryPreferences) = DurableProtocolStore(prefs).also { it.bind(owner, nonce) }

    @Test fun sequencesAndReplaysSurviveNewStoreInstance() {
        val prefs = preferences()
        assertEquals(1L, store(prefs).next(digest))
        assertEquals(2L, store(prefs).next(digest))
        assertTrue(store(prefs).accept(digest, 4L))
        assertFalse(store(prefs).accept(digest, 4L))
        assertFalse(store(prefs).accept(digest, 3L))
        assertTrue(store(prefs).accept(digest, 5L))
    }

    @Test fun independentActivityStoresReserveUniqueSequences() {
        val prefs = preferences()
        val first = store(prefs)
        val second = store(prefs)
        val executor = Executors.newFixedThreadPool(4)
        try {
            val results = executor.invokeAll((0 until 100).map { i -> Callable { (if (i % 2 == 0) first else second).next(digest) } }).map { it.get() }
            assertEquals((1L..100L).toSet(), results.toSet())
        } finally { executor.shutdownNow() }
    }

    @Test fun commitFailureNeverReturnsSuccessfulReservationOrAcceptance() {
        val prefs = preferences()
        val store = store(prefs)
        prefs.failCommits = true
        assertFails { store.next(digest) }
        assertFails { store.accept(digest, 1L) }
    }

    @Test fun missingOrChangedBootstrapFailsClosed() {
        val prefs = preferences()
        val store = store(prefs)
        prefs.data.remove("bootstrap")
        assertFails { store.next(digest) }
        assertFails { store.accept(digest, 1L) }
        prefs.data["bootstrap"] = "ff".repeat(32)
        assertFails { store.next(digest) }
    }

    @Test fun endpointStateCannotBeReusedWithMissingMarker() {
        val prefs = preferences()
        val endpoint = EndpointMaterial(owner, ByteArray(65), ByteArray(32), nonce)
        val identities = EndpointStore(MemoryPreferences(), prefs, CryptoProvider())
        identities.checkState(endpoint)
        prefs.data.clear()
        assertFails { identities.checkState(endpoint) }
    }

    @Test fun malformedOrExhaustedCounterFailsClosed() {
        val prefs = preferences()
        val store = store(prefs)
        prefs.data["sequence.$digest"] = Long.MAX_VALUE
        assertFails { store.next(digest) }
        prefs.data["sequence.$digest"] = "corrupt"
        assertFails { store.next(digest) }
        prefs.data["replay.$digest"] = -1L
        assertFails { store.accept(digest, 1L) }
    }

    private fun assertFails(block: () -> Unit) {
        try { block(); fail("Expected fail-closed exception") } catch (expected: RuntimeException) { /* rejection */ }
    }
}

private class MemoryPreferences : SharedPreferences {
    val data = mutableMapOf<String, Any?>()
    var failCommits = false
    override fun getAll(): MutableMap<String, *> = data.toMutableMap()
    override fun getString(key: String?, defValue: String?): String? = if (data.containsKey(key)) data[key] as String? else defValue
    @Suppress("UNCHECKED_CAST") override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
        if (data.containsKey(key)) (data[key] as Set<String>?)?.toMutableSet() else defValues
    override fun getInt(key: String?, defValue: Int): Int = if (data.containsKey(key)) data[key] as Int else defValue
    override fun getLong(key: String?, defValue: Long): Long = if (data.containsKey(key)) data[key] as Long else defValue
    override fun getFloat(key: String?, defValue: Float): Float = if (data.containsKey(key)) data[key] as Float else defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = if (data.containsKey(key)) data[key] as Boolean else defValue
    override fun contains(key: String?): Boolean = data.containsKey(key)
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        private val changes = mutableMapOf<String, Any?>()
        private val removed = mutableSetOf<String>()
        private var clear = false
        private fun put(key: String?, value: Any?): SharedPreferences.Editor { changes[requireNotNull(key)] = value; return this }
        override fun putString(key: String?, value: String?) = put(key, value)
        override fun putStringSet(key: String?, values: MutableSet<String>?) = put(key, values?.toSet())
        override fun putInt(key: String?, value: Int) = put(key, value)
        override fun putLong(key: String?, value: Long) = put(key, value)
        override fun putFloat(key: String?, value: Float) = put(key, value)
        override fun putBoolean(key: String?, value: Boolean) = put(key, value)
        override fun remove(key: String?): SharedPreferences.Editor { removed.add(requireNotNull(key)); return this }
        override fun clear(): SharedPreferences.Editor { clear = true; return this }
        override fun commit(): Boolean {
            if (failCommits) return false
            if (clear) data.clear()
            removed.forEach(data::remove)
            data.putAll(changes)
            return true
        }
        override fun apply() { check(commit()) }
    }
}
