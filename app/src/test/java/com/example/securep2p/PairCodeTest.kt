package com.example.securep2p

import com.example.securep2p.protocol.PairCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairCodeTest {
    @Test
    fun normalizesDisplayedPairCodeSeparators() {
        assertEquals("ABC234", PairCode.normalize(" abc 234 "))
        assertEquals("ABC234", PairCode.normalize("abc-234"))
    }

    @Test
    fun rejectsInvalidLengthAndCharacters() {
        assertNull(PairCode.normalize("ABC23"))
        assertNull(PairCode.normalize("ABCI34"))
        assertNull(PairCode.normalize("ABC 12@"))
    }
}
