package com.example.phap.experiments

import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class FunctionalTrialsTest {
    @Test fun controlledFaultExperimentsExerciseAllProductionConditionsAndExportEveryTrial() {
        val output = Files.createTempDirectory("phap-functional-smoke-")
        var passed = false
        try {
            val result = FunctionalTrials.run(output, trialsPerCondition = 2, seed = 20261029L)
            assertEquals(30, result.totalTrials)
            assertEquals("Failed conditions ${result.conditions.filter { it.expectationsFailed > 0 }}; raw rows at $output", 30, result.expectationsPassed)
            assertEquals(0, result.expectationsFailed)
            assertEquals(866, result.credentialBytes)
            assertEquals(15, result.conditions.size)
            assertEquals(31, Files.readAllLines(output.resolve("functional_trials.csv")).size)
            assertEquals(866L, Files.size(output.resolve("functional_credential.bin")))
            val missing = result.conditions.single { it.condition == "MISSING_FRAGMENT_TIMEOUT" }
            assertEquals(2, missing.expiredContexts)
            assertEquals(0, missing.actualInitialDeliveries)
            val altered = result.conditions.single { it.condition == "MODIFIED_BUFFERED_PAYLOAD" }
            assertEquals(0, altered.actualInitialDeliveries)
            assertEquals(2, altered.actualControlDeliveries)
            val duplicate = result.conditions.single { it.condition == "DUPLICATE_DEADLINE_AND_LATE_RECOVERY" }
            assertEquals(2, duplicate.expiredContexts)
            assertEquals(0, duplicate.actualInitialDeliveries)
            assertEquals(2, duplicate.actualControlDeliveries)
            passed = true
        } finally { if (passed) output.toFile().deleteRecursively() }
    }
}
