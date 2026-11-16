package org.danilopianini.noncryptohash.benchmarks

/**
 * Runs every workload on every algorithm, printing one `BENCHMARK <kind> <json>` line per record.
 * Gradle collects the lines of every target into the published results.
 */
fun main() {
    emit("runtime", json("target" to TARGET_NAME, "runtime" to runtimeDescription(), "quick" to BenchmarkConfig.QUICK))
    ALGORITHMS.forEach { algorithm ->
        WORKLOADS.forEach { workload -> emit("result", measure(algorithm, workload)) }
        emit("footprint", footprint(algorithm))
    }
    emit("end", json("sink" to sink))
}

private fun emit(kind: String, record: Any) = println("BENCHMARK $kind $record")
