package com.example.userauthentication.benchmark;

import org.junit.jupiter.api.Test;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Simple test to verify JMH benchmarks can be executed.
 * 
 * **Feature: user-authentication, Simple benchmark execution test**
 * 
 * Requirements: 2.1 (performance benchmarking), 2.5 (load testing), 5.4 (performance thresholds)
 */
public class SimpleBenchmarkTest {

    @Test
    void testBenchmarkExecution() throws RunnerException {
        // Run a quick benchmark test with minimal iterations
        Options options = new OptionsBuilder()
                .include(AuthenticationBenchmark.class.getSimpleName())
                .include("benchmarkJwtTokenGeneration") // Run only one specific benchmark
                .forks(1)
                .warmupIterations(1)
                .measurementIterations(1)
                .shouldDoGC(true)
                .shouldFailOnError(true)
                .build();

        Runner runner = new Runner(options);
        runner.run();
    }
}