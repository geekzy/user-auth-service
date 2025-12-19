package com.example.userauthentication.config;

import io.micrometer.core.aop.TimedAspect;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Configuration for performance monitoring and method-level timing.
 * Enables @Timed annotations and configures performance aspects.
 */
@Configuration
@EnableAspectJAutoProxy
public class PerformanceMonitoringConfig {

    /**
     * Enable @Timed annotation support for method-level performance monitoring.
     */
    @Bean
    public TimedAspect timedAspect(MeterRegistry meterRegistry) {
        return new TimedAspect(meterRegistry);
    }
}