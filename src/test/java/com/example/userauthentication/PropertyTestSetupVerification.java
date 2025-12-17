package com.example.userauthentication;

import net.jqwik.api.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verification that jqwik property-based testing framework is properly configured
 */
class PropertyTestSetupVerification {

    @Property
    @Report(Reporting.GENERATED)
    void stringConcatenationIsAssociative(@ForAll String s1, @ForAll String s2, @ForAll String s3) {
        String left = (s1 + s2) + s3;
        String right = s1 + (s2 + s3);
        assertThat(left).isEqualTo(right);
    }

    @Property(tries = 100)
    void additionIsCommutative(@ForAll int a, @ForAll int b) {
        assertThat(a + b).isEqualTo(b + a);
    }

    @Test
    void junitStillWorks() {
        org.junit.jupiter.api.Assertions.assertTrue(true);
    }
}