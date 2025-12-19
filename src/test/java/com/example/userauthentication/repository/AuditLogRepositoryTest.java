package com.example.userauthentication.repository;

import com.example.userauthentication.model.AuditLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for AuditLogRepository.
 * Tests security event logging and timestamp recording functionality.
 * 
 * Requirements: 3.4, 5.5
 */
@DataJpaTest
@ActiveProfiles("test")
class AuditLogRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private AuditLogRepository auditLogRepository;

    private AuditLog testAuditLog;
    private LocalDateTime testTime;

    @BeforeEach
    void setUp() {
        testTime = LocalDateTime.now();
        testAuditLog = new AuditLog(
            1L,
            AuditLog.EVENT_USER_LOGIN,
            "User login successful",
            true,
            "192.168.1.1",
            "Mozilla/5.0"
        );
    }

    @Test
    void shouldCreateAndSaveAuditLogEntry() {
        // When
        AuditLog savedLog = auditLogRepository.save(testAuditLog);
        entityManager.flush();

        // Then
        assertThat(savedLog.getId()).isNotNull();
        assertThat(savedLog.getUserId()).isEqualTo(1L);
        assertThat(savedLog.getEventType()).isEqualTo(AuditLog.EVENT_USER_LOGIN);
        assertThat(savedLog.getEventDescription()).isEqualTo("User login successful");
        assertThat(savedLog.getSuccess()).isTrue();
        assertThat(savedLog.getIpAddress()).isEqualTo("192.168.1.1");
        assertThat(savedLog.getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(savedLog.getCreatedAt()).isNotNull();
    }

    @Test
    void shouldAutomaticallySetTimestampOnCreation() {
        // Given
        LocalDateTime beforeSave = LocalDateTime.now();

        // When
        AuditLog savedLog = auditLogRepository.save(testAuditLog);
        entityManager.flush();

        // Then
        LocalDateTime afterSave = LocalDateTime.now();
        assertThat(savedLog.getCreatedAt()).isNotNull();
        assertThat(savedLog.getCreatedAt()).isAfter(beforeSave.minusSeconds(1));
        assertThat(savedLog.getCreatedAt()).isBefore(afterSave.plusSeconds(1));
    }

    @Test
    void shouldFindAuditLogsByUserId() {
        // Given
        AuditLog log1 = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Login", true, "192.168.1.1", "Browser");
        AuditLog log2 = new AuditLog(1L, AuditLog.EVENT_USER_LOGOUT, "Logout", true, "192.168.1.1", "Browser");
        AuditLog log3 = new AuditLog(2L, AuditLog.EVENT_USER_LOGIN, "Login", true, "192.168.1.2", "Browser");
        
        auditLogRepository.saveAll(Arrays.asList(log1, log2, log3));
        entityManager.flush();

        Pageable pageable = PageRequest.of(0, 10);

        // When
        Page<AuditLog> result = auditLogRepository.findByUserIdOrderByCreatedAtDesc(1L, pageable);

        // Then
        assertThat(result.getContent()).hasSize(2);
        assertThat(result.getContent()).extracting(AuditLog::getUserId).containsOnly(1L);
        assertThat(result.getContent()).extracting(AuditLog::getEventType)
            .containsExactly(AuditLog.EVENT_USER_LOGOUT, AuditLog.EVENT_USER_LOGIN); // Ordered by created desc
    }

    @Test
    void shouldFindAuditLogsByEventType() {
        // Given
        AuditLog loginLog1 = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Login 1", true, "192.168.1.1", "Browser");
        AuditLog loginLog2 = new AuditLog(2L, AuditLog.EVENT_USER_LOGIN, "Login 2", true, "192.168.1.2", "Browser");
        AuditLog logoutLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGOUT, "Logout", true, "192.168.1.1", "Browser");
        
        auditLogRepository.saveAll(Arrays.asList(loginLog1, loginLog2, logoutLog));
        entityManager.flush();

        Pageable pageable = PageRequest.of(0, 10);

        // When
        Page<AuditLog> result = auditLogRepository.findByEventTypeOrderByCreatedAtDesc(AuditLog.EVENT_USER_LOGIN, pageable);

        // Then
        assertThat(result.getContent()).hasSize(2);
        assertThat(result.getContent()).extracting(AuditLog::getEventType).containsOnly(AuditLog.EVENT_USER_LOGIN);
    }

    @Test
    void shouldFindAuditLogsBySuccessStatus() {
        // Given
        AuditLog successLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Success", true, "192.168.1.1", "Browser");
        AuditLog failureLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Failure", false, "192.168.1.1", "Browser");
        
        auditLogRepository.saveAll(Arrays.asList(successLog, failureLog));
        entityManager.flush();

        Pageable pageable = PageRequest.of(0, 10);

        // When
        Page<AuditLog> successResults = auditLogRepository.findBySuccessOrderByCreatedAtDesc(true, pageable);
        Page<AuditLog> failureResults = auditLogRepository.findBySuccessOrderByCreatedAtDesc(false, pageable);

        // Then
        assertThat(successResults.getContent()).hasSize(1);
        assertThat(successResults.getContent().get(0).getSuccess()).isTrue();
        
        assertThat(failureResults.getContent()).hasSize(1);
        assertThat(failureResults.getContent().get(0).getSuccess()).isFalse();
    }

    @Test
    void shouldFindAuditLogsWithinTimeRange() {
        // Given
        LocalDateTime startTime = LocalDateTime.now().minusHours(2);
        LocalDateTime endTime = LocalDateTime.now().minusHours(1);
        
        AuditLog oldLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Old", true, "192.168.1.1", "Browser");
        AuditLog recentLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Recent", true, "192.168.1.1", "Browser");
        
        // Save old log first, then manipulate its timestamp
        auditLogRepository.save(oldLog);
        entityManager.flush();
        
        // Manually set timestamp for testing
        entityManager.getEntityManager()
            .createQuery("UPDATE AuditLog a SET a.createdAt = :oldTime WHERE a.id = :id")
            .setParameter("oldTime", startTime.minusHours(1))
            .setParameter("id", oldLog.getId())
            .executeUpdate();
            
        auditLogRepository.save(recentLog);
        entityManager.flush();
        
        // Set recent log timestamp within range
        entityManager.getEntityManager()
            .createQuery("UPDATE AuditLog a SET a.createdAt = :recentTime WHERE a.id = :id")
            .setParameter("recentTime", startTime.plusMinutes(30))
            .setParameter("id", recentLog.getId())
            .executeUpdate();

        Pageable pageable = PageRequest.of(0, 10);

        // When
        Page<AuditLog> result = auditLogRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(startTime, endTime, pageable);

        // Then
        assertThat(result.getContent()).hasSize(1);
        assertThat(result.getContent().get(0).getEventDescription()).isEqualTo("Recent");
    }

    @Test
    void shouldFindSecurityEventsByUserId() {
        // Given
        AuditLog loginLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Login", true, "192.168.1.1", "Browser");
        AuditLog logoutLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGOUT, "Logout", true, "192.168.1.1", "Browser");
        AuditLog registrationLog = new AuditLog(1L, AuditLog.EVENT_USER_REGISTRATION, "Registration", true, "192.168.1.1", "Browser");
        AuditLog suspiciousLog = new AuditLog(1L, AuditLog.EVENT_SUSPICIOUS_ACTIVITY, "Suspicious", false, "192.168.1.1", "Browser");
        
        auditLogRepository.saveAll(Arrays.asList(loginLog, logoutLog, registrationLog, suspiciousLog));
        entityManager.flush();

        Pageable pageable = PageRequest.of(0, 10);

        // When
        Page<AuditLog> result = auditLogRepository.findSecurityEventsByUserId(1L, pageable);

        // Then
        assertThat(result.getContent()).hasSize(3); // login, logout, suspicious (not registration)
        assertThat(result.getContent()).extracting(AuditLog::getEventType)
            .containsExactlyInAnyOrder(
                AuditLog.EVENT_USER_LOGIN,
                AuditLog.EVENT_USER_LOGOUT,
                AuditLog.EVENT_SUSPICIOUS_ACTIVITY
            );
    }

    @Test
    void shouldFindFailedAuthenticationAttemptsByIpAndTimeRange() {
        // Given
        LocalDateTime startTime = LocalDateTime.now().minusHours(1);
        LocalDateTime endTime = LocalDateTime.now().plusHours(1); // Extended end time to include current logs
        
        AuditLog failedLogin = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Failed login", false, "192.168.1.100", "Browser");
        AuditLog successfulLogin = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Successful login", true, "192.168.1.100", "Browser");
        AuditLog differentIp = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Failed from different IP", false, "192.168.1.200", "Browser");
        
        auditLogRepository.saveAll(Arrays.asList(failedLogin, successfulLogin, differentIp));
        entityManager.flush();

        // When
        List<AuditLog> result = auditLogRepository.findFailedAuthenticationAttemptsByIpAndTimeRange(
            "192.168.1.100", startTime, endTime);

        // Then
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getEventDescription()).isEqualTo("Failed login");
        assertThat(result.get(0).getSuccess()).isFalse();
        assertThat(result.get(0).getIpAddress()).isEqualTo("192.168.1.100");
    }

    @Test
    void shouldCountEventsByTypeAndTimeRange() {
        // Given
        LocalDateTime startTime = LocalDateTime.now().minusHours(1);
        LocalDateTime endTime = LocalDateTime.now().plusHours(1); // Extended end time to include current logs
        
        AuditLog login1 = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Login 1", true, "192.168.1.1", "Browser");
        AuditLog login2 = new AuditLog(2L, AuditLog.EVENT_USER_LOGIN, "Login 2", true, "192.168.1.2", "Browser");
        AuditLog logout = new AuditLog(1L, AuditLog.EVENT_USER_LOGOUT, "Logout", true, "192.168.1.1", "Browser");
        
        auditLogRepository.saveAll(Arrays.asList(login1, login2, logout));
        entityManager.flush();

        // When
        long loginCount = auditLogRepository.countByEventTypeAndTimeRange(AuditLog.EVENT_USER_LOGIN, startTime, endTime);
        long logoutCount = auditLogRepository.countByEventTypeAndTimeRange(AuditLog.EVENT_USER_LOGOUT, startTime, endTime);

        // Then
        assertThat(loginCount).isEqualTo(2);
        assertThat(logoutCount).isEqualTo(1);
    }

    @Test
    void shouldCheckIfAuditLogsExistForUser() {
        // Given
        AuditLog userLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Login", true, "192.168.1.1", "Browser");
        auditLogRepository.save(userLog);
        entityManager.flush();

        // When
        boolean existsForUser1 = auditLogRepository.existsByUserId(1L);
        boolean existsForUser2 = auditLogRepository.existsByUserId(2L);

        // Then
        assertThat(existsForUser1).isTrue();
        assertThat(existsForUser2).isFalse();
    }

    @Test
    void shouldCreateAuditLogWithFactoryMethods() {
        // When
        AuditLog successLog = AuditLog.success(1L, AuditLog.EVENT_USER_LOGIN, "Login successful", "192.168.1.1", "Browser");
        AuditLog failureLog = AuditLog.failure(1L, AuditLog.EVENT_USER_LOGIN, "Login failed", "192.168.1.1", "Browser");
        
        auditLogRepository.saveAll(Arrays.asList(successLog, failureLog));
        entityManager.flush();

        // Then
        assertThat(successLog.getSuccess()).isTrue();
        assertThat(failureLog.getSuccess()).isFalse();
        assertThat(successLog.getEventType()).isEqualTo(AuditLog.EVENT_USER_LOGIN);
        assertThat(failureLog.getEventType()).isEqualTo(AuditLog.EVENT_USER_LOGIN);
    }

    @Test
    void shouldValidateSecurityEventIdentification() {
        // Given
        AuditLog loginLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "Login", true, "192.168.1.1", "Browser");
        AuditLog registrationLog = new AuditLog(1L, AuditLog.EVENT_USER_REGISTRATION, "Registration", true, "192.168.1.1", "Browser");
        
        // When & Then
        assertThat(loginLog.isSecurityEvent()).isTrue();
        assertThat(registrationLog.isSecurityEvent()).isFalse();
    }

    @Test
    void shouldHandleNullUserIdForSystemEvents() {
        // Given
        AuditLog systemLog = new AuditLog(null, AuditLog.EVENT_SUSPICIOUS_ACTIVITY, "System detected suspicious activity", false, "192.168.1.1", "Browser");
        
        // When
        AuditLog savedLog = auditLogRepository.save(systemLog);
        entityManager.flush();

        // Then
        assertThat(savedLog.getUserId()).isNull();
        assertThat(savedLog.hasUser()).isFalse();
        assertThat(savedLog.getEventType()).isEqualTo(AuditLog.EVENT_SUSPICIOUS_ACTIVITY);
    }

    @Test
    void shouldRecordTimestampAccuratelyForSecurityEvents() {
        // Given
        LocalDateTime beforeCreation = LocalDateTime.now();
        
        // When
        AuditLog securityLog = new AuditLog(1L, AuditLog.EVENT_ACCOUNT_LOCKED, "Account locked due to failed attempts", false, "192.168.1.1", "Browser");
        AuditLog savedLog = auditLogRepository.save(securityLog);
        entityManager.flush();
        
        LocalDateTime afterCreation = LocalDateTime.now();

        // Then
        assertThat(savedLog.getCreatedAt()).isNotNull();
        assertThat(savedLog.getCreatedAt()).isAfter(beforeCreation.minusSeconds(1));
        assertThat(savedLog.getCreatedAt()).isBefore(afterCreation.plusSeconds(1));
        assertThat(savedLog.isSecurityEvent()).isTrue();
    }

    @Test
    void shouldRetrieveAuditLogsInCorrectOrder() {
        // Given
        AuditLog firstLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGIN, "First login", true, "192.168.1.1", "Browser");
        AuditLog secondLog = new AuditLog(1L, AuditLog.EVENT_USER_LOGOUT, "Logout", true, "192.168.1.1", "Browser");
        
        // Save in order
        auditLogRepository.save(firstLog);
        entityManager.flush();
        
        // Small delay to ensure different timestamps
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        auditLogRepository.save(secondLog);
        entityManager.flush();

        Pageable pageable = PageRequest.of(0, 10);

        // When
        Page<AuditLog> result = auditLogRepository.findByUserIdOrderByCreatedAtDesc(1L, pageable);

        // Then
        assertThat(result.getContent()).hasSize(2);
        // Should be ordered by created date descending (most recent first)
        assertThat(result.getContent().get(0).getEventType()).isEqualTo(AuditLog.EVENT_USER_LOGOUT);
        assertThat(result.getContent().get(1).getEventType()).isEqualTo(AuditLog.EVENT_USER_LOGIN);
    }
}