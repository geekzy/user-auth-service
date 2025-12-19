package com.example.userauthentication.service;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Test utility class for capturing log messages during testing.
 * Used to verify that email service operations are properly logged.
 */
public class TestLogAppender extends AppenderBase<ILoggingEvent> {
    
    private final List<String> messages = Collections.synchronizedList(new ArrayList<>());

    @Override
    protected void append(ILoggingEvent event) {
        messages.add(event.getFormattedMessage());
    }

    /**
     * Gets all captured log messages.
     * 
     * @return list of log messages
     */
    public List<String> getMessages() {
        return new ArrayList<>(messages);
    }

    /**
     * Clears all captured log messages.
     */
    public void clear() {
        messages.clear();
    }

    /**
     * Gets the number of captured messages.
     * 
     * @return message count
     */
    public int getMessageCount() {
        return messages.size();
    }

    /**
     * Checks if any message contains the specified text.
     * 
     * @param text the text to search for
     * @return true if any message contains the text
     */
    public boolean containsMessage(String text) {
        return messages.stream().anyMatch(msg -> msg.contains(text));
    }
}