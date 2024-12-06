package com.nob.keycloakextension;

import lombok.extern.slf4j.Slf4j;

/**
 * Service for sent sms
 * @author Truong Ngo
 * */
public interface SmsService {

    /**
     * Sent sms to a given phone number
     * @param phoneNumber destination phone number
     * @param message message need to sent
     * */
    void sendSms(String phoneNumber, String message);


    /**
     * Simulator of {@link SmsService}, simply logging the message to console
     * */
    @Slf4j
    class SimulatorSmsService implements SmsService {

        @Override
        public void sendSms(String phoneNumber, String message) {
            log.info("Sending message to phone number {}, message: {}", phoneNumber, message);
        }

    }
}
