package com.nob.keycloakextension;

public class Message {
    public static final String INTERNAL_SERVER_ERROR = "Internal server error";
    public static final String TOTP_ALREADY_CONFIGURED = "TOTP is already configured for this user";
    public static final String TOTP_ALREADY_DISABLED = "TOTP is already disabled for this user";
    public static final String TOTP_NOT_ENABLED = "TOTP is not enabled for this user";
    public static final String OTP_HAS_BEEN_SEND = "OTP has been sent via SMS";
    public static final String SUCCESS = "success";
    public static final String UNAUTHORIZED = "Unauthorized";
    public static final String FORBIDDEN = "Forbidden";
    public static final String INVALID_CODE = "Invalid code or code expired";
    public static final String DISABLE_TOTP_FAILED = "Failed to disable TOTP";
    public static final String VALIDATE_AND_DISABLE_TOTP_SUCCESS = "TOTP validated and disabled successfully";
    public static final String TOTP_CREDENTIAL_REMOVED = "TOTP credential removed for user: {}";
}
