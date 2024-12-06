package com.nob.keycloakextension;


public class ResponseCode {
    public static final int CODE_SUCCESS = 0;
    public static final int CODE_INVALID_USER_ID = 1;
    public static final int CODE_INVALID_CODE = 2;
    public static final int CODE_TOTP_NOT_ENABLED = 3;
    public static final int CODE_TOTP_ALREADY_ENABLED = 4;
    public static final int CODE_SERVER_ERROR = 5;
    public static final int CODE_TOTP_SETUP_REQUIRED = 6;
    public static final int CODE_INVALID_TOTP = 7;
    public static final int CODE_OPERATION_FAILED = 8;
    public static final int CODE_UNAUTHORIZED = 9;
    public static final int CODE_FORBIDDEN = 10;
}
