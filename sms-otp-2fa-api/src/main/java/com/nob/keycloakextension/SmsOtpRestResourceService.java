package com.nob.keycloakextension;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.credential.CredentialModel;
import org.keycloak.forms.login.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.TimeBasedOTP;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Service for sms otp 2fa via rest api
 * @author Truong Ngo
 * */
@Slf4j
@RequiredArgsConstructor
public class SmsOtpRestResourceService {


    private final KeycloakSession session;

    private final SmsOtpRestResourceHelper helper = SmsOtpRestResourceHelper.INSTANCE;


    /**
     * Generate otp code and enable user totp credential
     * @param userId 2fa user identifier
     * @return {@code Response}
     * */
    public Response generateOtpCodeAndEnabledTotpCredential(String userId) {
        try {
            Response requireUserId = helper.requireValue(userId, "userId", ResponseCode.CODE_INVALID_USER_ID);
            if (Objects.nonNull(requireUserId)) return requireUserId;

            helper.checkAuthentication(session, userId);
            UserModel user = helper.getUserContext(session, userId);

            Response isEnableTotp = helper.checkEnableTotp(user, false);
            if (Objects.nonNull(isEnableTotp)) return isEnableTotp;

            RealmModel realm = session.getContext().getRealm();
            TotpBean totpBean = new TotpBean(session, realm, user, null);
            String totpSecret = totpBean.getTotpSecret();

            OTPPolicy otpPolicy = realm.getOTPPolicy();
            TimeBasedOTP timeBasedOTP = new TimeBasedOTP(
                    otpPolicy.getAlgorithm(),
                    otpPolicy.getDigits(),
                    otpPolicy.getPeriod(),
                    otpPolicy.getLookAheadWindow()
            );

            OTPCredentialModel otpCredential = OTPCredentialModel.createTOTP(
                    totpSecret,
                    otpPolicy.getDigits(),
                    otpPolicy.getPeriod(),
                    otpPolicy.getAlgorithm()
            );

            user.credentialManager().createStoredCredential(otpCredential);

            String otpCode = timeBasedOTP.generateTOTP(totpSecret);
            String message = String.format("Sending OTP via SMS to user [%s]: %s", user.getUsername(), otpCode);
            SmsService simulatorSmsService = new SmsService.SimulatorSmsService();
            simulatorSmsService.sendSms(null, message);

            return Response.ok(Map.of(
                    Constant.MESSAGE, Message.OTP_HAS_BEEN_SEND,
                    Constant.STATUS, Message.SUCCESS,
                    Constant.SUPPORTED_APP, totpBean.getSupportedApplications(),
                    Constant.USER_ID, userId,
                    Constant.CODE, ResponseCode.CODE_SUCCESS
            )).build();

        } catch (NotAuthorizedException e) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            Constant.ERROR, Message.UNAUTHORIZED,
                            Constant.CODE, ResponseCode.CODE_UNAUTHORIZED
                    ))
                    .build();
        } catch (ForbiddenException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            Constant.ERROR, Message.FORBIDDEN,
                            Constant.CODE, ResponseCode.CODE_FORBIDDEN
                    ))
                    .build();
        } catch (Exception e) {
            return helper.handleServerError("setting up TOTP", userId, e);
        }
    }


    /**
     * Validate otp code and disable totp credential
     * @param userId 2fa user identifier
     * @param data data contains otp code
     * @return {@code Response}
     * */
    public Response validateOtpCodeAndDisabledTotpCredential(String userId, Map<String, String> data) {
        try {
            Response requireUserId = helper.requireValue(userId, "userId", ResponseCode.CODE_INVALID_USER_ID);
            if (Objects.nonNull(requireUserId)) return requireUserId;

            Response requireCode = helper.requireValue(data.get(Constant.CODE), "code", ResponseCode.CODE_INVALID_USER_ID);
            if (Objects.nonNull(requireCode)) return requireCode;

            helper.checkAuthentication(session, userId);
            UserModel user = helper.getUserContext(session, userId);

            Response isEnableTotp = helper.checkEnableTotp(user, true);
            if (Objects.nonNull(isEnableTotp)) return isEnableTotp;

            RealmModel realm = session.getContext().getRealm();
            OTPPolicy otpPolicy = realm.getOTPPolicy();
            TimeBasedOTP timeBasedOTP = new TimeBasedOTP(
                    otpPolicy.getAlgorithm(),
                    otpPolicy.getDigits(),
                    otpPolicy.getPeriod(),
                    otpPolicy.getLookAheadWindow()
            );

            List<CredentialModel> totpCredentials = user.credentialManager()
                    .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .toList();
            OTPCredentialModel credential = OTPCredentialModel.createFromCredentialModel(totpCredentials.get(0));

            if (!timeBasedOTP.validateTOTP(data.get(Constant.CODE), credential.getDecodedSecret())) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                Constant.ERROR, Message.INVALID_CODE,
                                Constant.CODE, ResponseCode.CODE_INVALID_CODE))
                        .build();
            }

            for (CredentialModel cred : totpCredentials) {
                try {
                    user.credentialManager().removeStoredCredentialById(cred.getId());
                    log.info(Message.TOTP_CREDENTIAL_REMOVED, userId);
                } catch (Exception e) {
                    assert log != null;
                    log.error("Failed to remove TOTP credential for user: {}", userId, e);
                    return Response.serverError()
                            .entity(Map.of(
                                    Constant.ERROR, Message.DISABLE_TOTP_FAILED,
                                    Constant.CODE, ResponseCode.CODE_OPERATION_FAILED))
                            .build();
                }
            }

            return Response.ok(Map.of(
                    Constant.MESSAGE, Message.VALIDATE_AND_DISABLE_TOTP_SUCCESS,
                    Constant.ENABLED, false,
                    Constant.USER_ID, userId,
                    Constant.CODE, ResponseCode.CODE_SUCCESS
            )).build();

        } catch (NotAuthorizedException e) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            Constant.ERROR, Message.UNAUTHORIZED,
                            Constant.CODE, ResponseCode.CODE_UNAUTHORIZED
                    ))
                    .build();
        } catch (ForbiddenException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            Constant.ERROR, Message.FORBIDDEN,
                            Constant.CODE, ResponseCode.CODE_FORBIDDEN
                    ))
                    .build();
        } catch (Exception e) {
            return helper.handleServerError("disabling TOTP with validation", userId, e);
        }
    }


    /**
     * Disable totp manually
     * @param userId 2fa user identifier
     * @return {@code Response}
     * */
    public Response disableTotpCredential(String userId) {
        try {
            Response requireUserId = helper.requireValue(userId, "userId", ResponseCode.CODE_INVALID_USER_ID);
            if (Objects.nonNull(requireUserId)) return requireUserId;

            helper.checkAuthentication(session, userId);
            UserModel user = helper.getUserContext(session, userId);

            List<CredentialModel> totpCredentials = user.credentialManager()
                    .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                    .toList();

            if (totpCredentials.isEmpty()) {
                return Response.status(Response.Status.OK)
                        .entity(Map.of(
                                Constant.MESSAGE, Message.TOTP_ALREADY_DISABLED,
                                Constant.CODE, ResponseCode.CODE_SUCCESS
                        ))
                        .build();
            }

            for (CredentialModel credential : totpCredentials) {
                try {
                    user.credentialManager().removeStoredCredentialById(credential.getId());
                    log.info(Message.TOTP_CREDENTIAL_REMOVED, userId);
                } catch (Exception e) {
                    assert log != null;
                    log.info("Failed to remove TOTP credential for user: {}", userId);
                    return Response.serverError()
                            .entity(Map.of(
                                    Constant.ERROR, Message.DISABLE_TOTP_FAILED,
                                    Constant.CODE, ResponseCode.CODE_OPERATION_FAILED))
                            .build();
                }
            }

            return Response.ok(Map.of(
                    Constant.MESSAGE, Message.VALIDATE_AND_DISABLE_TOTP_SUCCESS,
                    Constant.ENABLED, false,
                    Constant.USER_ID, userId,
                    Constant.CODE, ResponseCode.CODE_SUCCESS
            )).build();

        } catch (NotAuthorizedException e) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            Constant.ERROR, Message.UNAUTHORIZED,
                            Constant.CODE, ResponseCode.CODE_UNAUTHORIZED
                    ))
                    .build();
        } catch (ForbiddenException e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            Constant.ERROR, Message.FORBIDDEN,
                            Constant.CODE, ResponseCode.CODE_FORBIDDEN
                    ))
                    .build();
        } catch (Exception e) {
            return helper.handleServerError("disabling TOTP with validation", userId, e);
        }
    }
}
