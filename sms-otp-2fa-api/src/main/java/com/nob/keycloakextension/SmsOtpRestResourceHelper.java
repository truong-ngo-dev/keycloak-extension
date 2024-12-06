package com.nob.keycloakextension;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Helper class provide utility method for {@code SmsOtpRestResourceService}
 * @see SmsOtpRestResourceService
 * @author Truong Ngo
 * */
@Slf4j
public class SmsOtpRestResourceHelper {

    /**
     * Singleton instance
     * */
    public static SmsOtpRestResourceHelper INSTANCE = new SmsOtpRestResourceHelper();

    /**
     * Private controller
     * */
    private SmsOtpRestResourceHelper() {
    }

    /**
     * Get user from session
     * @param userid user identifier
     * @return Authenticated user
     * @throws ForbiddenException if user is not existed in session
     * */
    public UserModel getUserContext(KeycloakSession session, String userid) {
        UserModel user = session.users().getUserById(session.getContext().getRealm(), userid);
        if (Objects.isNull(user)) throw new ForbiddenException("Invalid user!");
        return user;
    }


    /**
     * Check if user from token is valid or not
     * @param userId user identifier for checking the bearer token user
     * @throws NotAuthorizedException if bearer token is not existed
     * @throws ForbiddenException if bearer token user is not match with user id
     * */
    public void checkAuthentication(KeycloakSession session, String userId) {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (Objects.isNull(auth)) throw new NotAuthorizedException("Required bearer token!");
        UserModel authenticatedUser = auth.getUser();

        if (Objects.nonNull(authenticatedUser) &&
                Objects.nonNull(authenticatedUser.getServiceAccountClientLink())) {
            return;
        }

        if (Objects.nonNull(authenticatedUser) &&
                Objects.nonNull(authenticatedUser.getId())) {
            if (Objects.nonNull(userId) && !userId.equals(authenticatedUser.getId())) {
                throw new ForbiddenException("Only the owner of the token can access this resource!");
            }
            return;
        }
        throw new NotAuthorizedException("Invalid authentication: requires either client credentials or user token");
    }


    /**
     * Ensure that value is required
     * @param value check value
     * @param name value name
     * @param errorCode error code in case failed
     * @return error {@code Response} if value is not required otherwise {@code null}
     * */
    public Response requireValue(String value, String name, Integer errorCode) {
        if (Objects.isNull(value) || value.trim().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            Constant.ERROR,  name + " is required!",
                            Constant.CODE, errorCode
                    ))
                    .build();
        }
        return null;
    }


    public Response checkEnableTotp(UserModel user, boolean shouldBeEnabled) {
        List<CredentialModel> totpCredentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(OTPCredentialModel.TYPE)
                .toList();

        boolean hasTotp = !totpCredentials.isEmpty();

        if (shouldBeEnabled && !hasTotp) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            Constant.ERROR, Message.TOTP_NOT_ENABLED,
                            Constant.CODE, ResponseCode.CODE_TOTP_NOT_ENABLED
                    ))
                    .build();
        }

        if (!shouldBeEnabled && hasTotp) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of(
                            Constant.ERROR, Message.TOTP_ALREADY_CONFIGURED,
                            Constant.CODE, ResponseCode.CODE_TOTP_ALREADY_ENABLED
                    ))
                    .build();
        }

        return null;
    }


    /**
     * Handler exception occur during 2fa process
     * @param operation 2fa operation
     * @param userid authenticate user
     * @param e exception occur
     * @return {@code Response} for exception occur in each operation
     * */
    public Response handleServerError(String operation, String userid, Exception e) {
        log.error("Error while {} for user: {}", operation, userid, e);
        return Response.serverError()
                .entity(Map.of(
                        Constant.ERROR, Message.INTERNAL_SERVER_ERROR,
                        Constant.CODE, ResponseCode.CODE_SERVER_ERROR))
                .build();
    }
}
