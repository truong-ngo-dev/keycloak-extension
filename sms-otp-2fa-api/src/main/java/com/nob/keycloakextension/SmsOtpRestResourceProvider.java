package com.nob.keycloakextension;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Map;

@Slf4j
public class SmsOtpRestResourceProvider implements RealmResourceProvider {

    private final SmsOtpRestResourceService smsOtpRestResourceService;

    public SmsOtpRestResourceProvider(KeycloakSession session) {
        this.smsOtpRestResourceService = new SmsOtpRestResourceService(session);
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }


    @POST
    @Path("totp/generate/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Setup TOTP for user")
    @APIResponse(responseCode = "200", description = "TOTP setup successful")
    @APIResponse(responseCode = "400", description = "Invalid user ID or TOTP already configured")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response setupTotp(@PathParam("user_id") final String userid) {
        return smsOtpRestResourceService.generateOtpCodeAndEnabledTotpCredential(userid);
    }

    @DELETE
    @Path("totp/{user_id}")
    @Produces(MediaType.APPLICATION_JSON)
    @APIResponse(
            responseCode = "200",
            description = "TOTP disabled successfully",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    @APIResponse(
            responseCode = "400",
            description = "TOTP not enabled or invalid user ID"
    )
    @APIResponse(
            responseCode = "500",
            description = "Internal server error"
    )
    @Operation(
            summary = "Disable TOTP for user",
            description = "This endpoint disables TOTP for the user."
    )
    public Response disableTotp(@PathParam("user_id") final String userid) {
        return smsOtpRestResourceService.disableTotpCredential(userid);
    }

    @POST
    @Path("totp/disable-with-validation/{user_id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Disable TOTP with validation for user",
            description = "This endpoint validates TOTP before disabling it for the user"
    )
    @APIResponse(
            responseCode = "200",
            description = "TOTP disabled successfully",
            content = {@Content(
                    schema = @Schema(
                            implementation = Response.class,
                            type = SchemaType.OBJECT
                    )
            )}
    )
    @APIResponse(responseCode = "400", description = "TOTP not enabled, invalid code, or invalid user ID")
    @APIResponse(responseCode = "500", description = "Internal server error")
    public Response disableTotpWithValidation(@PathParam("user_id") final String userid, Map<String, String> data) {
        return smsOtpRestResourceService.validateOtpCodeAndDisabledTotpCredential(userid, data);
    }
}
