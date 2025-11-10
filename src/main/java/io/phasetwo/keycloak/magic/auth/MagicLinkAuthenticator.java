package io.phasetwo.keycloak.magic.auth;

import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.phasetwo.keycloak.magic.MagicLink;
import io.phasetwo.keycloak.magic.auth.token.MagicLinkActionToken;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

@JBossLog
public class MagicLinkAuthenticator extends UsernamePasswordForm {

  static final String CREATE_NONEXISTENT_USER_CONFIG_PROPERTY = "ext-magic-create-nonexistent-user";
  static final String UPDATE_PROFILE_ACTION_CONFIG_PROPERTY = "ext-magic-update-profile-action";
  static final String UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY = "ext-magic-update-password-action";

  static final String ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY = "ext-magic-allow-token-reuse";

  static final String RECAPTCHA_SITE_KEY_CONFIG_PROPERTY = "ext-magic-recaptcha-site-key";
  static final String RECAPTCHA_SECRET_CONFIG_PROPERTY = "ext-magic-recaptcha-secret";
  static final String RECAPTCHA_MIN_SCORE_CONFIG_PROPERTY = "ext-magic-recaptcha-min-score";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.authenticate");
    String attemptedUsername = MagicLink.getAttemptedUsername(context);
    if (attemptedUsername == null) {
        String recaptchaSiteKey = context.getAuthenticatorConfig() == null
                ? null
                : context.getAuthenticatorConfig().getConfig().get(MagicLinkAuthenticator.RECAPTCHA_SITE_KEY_CONFIG_PROPERTY);
        if (recaptchaSiteKey != null) {
            context.form().setAttribute("recaptchaSiteKey", recaptchaSiteKey);
        }
      super.authenticate(context);
    } else {
      log.debugf(
          "Found attempted username %s from previous authenticator, skipping login form",
          attemptedUsername);
      action(context);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    log.debug("MagicLinkAuthenticator.action");

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

    String recaptchaResponse = formData.getFirst("g-recaptcha-response");
    if (!verifyRecaptcha(context, recaptchaResponse)) {
        // failed; show error and re-render form
        context.getEvent().user(context.getUser());
        context.getEvent().error("invalid_recaptcha");

        LoginFormsProvider form = context.form().setError("Invalid reCAPTCHA. Please try again.");
        String siteKey = context.getAuthenticatorConfig() == null
                ? null
                : context.getAuthenticatorConfig().getConfig().get(RECAPTCHA_SITE_KEY_CONFIG_PROPERTY);
        if (siteKey != null) {
            form.setAttribute("recaptchaSiteKey", siteKey);
        }

        Response challengeResponse = challenge(context, (String) null);
        context.failureChallenge(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challengeResponse);
        return;
    }

    String email = MagicLink.trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    // check for empty email
    if (email == null) {
      // - first check for email from previous authenticator
      email = MagicLink.getAttemptedUsername(context);
    }
    log.debugf("email in action is %s", email);
    // - throw error if still empty
    if (email == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }
    String clientId = context.getSession().getContext().getClient().getClientId();

    EventBuilder event = context.newEvent();

    UserModel user =
        MagicLink.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            isForceCreate(context, false),
            isUpdateProfile(context, false),
            isUpdatePassword(context, false),
            MagicLink.registerEvent(event));

    // check for no/invalid email address
    if (user == null
        || MagicLink.trimToNull(user.getEmail()) == null
        || !MagicLink.isValidEmail(user.getEmail())) {
      context.getEvent()
              .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
              .event(EventType.LOGIN_ERROR).error(Errors.INVALID_EMAIL);
      context
              .getAuthenticationSession()
              .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
      log.debugf("user attempted to login with username/email: %s", email);
      context.forceChallenge(context.form().createForm("view-email.ftl"));
      return;
    }

    log.debugf("user is %s %s", user.getEmail(), user.isEnabled());

    // check for enabled user
    if (!enabledUser(context, user)) {
      return; // the enabledUser method sets the challenge
    }

    MagicLinkActionToken token =
        MagicLink.createActionToken(
            user,
            clientId,
            OptionalInt.empty(),
            rememberMe(context),
            context.getAuthenticationSession(),
            isActionTokenPersistent(context, true));
    String link = MagicLink.linkFromActionToken(context.getSession(), context.getRealm(), token);
    boolean sent = MagicLink.sendMagicLinkEmail(context.getSession(), user, link);
    log.debugf("sent email to %s? %b. Link? %s", user.getEmail(), sent, link);

    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
    context.challenge(context.form().createForm("view-email.ftl"));
  }

  private boolean rememberMe(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String rememberMe = formData.getFirst("rememberMe");
    return context.getRealm().isRememberMe()
        && rememberMe != null
        && rememberMe.equalsIgnoreCase("on");
  }

  private boolean isForceCreate(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, CREATE_NONEXISTENT_USER_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdateProfile(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PROFILE_ACTION_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isUpdatePassword(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, UPDATE_PASSWORD_ACTION_CONFIG_PROPERTY, defaultValue);
  }

  private boolean isActionTokenPersistent(AuthenticationFlowContext context, boolean defaultValue) {
    return is(context, ACTION_TOKEN_PERSISTENT_CONFIG_PROPERTY, defaultValue);
  }

  private boolean is(AuthenticationFlowContext context, String propName, boolean defaultValue) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null) return defaultValue;

    Map<String, String> config = authenticatorConfig.getConfig();
    if (config == null) return defaultValue;

    String v = config.get(propName);
    if (v == null || "".equals(v)) return defaultValue;

    return v.trim().toLowerCase().equals("true");
  }

  private boolean verifyRecaptcha(AuthenticationFlowContext context, String recaptchaResponse) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null) {
      return false;
    }

    String recaptchaSecret = config.getConfig().get(RECAPTCHA_SECRET_CONFIG_PROPERTY);
    if (recaptchaSecret == null || recaptchaSecret.isBlank()) {
      return true; // recaptcha not configured
    }

    if (recaptchaResponse == null || recaptchaResponse.isBlank()) {
      return false;
    }

    String minScoreStr = config.getConfig().getOrDefault(RECAPTCHA_MIN_SCORE_CONFIG_PROPERTY, "0");
    double minScore = Double.parseDouble(minScoreStr);

    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      HttpPost httpPost = new HttpPost("https://www.google.com/recaptcha/api/siteverify");
      httpPost.setEntity(new UrlEncodedFormEntity(List.of(
              new BasicNameValuePair("secret", recaptchaSecret),
              new BasicNameValuePair("response", recaptchaResponse)
      )));

      try(CloseableHttpResponse response = httpClient.execute(httpPost)) {
        String body = EntityUtils.toString(response.getEntity());

        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != 200) {
          log.error("non-200 response for recaptcha (" + statusCode + "): " + body);
          return false;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(body);
        boolean isSuccess = jsonNode.get("success").asBoolean();
        if (!isSuccess) {
          return false;
        }

        if (minScore > 0 && jsonNode.hasNonNull("score")) {
          double score = jsonNode.get("score").asDouble();
          return score >= minScore;
        }

        return true;
      } catch (Exception e) {
          log.error("Failed to process recaptcha response", e);
          return false;
      }
    } catch (Exception e) {
      log.error("Failed to verify recaptcha", e);
      return false;
    }
  }

  @Override
  protected boolean validateForm(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    log.debug("validateForm");
    return validateUser(context, formData);
  }

  @Override
  protected Response challenge(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    log.debug("challenge");
    LoginFormsProvider forms = context.form();
    if (!formData.isEmpty()) forms.setFormData(formData);
    return forms.createLoginUsername();
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    log.debug("createLoginForm");
    return form.createLoginUsername();
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    log.debug("getDefaultChallengeMessage");
    return context.getRealm().isLoginWithEmailAllowed()
        ? Messages.INVALID_USERNAME_OR_EMAIL
        : Messages.INVALID_USERNAME;
  }
}
