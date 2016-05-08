package win.zqxu.shiro.oltu.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import win.zqxu.shiro.oltu.client.OAuthAuthorizeRealm;
import win.zqxu.shiro.oltu.client.OAuthClientToken;

/**
 * <p>
 * OAuth2 authentication filter for SHIRO, set this filter and
 * {@link OAuthAuthorizeRealm} or its sub-class to SHIRO
 * </p>
 * 
 * <p>
 * INI settings example, <b>change properties to real value</b>:<br>
 * <br>
 * [main]<br>
 * # use extended Class to provide more user attributes<br>
 * oAuthRealm = win.zqxu.shiro.oltu.client.OAuthAuthorizeRealm<br>
 * # change below properties to real value<br>
 * oAuthRealm.tokenURI = https://server/path_to/token<br>
 * oAuthRealm.clientId = xxxx<br>
 * oAuthRealm.clientSecret = xxxx<br>
 * # unmark below two properties to set user default roles and permissions<br>
 * # please read Shiro documentation<br>
 * #oAuthRealm.defaultRoles = default roles<br>
 * #oAuthRealm.defaultPermissions = default permissions<br>
 * <br>
 * # filter to get authorization code and call realm to login<br>
 * oAuthFilter = win.zqxu.shiro.oltu.web.OAuthAuthenticationFilter<br>
 * # verify client request state, must equal to state in loginUrl<br>
 * #oAuthFilter.state = client state<br>
 * # redirect to error page if login failure<br>
 * #oAuthFilter.failureURI = /error.jsp<br>
 * <br>
 * # make login url builder<br>
 * loginUrlBuilder = win.zqxu.shiro.oltu.web.OAuthLoginUrlBuilder<br>
 * loginUrlBuilder.authorizeURI = https://server/path_to/authorize<br>
 * loginUrlBuilder.clientId = xxxx<br>
 * # client request scopes<br>
 * #loginUrlBuilder.scopes = scope1,scope2,...<br>
 * # client request state, muse equal to oAuthFilter.state upstair<br>
 * #loginUrlBuilder.state = client state<br>
 * # callback uri to oAuthFilter<br>
 * loginUrlBuilder.callbackURI = http://this_site/shiro-oauth<br>
 * # use login url builder to generate login url, or you can<br>
 * # input whole login url here instead of use login url builder<br>
 * shiro.loginUrl = $loginUrlBuilder<br>
 * <br>
 * [urls]<br>
 * # callback uri for oAuthFilter<br>
 * /shiro-oauth = oAuthFilter<br>
 * # protect some pages and ask user login first<br>
 * /account/** = authc<br>
 * # other pages would be accessed by anonymous<br>
 * /** = anon<br>
 * </p>
 * 
 * the client application can extends OAuthAuthorizeRealm to provide more
 * subject attributes
 * 
 * @author zqxu
 */
public class OAuthAuthenticationFilter extends AuthenticatingFilter {
  private static final Logger log = LoggerFactory.getLogger(OAuthAuthenticationFilter.class);
  private String state;
  private String failureURI;

  /**
   * get the state to be checked in OAuth2 authentication
   * 
   * @return the state
   */
  public String getState() {
    return state;
  }

  /**
   * set the state to be checked in OAuth2 authentication
   * 
   * @param state
   *          the state
   */
  public void setState(String state) {
    this.state = state;
  }

  /**
   * get failure URI
   * 
   * @return failure URI
   */
  public String getFailureURI() {
    return failureURI;
  }

  /**
   * set failure URI, when OAuth authorization failed, redirect to this URI with
   * parameters error and error_description.
   * <p>
   * the failure page should use {@link OAuthError#OAUTH_ERROR} and
   * {@link OAuthError#OAUTH_ERROR_DESCRIPTION} instead of hard-code parameter
   * name
   * </p>
   * 
   * @param failureURI
   *          failure URI
   */
  public void setFailureURI(String failureURI) {
    this.failureURI = failureURI;
  }

  @Override
  protected AuthenticationToken createToken(ServletRequest request, ServletResponse response)
      throws Exception {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String authCode = httpRequest.getParameter(OAuth.OAUTH_CODE);
    String scope = httpRequest.getParameter(OAuth.OAUTH_SCOPE);
    return OAuthClientToken.authCode(authCode, OAuthUtils.decodeScopes(scope));
  }

  /**
   * Always return false
   */
  @Override
  protected boolean isAccessAllowed(ServletRequest request, ServletResponse response,
      Object mappedValue) {
    return false;
  }

  @Override
  protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
      ServletRequest request, ServletResponse response) throws Exception {
    issueSuccessRedirect(request, response);
    return false;
  }

  @Override
  protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException ex,
      ServletRequest request, ServletResponse response) {
    Subject subject = getSubject(request, response);
    try {
      if (subject.isAuthenticated() || subject.isRemembered()) {
        issueSuccessRedirect(request, response);
      } else {
        log.error("login_failure", ex);
        processAuthorizationError(request, response, "login_failure", ex.getMessage());
      }
    } catch (Exception exception) {
      log.error("error login", exception);
    }
    return false;
  }

  @Override
  protected boolean onAccessDenied(ServletRequest request, ServletResponse response)
      throws Exception {
    String error = request.getParameter(OAuthError.OAUTH_ERROR);
    String description = request.getParameter(OAuthError.OAUTH_ERROR_DESCRIPTION);
    if (!OAuthUtils.isEmpty(error))
      return processAuthorizationError(request, response, error, description);
    if (!OAuthUtils.isEmpty(state) && !state.equals(request.getParameter(OAuth.OAUTH_STATE)))
      return processAuthorizationError(request, response, OAuthError.CodeResponse.SERVER_ERROR,
          "server response state inconsistent with sent state");
    Subject subject = getSubject(request, response);
    if (!subject.isAuthenticated()) {
      if (OAuthUtils.isEmpty(request.getParameter(OAuth.OAUTH_CODE))) {
        saveRequestAndRedirectToLogin(request, response);
        return false;
      }
    }
    return executeLogin(request, response);
  }

  /**
   * the OAuth2 server response error, redirect to failure URI or write error
   * message.
   * 
   * @param request
   *          servlet request
   * @param response
   *          servlet response
   * @param error
   *          OAuth error
   * @param description
   *          error description
   * @return always return false
   * @throws IOException
   *           If an IO exception occurs
   */
  protected boolean processAuthorizationError(ServletRequest request, ServletResponse response,
      String error, String description) throws IOException {
    if (OAuthUtils.isEmpty(failureURI)) {
      PrintWriter writer = response.getWriter();
      writer.println("<div>error: " + error + "</div>");
      writer.println("<div>description: " + description + "</div>");
    } else {
      Map<String, String> parameters = new HashMap<String, String>();
      parameters.put(OAuthError.OAUTH_ERROR, error);
      parameters.put(OAuthError.OAUTH_ERROR_DESCRIPTION, description);
      WebUtils.issueRedirect(request, response, failureURI, parameters);
    }
    return false;
  }
}