package win.zqxu.shiro.oltu.server;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;

/**
 * A SHIRO filter for generate OAuth2 authentication code. This filter need a
 * custom OAuthService object, set through oAuthService property.
 * 
 * <p>
 * add this filter in shiro.ini file like this:<br>
 * [main]<br>
 * oAuthService = &lt;custom oAuthService class&gt;<br>
 * oAuthorizeFilter = win.zqxu.shiro.oltu.server.AuthorizeFilter<br>
 * oAuthorizeFilter.oAuthService = $oAuthService<br>
 * <br>
 * [urls]<br>
 * &#47;oauth&#47;authorize = authc, oAuthorizeFilter
 * </p>
 * Note that the authorize filter should only access by authenticated user
 * 
 * @author zqxu
 */
public class AuthorizeFilter extends AdviceFilter {
  private static final String SAVED_OAUTH_REQUEST_KEY = AuthorizeFilter.class.getName()
      + "_SAVED_OAUTH_REQUEST";
  private OAuthService oAuthService;

  public OAuthService getoAuthService() {
    return oAuthService;
  }

  public void setoAuthService(OAuthService oAuthService) {
    this.oAuthService = oAuthService;
  }

  @Override
  protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
    I18N i18n = new I18N(request.getLocale());
    if (!SecurityUtils.getSubject().isAuthenticated()) {
      throw new IllegalStateException(i18n.getString("NOT_AUTHENTICATED"));
    }
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    try {
      if (noSavedRequest())
        return processOAuthRequest(httpRequest, httpResponse);
      else
        return processSavedRequest(httpRequest, httpResponse);
    } catch (OAuthProblemException ex) {
      if (OAuthUtils.isEmpty(ex.getError()))
        return ResponseUtils.processResponse(httpResponse, ex.getRedirectUri(),
            ResponseUtils.responseInvalidRequest(ex.getDescription()));
      return ResponseUtils.processResponse(httpResponse, ex.getRedirectUri(),
          ResponseUtils.responseBadRequest(ex));
    }
  }

  /**
   * process new OAuth request
   * 
   * @param request
   *          HTTP request
   * @param response
   *          HTTP response
   * @return always returns false
   * @throws IOException
   * @throws OAuthSystemException
   * @throws OAuthProblemException
   */
  protected boolean processOAuthRequest(HttpServletRequest request, HttpServletResponse response)
      throws IOException, OAuthProblemException, OAuthSystemException {
    I18N i18n = new I18N(request.getLocale());
    OAuthAuthzRequest oAuthRequest = new OAuthAuthzRequest(request);
    String clientId = oAuthRequest.getClientId();
    String redirectURI = oAuthRequest.getRedirectURI();
    // check client id
    if (!oAuthService.checkClient(clientId))
      return ResponseUtils.processResponse(response, redirectURI,
          ResponseUtils.responseInvalidClient(i18n.getString("INVALID_CLIENT_ID")));
    // check response type
    String responseType = oAuthRequest.getResponseType();
    if (!ResponseType.CODE.toString().equals(responseType))
      return ResponseUtils.processResponse(response, redirectURI,
          ResponseUtils.responseInvalidRequest(i18n.getString("UNSUPPORT_RESP_TYPE")));
    // check scopes
    Set<String> scopes = oAuthRequest.getScopes();
    for (String scope : scopes) {
      if (!oAuthService.checkScope(scope))
        return ResponseUtils.processResponse(response, redirectURI,
            ResponseUtils.responseInvalidScope(i18n.getString("INVALID_SCOPE") + scope));
    }
    // determine whether need user confirm or not
    if (oAuthService.askUserConfirm(clientId, scopes)) {
      if (!OAuthUtils.isEmpty(oAuthService.userConfirmURI()))
        return redirectToUserConfirm(request, response, oAuthRequest);
    }
    // generate authorization code and redirect back
    return generateAuthorizationCode(request, response, new SavedOAuthRequest(oAuthRequest));
  }

  /**
   * redirect to user confirm page
   * 
   * @param oAuthRequest
   *          OAuth request
   * @return always returns false
   * @throws IOException
   */
  protected boolean redirectToUserConfirm(HttpServletRequest request, HttpServletResponse response,
      OAuthAuthzRequest oAuthRequest) throws IOException {
    saveOAuthRequest(oAuthRequest);
    SavedOAuthRequest savedRequest = readSavedRequest();
    Map<String, String> parameters = new HashMap<String, String>();
    parameters.put(OAuthService.CONFIRM_KEY, savedRequest.confirmKey);
    parameters.put(OAuth.OAUTH_CLIENT_ID, oAuthRequest.getClientId());
    parameters.put(OAuth.OAUTH_SCOPE, oAuthRequest.getParam(OAuth.OAUTH_SCOPE));
    parameters.put(OAuth.OAUTH_REDIRECT_URI, request.getRequestURI());
    WebUtils.issueRedirect(request, response, oAuthService.userConfirmURI(), parameters);
    return false;
  }

  /**
   * process saved request
   * 
   * @param request
   *          HTTP request
   * @param response
   *          HTTP response
   * @return always returns false
   * @throws IOException
   * @throws OAuthSystemException
   * @throws OAuthProblemException
   */
  protected boolean processSavedRequest(HttpServletRequest request, HttpServletResponse response)
      throws IOException, OAuthProblemException, OAuthSystemException {
    I18N i18n = new I18N(request.getLocale());
    // Check new OAuth request
    String confirmKey = request.getParameter(OAuthService.CONFIRM_KEY);
    if (OAuthUtils.isEmpty(confirmKey)) {
      clearSavedRequest(); // ignore saved request because new request come in
      return processOAuthRequest(request, response);
    }
    // Check saved request expired
    SavedOAuthRequest savedRequest = readSavedRequest();
    if (!savedRequest.confirmKey.equals(confirmKey)) {
      return ResponseUtils.processResponse(response, null,
          ResponseUtils.responseInvalidRequest(i18n.getString("REQUEST_EXPIRED")));
    }
    // Check user confirmed result
    String confirmResult = request.getParameter(OAuthService.CONFIRM_RESULT);
    if (!Boolean.valueOf(confirmResult))
      return ResponseUtils.processResponse(response, savedRequest.redirectURI,
          ResponseUtils.responseAccessDenied(i18n.getString("USER_REJECT_REQUEST")));
    // Update authorization scopes
    String scope = request.getParameter(OAuth.OAUTH_SCOPE);
    savedRequest.scopes = OAuthUtils.decodeScopes(scope);
    // Generate authorization code and redirect back
    return generateAuthorizationCode(request, response, savedRequest);
  }

  /**
   * All check passed, generate authorization code and redirect back
   * 
   * @param request
   *          HTTP request
   * @param response
   *          HTTP response
   * @param savedRequest
   *          saved request
   * @return always returns false
   * @throws OAuthSystemException
   * @throws IOException
   */
  protected boolean generateAuthorizationCode(HttpServletRequest request,
      HttpServletResponse response, SavedOAuthRequest savedRequest)
      throws IOException, OAuthSystemException {
    String authCode = new OAuthIssuerImpl(new MD5Generator()).authorizationCode();
    String scope = null;
    if (savedRequest.scopes != null)
      scope = OAuthUtils.encodeScopes(savedRequest.scopes);
    oAuthService.addAuthCode(authCode, savedRequest.clientId, savedRequest.scopes);
    clearSavedRequest(); // Clear saved request before redirect back
    return ResponseUtils.processResponse(response, savedRequest.redirectURI,
        ResponseUtils.responseAuthCode(request, authCode, scope, savedRequest.state));
  }

  /**
   * Check if there is no saved request.
   * 
   * @return true if no saved request
   */
  protected boolean noSavedRequest() {
    Session session = SecurityUtils.getSubject().getSession();
    return session.getAttribute(SAVED_OAUTH_REQUEST_KEY) == null;
  }

  /**
   * Save OAuth request
   * 
   * @param oAuthRequest
   *          OAuth request
   */
  protected void saveOAuthRequest(OAuthAuthzRequest oAuthRequest) {
    Session session = SecurityUtils.getSubject().getSession();
    SavedOAuthRequest saved = new SavedOAuthRequest(oAuthRequest);
    session.setAttribute(SAVED_OAUTH_REQUEST_KEY, saved);
  }

  /**
   * Read saved OAuth request
   * 
   * @return saved OAuth request
   */
  protected SavedOAuthRequest readSavedRequest() {
    Session session = SecurityUtils.getSubject().getSession();
    return (SavedOAuthRequest) session.getAttribute(SAVED_OAUTH_REQUEST_KEY);
  }

  /**
   * Clear saved OAuth request
   */
  protected void clearSavedRequest() {
    Session session = SecurityUtils.getSubject().getSession();
    session.removeAttribute(SAVED_OAUTH_REQUEST_KEY);
  }

  /**
   * Used to save OAuth request attributes
   * 
   * @author zqxu
   */
  protected static class SavedOAuthRequest {
    public String confirmKey;
    public String clientId;
    public String state;
    public Set<String> scopes;
    public String redirectURI;

    public SavedOAuthRequest(OAuthAuthzRequest oAuthRequest) {
      confirmKey = UUID.randomUUID().toString();
      clientId = oAuthRequest.getClientId();
      state = oAuthRequest.getState();
      scopes = oAuthRequest.getScopes();
      redirectURI = oAuthRequest.getRedirectURI();
    }
  }
}
