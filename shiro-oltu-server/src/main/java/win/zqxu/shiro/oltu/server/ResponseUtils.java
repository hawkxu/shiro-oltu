package win.zqxu.shiro.oltu.server;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.OAuthResponse.OAuthResponseBuilder;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.oltu.oauth2.rs.response.OAuthRSResponse;

/**
 * Toolkit class for generate OAuth2 response, for internal use.
 * 
 * @author zqxu
 */
class ResponseUtils {
  /**
   * create invalid client response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseInvalidClient(String description) {
    return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
        .setError(OAuthError.TokenResponse.INVALID_CLIENT).setErrorDescription(description);
  }

  /**
   * create unauthorized client response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseUnauthClient(String description) {
    return OAuthResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
        .setError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).setErrorDescription(description);
  }

  /**
   * create access denied response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseAccessDenied(String description) {
    return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
        .setError(OAuthError.CodeResponse.ACCESS_DENIED).setErrorDescription(description);
  }

  /**
   * create invalid request response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseInvalidRequest(String description) {
    return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
        .setError(OAuthError.TokenResponse.INVALID_REQUEST).setErrorDescription(description);
  }

  /**
   * create invalid scope response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseInvalidScope(String description) {
    return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
        .setError(OAuthError.CodeResponse.INVALID_SCOPE).setErrorDescription(description);
  }

  /**
   * create invalid grant response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseInvalidGrant(String description) {
    return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
        .setError(OAuthError.TokenResponse.INVALID_GRANT).setErrorDescription(description);
  }

  /**
   * create unsupported grant type response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseUnsuppGrant(String description) {
    return OAuthResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
        .setError(OAuthError.TokenResponse.UNSUPPORTED_GRANT_TYPE).setErrorDescription(description);
  }

  /**
   * create general bad request response builder
   * 
   * @param ex
   *          OAuth exception object
   * @return response builder
   */
  public static OAuthResponseBuilder responseBadRequest(OAuthProblemException ex) {
    return OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST).error(ex);
  }

  /**
   * create success response builder with authorization code, scope and state
   * 
   * @param request
   *          HTTP request object
   * @param authCode
   *          OAuth authorization code
   * @param scope
   *          OAuth authorization scope
   * @param state
   *          OAuth state
   * @return response builder
   */
  public static OAuthResponseBuilder responseAuthCode(HttpServletRequest request, String authCode,
      String scope, String state) {
    request = new ReplaceStateRequest(request, state);
    return OAuthASResponse.authorizationResponse(request, HttpServletResponse.SC_OK)
        .setCode(authCode).setScope(scope);
  }

  /**
   * create success response builder with access token, expire in and refresh
   * token
   * 
   * @param accessToken
   *          access token
   * @param expireIn
   *          access token expire in
   * @param refreshToken
   *          refresh token
   * @return response builder
   */
  public static OAuthResponseBuilder responseAccessCode(String accessToken, long expireIn,
      String refreshToken) {
    return OAuthASResponse.tokenResponse(HttpServletResponse.SC_OK).setAccessToken(accessToken)
        .setExpiresIn(String.valueOf(expireIn)).setRefreshToken(refreshToken);
  }

  /**
   * create invalid token response builder
   * 
   * @param description
   *          error description
   * @return response builder
   */
  public static OAuthResponseBuilder responseInvalidToken(String description) {
    return OAuthRSResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
        .setError(OAuthError.ResourceResponse.INVALID_TOKEN).setErrorDescription(description);
  }

  /**
   * send OAuth response to client
   * 
   * @param response
   *          HTTP response
   * @param redirectURI
   *          redirect URI
   * @param builder
   *          response builder
   * @return always return false
   * @throws IOException
   *           If an input or output exception occurs
   * @throws OAuthSystemException
   *           If an OAuth system exception occurs
   */
  public static boolean processResponse(HttpServletResponse response, String redirectURI,
      OAuthResponseBuilder builder) throws IOException, OAuthSystemException {
    if (OAuthUtils.isEmpty(redirectURI)) {
      OAuthResponse oAuthResponse = builder.buildJSONMessage();
      response.setStatus(oAuthResponse.getResponseStatus());
      response.getWriter().print(oAuthResponse.getBody());
    } else {
      builder.location(redirectURI);
      OAuthResponse oAuthResponse = builder.buildQueryMessage();
      response.setStatus(HttpServletResponse.SC_FOUND);
      response.sendRedirect(oAuthResponse.getLocationUri());
    }
    return false; // this method must return false to break filter chain
  }

  private static class ReplaceStateRequest extends HttpServletRequestWrapper {
    private String state;

    public ReplaceStateRequest(HttpServletRequest request, String state) {
      super(request);
      this.state = state;
    }

    @Override
    public String getParameter(String name) {
      if (name.equals(OAuth.OAUTH_STATE))
        return state;
      else
        return super.getParameter(name);
    }
  }
}
