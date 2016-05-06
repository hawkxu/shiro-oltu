package win.zqxu.shiro.oltu.server;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.apache.oltu.oauth2.common.OAuth;

/**
 * <p>
 * The application using this library need to implement this interface, to
 * provide authorization code and token verification.
 * </p>
 * <p>
 * Note that the implementation may need to handling synchronization problems.
 * </p>
 * 
 * @author zqxu
 *
 */
public interface OAuthService {
  static final String CONFIRM_KEY = "confirm_key";
  static final String CONFIRM_RESULT = "confirm_result";

  /**
   * Check client id
   * 
   * @param clientId
   *          client id
   * @return true if client id is valid
   */
  boolean checkClient(String clientId);

  /**
   * Check client id and secret
   * 
   * @param clientId
   *          client id
   * @param secret
   *          client secret
   * @return true if client id and secret are valid
   */
  boolean checkClient(String clientId, String secret);

  /**
   * whether the client must provide scope or not. if this method returns true,
   * the client must provide at least one scope for request authorization code.
   * 
   * @param clientId
   *          client id
   * @return true if the client must provide scope
   */
  boolean scopeRequired(String clientId);

  /**
   * Check scope, one of the scopes per time
   * 
   * @param clientId
   *          client id
   * @param scope
   *          scope
   * @return true if scope is valid
   */
  boolean checkScope(String clientId, String scope);

  /**
   * user confirm URI for authorization code requisition, if not null, the
   * LIBRARY will redirect to this URI with <b>confirm_key</b> and
   * <b>client_id</b> and <b>scope</b> and a <b>redirect_uri</b> to redirect
   * back, after user confirmed or cancelled, the confirm page must redirect
   * back with <b>confirm_key</b> and <b>confirm_result</b> (true or false) and
   * <b>scope</b><br>
   * the User confirm page should use constants {@link OAuthService#CONFIRM_KEY}
   * and {@link OAuthService#CONFIRM_RESULT} and {@link OAuth#OAUTH_CLIENT_ID}
   * and {@link OAuth#OAUTH_SCOPE} and {@link OAuth#OAUTH_REDIRECT_URI} instead
   * of hard-code parameter name
   * 
   * @param clientId
   *          client id
   * @param scopes
   *          scopes
   * @return user confirm URI, or null if no confirmation needed
   */
  String userConfirmURI(String clientId, Set<String> scopes);

  /**
   * Client requested an authorization code
   * 
   * @param authCode
   *          authorization code
   * @param clientId
   *          client id
   * @param scopes
   *          scopes
   */
  void addAuthCode(String authCode, String clientId, Set<String> scopes);

  /**
   * Check authorization code
   * 
   * @param authCode
   *          authorization code
   * @param clientId
   *          client id
   * @return true if authorization is valid
   */
  boolean checkAuthCode(String authCode, String clientId);

  /**
   * Client requested an access token using the authorization code.
   * 
   * @param accessToken
   *          access token
   * @param authCode
   *          authorization code
   */
  void addAcessToken(String accessToken, String authCode);

  /**
   * access token expire time in millisecond, the client should request new
   * access token after the access token expires.
   * 
   * @param accessToken
   *          access token
   * 
   * @return access token expire time in millisecond
   */
  long getExpireIn(String accessToken);

  /**
   * Determine whether the implementation class supported refresh token
   * 
   * @return true if the implementation class supported refresh token
   */
  boolean refreshTokenSupported();

  /**
   * Client requested a refresh token for get new access code after the access
   * code expires
   * 
   * @param refreshToken
   *          refresh token to get new access code after the access code expires
   * @param accessToken
   *          the access token
   */
  void addRefreshToken(String refreshToken, String accessToken);

  /**
   * Check refresh token
   * 
   * @param refreshToken
   *          refresh token
   * @param clientId
   *          client id
   * @return true if the refresh token is valid
   */
  boolean checkRefreshToken(String refreshToken, String clientId);

  /**
   * Client requested an access token using the refresh token.
   * 
   * @param accessToken
   *          then new access token requested
   * @param refreshToken
   *          the refresh token used to request access token
   */
  void refreshAccessToken(String accessToken, String refreshToken);

  /**
   * Check access token
   * 
   * @param accessToken
   *          access token
   * @param request
   *          HTTP request
   * @return true if the access token is valid
   */
  boolean checkAccessToken(String accessToken, HttpServletRequest request);
}
