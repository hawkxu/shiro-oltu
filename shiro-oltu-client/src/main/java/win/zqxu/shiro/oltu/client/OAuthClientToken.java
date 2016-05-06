package win.zqxu.shiro.oltu.client;

import java.util.Set;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.shiro.authc.AuthenticationToken;

/**
 * OAuth client token
 * 
 * @author zqxu
 */
public class OAuthClientToken implements AuthenticationToken {
  private static final long serialVersionUID = 1L;
  private GrantType grantType;
  private String authCode;
  private Set<String> scopes;
  private String refreshToken;

  private OAuthClientToken() {
  }

  /**
   * create OAuthClientToken using authorization code
   * 
   * @param authCode
   *          authorization code
   * @param scopes
   *          OAuth scopes
   * @return OAuth client token
   */
  public static OAuthClientToken authCode(String authCode, Set<String> scopes) {
    OAuthClientToken token = new OAuthClientToken();
    token.authCode = authCode;
    token.scopes = scopes;
    token.grantType = GrantType.AUTHORIZATION_CODE;
    return token;
  }

  /**
   * create OAuthClientToken using refresh token
   * 
   * @param refreshToken
   *          refresh token
   * @param scopes
   *          OAuth scopes
   * @return OAuth client token
   */
  public static OAuthClientToken refreshToken(String refreshToken, Set<String> scopes) {
    OAuthClientToken token = new OAuthClientToken();
    token.refreshToken = refreshToken;
    token.scopes = scopes;
    token.grantType = GrantType.REFRESH_TOKEN;
    return token;
  }

  /**
   * get grant type
   * 
   * @return grant type
   */
  public GrantType getGrantType() {
    return grantType;
  }

  /**
   * get OAuth authorization code
   * 
   * @return OAuth authorization code
   */
  public String getAuthCode() {
    return authCode;
  }

  /**
   * OAuth authorization scopes
   * 
   * @return scopes
   */
  public Set<String> getScopes() {
    return scopes;
  }

  /**
   * get refresh token
   * 
   * @return refresh token
   */
  public String getRefreshToken() {
    return refreshToken;
  }

  /**
   * always return null
   * 
   * @return principal principal
   */
  @Override
  public Object getPrincipal() {
    return null;
  }

  /**
   * 
   * returns principal according to grant type, for
   * {@link GrantType#AUTHORIZATION_CODE} returns authCode, otherwise returns
   * refreshToken
   * 
   * @return null
   */
  @Override
  public Object getCredentials() {
    if (grantType == GrantType.AUTHORIZATION_CODE)
      return getAuthCode();
    else
      return getRefreshToken();
  }
}