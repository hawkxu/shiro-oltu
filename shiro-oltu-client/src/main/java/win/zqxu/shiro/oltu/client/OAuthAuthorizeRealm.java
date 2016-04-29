package win.zqxu.shiro.oltu.client;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;

/**
 * <p>
 * OAuth authorize realm, authorize through OAuth authorization code and get
 * access token from OAuth server.
 * </p>
 * 
 * <p>
 * the client application can extends this class and override
 * {@link #requestAttributes} method to provide more attributes
 * </p>
 * 
 * @author zqxu
 */
public class OAuthAuthorizeRealm extends AuthorizingRealm {
  private String tokenURI;
  private String clientId;
  private String clientSecret;
  private String defaultRoles;
  private String defaultPermissions;

  /**
   * Constructor, set authentication token class to {@link OAuthClientToken}
   */
  public OAuthAuthorizeRealm() {
    super();
    setAuthenticationTokenClass(OAuthClientToken.class);
    setCredentialsMatcher(new AllowAllCredentialsMatcher());
  }

  /**
   * get token URI
   * 
   * @return token URI
   */
  public String getTokenURI() {
    return tokenURI;
  }

  /**
   * set token URI
   * 
   * @param tokenURI
   *          token URI
   */
  public void setTokenURI(String tokenURI) {
    this.tokenURI = tokenURI;
  }

  /**
   * get client id
   * 
   * @return client id
   */
  public String getClientId() {
    return clientId;
  }

  /**
   * set client id
   * 
   * @param clientId
   *          client id
   */
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  /**
   * get client secret
   * 
   * @return client secret
   */
  public String getClientSecret() {
    return clientSecret;
  }

  /**
   * set client secret
   * 
   * @param clientSecret
   *          client secret
   */
  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  /**
   * get default roles for OAuth2 authenticated user
   * 
   * @return default roles
   */
  public String getDefaultRoles() {
    return defaultRoles;
  }

  /**
   * set default roles for OAuth2 authenticated user
   * 
   * @param defaultRoles
   *          default roles, separated by comma
   */
  public void setDefaultRoles(String defaultRoles) {
    this.defaultRoles = defaultRoles;
  }

  /**
   * get default permissions for OAuth2 authenticated user
   * 
   * @return default permissions
   */
  public String getDefaultPermissions() {
    return defaultPermissions;
  }

  /**
   * set default permissions for OAuth2 authenticated user
   * 
   * @param defaultPermissions
   *          default permissions, separated by comma
   */
  public void setDefaultPermissions(String defaultPermissions) {
    this.defaultPermissions = defaultPermissions;
  }

  /**
   * authenticate through OAuth token URI
   */
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
      throws AuthenticationException {
    OAuthClientToken clientToken = (OAuthClientToken) token;
    OAuthClient client = new OAuthClient(new CloseableHttpClient4());
    try {
      OAuthClientRequest oAuthRequest = OAuthClientRequest.tokenLocation(tokenURI)
          .setClientId(clientId).setClientSecret(clientSecret)
          .setGrantType(clientToken.getGrantType()).setCode(clientToken.getAuthCode())
          .setRefreshToken(clientToken.getRefreshToken()).setRedirectURI("client")
          .buildBodyMessage();
      return buildAuthenticationInfo(clientToken, client.accessToken(oAuthRequest));
    } catch (OAuthSystemException | OAuthProblemException ex) {
      throw new AuthenticationException(ex.getMessage(), ex);
    } finally {
      client.shutdown();
    }
  }

  /**
   * create authentication info, by default, this create
   * SimpleAuthenticationInfo with principals using access token as primary
   * principal and a map contains attributes {@link OAuth#OAUTH_ACCESS_TOKEN}
   * and {@link OAuth#OAUTH_EXPIRES_IN} and {@link OAuth#OAUTH_REFRESH_TOKEN}
   * and {@link OAuthConstants#OAUTH_TOKEN_TIME} and
   * {@link OAuthConstants#OAUTH_SCOPES}, the credentials set to byte array of
   * access token. if sub-class override requestAttributes and returned
   * attributes contains key {@link OAuthConstants#OAUTH_PRINCIPAL}, then the
   * value will be used as primary principal.
   * 
   * @param clientToken
   *          the client token
   * @param oAuthResponse
   *          OAuth access token response
   * @return
   */
  protected AuthenticationInfo buildAuthenticationInfo(OAuthClientToken clientToken,
      OAuthAccessTokenResponse oAuthResponse) {
    String accessToken = oAuthResponse.getAccessToken();
    Date tokenTime = new Date();
    Map<String, Object> attributes = requestAttributes(oAuthResponse);
    if (attributes == null)
      attributes = new HashMap<String, Object>();
    else
      attributes = new HashMap<String, Object>(attributes);
    List<Object> principals = new ArrayList<Object>();
    if (attributes.containsKey(OAuthConstants.OAUTH_PRINCIPAL))
      principals.add(attributes.get(OAuthConstants.OAUTH_PRINCIPAL));
    else
      principals.add(accessToken);
    attributes.put(OAuth.OAUTH_ACCESS_TOKEN, accessToken);
    attributes.put(OAuth.OAUTH_EXPIRES_IN, oAuthResponse.getExpiresIn());
    attributes.put(OAuth.OAUTH_REFRESH_TOKEN, oAuthResponse.getRefreshToken());
    attributes.put(OAuthConstants.OAUTH_TOKEN_TIME, tokenTime);
    attributes.put(OAuthConstants.OAUTH_SCOPES, clientToken.getScopes());
    principals.add(attributes);
    PrincipalCollection collection = new SimplePrincipalCollection(principals, getName());
    return new SimpleAuthenticationInfo(collection, accessToken);
  }

  /**
   * sub-class should override this method to request principal attributes,
   * these attributes will put as Subject second principal in type Map. Note
   * {@link OAuth#OAUTH_ACCESS_TOKEN} and {@link OAuth#OAUTH_EXPIRES_IN} and
   * {@link OAuth#OAUTH_REFRESH_TOKEN} and
   * {@link OAuthConstants#OAUTH_TOKEN_TIME} and
   * {@link OAuthConstants#OAUTH_SCOPES} will be put later, so do not use those
   * five keys.
   * 
   * @param oAuthResponse
   *          OAuth access token response
   * @return principal attributes, if the returned attributes contains key
   *         <b>principal</b>, then the value will be used as Subject primary
   *         principal
   */
  protected Map<String, Object> requestAttributes(OAuthAccessTokenResponse oAuthResponse) {
    return null;
  }

  /**
   * create authorization info using defaultRoles and defaultPermissions
   */
  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    SimpleAuthorizationInfo authorization = new SimpleAuthorizationInfo();
    if (!OAuthUtils.isEmpty(defaultRoles))
      authorization.addRoles(split(defaultRoles));
    if (!OAuthUtils.isEmpty(defaultPermissions))
      authorization.addStringPermissions(split(defaultPermissions));
    return authorization;
  }

  private List<String> split(String value) {
    List<String> splitted = new ArrayList<String>();
    for (String item : value.split(","))
      splitted.add(item.trim());
    return splitted;
  }
}
