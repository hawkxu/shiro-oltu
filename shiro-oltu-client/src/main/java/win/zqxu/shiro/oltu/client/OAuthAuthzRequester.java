package win.zqxu.shiro.oltu.client;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;

/**
 * Authorize with OAuth2 server, get authorization code.
 * 
 * @author zqxu
 */
public class OAuthAuthzRequester {
  private URI authorizeURI;
  private String clientId;
  private Set<String> scopes;
  private String state;

  /**
   * get authorize URI
   * 
   * @return authorize URI without parameter
   */
  public String getAuthorizeURI() {
    return authorizeURI == null ? null : authorizeURI.toString();
  }

  /**
   * set authorize URI
   * 
   * @param authorizeURI
   *          authorize URI without parameter
   */
  public void setAuthorizeURI(String authorizeURI) {
    try {
      if (OAuthUtils.isEmpty(authorizeURI))
        this.authorizeURI = null;
      else
        this.authorizeURI = new URI(authorizeURI);
    } catch (URISyntaxException ex) {
      throw new IllegalArgumentException("invalid authorize URI", ex);
    }
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
   * get request scopes
   * 
   * @return request scopes
   */
  public Set<String> getScopes() {
    return scopes;
  }

  /**
   * set request scopes
   * 
   * @param scopes
   *          request scopes
   */
  public void setScopes(Set<String> scopes) {
    this.scopes = scopes;
  }

  /**
   * get state
   * 
   * @return set state
   */
  public String getState() {
    return state;
  }

  /**
   * set state
   * 
   * @param state
   *          state
   */
  public void setState(String state) {
    this.state = state;
  }

  /**
   * get full authorize URI with parameters
   * 
   * @return full authorize URI with parameters
   */
  public String getQueryURI() {
    URIBuilder builder = new URIBuilder(authorizeURI);
    builder.addParameter(OAuth.OAUTH_RESPONSE_TYPE, ResponseType.CODE.toString());
    builder.addParameter(OAuth.OAUTH_CLIENT_ID, clientId);
    if (scopes != null)
      builder.addParameter(OAuth.OAUTH_SCOPE, OAuthUtils.encodeScopes(scopes));
    return builder.addParameter(OAuth.OAUTH_STATE, state).toString();
  }

  /**
   * authorize by URI, the client must be HTTP session authenticated before
   * OAuth authorization
   * 
   * @param client
   *          HTTP client
   * @return {@link OAuthClientToken} object
   * @throws OAuthSystemException
   * @throws OAuthProblemException
   */
  public OAuthClientToken authorize(CloseableHttpClient client)
      throws OAuthSystemException, OAuthProblemException {
    try {
      CloseableHttpResponse response = client.execute(new HttpGet(getQueryURI()));
      try {
        String content = EntityUtils.toString(response.getEntity());
        OAuthAuthzResponse oAuthResponse = new OAuthAuthzResponse();
        oAuthResponse.init(content, null, response.getStatusLine().getStatusCode());
        if (!OAuthUtils.isEmpty(state) && !state.equals(oAuthResponse.getState())) {
          throw OAuthProblemException.error(OAuthError.CodeResponse.SERVER_ERROR,
              "server response state inconsistent with sent state");
        }
        return OAuthClientToken.authCode(oAuthResponse.getCode(), oAuthResponse.getScopes());
      } finally {
        response.close();
      }
    } catch (IOException ex) {
      throw new OAuthSystemException(ex);
    }
  }
}