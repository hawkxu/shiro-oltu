package win.zqxu.shiro.oltu.client;

import java.util.Set;

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.validator.CodeValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;

/**
 * OAuth response using JSON body
 * 
 * @author zqxu
 */
public class OAuthAuthzResponse extends OAuthClientResponse {
  public OAuthAuthzResponse() {
    this.validator = new CodeValidator();
  }

  @Override
  protected void init(String body, String contentType, int responseCode)
      throws OAuthProblemException {
    super.init(body, contentType, responseCode);
  }

  /**
   * get authorization code
   * 
   * @return authorization code
   */
  public String getCode() {
    return getParam(OAuth.OAUTH_CODE);
  }

  /**
   * get scopes
   * 
   * @return scopes
   */
  public Set<String> getScopes() {
    return OAuthUtils.decodeScopes(getParam(OAuth.OAUTH_SCOPE));
  }

  /**
   * get state
   * 
   * @return state
   */
  public String getState() {
    return getParam(OAuth.OAUTH_STATE);
  }

  public String getBody() {
    return body;
  }

  @Override
  protected void setBody(String body) throws OAuthProblemException {
    this.body = body;
    try {
      this.parameters = JSONUtils.parseJSON(body);
    } catch (Exception ex) {
      throw OAuthProblemException.error(OAuthError.CodeResponse.UNSUPPORTED_RESPONSE_TYPE,
          "Invalid response! Response body is not application/json encoded");
    }
  }

  public String getContentType() {
    return contentType;
  }

  @Override
  protected void setContentType(String contentType) {
    this.contentType = contentType;
  }

  public int getResponseCode() {
    return responseCode;
  }

  @Override
  protected void setResponseCode(int responseCode) {
    this.responseCode = responseCode;
  }
}
