package win.zqxu.shiro.oltu.client;

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;

/**
 * OAuth resource response
 * 
 * @author zqxu
 */
public class OAuthResResponse extends OAuthClientResponse {
  public OAuthResResponse() {
    validator = new OAuthResValidator();
  }

  public String getBody() {
    return body;
  }

  @Override
  protected void setBody(String body) throws OAuthProblemException {
    this.body = body;
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
