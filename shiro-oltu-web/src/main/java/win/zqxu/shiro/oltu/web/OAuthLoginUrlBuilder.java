package win.zqxu.shiro.oltu.web;

import org.apache.oltu.oauth2.common.OAuth;

import win.zqxu.shiro.oltu.client.OAuthAuthzRequester;

public class OAuthLoginUrlBuilder extends OAuthAuthzRequester {
  private String callbackURI;

  /**
   * get call back URI on this server
   * 
   * @return call back URI
   */
  public String getCallbackURI() {
    return callbackURI;
  }

  /**
   * set call back URI on this server
   * 
   * @param callbackURI
   *          call back URI
   */
  public void setCallbackURI(String callbackURI) {
    this.callbackURI = callbackURI;
  }

  public String getShiroLoginUrl() {
    return getQueryURI() + "&" + OAuth.OAUTH_REDIRECT_URI + "=" + getCallbackURI();
  }

  public String toString() {
    return getShiroLoginUrl();
  }
}
