package win.zqxu.shiro.oltu.client;

public interface OAuthConstants {
  /**
   * attribute key for access token request time, the attribute value type
   * should be java.util.Date
   */
  String OAUTH_TOKEN_TIME = "token_time";

  /**
   * attribute key for OAuth scopes, the attribute value type should be
   * Set&lt;String&gt;
   */
  String OAUTH_SCOPES = "scopes";

  /**
   * attribute key for principal
   */
  String OAUTH_PRINCIPAL = "principal";
}
