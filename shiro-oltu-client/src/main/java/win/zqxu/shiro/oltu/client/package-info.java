/**
 * <p>
 * Integrate SHIRO with OLTU as OAuth2 client library, can using in stand-alone
 * application
 * </p>
 * <ul>
 * <li>Create realm object by using or extends OAuthAuthorizeRealm</li>
 * <li>Using the realm object to construct SHRIO SecurityManager and pass to
 * SecurityUtils.setSecurityManager</li>
 * <li>Done HTTP session authentication using HttpClient4 and save the
 * HttpClient object</li>
 * <li>Create OAuthAuthzRequester instance (the requester) and set necessary
 * properties, get OAuthClientToken object using the requester by pass the HTTP
 * session authenticated HttpClient object to it</li>
 * <li>do SHIRO login using the OAuthClientToken object</li>
 * </ul>
 * <p>
 * The client application can get OAuth2 resource by using OAuthResRequester or
 * using OAuthClient API directly
 * </p>
 * 
 * @author zqxu
 */
package win.zqxu.shiro.oltu.client;