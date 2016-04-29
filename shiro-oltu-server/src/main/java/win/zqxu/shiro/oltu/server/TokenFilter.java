package win.zqxu.shiro.oltu.server;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.shiro.web.servlet.AdviceFilter;

/**
 * A SHIRO filter for generate OAuth2 access token and refresh token. This
 * filter need a custom OAuthService object, set through oAuthService property.
 * 
 * <p>
 * add this filter in shiro.ini file like this:<br>
 * [main]<br>
 * oAuthService = &lt;custom oAuthService class&gt;<br>
 * oTokenFilter = win.zqxu.shiro.oltu.server.TokenFilter<br>
 * oTokenFilter.oAuthService = $oAuthService<br>
 * <br>
 * [urls]<br>
 * &#47;oauth&#47;token = oTokenFilter
 * </p>
 * Note that the token filter should access by SHIRO anonymous
 * 
 * @author zqxu
 */
public class TokenFilter extends AdviceFilter {
  private OAuthService oAuthService;

  public OAuthService getoAuthService() {
    return oAuthService;
  }

  public void setoAuthService(OAuthService oAuthService) {
    this.oAuthService = oAuthService;
  }

  @Override
  protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    I18N i18n = new I18N(request.getLocale());
    try {
      OAuthTokenRequest oAuthRequest = new OAuthTokenRequest(httpRequest);
      String clientId = oAuthRequest.getClientId();
      // Check client id
      if (!oAuthService.checkClient(clientId))
        return ResponseUtils.processResponse(httpResponse, null,
            ResponseUtils.responseInvalidClient(i18n.getString("INVALID_CLIENT_ID")));
      // Check client secret
      if (!oAuthService.checkClient(clientId, oAuthRequest.getClientSecret()))
        return ResponseUtils.processResponse(httpResponse, null,
            ResponseUtils.responseUnauthClient(i18n.getString("INVALID_CLIENT_SECRET")));
      // Check grant data according to grant type
      String grantType = oAuthRequest.getGrantType();
      String authCode = oAuthRequest.getCode();
      String refreshToken = oAuthRequest.getRefreshToken();
      if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType)) {
        if (!oAuthService.checkAuthCode(authCode, clientId))
          return ResponseUtils.processResponse(httpResponse, null,
              ResponseUtils.responseInvalidGrant(i18n.getString("INVALID_AUTH_CODE")));
      } else if (oAuthService.refreshTokenSupported()
          && GrantType.REFRESH_TOKEN.toString().equals(grantType)) {
        if (!oAuthService.checkRefreshToken(refreshToken, clientId))
          return ResponseUtils.processResponse(httpResponse, null,
              ResponseUtils.responseInvalidGrant(i18n.getString("INVALID_REFRESH_CODE")));
      } else {
        return ResponseUtils.processResponse(httpResponse, null,
            ResponseUtils.responseUnsuppGrant(i18n.getString("UNSUPPORT_GRANT_TYPE")));
      }
      // generate access token
      OAuthIssuerImpl oAuthIssuer = new OAuthIssuerImpl(new MD5Generator());
      String accessToken = oAuthIssuer.accessToken();
      if (GrantType.AUTHORIZATION_CODE.toString().equals(grantType))
        oAuthService.addAcessToken(accessToken, authCode);
      else
        oAuthService.refreshAccessToken(accessToken, refreshToken);
      // generate refresh token
      refreshToken = null;
      if (oAuthService.refreshTokenSupported()) {
        refreshToken = oAuthIssuer.refreshToken();
        oAuthService.addRefreshToken(refreshToken, accessToken);
      }
      // generate page content
      String expireIn = String.valueOf(oAuthService.getExpireIn());
      return ResponseUtils.processResponse(httpResponse, null,
          OAuthASResponse.tokenResponse(HttpServletResponse.SC_OK).setExpiresIn(expireIn)
              .setAccessToken(accessToken).setRefreshToken(refreshToken));
    } catch (OAuthProblemException ex) {
      return ResponseUtils.processResponse(httpResponse, null,
          ResponseUtils.responseBadRequest(ex));
    }
  }
}
