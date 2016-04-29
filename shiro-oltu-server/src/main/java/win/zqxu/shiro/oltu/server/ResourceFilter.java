package win.zqxu.shiro.oltu.server;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.rs.request.OAuthAccessResourceRequest;
import org.apache.oltu.oauth2.rs.response.OAuthRSResponse;
import org.apache.shiro.web.servlet.AdviceFilter;

/**
 * <p>
 * A SHIRO filter to provide OAuth2 resource access control, if client has valid
 * access token, then the filter let it pass through, otherwise the filter
 * reject access and send back OAuth2 error.
 * </p>
 * 
 * <p>
 * The OAuth2 resource can be any page accept HTTP GET method, because OAuth2
 * client can only access resource using GET method.
 * </p>
 * 
 * <p>
 * This filter need a custom OAuthService object, set through oAuthService
 * property.
 * </p>
 * 
 * <p>
 * add this filter in shiro.ini file like this:<br>
 * [main]<br>
 * oAuthService = &lt;custom oAuthService class&gt;<br>
 * oResourceFilter = win.zqxu.shiro.oltu.server.ResourceFilter<br>
 * oResourceFilter.oAuthService = $oAuthService<br>
 * <br>
 * [urls]<br>
 * &#47;resource&#47;** = oResourceFilter
 * </p>
 * Note that the resources should access by SHIRO anonymous.
 * 
 * @author zqxu
 */
public class ResourceFilter extends AdviceFilter {
  private OAuthService oAuthService;

  public OAuthService getoAuthService() {
    return oAuthService;
  }

  public void setoAuthService(OAuthService oAuthService) {
    this.oAuthService = oAuthService;
  }

  @Override
  protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
    return CheckAccessToken((HttpServletRequest) request, (HttpServletResponse) response);
  }

  protected boolean CheckAccessToken(HttpServletRequest request, HttpServletResponse response)
      throws IOException, OAuthSystemException {
    try {
      String accessToken = new OAuthAccessResourceRequest(request).getAccessToken();
      if (oAuthService.checkAccessToken(accessToken, request))
        return true;
      // because OLTU client not process error in response header
      // so still send JSON data back, the client need process this error
      I18N i18n = new I18N(request.getLocale());
      return ResponseUtils.processResponse(response, null,
          ResponseUtils.responseInvalidToken(i18n.getString("INVALID_TOKEN")));
    } catch (OAuthProblemException ex) {
      return ResponseUtils.processResponse(response, null,
          OAuthRSResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED).error(ex));
    }
  }
}
