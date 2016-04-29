package win.zqxu.shiro.oltu.client;

import java.util.Map;

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.validator.OAuthClientValidator;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;

public class OAuthResValidator extends OAuthClientValidator {

  @Override
  public void validate(OAuthClientResponse response) throws OAuthProblemException {
    if (response instanceof OAuthResResponse)
      validateResouceResponse((OAuthResResponse) response);
  }

  private void validateResouceResponse(OAuthResResponse response) throws OAuthProblemException {
    int responseCode = response.getResponseCode();
    if (responseCode != 400 && responseCode != 401)
      return;
    try {
      Map<String, Object> values = JSONUtils.parseJSON(response.getBody());
      String error = (String) values.get(OAuthError.OAUTH_ERROR);
      if (error == null || error.isEmpty())
        return;
      String description = (String) values.get(OAuthError.OAUTH_ERROR_DESCRIPTION);
      throw OAuthProblemException.error(error, description);
    } catch (IllegalArgumentException ex) {
      // body not in JSON format, ignore it
    }
  }
}
