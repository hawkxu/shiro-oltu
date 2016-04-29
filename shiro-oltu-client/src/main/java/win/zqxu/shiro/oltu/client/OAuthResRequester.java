package win.zqxu.shiro.oltu.client;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;

public class OAuthResRequester {
  /**
   * get resource body from OAuth2 resource body
   * 
   * @param URI
   *          resource URI
   * @param accessToken
   *          access token
   * @return resource body
   * @throws URISyntaxException
   * @throws OAuthSystemException
   * @throws OAuthProblemException
   */
  public static String resource(String URI, String accessToken)
      throws URISyntaxException, OAuthSystemException, OAuthProblemException {
    return resource(URI, null, accessToken);
  }

  /**
   * get resource body from OAuth2 resource body
   * 
   * @param URI
   *          resource URI
   * @param parameters
   *          resource parameters
   * @param accessToken
   *          access token
   * @return resource body
   * @throws URISyntaxException
   * @throws OAuthSystemException
   * @throws OAuthProblemException
   */
  public static String resource(String URI, Map<String, String> parameters, String accessToken)
      throws URISyntaxException, OAuthSystemException, OAuthProblemException {
    CloseableHttpClient client = HttpClients.custom().setRedirectStrategy(new LaxRedirectStrategy())
        .build();
    try {
      return resource(client, URI, parameters, accessToken);
    } finally {
      try {
        client.close();
      } catch (IOException e) {
        // this can be safely ignored
      }
    }
  }

  /**
   * get resource body from OAuth2 resource body
   * 
   * @param client
   *          HttpClient object
   * @param URI
   *          resource URI
   * @param parameters
   *          resource parameters
   * @param accessToken
   *          access token
   * @return resource body
   * @throws URISyntaxException
   * @throws OAuthSystemException
   * @throws OAuthProblemException
   */
  public static String resource(CloseableHttpClient client, String URI,
      Map<String, String> parameters, String accessToken)
      throws URISyntaxException, OAuthSystemException, OAuthProblemException {
    if (parameters != null)
      URI = rebuildURI(URI, parameters);
    CloseableHttpClient4 proxy = new CloseableHttpClient4(client);
    OAuthClient oAuthClient = new OAuthClient(proxy);
    OAuthClientRequest request = new OAuthBearerClientRequest(URI).setAccessToken(accessToken)
        .buildHeaderMessage();
    OAuthResResponse response = oAuthClient.resource(request, OAuth.HttpMethod.GET,
        OAuthResResponse.class);
    return response.getBody();
  }

  private static String rebuildURI(String URI, Map<String, String> parameters)
      throws URISyntaxException {
    URIBuilder builder = new URIBuilder(URI);
    for (Entry<String, String> param : parameters.entrySet())
      builder.addParameter(param.getKey(), param.getValue());
    return builder.toString();
  }
}
