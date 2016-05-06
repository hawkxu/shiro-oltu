package win.zqxu.shiro.oltu.client;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;

/**
 * Get resource response body from OAuth2 resource server.
 * 
 * @author zqxu
 */
public class OAuthResRequester {
  private String accessToken;
  private String charset;

  /**
   * Constructor with access token, posting charset set to UTF-8
   * 
   * @param accessToken
   *          access token
   */
  public OAuthResRequester(String accessToken) {
    this(accessToken, null);
  }

  /**
   * Constructor with access token and posting charset
   * 
   * @param accessToken
   *          access token
   * @param charset
   *          charset for post methods, use UTF-8 if null.
   */
  public OAuthResRequester(String accessToken, String charset) {
    if (OAuthUtils.isEmpty(accessToken))
      throw new IllegalArgumentException("access token can not be empty");
    this.accessToken = accessToken;
    this.charset = charset == null ? "UTF-8" : charset;
  }

  /**
   * get access token
   * 
   * @return access token
   */
  public String getAccessToken() {
    return accessToken;
  }

  /**
   * get posting charset
   * 
   * @return posting charset
   */
  public String getCharset() {
    return charset;
  }

  /**
   * get resource body from OAuth2 resource response using HTTP GET method
   * 
   * @param uri
   *          resource URI
   * @return resource body
   * @throws OAuthSystemException
   *           If an OAuth system exception occurs
   * @throws OAuthProblemException
   *           If an OAuth problem exception occurs
   */
  public String get(String uri) throws OAuthSystemException, OAuthProblemException {
    return get(uri, null);
  }

  /**
   * get resource body from OAuth2 resource response using HTTP GET method
   * 
   * @param uri
   *          resource URI
   * @param parameters
   *          resource parameters
   * @return resource body
   * @throws OAuthSystemException
   *           If an OAuth system exception occurs
   * @throws OAuthProblemException
   *           If an OAuth problem exception occurs
   */
  public String get(String uri, Map<String, String> parameters)
      throws OAuthSystemException, OAuthProblemException {
    CloseableHttpClient client = HttpClients.custom().setRedirectStrategy(new LaxRedirectStrategy())
        .build();
    try {
      return get(client, uri, parameters);
    } finally {
      try {
        client.close();
      } catch (IOException e) {
        // this can be safely ignored
      }
    }
  }

  /**
   * get resource body from OAuth2 resource response using HTTP GET method
   * 
   * @param client
   *          HttpClient object
   * @param uri
   *          resource URI
   * @param parameters
   *          resource parameters
   * @return resource body
   * @throws OAuthSystemException
   *           If an OAuth system exception occurs
   * @throws OAuthProblemException
   *           If an OAuth problem exception occurs
   */
  public String get(CloseableHttpClient client, String uri, Map<String, String> parameters)
      throws OAuthSystemException, OAuthProblemException {
    if (parameters != null)
      uri = rebuildURI(uri, parameters);
    CloseableHttpClient4 proxy = new CloseableHttpClient4(client);
    OAuthClient oAuthClient = new OAuthClient(proxy);
    OAuthClientRequest request = new OAuthBearerClientRequest(uri).setAccessToken(accessToken)
        .buildHeaderMessage();
    return oAuthClient.resource(request, OAuth.HttpMethod.GET, OAuthResResponse.class).getBody();
  }

  private static String rebuildURI(String uri, Map<String, String> parameters) {
    URIBuilder builder = new URIBuilder(URI.create(uri));
    for (Entry<String, String> param : parameters.entrySet())
      builder.addParameter(param.getKey(), param.getValue());
    return builder.toString();
  }

  /**
   * get resource body from OAuth2 resource response using HTTP POST method
   * 
   * @param uri
   *          resource URI
   * @return resource body
   * @throws OAuthSystemException
   *           If an OAuth system exception occurs
   * @throws OAuthProblemException
   *           If an OAuth problem exception occurs
   */
  public String post(String uri) throws OAuthSystemException, OAuthProblemException {
    return post(uri, null);
  }

  /**
   * get resource body from OAuth2 resource response using HTTP POST method with
   * UTF-8 encoded parameters
   * 
   * @param uri
   *          resource URI
   * @param parameters
   *          resource parameters
   * @return resource body
   * @throws OAuthSystemException
   *           If an OAuth system exception occurs
   * @throws OAuthProblemException
   *           If an OAuth problem exception occurs
   */
  public String post(String uri, Map<String, String> parameters)
      throws OAuthSystemException, OAuthProblemException {
    CloseableHttpClient client = HttpClients.custom().setRedirectStrategy(new LaxRedirectStrategy())
        .build();
    try {
      return post(client, uri, parameters);
    } finally {
      try {
        client.close();
      } catch (IOException e) {
        // this can be safely ignored
      }
    }
  }

  /**
   * get resource body from OAuth2 resource response using HTTP POST method with
   * UTF-8 encoded parameters
   * 
   * @param client
   *          HttpClient object
   * @param uri
   *          resource URI
   * @param parameters
   *          resource parameters
   * @return resource body
   * @throws OAuthSystemException
   *           If an OAuth system exception occurs
   * @throws OAuthProblemException
   *           If an OAuth problem exception occurs
   */
  public String post(CloseableHttpClient client, String uri, Map<String, String> parameters)
      throws OAuthSystemException, OAuthProblemException {
    CloseableHttpClient4 proxy = new CloseableHttpClient4(client);
    OAuthClient oAuthClient = new OAuthClient(proxy);
    OAuthClientRequest request = new OAuthBearerClientRequest(uri).setAccessToken(accessToken)
        .buildHeaderMessage();
    if (parameters != null)
      attachParameters(request, parameters);
    return oAuthClient.resource(request, OAuth.HttpMethod.POST, OAuthResResponse.class).getBody();
  }

  private void attachParameters(OAuthClientRequest request, Map<String, String> parameters)
      throws OAuthSystemException {
    List<NameValuePair> params = new ArrayList<NameValuePair>();
    for (Entry<String, String> item : parameters.entrySet()) {
      params.add(new BasicNameValuePair(item.getKey(), item.getValue()));
    }
    try {
      UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params, charset);
      Header contentType = entity.getContentType();
      request.addHeader(contentType.getName(), contentType.getValue());
      request.setBody(EntityUtils.toString(entity));
    } catch (IOException ex) {
      throw new OAuthSystemException("attach resource parameters", ex);
    }
  }
}
