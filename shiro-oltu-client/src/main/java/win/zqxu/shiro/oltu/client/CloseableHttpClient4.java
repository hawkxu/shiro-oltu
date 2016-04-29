package win.zqxu.shiro.oltu.client;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.client.HttpClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponseFactory;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;

public class CloseableHttpClient4 implements HttpClient {
  private CloseableHttpClient client;

  public CloseableHttpClient4() {
    client = HttpClients.custom().setRedirectStrategy(new LaxRedirectStrategy()).build();
  }

  public CloseableHttpClient4(CloseableHttpClient client) {
    this.client = client;
  }

  @Override
  public <T extends OAuthClientResponse> T execute(OAuthClientRequest request,
      Map<String, String> headers, String requestMethod, Class<T> responseClass)
      throws OAuthSystemException, OAuthProblemException {
    try {
      URI location = new URI(request.getLocationUri());
      HttpRequestBase req = null;
      String responseBody = "";

      if (!OAuthUtils.isEmpty(requestMethod) && OAuth.HttpMethod.POST.equals(requestMethod)) {
        req = new HttpPost(location);
        HttpEntity entity = new StringEntity(request.getBody());
        ((HttpPost) req).setEntity(entity);
      } else {
        req = new HttpGet(location);
      }
      if (headers != null && !headers.isEmpty()) {
        for (Map.Entry<String, String> header : headers.entrySet()) {
          req.setHeader(header.getKey(), header.getValue());
        }
      }
      if (request.getHeaders() != null) {
        for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
          req.setHeader(header.getKey(), header.getValue());
        }
      }
      CloseableHttpResponse response = client.execute(req);
      try {
        Header contentTypeHeader = null;
        HttpEntity entity = response.getEntity();
        if (entity != null) {
          responseBody = EntityUtils.toString(entity);
          contentTypeHeader = entity.getContentType();
        }
        String contentType = null;
        if (contentTypeHeader != null) {
          contentType = contentTypeHeader.toString();
        }
        return OAuthClientResponseFactory.createCustomResponse(responseBody, contentType,
            response.getStatusLine().getStatusCode(), responseClass);
      } finally {
        response.close();
      }
    } catch (Exception e) {
      throw new OAuthSystemException(e);
    }
  }

  @Override
  public void shutdown() {
    try {
      if (client != null)
        client.close();
    } catch (IOException e) {
      // close client failed, this can be safely ignored
    }
  }
}
