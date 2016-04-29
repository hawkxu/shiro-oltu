package win.zqxu.shiro.oltu.server;

import java.util.Locale;
import java.util.ResourceBundle;

final class I18N {
  private static final String BASE_NAME = I18N.class.getName().toLowerCase();
  private ResourceBundle bundle;

  public I18N(Locale locale) {
    if (locale == null)
      locale = Locale.getDefault();
    bundle = ResourceBundle.getBundle(BASE_NAME, locale);
  }

  public String getString(String key) {
    return bundle.getString(key);
  }
}
