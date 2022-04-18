package org.nuclearfog.cryptolesson;

import android.app.Dialog;
import android.content.Context;
import android.webkit.WebView;

/**
 * dialog class to show app license
 *
 * @author nuclearfog
 */
public class LicenseDialog extends Dialog {


    public LicenseDialog(Context context) {
        super(context, R.style.LicenseDialogStyle);
        WebView webView = new WebView(context);
        setContentView(webView);

        webView.loadUrl("file:///android_asset/licenses.html");
    }
}