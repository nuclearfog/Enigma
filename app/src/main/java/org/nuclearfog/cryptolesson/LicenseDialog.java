package org.nuclearfog.cryptolesson;

import android.app.Dialog;
import android.content.Context;

import com.larswerkman.licenseview.LicenseView;


public class LicenseDialog extends Dialog {


    public LicenseDialog(Context context) {
        super(context, R.style.LicenseDialogStyle);
        setContentView(R.layout.dialog_license);
        LicenseView licenseView = findViewById(R.id.license_view);
        try {
            licenseView.setLicenses(R.xml.licenses);
        } catch (Exception err) {
            dismiss();
        }
    }
}