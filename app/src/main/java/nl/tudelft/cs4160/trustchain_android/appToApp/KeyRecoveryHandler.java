package nl.tudelft.cs4160.trustchain_android.appToApp;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import java.security.KeyPair;

import nl.tudelft.cs4160.trustchain_android.SharedPreferences.UserNameStorage;
import nl.tudelft.cs4160.trustchain_android.Util.Key;

/**
 * Created by tim on 1/17/18.
 */

public class KeyRecoveryHandler {

    private final static String TAG = "KeyRecoveryHandler";

    public boolean startPassbuddies(Activity activity) {
        Intent keyRecoveryIntent = new Intent("org.blockchainbeasts.passbuddies.INIT_SECRET");
        if (keyRecoveryIntent == null) {
            Log.i(TAG,"Cannot find app");
            return false;
        } else {
            Log.i(TAG, "Attempting to launch passbuddies app");
            try {
                String userName = UserNameStorage.getUserName(activity);
                byte[] secret = Key.loadKeys(activity).getPrivate().getEncoded();

                keyRecoveryIntent.putExtra("user_name", userName);
                keyRecoveryIntent.putExtra("secret", secret);
                activity.startActivity(keyRecoveryIntent);
            } catch (ActivityNotFoundException e) {
                Log.e(TAG, e.toString());
                Toast.makeText(activity, "Key recovery app not found", Toast.LENGTH_LONG).show();
                return false;
            }
            return true;
        }
    }
}
