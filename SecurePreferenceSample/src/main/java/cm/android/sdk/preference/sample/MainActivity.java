package cm.android.sdk.preference.sample;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import cm.android.sdk.preference.SecureFactory;


public class MainActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(cm.android.sdk.preference.sample.R.layout.activity_main);

        TextView keyView = (TextView) this.findViewById(R.id.key);
        TextView valueView = (TextView) this.findViewById(R.id.value);

        SharedPreferences preferences = SecureFactory.getPreferences(this, "test_pref");

        SharedPreferences.Editor editor = preferences.edit();
        editor.putString("ggg_key_str", "ggg_value");
        editor.commit();

        String str = preferences.getString("ggg_key_str", "");
        keyView.setText("ggg_key_str");
        valueView.setText(str);

    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(cm.android.sdk.preference.sample.R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == cm.android.sdk.preference.sample.R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
