package cm.android.preference.sample;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import cm.android.preference.SecureFactory;

import java.util.Random;

import static cm.android.preference.sample.R.id;
import static cm.android.preference.sample.R.layout;


public class MainActivity extends ActionBarActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(layout.activity_main);

        Button refreshView = (Button) this.findViewById(id.refresh);
        refreshView.setClickable(true);
        refreshView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                refresh();
            }
        });

    }

    private void refresh() {
        SharedPreferences preferences = SecureFactory.getPreferences(this, "test_pref");

        SharedPreferences.Editor editor = preferences.edit();
        String key = "ggg_key_str" + new Random().nextInt(100);
        editor.putString(key, "ggg_value");
        editor.commit();

        String str = preferences.getString(key, "");

        TextView keyView = (TextView) this.findViewById(id.key);
        TextView valueView = (TextView) this.findViewById(id.value);
        keyView.setText(key);
        valueView.setText(str);
        Log.e("ggg", "ggg key = " + key);
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(cm.android.preference.sample.R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == cm.android.preference.sample.R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
