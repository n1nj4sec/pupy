/* This code is used to restart DAS service at boot */
package org.egambit.das;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.content.Context;
import org.renpy.android.PythonActivity;
public class MyBroadcastReceiver extends BroadcastReceiver {
	public void onReceive(Context context, Intent intent) {
		Intent ix = new Intent(context,PythonActivity.class);
		ix.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		context.startActivity(ix);
	}
}

