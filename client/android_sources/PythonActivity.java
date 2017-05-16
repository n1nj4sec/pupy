package org.renpy.android;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.os.Bundle;
import android.os.Environment;
import android.view.KeyEvent;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Toast;
import android.util.Log;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;

import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;

// Billing
import org.renpy.android.Configuration;
import org.renpy.android.billing.BillingService.RequestPurchase;
import org.renpy.android.billing.BillingService.RestoreTransactions;
import org.renpy.android.billing.Consts.PurchaseState;
import org.renpy.android.billing.Consts.ResponseCode;
import org.renpy.android.billing.PurchaseObserver;
import org.renpy.android.billing.BillingService;
import org.renpy.android.billing.PurchaseDatabase;
import org.renpy.android.billing.Consts;
import org.renpy.android.billing.ResponseHandler;
import org.renpy.android.billing.Security;
import android.os.Handler;
import android.database.Cursor;
import java.util.List;
import java.util.ArrayList;
import android.content.SharedPreferences;
import android.content.Context;


public class PythonActivity extends Activity implements Runnable {
    private static String TAG = "Python";

    // The audio thread for streaming audio...
    private static AudioThread mAudioThread = null;

    // The SDLSurfaceView we contain.
    public static SDLSurfaceView mView = null;
    public static PythonActivity mActivity = null;
    public static ApplicationInfo mInfo = null;

    // Did we launch our thread?
    private boolean mLaunchedThread = false;

    private ResourceManager resourceManager;

    // The path to the directory contaning our external storage.
    private File externalStorage;

    // The path to the directory containing the game.
    private File mPath = null;

    boolean _isPaused = false;

    private static final String DB_INITIALIZED = "db_initialized";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Hardware.context = this;
        Action.context = this;
        this.mActivity = this;

        getWindowManager().getDefaultDisplay().getMetrics(Hardware.metrics);

        resourceManager = new ResourceManager(this);
        externalStorage = new File(Environment.getExternalStorageDirectory(), getPackageName());

        // Figure out the directory where the game is. If the game was
        // given to us via an intent, then we use the scheme-specific
        // part of that intent to determine the file to launch. We
        // also use the android.txt file to determine the orientation.
        //
        // Otherwise, we use the public data, if we have it, or the
        // private data if we do not.
        if (getIntent() != null && getIntent().getAction() != null &&
                getIntent().getAction().equals("org.renpy.LAUNCH")) {
            mPath = new File(getIntent().getData().getSchemeSpecificPart());

            Project p = Project.scanDirectory(mPath);

            if (p != null) {
                if (p.landscape) {
                    setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
                } else {
                    setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
                }
            }

            // Let old apps know they started.
            try {
                FileWriter f = new FileWriter(new File(mPath, ".launch"));
                f.write("started");
                f.close();
            } catch (IOException e) {
                // pass
            }



        } else if (resourceManager.getString("public_version") != null) {
            mPath = externalStorage;
        } else {
            mPath = getFilesDir();
        }

        requestWindowFeature(Window.FEATURE_NO_TITLE);

        // go to fullscreen mode if requested
        try {
            this.mInfo = this.getPackageManager().getApplicationInfo(
                    this.getPackageName(), PackageManager.GET_META_DATA);
            Log.v("python", "metadata fullscreen is" + this.mInfo.metaData.get("fullscreen"));
            if ( (Integer)this.mInfo.metaData.get("fullscreen") == 1 ) {
                getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                        WindowManager.LayoutParams.FLAG_FULLSCREEN);
            }
        } catch (PackageManager.NameNotFoundException e) {
        }

        if ( Configuration.use_billing ) {
            mBillingHandler = new Handler();
        }

        // Start showing an SDLSurfaceView.
        mView = new SDLSurfaceView(
                this,
                mPath.getAbsolutePath());

        Hardware.view = mView;
        setContentView(mView);

        // Force the background window color if asked
        if ( this.mInfo.metaData.containsKey("android.background_color") ) {
            getWindow().getDecorView().setBackgroundColor(
                this.mInfo.metaData.getInt("android.background_color"));
        }
    }

    /**
     * Show an error using a toast. (Only makes sense from non-UI
     * threads.)
     */
    public void toastError(final String msg) {

        final Activity thisActivity = this;

        runOnUiThread(new Runnable () {
            public void run() {
                Toast.makeText(thisActivity, msg, Toast.LENGTH_LONG).show();
            }
        });

        // Wait to show the error.
        synchronized (this) {
            try {
                this.wait(1000);
            } catch (InterruptedException e) {
            }
        }
    }

    public void recursiveDelete(File f) {
        if (f.isDirectory()) {
            for (File r : f.listFiles()) {
                recursiveDelete(r);
            }
        }
        f.delete();
    }


    /**
     * This determines if unpacking one the zip files included in
     * the .apk is necessary. If it is, the zip file is unpacked.
     */
    public void unpackData(final String resource, File target) {

        // The version of data in memory and on disk.
        String data_version = resourceManager.getString(resource + "_version");
        String disk_version = null;

        // If no version, no unpacking is necessary.
        if (data_version == null) {
            return;
        }

        // Check the current disk version, if any.
        String filesDir = target.getAbsolutePath();
        String disk_version_fn = filesDir + "/" + resource + ".version";

        try {
            byte buf[] = new byte[64];
            InputStream is = new FileInputStream(disk_version_fn);
            int len = is.read(buf);
            disk_version = new String(buf, 0, len);
            is.close();
        } catch (Exception e) {
            disk_version = "";
        }

        // If the disk data is out of date, extract it and write the
        // version file.
        if (! data_version.equals(disk_version)) {
            Log.v(TAG, "Extracting " + resource + " assets.");

            recursiveDelete(target);
            target.mkdirs();

            AssetExtract ae = new AssetExtract(this);
            if (!ae.extractTar(resource + ".mp3", target.getAbsolutePath())) {
                toastError("Could not extract " + resource + " data.");
            }

            try {
                // Write .nomedia.
                new File(target, ".nomedia").createNewFile();

                // Write version file.
                FileOutputStream os = new FileOutputStream(disk_version_fn);
                os.write(data_version.getBytes());
                os.close();
            } catch (Exception e) {
                Log.w("python", e);
            }
        }

    }

    public void run() {

        unpackData("private", getFilesDir());
        unpackData("public", externalStorage);

        System.loadLibrary("sdl");
        System.loadLibrary("sdl_image");
        System.loadLibrary("sdl_ttf");
        System.loadLibrary("sdl_mixer");
        System.loadLibrary("python2.7");
        System.loadLibrary("application");
        System.loadLibrary("sdl_main");

        System.load(getFilesDir() + "/lib/python2.7/lib-dynload/_io.so");
        System.load(getFilesDir() + "/lib/python2.7/lib-dynload/unicodedata.so");

        try {
            System.loadLibrary("sqlite3");
            System.load(getFilesDir() + "/lib/python2.7/lib-dynload/_sqlite3.so");
        } catch(UnsatisfiedLinkError e) {
        }

        try {
            System.load(getFilesDir() + "/lib/python2.7/lib-dynload/_imaging.so");
            System.load(getFilesDir() + "/lib/python2.7/lib-dynload/_imagingft.so");
            System.load(getFilesDir() + "/lib/python2.7/lib-dynload/_imagingmath.so");
        } catch(UnsatisfiedLinkError e) {
        }

        if ( mAudioThread == null ) {
            Log.i("python", "Starting audio thread");
            mAudioThread = new AudioThread(this);
        }

        runOnUiThread(new Runnable () {
            public void run() {
                mView.start();
            }
        });
    }

    @Override
    protected void onPause() {
        _isPaused = true;
        super.onPause();

        if (mView != null) {
            mView.onPause();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        _isPaused = false;

        if (!mLaunchedThread) {
            mLaunchedThread = true;
            new Thread(this).start();
        }

        if (mView != null) {
            mView.onResume();
        }
    }

    public boolean isPaused() {
        return _isPaused;
    }

    @Override
    public boolean onKeyDown(int keyCode, final KeyEvent event) {
        //Log.i("python", "key2 " + mView + " " + mView.mStarted);
        if (mView != null && mView.mStarted && SDLSurfaceView.nativeKey(keyCode, 1, event.getUnicodeChar())) {
            return true;
        } else {
            return super.onKeyDown(keyCode, event);
        }
    }

    @Override
    public boolean onKeyUp(int keyCode, final KeyEvent event) {
        //Log.i("python", "key up " + mView + " " + mView.mStarted);
        if (mView != null && mView.mStarted && SDLSurfaceView.nativeKey(keyCode, 0, event.getUnicodeChar())) {
            return true;
        } else {
            return super.onKeyUp(keyCode, event);
        }
    }

    protected void onDestroy() {
        if (mPurchaseDatabase != null) {
            mPurchaseDatabase.close();
        }

        if (mBillingService != null) {
            mBillingService.unbind();
        }

        if (mView != null) {
            mView.onDestroy();
        }

        //Log.i(TAG, "on destroy (exit1)");
        System.exit(0);
    }

    public static void start_service(String serviceTitle, String serviceDescription,
            String pythonServiceArgument) {
        Intent serviceIntent = new Intent(PythonActivity.mActivity, PythonService.class);
        String argument = PythonActivity.mActivity.getFilesDir().getAbsolutePath();
        String filesDirectory = PythonActivity.mActivity.mPath.getAbsolutePath();
        serviceIntent.putExtra("androidPrivate", argument);
        serviceIntent.putExtra("androidArgument", filesDirectory);
        serviceIntent.putExtra("pythonHome", argument);
        serviceIntent.putExtra("pythonPath", argument + ":" + filesDirectory + "/lib");
        serviceIntent.putExtra("serviceTitle", serviceTitle);
        serviceIntent.putExtra("serviceDescription", serviceDescription);
        serviceIntent.putExtra("pythonServiceArgument", pythonServiceArgument);
        PythonActivity.mActivity.startService(serviceIntent);
    }

    public static void stop_service() {
        Intent serviceIntent = new Intent(PythonActivity.mActivity, PythonService.class);
        PythonActivity.mActivity.stopService(serviceIntent);
    }

    //----------------------------------------------------------------------------
    // Listener interface for onNewIntent
    //

    public interface NewIntentListener {
        void onNewIntent(Intent intent);
    }

    private List<NewIntentListener> newIntentListeners = null;

    public void registerNewIntentListener(NewIntentListener listener) {
        if ( this.newIntentListeners == null )
            this.newIntentListeners = Collections.synchronizedList(new ArrayList<NewIntentListener>());
        this.newIntentListeners.add(listener);
    }

    public void unregisterNewIntentListener(NewIntentListener listener) {
        if ( this.newIntentListeners == null )
            return;
        this.newIntentListeners.remove(listener);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        if ( this.newIntentListeners == null )
            return;
        if ( this.mView != null )
            this.mView.onResume();
        synchronized ( this.newIntentListeners ) {
            Iterator<NewIntentListener> iterator = this.newIntentListeners.iterator();
            while ( iterator.hasNext() ) {
                (iterator.next()).onNewIntent(intent);
            }
        }
    }

    //----------------------------------------------------------------------------
    // Listener interface for onActivityResult
    //

    public interface ActivityResultListener {
        void onActivityResult(int requestCode, int resultCode, Intent data);
    }

    private List<ActivityResultListener> activityResultListeners = null;

    public void registerActivityResultListener(ActivityResultListener listener) {
        if ( this.activityResultListeners == null )
            this.activityResultListeners = Collections.synchronizedList(new ArrayList<ActivityResultListener>());
        this.activityResultListeners.add(listener);
    }

    public void unregisterActivityResultListener(ActivityResultListener listener) {
        if ( this.activityResultListeners == null )
            return;
        this.activityResultListeners.remove(listener);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if ( this.activityResultListeners == null )
            return;
        if ( this.mView != null )
            this.mView.onResume();
        synchronized ( this.activityResultListeners ) {
            Iterator<ActivityResultListener> iterator = this.activityResultListeners.iterator();
            while ( iterator.hasNext() )
                (iterator.next()).onActivityResult(requestCode, resultCode, intent);
        }
    }

    //----------------------------------------------------------------------------
    // Billing
    //
    class PythonPurchaseObserver extends PurchaseObserver {
        public PythonPurchaseObserver(Handler handler) {
            super(PythonActivity.this, handler);
        }

        @Override
        public void onBillingSupported(boolean supported, String type) {
            if (Consts.DEBUG) {
                Log.i(TAG, "supported: " + supported);
            }

            String sup = "1";
            if ( !supported )
                sup = "0";
            if (type == null)
                type = Consts.ITEM_TYPE_INAPP;

            // add notification for python message queue
            mActivity.mBillingQueue.add("billingSupported|" + type + "|" + sup);

            // for managed items, restore the database
            if ( type == Consts.ITEM_TYPE_INAPP && supported ) {
                restoreDatabase();
            }
        }

        @Override
        public void onPurchaseStateChange(PurchaseState purchaseState, String itemId,
                int quantity, long purchaseTime, String developerPayload) {
            mActivity.mBillingQueue.add(
                "purchaseStateChange|" + itemId + "|" + purchaseState.toString());
        }

        @Override
        public void onRequestPurchaseResponse(RequestPurchase request,
                ResponseCode responseCode) {
            mActivity.mBillingQueue.add(
                "requestPurchaseResponse|" + request.mProductId + "|" + responseCode.toString());
        }

        @Override
        public void onRestoreTransactionsResponse(RestoreTransactions request,
                ResponseCode responseCode) {
            if (responseCode == ResponseCode.RESULT_OK) {
                mActivity.mBillingQueue.add("restoreTransaction|ok");
                if (Consts.DEBUG) {
                    Log.d(TAG, "completed RestoreTransactions request");
                }
                // Update the shared preferences so that we don't perform
                // a RestoreTransactions again.
                SharedPreferences prefs = getPreferences(Context.MODE_PRIVATE);
                SharedPreferences.Editor edit = prefs.edit();
                edit.putBoolean(DB_INITIALIZED, true);
                edit.commit();
            } else {
                if (Consts.DEBUG) {
                    Log.d(TAG, "RestoreTransactions error: " + responseCode);
                }

                mActivity.mBillingQueue.add(
                    "restoreTransaction|error|" + responseCode.toString());
            }
        }
    }

    /**
     * If the database has not been initialized, we send a
     * RESTORE_TRANSACTIONS request to Android Market to get the list of purchased items
     * for this user. This happens if the application has just been installed
     * or the user wiped data. We do not want to do this on every startup, rather, we want to do
     * only when the database needs to be initialized.
     */
    private void restoreDatabase() {
        SharedPreferences prefs = getPreferences(MODE_PRIVATE);
        boolean initialized = prefs.getBoolean(DB_INITIALIZED, false);
        if (!initialized) {
            mBillingService.restoreTransactions();
        }
    }

    /** An array of product list entries for the products that can be purchased. */

    private enum Managed { MANAGED, UNMANAGED, SUBSCRIPTION }


    private PythonPurchaseObserver mPythonPurchaseObserver;
    private Handler mBillingHandler;
    private BillingService mBillingService;
    private PurchaseDatabase mPurchaseDatabase;
    private String mPayloadContents;
    public List<String> mBillingQueue;

    public void billingServiceStart_() {
        mBillingQueue = new ArrayList<String>();

        // Start the billing part
        mPythonPurchaseObserver = new PythonPurchaseObserver(mBillingHandler);
        mBillingService = new BillingService();
        mBillingService.setContext(this);
        mPurchaseDatabase = new PurchaseDatabase(this);

        ResponseHandler.register(mPythonPurchaseObserver);
        if (!mBillingService.checkBillingSupported()) {
            //showDialog(DIALOG_CANNOT_CONNECT_ID);
            Log.w(TAG, "NO BILLING SUPPORTED");
        }
        if (!mBillingService.checkBillingSupported(Consts.ITEM_TYPE_SUBSCRIPTION)) {
            //showDialog(DIALOG_SUBSCRIPTIONS_NOT_SUPPORTED_ID);
            Log.w(TAG, "NO SUBSCRIPTION SUPPORTED");
        }
    }

    public void billingServiceStop_() {
    }

    public void billingBuy_(String mSku) {
        Managed mManagedType = Managed.MANAGED;
        if (Consts.DEBUG) {
            Log.d(TAG, "buying sku: " + mSku);
        }

        if (mManagedType == Managed.MANAGED) {
            if (!mBillingService.requestPurchase(mSku, Consts.ITEM_TYPE_INAPP, mPayloadContents)) {
                Log.w(TAG, "ERROR IN BILLING REQUEST PURCHASE");
            }
        } else if (mManagedType == Managed.SUBSCRIPTION) {
            if (!mBillingService.requestPurchase(mSku, Consts.ITEM_TYPE_INAPP, mPayloadContents)) {
                Log.w(TAG, "ERROR IN BILLING REQUEST PURCHASE");
            }
        }
    }

    public String billingGetPurchasedItems_() {
        String ownedItems = "";
        Cursor cursor = mPurchaseDatabase.queryAllPurchasedItems();
        if (cursor == null)
            return "";

        try {
            int productIdCol = cursor.getColumnIndexOrThrow(
                    PurchaseDatabase.PURCHASED_PRODUCT_ID_COL);
            int qtCol = cursor.getColumnIndexOrThrow(
                    PurchaseDatabase.PURCHASED_QUANTITY_COL);
            while (cursor.moveToNext()) {
                String productId = cursor.getString(productIdCol);
                String qt = cursor.getString(qtCol);

                productId = Security.unobfuscate(this, Configuration.billing_salt, productId);
                if ( productId == null )
                    continue;

                if ( ownedItems != "" )
                    ownedItems += "\n";
                ownedItems += productId + "," + qt;
            }
        } finally {
            cursor.close();
        }

        return ownedItems;
    }


    static void billingServiceStart() {
        mActivity.billingServiceStart_();
    }

    static void billingServiceStop() {
        mActivity.billingServiceStop_();
    }

    static void billingBuy(String sku) {
        mActivity.billingBuy_(sku);
    }

    static String billingGetPurchasedItems() {
        return mActivity.billingGetPurchasedItems_();
    }

    static String billingGetPendingMessage() {
        if (mActivity.mBillingQueue.isEmpty())
            return null;
        return mActivity.mBillingQueue.remove(0);
    }

}

