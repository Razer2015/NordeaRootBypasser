package fi.razerman.nordearootbypasser;

/**
 * Created by Razerman on 1.10.2016.
 */

import android.util.Log;

import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import de.robv.android.xposed.IXposedHookLoadPackage;
import static de.robv.android.xposed.XposedBridge.log;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;
import static de.robv.android.xposed.XC_MethodReplacement.returnConstant;
import static de.robv.android.xposed.XposedHelpers.setBooleanField;

import java.util.ArrayList;
import java.util.List;

public class RootDetectionBypass implements IXposedHookLoadPackage {
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName.equals("com.nordea.mobiletoken")){
            Log.d("nordearootbypasser", "Nordea Codes app detected, starting to bypass root detection!");
            try {
                findAndHookMethod("o.ˊ", lpparam.classLoader, "ʻ", returnConstant(false));                                  // Check 1
                findAndHookMethod("o.ˊ", lpparam.classLoader, "ˊ", returnConstant(false));                                  // Check 2
                findAndHookMethod("o.ˊ", lpparam.classLoader, "ˊ", String.class, returnConstant(false));                    // Check 3
                findAndHookMethod("o.ˊ", lpparam.classLoader, "ˊ", String.class, String.class, returnConstant(false));      // Check 4
                findAndHookMethod("o.ˊ", lpparam.classLoader, "ˊ", new byte[0].getClass(), returnConstant(false));          // Check 5
                findAndHookMethod("o.ˊ", lpparam.classLoader, "ˋ", returnConstant(false));                                  // Check 6
                findAndHookMethod("o.ˊ", lpparam.classLoader, "ˋ", String.class, String.class, returnConstant(false));      // Check 7

                Log.d("nordearootbypasser", "Bypassed Nordea Codes root detection!");
            } catch (Throwable t) {
                log(t);

                try{
                    Log.d("nordearootbypasser", "Nordea Codes root bypass 1 failed, trying another one!");

                    findAndHookMethod("util.m.e", lpparam.classLoader, "d", new byte[0].getClass(), List.class, returnConstant(new byte[] { 1, 0, 0 })); // Hook detection O_O

                    findAndHookMethod("util.m.e", lpparam.classLoader, "d", new byte[0].getClass(), returnConstant(new byte[] { 1, 0, 0 })); // Root detection

                    Log.d("nordearootbypasser", "Nordea Codes root bypass 2 succeeded!");
                } catch (Throwable err) {
                    log(err);
                }
            }
        }

        if (lpparam.packageName.equals("fi.nordea.mep.npay")){
            Log.d("nordearootbypasser", "Nordea Pay app detected, starting to bypass root detection!");
            try {
                // Checking order is: c, d, e, f, g, b

                /* Check if OS Version is any of these and return true (rooted) if it is
                * cyanogenmod
                * carbonrom
                * vanilla
                * slimbean
                * xylon
                * codefirex
                * euroskank
                * aokp
                * avatar
                * asob
                * baked
                * carbon
                * chameleon
                * cyanfox
                * eclipse
                * evervolv
                * jellybam
                * linuxonandroid
                * liquidsmooth
                * minicm
                * miui
                * mokee
                */
                findAndHookMethod("arl", lpparam.classLoader, "b", returnConstant(false));

                /* Check if Busybox is installed and return true (rooted) if it is */
                findAndHookMethod("arl", lpparam.classLoader, "c", returnConstant(false));

                /* Check if any of the following packages is installed and return true (rooted) if it is
                * com.noshufou.android.su
                * com.thirdparty.superuser
                * eu.chainfire.supersu
                * com.koushikdutta.superuser
                * com.zachspong.temprootremovejb
                * com.ramdroid.appquarantine
                * fahrbot.apps.rootcallblocker
                * com.quillapps.root.android.without.computer
                * eu.chainfire.supersu (again :D?)
                * com.yellowes.su
                */
                findAndHookMethod("arl", lpparam.classLoader, "d", returnConstant(false));

                /* Check if any of the following files are found and return true (rooted) if it is
                * /system/xbin/which
                * /system/bin/su
                * /system/xbin/su
                * /sbin/su
                * /system/su
                * /system/bin/.ext/.su
                * /system/usr/we-need-root/su-backup
                * /system/xbin/mu
                */
                findAndHookMethod("arl", lpparam.classLoader, "e", returnConstant(false));

                /* Check if Build Tags contains "test-keys" and return true (rooted) if it is */
                findAndHookMethod("arl", lpparam.classLoader, "f", returnConstant(false));

                /* Check if /etc/security/otacerts.zip are found and return false (rooted) if they aren't */
                findAndHookMethod("arl", lpparam.classLoader, "g", returnConstant(true));

                Log.d("nordearootbypasser", "Bypassed Nordea Pays root detection!");
            } catch (Throwable t) {
                log(t);
            }
        }
    }
}
