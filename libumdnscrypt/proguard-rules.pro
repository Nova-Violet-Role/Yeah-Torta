# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

#-keep public class pillar.kuma_saimono.libumdnscrypt.vpn.** {
#  public *;
#}

-keep class com.android.vending.billing.**
#fix android.view.InflateException: Error inflating class com.google.android.material.chip.Chip for Android 4.4.2
-keepclassmembers,allowoptimization,allowobfuscation public class com.google.android.material.chip.** {*;}

-keepattributes *Annotation*,SourceFile,LineNumberTable,Signature
-keep class kotlin.coroutines.Continuation

-keepclassmembers,allowoptimization,allowobfuscation public class pillar.kuma_saimono.libumdnscrypt.dialogs.ExtendedDialogFragment {*;}

# Fragments referenced by class-NAME string in layout XML (FragmentContainerView / <fragment>) are
# instantiated reflectively by the framework — R8 must NOT rename them or release builds crash at
# inflation. e.g. DnsEngineDashboardFragment (main_fragment.xml), TopFragment, BackupFragment.
-keep public class * extends androidx.fragment.app.Fragment { public <init>(); }

# WorkManager instantiates workers by class name via reflection (CheckDnsCryptBinaryUpdateWorker,
# UpdateRemoteDnsRulesWorker, …) — keep their (Context, WorkerParameters) constructors.
-keep class * extends androidx.work.ListenableWorker { <init>(...); }

# P6 Wireless Debug (no-root) — libadb-android + Conscrypt (native/JNI) + the sun.security X.509
# shim are reflection/native-heavy; R8 must not strip or rename them (release-only crash class).
-keep class io.github.muntashirakon.adb.** { *; }
-dontwarn io.github.muntashirakon.adb.**
-keep class android.sun.security.** { *; }
-dontwarn android.sun.security.**
-keep class org.conscrypt.** { *; }
-keepclasseswithmembernames class org.conscrypt.** { native <methods>; }
-dontwarn org.conscrypt.**

# UniFFI JNA runtime — generated torta_core.* Kotlin calls the Rust .so via JNA (libffi).
# libjnidispatch.so looks up fields/methods by NAME (e.g. com.sun.jna.Pointer "peer") via JNI
# field IDs. R8 obfuscation renames "peer" -> a -> JNI field lookup throws:
#   UnsatisfiedLinkError: Can't obtain peer field ID for class com.sun.jna.Pointer
# which kills every JNA call -> NoClassDefFoundError: com.sun.jna.Native -> TunnelController.start
# dies -> DNSCrypt engine never spawns (F6/fix-blocker). Keep ALL JNA classes + members + native.
-keep class com.sun.jna.** { *; }
-keepclassmembers class com.sun.jna.** { *; }
-keepclasseswithmembernames,includedescriptorclasses class com.sun.jna.** { native <methods>; }
-dontwarn com.sun.jna.**

# Rust native core (torta_core) — JNI entry points are matched by fixed .so symbol names, so R8
# must not rename or strip the classes that declare native methods (P7 horsepower / P9 Fortress).
-keepclasseswithmembernames,includedescriptorclasses class * { native <methods>; }
