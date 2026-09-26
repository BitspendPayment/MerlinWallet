package com.vtxos.app

import android.app.Activity
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.concurrent.Executors

/**
 * Flutter platform channel plugin for WebAuthn passkeys via Jetpack Credential
 * Manager (androidx.credentials).
 *
 * Exposes methods `create` (registration) and `get` (assertion) over
 * MethodChannel "com.mpcwallet.ap/passkey". Each takes a WebAuthn options JSON
 * string ("requestJson") and returns the corresponding
 * registration/authentication response JSON string.
 *
 * Credential Manager requires an ACTIVITY context (not the application context),
 * so this plugin is ActivityAware and holds the current Activity. It uses the
 * async callback variants of the Credential Manager APIs (no coroutines dep);
 * results are marshalled back to the Flutter main thread via mainHandler.
 */
class PasskeyPlugin : FlutterPlugin, ActivityAware, MethodChannel.MethodCallHandler {

    companion object {
        private const val TAG = "PasskeyPlugin"
        private const val CHANNEL = "com.mpcwallet.ap/passkey"
        // Credential Manager requires API 28+.
        private const val MIN_SDK = 28
    }

    private lateinit var channel: MethodChannel
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor = Executors.newSingleThreadExecutor()

    private var activity: Activity? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        executor.shutdown()
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "create" -> create(call, result)
            "get" -> get(call, result)
            else -> result.notImplemented()
        }
    }

    private fun create(call: MethodCall, result: MethodChannel.Result) {
        if (Build.VERSION.SDK_INT < MIN_SDK) {
            result.error("passkey_unsupported", "Credential Manager requires Android 9 (API 28)+", null)
            return
        }
        val activity = this.activity ?: run {
            result.error("passkey_no_activity", "No Activity attached; cannot show passkey UI", null)
            return
        }
        val requestJson = call.argument<String>("requestJson") ?: run {
            result.error("passkey_bad_args", "Missing requestJson", null)
            return
        }

        val flutterResult = result
        val cm = CredentialManager.create(activity)
        val request = CreatePublicKeyCredentialRequest(requestJson)
        cm.createCredentialAsync(
            activity,
            request,
            null,
            executor,
            object : CredentialManagerCallback<CreateCredentialResponse, CreateCredentialException> {
                override fun onResult(result: CreateCredentialResponse) {
                    val json = (result as CreatePublicKeyCredentialResponse).registrationResponseJson
                    mainHandler.post { flutterResult.success(json) }
                }

                override fun onError(e: CreateCredentialException) {
                    Log.e(TAG, "createCredential failed", e)
                    mainHandler.post { flutterResult.error("passkey_create", e.message, null) }
                }
            },
        )
    }

    private fun get(call: MethodCall, result: MethodChannel.Result) {
        if (Build.VERSION.SDK_INT < MIN_SDK) {
            result.error("passkey_unsupported", "Credential Manager requires Android 9 (API 28)+", null)
            return
        }
        val activity = this.activity ?: run {
            result.error("passkey_no_activity", "No Activity attached; cannot show passkey UI", null)
            return
        }
        val requestJson = call.argument<String>("requestJson") ?: run {
            result.error("passkey_bad_args", "Missing requestJson", null)
            return
        }

        // With `immediate`, a passkey that is not usable on this device right now fails fast as
        // NoCredentialException instead of opening the "Sign in another way" sheet. A passkey that
        // was created seconds ago is in exactly that state until the provider has indexed it, so
        // the app can wait for it without putting UI in front of the user.
        val immediate = call.argument<Boolean>("immediate") ?: false

        val flutterResult = result
        val cm = CredentialManager.create(activity)
        val option = GetPublicKeyCredentialOption(requestJson)
        val request = GetCredentialRequest(
            listOf(option),
            preferImmediatelyAvailableCredentials = immediate,
        )
        cm.getCredentialAsync(
            activity,
            request,
            null,
            executor,
            object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                override fun onResult(result: GetCredentialResponse) {
                    val json = (result.credential as PublicKeyCredential).authenticationResponseJson
                    mainHandler.post { flutterResult.success(json) }
                }

                override fun onError(e: GetCredentialException) {
                    Log.e(TAG, "getCredential failed", e)
                    val code = when (e) {
                        is NoCredentialException -> "passkey_no_credential"
                        is GetCredentialCancellationException -> "passkey_cancelled"
                        else -> "passkey_get"
                    }
                    mainHandler.post { flutterResult.error(code, e.message, null) }
                }
            },
        )
    }
}
