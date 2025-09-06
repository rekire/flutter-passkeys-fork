import 'package:passkeys_platform_interface/types/authenticate_request.dart';
import 'package:passkeys_platform_interface/types/authenticate_response.dart';

import 'passkeys_authenticate_ffi.dart';
import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'dart:convert';
import 'package:win32/win32.dart';

class PasskeysAuthenticator {
  final WebAuthnBindings _bindings;

  PasskeysAuthenticator() : _bindings = WebAuthnBindings();

  final getLastError = DynamicLibrary.open('kernel32.dll')
      .lookupFunction<Uint32 Function(), int Function()>('GetLastError');

  AuthenticateResponseType authenticate(AuthenticateRequestType request) {
    final rpId = request.relyingPartyId;
    final rpIdW = rpId.toNativeUtf16();
    final rpNameW = rpId.toNativeUtf16();
    final rpInfoPtr = calloc<WEBAUTHN_RP_ENTITY_INFORMATION>();
    rpInfoPtr.ref.dwVersion = 1;
    rpInfoPtr.ref.pwszId = rpIdW;
    rpInfoPtr.ref.pwszName = rpNameW;
    rpInfoPtr.ref.pwszIcon = nullptr;

    final origin = 'http://$rpId';
    final challengeBytes = base64Url.decode(request.challenge.padRight((request.challenge.length + 3) ~/ 4 * 4, '='));
    final challengeB64Url = base64Url.encode(challengeBytes).replaceAll('=', '');
    final clientDataJson = jsonEncode({
      'type': 'webauthn.get',
      'challenge': challengeB64Url,
      'origin': origin,
    });
    final clientDataBytes = utf8.encode(clientDataJson);
    final clientDataPtr = calloc<WEBAUTHN_CLIENT_DATA>();
    clientDataPtr.ref.dwVersion = 1;
    clientDataPtr.ref.cbClientDataJSON = clientDataBytes.length;
    clientDataPtr.ref.pbClientDataJSON = clientDataJson.toNativeUtf8().cast();
    clientDataPtr.ref.pwszHashAlgId = 'SHA-256'.toNativeUtf16();

    final optionsPtr = calloc<WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS>();
    optionsPtr.ref.dwVersion = 8;
    optionsPtr.ref.dwTimeoutMilliseconds = request.timeout ?? 60000;
    //optionsPtr.ref.CredentialList.cCredentials = 0;
    //optionsPtr.ref.CredentialList.pCredentials = nullptr;
    //optionsPtr.ref.Extensions.cExtensions = 0;
    //optionsPtr.ref.Extensions.pExtensions = nullptr;
    //optionsPtr.ref.dwAuthenticatorAttachment = 0;
    var uv = 0; // ANY
    if (request.userVerification == 'required') uv = 1;
    if (request.userVerification == 'preferred') uv = 2;
    if (request.userVerification == 'discouraged') uv = 3;
    optionsPtr.ref.dwUserVerificationRequirement = uv;
    //optionsPtr.ref.dwFlags = 0;
    //optionsPtr.ref.pwszU2fAppId = nullptr;
    //optionsPtr.ref.pbU2fAppId = nullptr;
    //optionsPtr.ref.pCancellationId = nullptr;
    //optionsPtr.ref.pAllowCredentialList = nullptr;
    //optionsPtr.ref.dwCredLargeBlobOperation = 0;
    //optionsPtr.ref.cbCredLargeBlob = 0;
    //optionsPtr.ref.pbCredLargeBlob = nullptr;
    //optionsPtr.ref.pHmacSecretSaltValues = nullptr;
    //optionsPtr.ref.bBrowserInPrivateMode = 0;
    //optionsPtr.ref.pLinkedDevice = nullptr;
    //optionsPtr.ref.bAutoFill = 0;
    //optionsPtr.ref.cbJsonExt = 0;
    //optionsPtr.ref.pbJsonExt = nullptr;
    //optionsPtr.ref.cCredentialHints = 0;
    //optionsPtr.ref.ppwszCredentialHints = nullptr;

    // --- HWND des Flutter-Fensters suchen ---
    final className = 'FLUTTER_RUNNER_WIN32_WINDOW'.toNativeUtf16();
    final hwnd = FindWindow(className, nullptr);
    calloc.free(className);

    if (hwnd == 0) {
      calloc
        ..free(rpIdW)
        ..free(rpNameW)
        ..free(rpInfoPtr)
        ..free(clientDataPtr.ref.pbClientDataJSON)
        ..free(clientDataPtr.ref.pwszHashAlgId)
        ..free(clientDataPtr)
        ..free(optionsPtr);
      throw Exception('Flutter HWND konnte nicht gefunden werden!');
    }

    // --- Assertion Call ---
    final assertionPtrPtr = calloc<Pointer<WEBAUTHN_ASSERTION>>();
    final hr = _bindings.getAssertion(
      Pointer.fromAddress(hwnd),
      rpIdW,
      clientDataPtr,
      optionsPtr,
      assertionPtrPtr,
    );
    if (hr != 0) {
      calloc
        ..free(rpIdW)
        ..free(rpNameW)
        ..free(rpInfoPtr)
        ..free(clientDataPtr.ref.pbClientDataJSON)
        ..free(clientDataPtr.ref.pwszHashAlgId)
        ..free(clientDataPtr)
        ..free(optionsPtr)
        ..free(assertionPtrPtr);
      if (hr == 0xFFFFFFFF800704C7) {
        throw Exception('The operation was canceled by the user (HRESULT: 0x800704C7)');
      } else if (hr == 0xFFFFFFFF80070057) {
        throw Exception('One or more arguments are invalid (HRESULT: 0x80070057)');
      } else if (hr == -2147024891) {
        throw Exception('Access is denied (HRESULT: 0x80070005)');
      } else if (hr == -2145648636) {
        throw Exception('The user has not registered any credentials (HRESULT: 0x801C0004)');
      } else if (hr == -2146893785/*0x80090027*/) {
        throw Exception('NTE_INVALID_PARAMETER (HRESULT: 0x80090027)');
      }
      throw Exception('WebAuthNAuthenticatorGetAssertion failed: $hr');
    }
    final assertionPtr = assertionPtrPtr.value;
    var id = '';
    var rawId = '';
    var clientDataJSON = '';
    var authenticatorData = '';
    var signature = '';
    var userHandle = '';
    if (assertionPtr.ref.Credential.cbId > 0 && assertionPtr.ref.Credential.pbId != nullptr) {
      rawId = base64Url.encode(assertionPtr.ref.Credential.pbId.asTypedList(assertionPtr.ref.Credential.cbId)).replaceAll('=', '');
      id = rawId;
    }
    clientDataJSON = base64Url.encode(clientDataBytes).replaceAll('=', '');
    if (assertionPtr.ref.cbAuthenticatorData > 0 && assertionPtr.ref.pbAuthenticatorData != nullptr) {
      authenticatorData = base64Url.encode(assertionPtr.ref.pbAuthenticatorData.asTypedList(assertionPtr.ref.cbAuthenticatorData)).replaceAll('=', '');
    }
    if (assertionPtr.ref.cbSignature > 0 && assertionPtr.ref.pbSignature != nullptr) {
      signature = base64Url.encode(assertionPtr.ref.pbSignature.asTypedList(assertionPtr.ref.cbSignature)).replaceAll('=', '');
    }
    if (assertionPtr.ref.cbUserId > 0 && assertionPtr.ref.pbUserId != nullptr) {
      userHandle = base64Url.encode(assertionPtr.ref.pbUserId.asTypedList(assertionPtr.ref.cbUserId)).replaceAll('=', '');
    }
    calloc
      ..free(rpIdW)
      ..free(clientDataPtr.ref.pbClientDataJSON)
      ..free(clientDataPtr.ref.pwszHashAlgId)
      ..free(clientDataPtr)
      ..free(optionsPtr)
      ..free(assertionPtrPtr);
    _bindings.freeAssertion(assertionPtr);
    return AuthenticateResponseType(
      id: id,
      rawId: rawId,
      clientDataJSON: clientDataJSON,
      authenticatorData: authenticatorData,
      signature: signature,
      userHandle: userHandle,
    );
  }
}
