import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart' show GUID;

base class AuthenticateRequestTypeC extends Struct {
  external Pointer<Utf8> relyingPartyId;
  external Pointer<Uint8> challenge;
  @Uint32()
  external int challengeLen;
  @Int32()
  external int timeout;
  external Pointer<Utf8> userVerification;
  // allowCredentials und weitere Felder können nach Bedarf ergänzt werden
  @Uint8()
  external int preferImmediatelyAvailableCredentials;
}

base class AuthenticateResponseTypeC extends Struct {
  external Pointer<Utf8> id;
  external Pointer<Uint8> rawId;
  @Uint32()
  external int rawIdLen;
  external Pointer<Uint8> clientDataJSON;
  @Uint32()
  external int clientDataJSONLen;
  external Pointer<Uint8> authenticatorData;
  @Uint32()
  external int authenticatorDataLen;
  external Pointer<Uint8> signature;
  @Uint32()
  external int signatureLen;
  external Pointer<Uint8> userHandle;
  @Uint32()
  external int userHandleLen;
}

typedef NativeAuthenticateC = Int32 Function(
  Pointer<AuthenticateRequestTypeC> request,
  Pointer<AuthenticateResponseTypeC> response,
);
typedef DartAuthenticateC = int Function(
  Pointer<AuthenticateRequestTypeC> request,
  Pointer<AuthenticateResponseTypeC> response,
);

class PasskeysAuthenticateBindings {
  late final DynamicLibrary _lib;
  late final DartAuthenticateC authenticateC;

  PasskeysAuthenticateBindings(String dllPath) {
    _lib = DynamicLibrary.open(dllPath);
    authenticateC = _lib.lookupFunction<NativeAuthenticateC, DartAuthenticateC>('authenticate_c');
  }
}

// Windows WebAuthn-Structs und FFI-Bindings

// WEBAUTHN_RP_ENTITY_INFORMATION
base class WEBAUTHN_RP_ENTITY_INFORMATION extends Struct {
  @Uint32()
  external int dwVersion;
  external Pointer<Utf16> pwszId;
  external Pointer<Utf16> pwszName;
  external Pointer<Utf16> pwszIcon;
}

// WEBAUTHN_EXTENSION
base class WEBAUTHN_EXTENSION extends Struct {
  external Pointer<Utf16> pwszExtensionIdentifier;
  @Uint32()
  external int cbExtension;
  external Pointer<Void> pvExtension;
}

// WEBAUTHN_EXTENSIONS
base class WEBAUTHN_EXTENSIONS extends Struct {
  @Uint32()
  external int cExtensions;
  external Pointer<WEBAUTHN_EXTENSION> pExtensions;
}

// WEBAUTHN_CREDENTIAL
base class WEBAUTHN_CREDENTIAL extends Struct {
  @Uint32()
  external int dwVersion;
  @Uint32()
  external int cbId;
  external Pointer<Uint8> pbId;
  external Pointer<Utf16> pwszCredentialType;
}

// WEBAUTHN_CREDENTIALS
base class WEBAUTHN_CREDENTIALS extends Struct {
  @Uint32()
  external int cCredentials;
  external Pointer<WEBAUTHN_CREDENTIAL> pCredentials;
}

// WEBAUTHN_CLIENT_DATA
base class WEBAUTHN_CLIENT_DATA extends Struct {
  @Uint32()
  external int dwVersion;
  @Uint32()
  external int cbClientDataJSON;
  external Pointer<Uint8> pbClientDataJSON;
  external Pointer<Utf16> pwszHashAlgId;
}

// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
base class WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS extends Struct {
  @Uint32()
  external int dwVersion;
  @Uint32()
  external int dwTimeoutMilliseconds;
  external WEBAUTHN_CREDENTIALS CredentialList;
  external WEBAUTHN_EXTENSIONS Extensions;
  @Uint32()
  external int dwAuthenticatorAttachment;
  @Uint32()
  external int dwUserVerificationRequirement;
  @Uint32()
  external int dwFlags;
  external Pointer<Utf16> pwszU2fAppId;
  external Pointer<Int32> pbU2fAppId;
  external Pointer<GUID> pCancellationId;
  external Pointer<Void> pAllowCredentialList; // PWEBAUTHN_CREDENTIAL_LIST
  @Uint32()
  external int dwCredLargeBlobOperation;
  @Uint32()
  external int cbCredLargeBlob;
  external Pointer<Uint8> pbCredLargeBlob;
  external Pointer<Void> pHmacSecretSaltValues; // PWEBAUTHN_HMAC_SECRET_SALT_VALUES
  @Int32()
  external int bBrowserInPrivateMode;
  external Pointer<Void> pLinkedDevice; // PCTAPCBOR_HYBRID_STORAGE_LINKED_DATA
  @Int32()
  external int bAutoFill;
  @Uint32()
  external int cbJsonExt;
  external Pointer<Uint8> pbJsonExt;
  @Uint32()
  external int cCredentialHints;
  external Pointer<Pointer<Utf16>> ppwszCredentialHints;
}

// WEBAUTHN_ASSERTION
base class WEBAUTHN_ASSERTION extends Struct {
  @Uint32()
  external int dwVersion;
  @Uint32()
  external int cbAuthenticatorData;
  external Pointer<Uint8> pbAuthenticatorData;
  @Uint32()
  external int cbSignature;
  external Pointer<Uint8> pbSignature;
  external WEBAUTHN_CREDENTIAL Credential;
  @Uint32()
  external int cbUserId;
  external Pointer<Uint8> pbUserId;
  // ... weitere Felder aus dem Header können ergänzt werden ...
}

// FFI-Binding für WebAuthNAuthenticatorGetAssertion
// HRESULT WebAuthnAuthenticatorGetAssertion(
//   HWND hWnd,
//   const WEBAUTHN_RP_ENTITY_INFORMATION* rpInformation,
//   const WEBAUTHN_CLIENT_DATA* clientData,
//   const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS* options,
//   WEBAUTHN_ASSERTION** assertion
// );
typedef NativeWebAuthNAuthenticatorGetAssertion = Int32 Function(
  Pointer<Void> hWnd,
  Pointer<Utf16> rpInfo,
  Pointer<WEBAUTHN_CLIENT_DATA> clientData,
  Pointer<WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS> options,
  Pointer<Pointer<WEBAUTHN_ASSERTION>> assertionPtr,
);
typedef DartWebAuthNAuthenticatorGetAssertion = int Function(
  Pointer<Void> hWnd,
  Pointer<Utf16> rpInfo,
  Pointer<WEBAUTHN_CLIENT_DATA> clientData,
  Pointer<WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS> options,
  Pointer<Pointer<WEBAUTHN_ASSERTION>> assertionPtr,
);

// FFI-Binding für WebAuthNFreeAssertion
// VOID WebAuthNFreeAssertion(PWEBAUTHN_ASSERTION pWebAuthNAssertion);
typedef NativeWebAuthNFreeAssertion = Void Function(Pointer<WEBAUTHN_ASSERTION> assertion);
typedef DartWebAuthNFreeAssertion = void Function(Pointer<WEBAUTHN_ASSERTION> assertion);

class WebAuthnBindings {
  late final DynamicLibrary _lib;
  late final DartWebAuthNAuthenticatorGetAssertion getAssertion;
  late final DartWebAuthNFreeAssertion freeAssertion;

  WebAuthnBindings() {
    _lib = DynamicLibrary.open('webauthn.dll');
    getAssertion = _lib.lookupFunction<NativeWebAuthNAuthenticatorGetAssertion, DartWebAuthNAuthenticatorGetAssertion>('WebAuthNAuthenticatorGetAssertion');
    freeAssertion = _lib.lookupFunction<NativeWebAuthNFreeAssertion, DartWebAuthNFreeAssertion>('WebAuthNFreeAssertion');
  }
}
