import 'package:flutter/foundation.dart';
import 'package:passkeys_windows/messages.g.dart';
import 'package:passkeys_platform_interface/passkeys_platform_interface.dart';
import 'package:passkeys_platform_interface/types/types.dart';
import 'passkeys_authenticate_wrapper.dart';

/// The Windows implementation of [PasskeysPlatform].
class PasskeysWindows extends PasskeysPlatform {
  /// The method channel used to interact with the native platform.
  PasskeysWindows({
    @visibleForTesting PasskeysApi? api,
  }) : _api = api ?? PasskeysApi();

  /// Registers this class as the default instance of [PasskeysPlatform]
  static void registerWith() => PasskeysPlatform.instance = PasskeysWindows();

  final PasskeysApi _api;

  @override
  Future<AuthenticateResponseType> authenticate(
    AuthenticateRequestType request,
  ) async {
    final authenticator = PasskeysAuthenticator();
    final resp = authenticator.authenticate(request);
    return AuthenticateResponseType(
      id: resp.id,
      rawId: resp.rawId,
      clientDataJSON: resp.clientDataJSON,
      authenticatorData: resp.authenticatorData,
      signature: resp.signature,
      userHandle: resp.userHandle,
    );
  }

  @override
  Future<bool> canAuthenticate() async {
    try {
      final r = await _api.canAuthenticate();
      return r;
    } catch (e) {
      return false;
    }
  }

  @override
  Future<RegisterResponseType> register(RegisterRequestType request) async {
    final userArg = User(
      displayName: request.user.displayName,
      name: request.user.name,
      id: request.user.id,
    );
    final relyingPartyArg = RelyingParty(
      name: request.relyingParty.name,
      id: request.relyingParty.id,
    );

    final a = request.authSelectionType;
    final authSelection = AuthenticatorSelection(
      authenticatorAttachment: a.authenticatorAttachment,
      requireResidentKey: a.requireResidentKey,
      residentKey: a.residentKey,
      userVerification: a.userVerification,
    );

    final r = await _api.register(
        request.challenge,
        relyingPartyArg,
        userArg,
        authSelection,
        request.pubKeyCredParams
            ?.map((e) => PubKeyCredParam(alg: e.alg, type: e.type))
            .toList(),
        request.timeout,
        request.attestation,
        request.excludeCredentials
            .map((e) => ExcludeCredential(id: e.id, type: e.type))
            .toList());

    return RegisterResponseType(
      id: r.id,
      rawId: r.rawId,
      clientDataJSON: r.clientDataJSON,
      attestationObject: r.attestationObject,
      transports: r.transports.whereType<String>().toList(),
    );
  }

  @override
  Future<void> cancelCurrentAuthenticatorOperation() async {
    return;
  }

  @override
  Future<AvailabilityType> getAvailability() async {
    // fake type for now
    return AvailabilityTypeAndroid(
      hasPasskeySupport: true,
      isUserVerifyingPlatformAuthenticatorAvailable: true,
      isNative: true,
    );
  }
}
