import 'package:flutter_test/flutter_test.dart';
import 'package:passkeys_windows/passkeys_windows.dart';
import 'package:passkeys_platform_interface/passkeys_platform_interface.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('PasskeysWindows', () {
    test('can be registered', () {
      PasskeysWindows.registerWith();
      expect(PasskeysPlatform.instance, isA<PasskeysWindows>());
    });
  });
}
