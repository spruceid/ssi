import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ssi/ssi.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('getVersion', () async {
    expect(Ssi.getVersion(), isInstanceOf<String>());
  });
}
