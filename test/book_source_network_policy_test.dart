import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:xxread/book_sources/protocol/book_source_protocol.dart';
import 'package:xxread/book_sources/services/book_source_network_policy.dart';

void main() {
  test('rejects hostnames resolving to non-public targets', () async {
    for (final address in [
      '127.0.0.1',
      '10.0.0.1',
      '172.16.0.1',
      '192.168.0.1',
      '169.254.169.254',
      '::1',
      'fd00::1',
      'fe80::1',
      '::ffff:127.0.0.1',
    ]) {
      final policy = BookSourceNetworkPolicy(
        lookup: (_) async => [InternetAddress(address)],
      );

      await expectLater(
        policy.validate(Uri.parse('https://source.example/api')),
        throwsA(isA<BookSourceProtocolException>()),
        reason: address,
      );
    }
  });

  test('rejects private IP literals without DNS resolution', () async {
    const policy = BookSourceNetworkPolicy();

    await expectLater(
      policy.validate(Uri.parse('http://192.168.1.10/api')),
      throwsA(isA<BookSourceProtocolException>()),
    );
  });

  test('allows a private target only when explicitly enabled', () async {
    const policy = BookSourceNetworkPolicy(allowPrivateNetwork: true);

    await expectLater(
      policy.validate(Uri.parse('http://127.0.0.1/api')),
      completes,
    );
  });

  test('synthetic DNS range is separately opt-in', () {
    final address = InternetAddress('198.18.0.7');

    expect(BookSourceNetworkPolicy.isBlockedAddress(address), isTrue);
    expect(
      BookSourceNetworkPolicy.isBlockedAddress(
        address,
        allowSyntheticDns: true,
      ),
      isFalse,
    );
  });

  test(
    'private mode still rejects unspecified and multicast targets',
    () async {
      const policy = BookSourceNetworkPolicy(allowPrivateNetwork: true);

      for (final target in ['0.0.0.0', '224.0.0.1', '::', 'ff02::1']) {
        final host = target.contains(':') ? '[$target]' : target;
        await expectLater(
          policy.validate(Uri.parse('http://$host/api')),
          throwsA(isA<BookSourceProtocolException>()),
          reason: target,
        );
      }
    },
  );

  test('direct http still uses the pinned socket', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) {
      request.response.statusCode = HttpStatus.ok;
      request.response.write('ok');
      request.response.close();
    });
    final client = const BookSourceNetworkPolicy(
      allowPrivateNetwork: true,
    ).createPinnedHttpClient();
    try {
      final request = await client.getUrl(
        Uri.parse('http://127.0.0.1:${server.port}/health'),
      );
      final response = await request.close();
      expect(response.statusCode, HttpStatus.ok);
      expect(await response.transform(utf8.decoder).join(), 'ok');
    } finally {
      client.close(force: true);
      await server.close(force: true);
    }
  });

  test('direct https starts tls instead of sending cleartext', () async {
    final temp = await Directory.systemTemp.createTemp('book-source-tls');
    addTearDown(() => temp.delete(recursive: true));
    final key = File('${temp.path}/key.pem');
    final cert = File('${temp.path}/cert.pem');
    final generated = await Process.run('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      key.path,
      '-out',
      cert.path,
      '-days',
      '1',
      '-nodes',
      '-subj',
      '/CN=127.0.0.1',
    ]);
    expect(generated.exitCode, 0, reason: '${generated.stderr}');
    final context = SecurityContext()
      ..useCertificateChain(cert.path)
      ..usePrivateKey(key.path);
    final server = await HttpServer.bindSecure(
      InternetAddress.loopbackIPv4,
      0,
      context,
    );
    server.listen((request) {
      request.response.statusCode = HttpStatus.ok;
      request.response.close();
    });
    final client = const BookSourceNetworkPolicy(
      allowPrivateNetwork: true,
    ).createPinnedHttpClient();
    try {
      final pending = client.getUrl(
        Uri.parse('https://127.0.0.1:${server.port}/'),
      );
      await expectLater(pending, throwsA(isA<HandshakeException>()));
    } finally {
      client.close(force: true);
      await server.close(force: true);
    }
  });

  test('cancelling an https handshake does not escape', () async {
    final temp = await Directory.systemTemp.createTemp('book-source-tls');
    addTearDown(() => temp.delete(recursive: true));
    final key = File('${temp.path}/key.pem');
    final cert = File('${temp.path}/cert.pem');
    final generated = await Process.run('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      key.path,
      '-out',
      cert.path,
      '-days',
      '1',
      '-nodes',
      '-subj',
      '/CN=127.0.0.1',
    ]);
    expect(generated.exitCode, 0, reason: '${generated.stderr}');
    final context = SecurityContext()
      ..useCertificateChain(cert.path)
      ..usePrivateKey(key.path);
    final server = await HttpServer.bindSecure(
      InternetAddress.loopbackIPv4,
      0,
      context,
    );
    server.listen((request) => request.response.close());
    final client = const BookSourceNetworkPolicy(
      allowPrivateNetwork: true,
    ).createPinnedHttpClient();
    final pending = client.getUrl(
      Uri.parse('https://127.0.0.1:${server.port}/'),
    );
    client.close(force: true);
    await expectLater(pending, throwsA(anything));
    await server.close(force: true);
    await Future<void>.delayed(const Duration(milliseconds: 300));
  });

  test('rejects unsafe redirects and HTTPS downgrades', () {
    expect(
      () => BookSourceNetworkPolicy.redirectTarget(
        Uri.parse('https://source.example/api'),
        'file:///tmp/source',
      ),
      throwsA(isA<BookSourceProtocolException>()),
    );
    expect(
      () => BookSourceNetworkPolicy.redirectTarget(
        Uri.parse('https://source.example/api'),
        'http://source.example/api',
      ),
      throwsA(isA<BookSourceProtocolException>()),
    );
  });
}
