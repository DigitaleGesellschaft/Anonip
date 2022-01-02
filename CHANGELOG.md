# Changelog

## v1.1.0
### Feature
 * Performance: Make column indexes zero-based internally. [`aa28386`](https://github.com/DigitaleGesellschaft/Anonip/commit/aa28386ecaefcb479f5646b4dac11a9ea6c1e4d4)
 * Performance: Calculate IP prefix for masking only once. [`70e4d55`](https://github.com/DigitaleGesellschaft/Anonip/commit/70e4d5504e8605691e43c8802c549556e10c2ac4)
 * Performance: Use a dict to store and access the IP prefixes used for masking. [`536e22b`](https://github.com/DigitaleGesellschaft/Anonip/commit/536e22b6e712040b5bf80a8566b13f783faa647f)
 * Performance: Avoid another useless use of str.format() in inner loop. [`d67bd11`](https://github.com/DigitaleGesellschaft/Anonip/commit/d67bd115e453dec40483ac3c64c86fc108d3d295)
 * Make Anonip.run() accept an optional input stream. [`3c44134`](https://github.com/DigitaleGesellschaft/Anonip/commit/3c44134c37d612326e2fd3396906d42bf53eff0d)
 * Add option "--input". [`1a2c4b4`](https://github.com/DigitaleGesellschaft/Anonip/commit/1a2c4b4cb7d3382ee4ee113bfcb775f38b55407d)
 * feat(logging): improve logging if no ip can be detected [`f9584f1`](https://github.com/DigitaleGesellschaft/Anonip/commit/f9584f16472cf6c450dd322d7754315a29ec9f32)
 * feat(cli): Regex based IP detection [`bf37456`](https://github.com/DigitaleGesellschaft/Anonip/commit/bf3745692a6acca9e99c2845c9f03d26861725ba)

### Fix
 * Fix warning message if column was not found. [`3831a29`](https://github.com/DigitaleGesellschaft/Anonip/commit/3831a29087dbacc222c19d036d9c528d0f35583f)
 * Fix: Log-messages get formatted even if not output. [`a4a0448`](https://github.com/DigitaleGesellschaft/Anonip/commit/a4a04483935f95d0d3889b8fa6b6976fe4491fa3)
 * Fix: Terminates if empty or all-white-space line is read. [`ddbfc86`](https://github.com/DigitaleGesellschaft/Anonip/commit/ddbfc860388d1cfc8a02f78eeb5908c8559db926)
 * fix(properties): use setter for columns property [`43b7002`](https://github.com/DigitaleGesellschaft/Anonip/commit/43b7002f5dcbb8f285a594605135cb2584c82b85)
 * fix(cli): handle KeyboardInterrupt [`b82da7a`](https://github.com/DigitaleGesellschaft/Anonip/commit/b82da7a659b9a47c6178d4868e9a6b5cb9549eed)
 * Bugfix: IPv6 address masquerading with python2.7 [`556b132`](https://github.com/DigitaleGesellschaft/Anonip/commit/556b1324b4d1ca159e2e0dc47918c378dbcc69c0)
 * fix(python2): Fix reading from stdin [`4ecfd91`](https://github.com/DigitaleGesellschaft/Anonip/commit/4ecfd91bc52e005fcaa188ff873a28a59cf6757e)
 * fix(logging) Avoid side-effect during module import [`474125d`](https://github.com/DigitaleGesellschaft/Anonip/commit/474125d1bf39c9b4bfee882a45aab7fb1b13b875)

### Docs
 * Readme: Remove useless use of `cat`. [`25939fc`](https://github.com/DigitaleGesellschaft/Anonip/commit/25939fc737bc5ad3a94d5c4ca87914f1d59e14bf)
 * Readme: Slightly restructure and update the Usage section. [`900263c`](https://github.com/DigitaleGesellschaft/Anonip/commit/900263cbd733a9504a62b05a3f1fde29d09df08a)
 * Readme: Add usage for nginx. [`3c0e4dd`](https://github.com/DigitaleGesellschaft/Anonip/commit/3c0e4dd057efa8fb5b7e1eb62b70f8fc6c6bb99c)
 * docs: fix ipaddress module link [`4c7628c`](https://github.com/DigitaleGesellschaft/Anonip/commit/4c7628ca11c370e259030188f033cc34af1ae07f)
 * docs: fix link for coverage shield [`1387f2e`](https://github.com/DigitaleGesellschaft/Anonip/commit/1387f2ea657e95f98eb568083d947cb0ab3fdce8)

## v1.0.0

Rewrite using the ipaddress module.
