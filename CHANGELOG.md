# Changelog

## [0.9.12](https://github.com/openkcm/extauthz/compare/v0.9.11...v0.9.12) (2025-12-01)


### Bug Fixes

* check result handling ([#192](https://github.com/openkcm/extauthz/issues/192)) ([937f7cd](https://github.com/openkcm/extauthz/commit/937f7cdd33c3ce1860531de2b607c3fbdb7e5449))

## [0.9.11](https://github.com/openkcm/extauthz/compare/v0.9.10...v0.9.11) (2025-12-01)


### Bug Fixes

* Fix test target ([#188](https://github.com/openkcm/extauthz/issues/188)) ([4f45b40](https://github.com/openkcm/extauthz/commit/4f45b40cad35c6c02ea0dad3a02f9479981a1ab0))
* update session manager for more debug logs ([#187](https://github.com/openkcm/extauthz/issues/187)) ([a07e932](https://github.com/openkcm/extauthz/commit/a07e932b2e89c210f32336143190717c68a905a4))

## [0.9.10](https://github.com/openkcm/extauthz/compare/v0.9.9...v0.9.10) (2025-11-27)


### Bug Fixes

* nil pointer dereference ([#185](https://github.com/openkcm/extauthz/issues/185)) ([c6cff47](https://github.com/openkcm/extauthz/commit/c6cff4739a00bb52875322d4aed7586e1ec061e1))

## [0.9.9](https://github.com/openkcm/extauthz/compare/v0.9.8...v0.9.9) (2025-11-27)


### Bug Fixes

* keep deprecated configs ([#183](https://github.com/openkcm/extauthz/issues/183)) ([b63e4c6](https://github.com/openkcm/extauthz/commit/b63e4c6782ce56ad061835d725e771cae76edfe7))

## [0.9.8](https://github.com/openkcm/extauthz/compare/v0.9.7...v0.9.8) (2025-11-27)


### Bug Fixes

* replace oidcproviderv1 with sessionv1 ([#177](https://github.com/openkcm/extauthz/issues/177)) ([8275235](https://github.com/openkcm/extauthz/commit/827523518812c60cf7efd3fa2d9cf3b9df2431c2))
* signing key handling ([#181](https://github.com/openkcm/extauthz/issues/181)) ([14b6a48](https://github.com/openkcm/extauthz/commit/14b6a48066cc9603db47995b3f096a1498825927))

## [0.9.7](https://github.com/openkcm/extauthz/compare/v0.9.6...v0.9.7) (2025-11-25)


### Bug Fixes

* include missing claims ([#173](https://github.com/openkcm/extauthz/issues/173)) ([bdc39ff](https://github.com/openkcm/extauthz/commit/bdc39ff37f83e723e4094c9617fc46301a456675))

## [0.9.6](https://github.com/openkcm/extauthz/compare/v0.9.5...v0.9.6) (2025-11-20)


### Bug Fixes

* token introspection feature flag ([#171](https://github.com/openkcm/extauthz/issues/171)) ([131881f](https://github.com/openkcm/extauthz/commit/131881f1f6e82c6a45c48a5a10c8a11c4b1fb59f))

## [0.9.5](https://github.com/openkcm/extauthz/compare/v0.9.4...v0.9.5) (2025-11-20)


### Bug Fixes

* add missing http client config for mTLS based token inspection ([#167](https://github.com/openkcm/extauthz/issues/167)) ([5c3f12c](https://github.com/openkcm/extauthz/commit/5c3f12cc2530afc5b0f9ed5278c4503bf49b1b30))

## [0.9.4](https://github.com/openkcm/extauthz/compare/v0.9.3...v0.9.4) (2025-11-18)


### Bug Fixes

* on error log the introspection result ([#165](https://github.com/openkcm/extauthz/issues/165)) ([6cf605f](https://github.com/openkcm/extauthz/commit/6cf605f3232f7f310bbb72124e0e93890da6ba37))

## [0.9.3](https://github.com/openkcm/extauthz/compare/v0.9.2...v0.9.3) (2025-11-18)


### Bug Fixes

* ignore nil options ([#163](https://github.com/openkcm/extauthz/issues/163)) ([bf34983](https://github.com/openkcm/extauthz/commit/bf34983875a62a6db901a9f2a127ab47a9b3fcf4))

## [0.9.2](https://github.com/openkcm/extauthz/compare/v0.9.1...v0.9.2) (2025-11-17)


### Bug Fixes

* store issuers as full URL ([#160](https://github.com/openkcm/extauthz/issues/160)) ([577ca34](https://github.com/openkcm/extauthz/commit/577ca3440b82cb8269d2fe23dfe026a4fd012ac8))

## [0.9.1](https://github.com/openkcm/extauthz/compare/v0.9.0...v0.9.1) (2025-11-14)


### Bug Fixes

* custom URI handling ([#158](https://github.com/openkcm/extauthz/issues/158)) ([41d8d1b](https://github.com/openkcm/extauthz/commit/41d8d1ba169eb878314db1af6a9e52b5cb8a81d2))

## [0.9.0](https://github.com/openkcm/extauthz/compare/v0.8.1...v0.9.0) (2025-11-13)


### Features

* add feature gate `enable-http-issuer-scheme` ([#155](https://github.com/openkcm/extauthz/issues/155)) ([5581c52](https://github.com/openkcm/extauthz/commit/5581c52460230cc571768654f75f907b59a9b57c))

## [0.8.1](https://github.com/openkcm/extauthz/compare/v0.8.0...v0.8.1) (2025-11-13)


### Bug Fixes

* add missing debug logs ([#153](https://github.com/openkcm/extauthz/issues/153)) ([d772cbd](https://github.com/openkcm/extauthz/commit/d772cbd00790c93a44c0644b7b0ebf343515ba1f))

## [0.8.0](https://github.com/openkcm/extauthz/compare/v0.7.0...v0.8.0) (2025-11-12)


### Features

* add mTLS support for valkey ([#151](https://github.com/openkcm/extauthz/issues/151)) ([e14f841](https://github.com/openkcm/extauthz/commit/e14f84106c123ccdf69fb162a06efab158960871))

## [0.7.0](https://github.com/openkcm/extauthz/compare/v0.6.1...v0.7.0) (2025-11-07)


### Features

* optionally disable JWT introspection ([#143](https://github.com/openkcm/extauthz/issues/143)) ([469abe7](https://github.com/openkcm/extauthz/commit/469abe791e20dcf5ccaf1c64a260fac54570c654))

## [0.6.1](https://github.com/openkcm/extauthz/compare/v0.6.0...v0.6.1) (2025-11-07)


### Bug Fixes

* log token header and payload for error analysis ([#141](https://github.com/openkcm/extauthz/issues/141)) ([fc27c1f](https://github.com/openkcm/extauthz/commit/fc27c1f1747f2b6b02b218bd897fbb5a1f9b0337))

## [0.6.0](https://github.com/openkcm/extauthz/compare/v0.5.4...v0.6.0) (2025-11-07)


### Features

* pass on all claims as raw JSON via client data ([#134](https://github.com/openkcm/extauthz/issues/134)) ([5389e04](https://github.com/openkcm/extauthz/commit/5389e04bd4ff0d00b12da4e350c8330b3100c78f))


### Bug Fixes

* better logs ([#139](https://github.com/openkcm/extauthz/issues/139)) ([9d32e86](https://github.com/openkcm/extauthz/commit/9d32e867d8ede5b2c7c3128a0aea7654e64ae256))

## [0.5.4](https://github.com/openkcm/extauthz/compare/v0.5.3...v0.5.4) (2025-11-03)


### Bug Fixes

* handling of static providers ([#130](https://github.com/openkcm/extauthz/issues/130)) ([4390a25](https://github.com/openkcm/extauthz/commit/4390a25502a1fc04d6ffcf48dfb29fb413225960))

## [0.5.3](https://github.com/openkcm/extauthz/compare/v0.5.2...v0.5.3) (2025-10-30)


### Bug Fixes

* log more details, when readiness changes ([#125](https://github.com/openkcm/extauthz/issues/125)) ([0582dcd](https://github.com/openkcm/extauthz/commit/0582dcd09c3bfcd9813c343d0367659b4d893864))

## [0.5.2](https://github.com/openkcm/extauthz/compare/v0.5.1...v0.5.2) (2025-10-29)


### Bug Fixes

* mark obsolete configs as deprecated instead of removing them ([#122](https://github.com/openkcm/extauthz/issues/122)) ([e767279](https://github.com/openkcm/extauthz/commit/e76727913448c0c0266e2fe927dfa8223c8daea5))

## [0.5.1](https://github.com/openkcm/extauthz/compare/v0.5.0...v0.5.1) (2025-10-28)


### Bug Fixes

* tests and chart ([#118](https://github.com/openkcm/extauthz/issues/118)) ([e6b434b](https://github.com/openkcm/extauthz/commit/e6b434b6ee0ece9a7844473306c0ae81c84ebaf3))

## [0.5.0](https://github.com/openkcm/extauthz/compare/v0.4.2...v0.5.0) (2025-10-27)


### Features

* integrate session manager ([#90](https://github.com/openkcm/extauthz/issues/90)) ([35ff06f](https://github.com/openkcm/extauthz/commit/35ff06f08d36cfc5a7a1afa8809c383d67e6c28d))


### Bug Fixes

* remove build_version.json leftofvers ([#109](https://github.com/openkcm/extauthz/issues/109)) ([220a94f](https://github.com/openkcm/extauthz/commit/220a94fcbe9e018a0380e4be8f872fbb41425eaf))
* use the commonfs Loader, loading from a given path by watching on their changes and load file content from memory ([#112](https://github.com/openkcm/extauthz/issues/112)) ([a5ccf64](https://github.com/openkcm/extauthz/commit/a5ccf648f3caf0a86c05f8017c8dc1eb66916469))

## [0.4.2](https://github.com/openkcm/extauthz/compare/v0.4.1...v0.4.2) (2025-10-07)


### Bug Fixes

* change the value for ALWAYS_ALLOW as wasn't merged the result ([#104](https://github.com/openkcm/extauthz/issues/104)) ([5224a54](https://github.com/openkcm/extauthz/commit/5224a54635e6fe47c95856794737efaf1340474f))
* **deps:** Bump github.com/envoyproxy/go-control-plane/envoy ([#96](https://github.com/openkcm/extauthz/issues/96)) ([3c133b1](https://github.com/openkcm/extauthz/commit/3c133b14accb8b54229d4f07df4198b0d798b681))
* **deps:** Bump github.com/go-jose/go-jose/v4 from 4.1.2 to 4.1.3 ([#103](https://github.com/openkcm/extauthz/issues/103)) ([e4539a4](https://github.com/openkcm/extauthz/commit/e4539a442d71050e32222067d11137f0e0c42770))
* **deps:** Bump github.com/openkcm/common-sdk from 1.4.0 to 1.4.5 ([#102](https://github.com/openkcm/extauthz/issues/102)) ([88f23aa](https://github.com/openkcm/extauthz/commit/88f23aaad4abffa34536ab25f28717c241ef6a81))
* **deps:** Bump google.golang.org/grpc from 1.75.1 to 1.76.0 ([#105](https://github.com/openkcm/extauthz/issues/105)) ([b1f9aa2](https://github.com/openkcm/extauthz/commit/b1f9aa28d2fe586de25490a0029cec0ee1939439))

## [0.4.1](https://github.com/openkcm/extauthz/compare/v0.4.0...v0.4.1) (2025-10-01)


### Bug Fixes

* do not log http headers ([#99](https://github.com/openkcm/extauthz/issues/99)) ([b1b80e6](https://github.com/openkcm/extauthz/commit/b1b80e65f60da0d3c389714b37f858747e763cce)), closes [#98](https://github.com/openkcm/extauthz/issues/98)
* get rid of the build_version.json file to inject build information ([#93](https://github.com/openkcm/extauthz/issues/93)) ([b22c611](https://github.com/openkcm/extauthz/commit/b22c6113f113c73ea6bcf255f270d9ff8012fe6c))

## [0.4.0](https://github.com/openkcm/extauthz/compare/v0.3.5...v0.4.0) (2025-08-19)


### Features

* refactor the cliendata and the policies ([#75](https://github.com/openkcm/extauthz/issues/75)) ([41d2c33](https://github.com/openkcm/extauthz/commit/41d2c33e698ca212b307f63a23aeaeb66dcc2377))


### Bug Fixes

* signing key management ([#71](https://github.com/openkcm/extauthz/issues/71)) ([9f7935f](https://github.com/openkcm/extauthz/commit/9f7935fd4011d369b427b805f6c91af948377a11))

## [0.3.5](https://github.com/openkcm/extauthz/compare/v0.3.4...v0.3.5) (2025-08-07)


### Bug Fixes

* use the lowercase feature gates keys as values, as this is imposed by viper destabilising from the yaml config ([#68](https://github.com/openkcm/extauthz/issues/68)) ([fc3dce9](https://github.com/openkcm/extauthz/commit/fc3dce91576442fa529839131ceae1e36042fd35))

## [0.3.4](https://github.com/openkcm/extauthz/compare/v0.3.3...v0.3.4) (2025-08-06)


### Bug Fixes

* subject and the issuer same way to stringify it according to rfc2253 ([#64](https://github.com/openkcm/extauthz/issues/64)) ([987e90f](https://github.com/openkcm/extauthz/commit/987e90f5079e710a5a0b2b7a26b56cc008c25ab9))

## [0.3.3](https://github.com/openkcm/extauthz/compare/v0.3.2...v0.3.3) (2025-08-06)


### Bug Fixes

* adjust to format the certificate subject in same way as envoy does to be able to verify agist envoy given subject ([#62](https://github.com/openkcm/extauthz/issues/62)) ([548cebd](https://github.com/openkcm/extauthz/commit/548cebd08c433c550f16c468040afcd0b1e812fe))

## [0.3.2](https://github.com/openkcm/extauthz/compare/v0.3.1...v0.3.2) (2025-08-05)


### Bug Fixes

* make the correction for the policyPath field under the cedar configuration ([#59](https://github.com/openkcm/extauthz/issues/59)) ([ab49862](https://github.com/openkcm/extauthz/commit/ab498620212151f9ed372d76df6fe6bef41f4de5))
* readiness probe ([#60](https://github.com/openkcm/extauthz/issues/60)) ([b37586c](https://github.com/openkcm/extauthz/commit/b37586c80dce3a58fde7910d8d910316da06620e))

## [0.3.1](https://github.com/openkcm/extauthz/compare/v0.3.0...v0.3.1) (2025-08-05)


### Bug Fixes

* subject parsing ([#57](https://github.com/openkcm/extauthz/issues/57)) ([b918e77](https://github.com/openkcm/extauthz/commit/b918e77baa42744c7abe675cb03d0c29916abe05))

## [0.3.0](https://github.com/openkcm/extauthz/compare/v0.2.3...v0.3.0) (2025-07-31)


### Features

* Add groups into headers and result ([#38](https://github.com/openkcm/extauthz/issues/38)) ([980cacf](https://github.com/openkcm/extauthz/commit/980cacf8ec78fde3e201e3dfdd0af28f12279131))
* enhance the grpc server creation ([#46](https://github.com/openkcm/extauthz/issues/46)) ([5a7eeec](https://github.com/openkcm/extauthz/commit/5a7eeec06f2b670f053aead099f6d72ee396bf4f))
* **github-actions:** update the release and added new one ([#45](https://github.com/openkcm/extauthz/issues/45)) ([720dbe0](https://github.com/openkcm/extauthz/commit/720dbe05f970d02e8832db3bf698babdabacad16))
* include the feature gates ([#51](https://github.com/openkcm/extauthz/issues/51)) ([72e7cd7](https://github.com/openkcm/extauthz/commit/72e7cd7c67b56e11c53bf2c5ead0e3bded568507))
* refactor the configurations and helm ([#49](https://github.com/openkcm/extauthz/issues/49)) ([59f29ef](https://github.com/openkcm/extauthz/commit/59f29efb6d842d54f65d316a2b23b7842d588674))
