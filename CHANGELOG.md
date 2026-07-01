# Changelog

## [0.12.0](https://github.com/openkcm/extauthz/compare/v0.11.3...v0.12.0) (2026-07-01)


### Features

* add agents.md ([#307](https://github.com/openkcm/extauthz/issues/307)) ([6afc82f](https://github.com/openkcm/extauthz/commit/6afc82f080be60a3195ba35d6af8d221da6800fb))
* add client data CreatedAt timestamp ([#293](https://github.com/openkcm/extauthz/issues/293)) ([5bc7388](https://github.com/openkcm/extauthz/commit/5bc7388ba29c996d40e33cf2386892f7dc749bcf))
* handle blocked tenant error ([#251](https://github.com/openkcm/extauthz/issues/251)) ([abb7a2a](https://github.com/openkcm/extauthz/commit/abb7a2ab3f3f335122e5dc2ec22a31ccd83ea17b))
* propagate trace context ([#319](https://github.com/openkcm/extauthz/issues/319)) ([bb67a00](https://github.com/openkcm/extauthz/commit/bb67a0027b00413f2fd322a3d34ac0900d255a5a))


### Bug Fixes

* bearer token introspection for tenant related requests ([#320](https://github.com/openkcm/extauthz/issues/320)) ([ee99adb](https://github.com/openkcm/extauthz/commit/ee99adba9135e00dfb69c4ff97ab0cef7b56b394))
* bump Go toolchain to v1.26.4 ([#309](https://github.com/openkcm/extauthz/issues/309)) ([4b030c5](https://github.com/openkcm/extauthz/commit/4b030c5af99a667a8bfa7d42405bba7ac80666c0))
* bump toolchain ([#279](https://github.com/openkcm/extauthz/issues/279)) ([db7ee34](https://github.com/openkcm/extauthz/commit/db7ee34725b832744ef31dca0e3be509dd782105))
* cedar request handling and policy configuration ([#303](https://github.com/openkcm/extauthz/issues/303)) ([ca5cd57](https://github.com/openkcm/extauthz/commit/ca5cd5782773eeaf4bde61ebcde952c2bac5dea4))
* certificate handling ([#305](https://github.com/openkcm/extauthz/issues/305)) ([df3b27d](https://github.com/openkcm/extauthz/commit/df3b27df7241ad45f13dec9e66136ca0addf1649))
* const error code declarations ([#290](https://github.com/openkcm/extauthz/issues/290)) ([55c0305](https://github.com/openkcm/extauthz/commit/55c0305dd67dd72bbbe118d341ccdc49daf6cb43))
* CxOne and linter findings ([#298](https://github.com/openkcm/extauthz/issues/298)) ([f4a14f2](https://github.com/openkcm/extauthz/commit/f4a14f267dadbed7d87585d2d3e9702d5473f3f8))
* CxONE reported race condition ([#311](https://github.com/openkcm/extauthz/issues/311)) ([eac6357](https://github.com/openkcm/extauthz/commit/eac635704487d6a2b041c9d946eb634a877d77f7))
* **deps:** bump actions/checkout from 6 to 7 ([#317](https://github.com/openkcm/extauthz/issues/317)) ([2c18e2e](https://github.com/openkcm/extauthz/commit/2c18e2e04c19ecb23256869c2a24b8233738906a))
* **deps:** bump distroless/static-debian12 from `a932952` to `d093aa3` ([#296](https://github.com/openkcm/extauthz/issues/296)) ([7092a85](https://github.com/openkcm/extauthz/commit/7092a85b19d8685c6f57ab091d95b1aa5e3ac901))
* **deps:** bump github.com/openkcm/api-sdk from 0.17.0 to 0.18.0 in the gomod-group group across 1 directory ([#314](https://github.com/openkcm/extauthz/issues/314)) ([3b3b704](https://github.com/openkcm/extauthz/commit/3b3b704417522e227718fcbed2d0bc18a59ed07f))
* **deps:** bump google.golang.org/grpc from 1.79.2 to 1.79.3 ([#265](https://github.com/openkcm/extauthz/issues/265)) ([2353266](https://github.com/openkcm/extauthz/commit/23532666cf5ef8f40053fdf0a254ad6a326edb4c))
* **deps:** bump google.golang.org/grpc from 1.80.0 to 1.81.0 in the gomod-group group ([#294](https://github.com/openkcm/extauthz/issues/294)) ([8f5880b](https://github.com/openkcm/extauthz/commit/8f5880b9be28769424b40225efc80870031e4664))
* **deps:** bump the gomod-group group across 1 directory with 2 updates ([#269](https://github.com/openkcm/extauthz/issues/269)) ([d3f43ac](https://github.com/openkcm/extauthz/commit/d3f43ac42f5b2c073e9526cae05ae008ade0015b))
* **deps:** bump the gomod-group group across 1 directory with 3 updates ([#302](https://github.com/openkcm/extauthz/issues/302)) ([f2ed305](https://github.com/openkcm/extauthz/commit/f2ed3051beaaac277199d211449667e825a9cbd1))
* **deps:** bump the gomod-group group across 1 directory with 7 updates ([#278](https://github.com/openkcm/extauthz/issues/278)) ([9279577](https://github.com/openkcm/extauthz/commit/9279577e45dcdfd81032f65ec5a1b2b60c4d5f0b))
* **deps:** bump the gomod-group group with 2 updates ([#297](https://github.com/openkcm/extauthz/issues/297)) ([538262f](https://github.com/openkcm/extauthz/commit/538262f2573cb8621028337a8447110d733ba718))
* **deps:** bump the gomod-group group with 2 updates ([#318](https://github.com/openkcm/extauthz/issues/318)) ([07ced2b](https://github.com/openkcm/extauthz/commit/07ced2b7b421a8e26edd8a481793b4d48cd583be))
* **deps:** bump the gomod-group group with 3 updates ([#310](https://github.com/openkcm/extauthz/issues/310)) ([5abd1c6](https://github.com/openkcm/extauthz/commit/5abd1c66437a56e049ee66e2602d858b4757e41f))
* do not automount service account token ([#264](https://github.com/openkcm/extauthz/issues/264)) ([9704b1a](https://github.com/openkcm/extauthz/commit/9704b1ade38c3d3a12c13238ee855ac658fd7b6a))
* do not log the client data signature ([#283](https://github.com/openkcm/extauthz/issues/283)) ([f2ec0bb](https://github.com/openkcm/extauthz/commit/f2ec0bb9a3565c48f60d9fb6a273325d7647fb59))
* enforce CSRF checks ([#287](https://github.com/openkcm/extauthz/issues/287)) ([56f80cd](https://github.com/openkcm/extauthz/commit/56f80cd8a63a98909e88376ebaf9c525696abcaa))
* **helm:** make image.tag or image.digest mandatory ([#295](https://github.com/openkcm/extauthz/issues/295)) ([2b583fb](https://github.com/openkcm/extauthz/commit/2b583fb4e340bb4c16bc0f8ea12370790f753334))
* potential race condition ([#304](https://github.com/openkcm/extauthz/issues/304)) ([28b5289](https://github.com/openkcm/extauthz/commit/28b528965635d21c79f2307b7826f14a9f792f1f))
* race condition reported by CxONE ([#300](https://github.com/openkcm/extauthz/issues/300)) ([acb2fc6](https://github.com/openkcm/extauthz/commit/acb2fc6ed3cf4acf1cd8252f938a55e3ae90bae7))
* Remove browser fingerprint ([#312](https://github.com/openkcm/extauthz/issues/312)) ([7cb887d](https://github.com/openkcm/extauthz/commit/7cb887d77c47efdfbdcfa1d59ce229623c81a457))
* remove critical flags ([#288](https://github.com/openkcm/extauthz/issues/288)) ([f21ca7a](https://github.com/openkcm/extauthz/commit/f21ca7a92d5c39668299a21987f117ba20018e9d))
* remove dependency ([#299](https://github.com/openkcm/extauthz/issues/299)) ([7f09861](https://github.com/openkcm/extauthz/commit/7f098619fe5341dbbe23f94ff9bcb0255310b87b))
* remove dependency github.com/go-andiamo/splitter ([#268](https://github.com/openkcm/extauthz/issues/268)) ([6f947a6](https://github.com/openkcm/extauthz/commit/6f947a61fc5b9f1d1bd96158f8455868c945671a))
* replace outdated package ([#286](https://github.com/openkcm/extauthz/issues/286)) ([cdf3bc2](https://github.com/openkcm/extauthz/commit/cdf3bc2e61438376832ba249997c3f349e5453ab))
* sha256 hashing ([#292](https://github.com/openkcm/extauthz/issues/292)) ([b3a5be4](https://github.com/openkcm/extauthz/commit/b3a5be4aa53fc954f14a5e97788bec88d806e72a))
* switch in-memory cache implementation ([#280](https://github.com/openkcm/extauthz/issues/280)) ([dd84a82](https://github.com/openkcm/extauthz/commit/dd84a82f28bd4bf52be4bb06b35ab016d9e59978))
* update common-sdk to fill up new ttl field on clientdata encode ([#315](https://github.com/openkcm/extauthz/issues/315)) ([8b5a17a](https://github.com/openkcm/extauthz/commit/8b5a17a6f4e1e7bb3870141745e715abaebdae36))
* update toolchain and vulnerable dependencies ([#306](https://github.com/openkcm/extauthz/issues/306)) ([4088142](https://github.com/openkcm/extauthz/commit/4088142dc9dfd97639d8ee7b26cbb0cbd54d9798))
* use a hash as cache key ([#289](https://github.com/openkcm/extauthz/issues/289)) ([0c8daf1](https://github.com/openkcm/extauthz/commit/0c8daf1d34e689baabb2be1aa54f9b5ea7048486))
* use an actively maintained yaml package ([#270](https://github.com/openkcm/extauthz/issues/270)) ([30b918f](https://github.com/openkcm/extauthz/commit/30b918f65982d1f8d1dde53ef85a54ac66b90261))
* use int32 for the status code ([#313](https://github.com/openkcm/extauthz/issues/313)) ([2266ad3](https://github.com/openkcm/extauthz/commit/2266ad303caa1383c3995b2c4a87fb2a100368d7))
* vulnerabilities in golang.org/x/* ([#308](https://github.com/openkcm/extauthz/issues/308)) ([cee4924](https://github.com/openkcm/extauthz/commit/cee4924688bc6a7d76f9ce67b06f34cfeea30321))

## [0.11.2](https://github.com/openkcm/extauthz/compare/v0.11.1...v0.11.2) (2025-12-18)


### Bug Fixes

* send 403 on permission denied ([#212](https://github.com/openkcm/extauthz/issues/212)) ([f25a9b0](https://github.com/openkcm/extauthz/commit/f25a9b0e788fbe6e085ad481e2cb1b0f9cb16475))

## [0.11.1](https://github.com/openkcm/extauthz/compare/v0.11.0...v0.11.1) (2025-12-18)


### Bug Fixes

* use lowercased header name ([#210](https://github.com/openkcm/extauthz/issues/210)) ([54c831d](https://github.com/openkcm/extauthz/commit/54c831d525048e8c911904b66d446ecd9a007890))

## [0.11.0](https://github.com/openkcm/extauthz/compare/v0.10.1...v0.11.0) (2025-12-18)


### Features

* use the new tenant specific session cookie ([#208](https://github.com/openkcm/extauthz/issues/208)) ([f4385a0](https://github.com/openkcm/extauthz/commit/f4385a08dba05ea49d1a23e157b5649f4487affc))

## [0.10.1](https://github.com/openkcm/extauthz/compare/v0.10.0...v0.10.1) (2025-12-17)


### Bug Fixes

* Fix linter error ([#204](https://github.com/openkcm/extauthz/issues/204)) ([ff40fac](https://github.com/openkcm/extauthz/commit/ff40fac5214e8b1e7258b487c35fb05213292140))

## [0.10.0](https://github.com/openkcm/extauthz/compare/v0.9.12...v0.10.0) (2025-12-08)


### Features

* validate CSRF token ([#198](https://github.com/openkcm/extauthz/issues/198)) ([707b710](https://github.com/openkcm/extauthz/commit/707b71022c74657fb4a2ed6070e144e680c81bd4))


### Bug Fixes

* Fix linter error ([#195](https://github.com/openkcm/extauthz/issues/195)) ([ce57a6a](https://github.com/openkcm/extauthz/commit/ce57a6ac6aee02437a24b2c653a408c3932449a7))
* improve debug logging ([#194](https://github.com/openkcm/extauthz/issues/194)) ([7497d15](https://github.com/openkcm/extauthz/commit/7497d1593133d7409abb0055900808ec32cfd3e1))
* only log on failing CSRF validation ([#201](https://github.com/openkcm/extauthz/issues/201)) ([d572783](https://github.com/openkcm/extauthz/commit/d572783522218e5f6c872d9894df04a4f4f984d8))

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
