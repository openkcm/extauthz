# Changelog

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
