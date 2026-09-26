/// Print the image options the e2e boots with, as one line: the `image_args` input of
/// enclave-runtime's "Publish a dev enclave" workflow. `make enclave-bundle-args`.
library;

import 'package:e2e/e2e_profile.dart';

void main() {
  print(e2eImageOptions().join(' '));
}
