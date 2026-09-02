## What this changes

<!-- One or two sentences. Link an issue if there is one. -->

## Why

<!-- What problem does it solve? -->

## Checks

- [ ] `make lint` passes
- [ ] `make test` passes
- [ ] `make e2e` passes
- [ ] Added or updated a test for the behaviour this changes

## Security

tvault stores authentication secrets, so please tick whichever apply:

- [ ] This does not change how secrets are stored, derived, or transmitted
- [ ] This changes the vault format (I bumped `FORMAT_VERSION` and handled the old one)
- [ ] This changes what crosses to the browser extension
- [ ] This adds or widens an extension permission — explained below

<!-- If you ticked any of the last three, describe the reasoning here. -->
