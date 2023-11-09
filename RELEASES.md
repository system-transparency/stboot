# Releases of stboot

## What is being released?

The following program is released and supported:

  - `./stboot`

New releases are announced on the System Transparency [announce list][].  What
changed in each release is documented in a [NEWS file](./NEWS).  The NEWS file
also specifies which other System Transparency components are known to be
interoperable, as well as which reference specifications are being implemented.

Note that a release is simply a git-tag specified on our mailing list.  The
source for this git-tag becomes available on the repository's release page:

  https://git.glasklar.is/system-transparency/core/stboot/-/releases

The stboot Go module is **not** considered stable before a v1.0.0 release.  By
the terms of the LICENSE file you are free to use this code "as is" in almost
any way you like, but for now, we support its use _only_ via the above program.
We don't aim to provide any backwards-compatibility for internal interfaces.

[announce list]: https://lists.system-transparency.org/mailman3/postorius/lists/st-announce.lists.system-transparency.org/

## What release cycle is used?

We make feature releases when something new is ready.  As a rule of thumb,
feature releases will not happen more often than once per month.

In case critical bugs are discovered, we intend to provide bug-fix-only updates
for the latest release in a timely manner.  Backporting bug-fixes to older
releases than the latest one will be considered on a case-by-case basis.  Such
consideration is most likely if the latest feature release is very recent and
upgrading to it is particularly disruptive due to the changes that it brings.

## Upgrading

You are expected to upgrade linearly from one advertised release to the next
advertised release, e.g., from v0.1.1 to v0.2.1.  We strive to make such linear
upgrades easy and well-documented to help with forward-compatibility.  Any
complications that are caused by changed reference specifications, command-line
flags, or similar will be clearly outlined in the [NEWS files](./NEWS).  Pay
close attention to the "Breaking changes" section for these migration notes.

Downgrading is in general not supported.

## Expected changes in upcoming releases

  - Transition to an OS package format based on _Unified Kernel Images (UKIs)_.
  - Transition to new signature format that's compatible with Sigsum.
  - Any changes to the System Transparency reference specifications will be
    implemented.  This could for example affect the format of configuration
    files such as host configuration oder trust policy.
  - New boot modes, such as booting from disk.

