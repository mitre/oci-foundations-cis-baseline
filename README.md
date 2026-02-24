# CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0

This InSpec Profile was created to facilitate testing and auditing of `CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0`
infrastructure and applications when validating compliancy with [Center for Internet Security (CIS) Benchmark](https://www.cisecurity.org/cis-benchmarks)
requirements.

- Profile Version: **3.0.0**
- Benchmark Date: **05 Nov 2025**
- Benchmark Version: **Version 3.0.0 Release 1 (V3.0.0R1)**

This profile was developed to reduce the time it takes to perform a security checks based upon the
CIS Benchmark Guidance from the Center for Internet Security (CIS).

The results of a profile run will provide information needed to support an Authority to Operate (ATO)
decision for the applicable technology.

The CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0 CIS Profile uses the [InSpec](https://github.com/inspec/inspec)
open-source compliance validation language to support automation of the required compliance, security
and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions
and Continuous Authority to Operate (cATO) processes.

Table of Contents
=================

- [CIS Benchmark  Information](#benchmark-information)
- [Requirements](#requirements)
  - [Prerequisites](#prerequisites)
  - [OCI Account Configuration](#oci-account-configuration)
- [Getting Started](#getting-started)
  - [Intended Usage](#intended-usage)
  - [Tailoring to Your Environment](#tailoring-to-your-environment)
  - [Testing the Profile Controls](#testing-the-profile-controls)
- [Setting up the Profile](#setting-up-the-profile)
- [Running the Profile](#running-the-profile)
  - [Directly from Github](#directly-from-github)
  - [Using a local Archive copy](#using-a-local-archive-copy)
  - [Different Run Options](#different-run-options)
- [Using Heimdall for Viewing Test Results](#using-heimdall-for-viewing-test-results)

## Benchmark Information

The Center for Internet Security, Inc. (CIS®) creates and maintains a set of Critical Security Controls (CIS Controls) for applications, computer systems and networks
connected to the Department of Defense (DoD). These guidelines are the primary security standards
used by the DoD agencies. In addition to defining security guidelines, the CISs also stipulate
how security training should proceed and when security checks should occur. Organizations must
stay compliant with these guidelines or they risk having their access to the DoD terminated.

Requirements associated with the CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0 CIS are derived from the
[Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide)
and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST)
[Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53)
Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The CIS Oracle Cloud Infrastructure Foundations Benchmark v3.0.0 CIS profile checks were developed to provide technical implementation
validation to the defined DoD requirements, the guidance can provide insight for any organizations wishing
to enhance their security posture and can be tailored easily for use in your organization.

## Requirements

### Prerequisites

- [Oracle Cloud Infrastructre CLI](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm)
- [CINC-auditor](https://cinc.sh/start/auditor/) or [InSpec](https://docs.chef.io/inspec/7.0/install/)

### OCI Account Configuration

To authenticate with Oracle Cloud Infrastructure (OCI), set up an API signing key and gather the values required for your `~/.oci/config` profile:

- `user` (User OCID)
- `fingerprint` (API signing key fingerprint)
- `tenancy` (Tenancy OCID)
- `region` (for example, `us-ashburn-1`)
- `key_file` (path to your private key `.pem` file)
- `pass_phrase` (optional, only if your private key is encrypted)

#### 1. Retrieve OCI Credentials

1. **Create an API signing key in OCI Console**

    In the OCI Console, navigate to **My Profile** -> **Tokens and keys** -> **Add API Key**.
    You can generate a new key pair or upload an existing public key.
    OCI displays a config template and fingerprint after setup.

2. **Collect and save required values**

    - **User OCID:** from **My Profile**
    - **Tenancy OCID:** from **Tenancy details**
    - **Fingerprint:** from the API key entry
    - **Region:** from the region selector in the OCI Console

#### 2. Configure Your OCI CLI Connection

Configure OCI credentials using one of the following options:

1. **Run the interactive OCI CLI wizard**

    ```sh
    oci setup config
    ```

2. **Configure files manually**

    1. **Create the OCI configuration directory**

        The OCI CLI uses `~/.oci/` by default:

        ```sh
        mkdir -p ~/.oci
        ```

    2. **Store your private key**

        Save your private key as a `.pem` file (example: `~/.oci/oci_api_key.pem`) and restrict permissions:

        ```sh
        chmod 600 ~/.oci/oci_api_key.pem
        ```

    3. **Create or update `~/.oci/config`**

        Use the template from OCI and replace placeholders with your values:

        ```ini
        [DEFAULT]
        user=<INSERT_USER_OCID>
        fingerprint=<INSERT_FINGERPRINT>
        tenancy=<INSERT_TENANCY_OCID>
        region=<INSERT_REGION>
        key_file=~/.oci/oci_api_key.pem
        ```

#### 3. Verify OCI CLI Authentication

1. **Run a namespace query**

    ```sh
    oci os ns get
    ```

2. **Confirm successful response**

    A successful result returns your Object Storage namespace in JSON output.

#### 4. Ensure Proper OCI Permissions

To avoid authorization failures during profile execution, verify the API key user has tenancy-level administrator access.

1. **Verify Identity Domain administrator membership**

    In the OCI Console:

    - Search for **Domains**.
    - Set the compartment selector to the **root compartment (tenancy)**.
    - Open the domain named **Default**.
    - Open **Administrators**.
    - Confirm your account appears under **Identity Domain Administrator**.

2. **Verify tenancy admin policy statement**

    In the OCI Console:

    - Search for **Policies**.
    - Set the compartment selector to the **root compartment (tenancy)**.
    - Open **Tenant Admin Policy**.
    - Open **Statements**.
    - Confirm the statement includes:

      ```text
      ALLOW GROUP Administrators to manage all-resources IN TENANCY
      ```

> [IMPORTANT]
> Missing IAM permissions can cause control failures even when authentication is configured correctly.

References:

- [API Signing Keys and Required IDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm)
- [Regions](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm)
- [OCI CLI SDK and Config File](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm)

## Getting Started

### InSpec (CINC-auditor) setup

For maximum flexibility/accessibility `cinc-auditor`, the open-source packaged binary version of Chef InSpec should be used,
compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef's always-open-source InSpec source code.
For more information see [CINC Home](https://cinc.sh/)

It is intended and recommended that CINC-auditor and this profile executed from a **"runner"** host
(such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop)
against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

> [!TIP]
> **For the best security of the runner, always install on the runner the latest version of CINC-auditor and any other supporting language components.**

To install CINC-auditor on a UNIX/Linux/MacOS platform use the following command:

```bash
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```

To install CINC-auditor on a Windows platform (Powershell) use the following command:

```powershell
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```

To confirm successful install of cinc-auditor:

```
cinc-auditor -v
```

Latest versions and other installation options are available at [CINC Auditor](https://cinc.sh/start/auditor/) site.

[top](#table-of-contents)

### Intended Usage

1. The latest `released` version of the profile is intended for use in A&A testing, as well as
    providing formal results to Authorizing Officials and Identity and Access Management (IAM)s.
    Please use the `released` versions of the profile in these types of workflows.

2. The `main` branch is a development branch that will become the next release of the profile.
    The `main` branch is intended for use in _developing and testing_ merge requests for the next
    release of the profile, and _is not intended_ be used for formal and ongoing testing on systems.

[top](#table-of-contents)

### Tailoring to Your Environment

This profile uses InSpec Inputs to provide flexibility during testing. Inputs allow for
customizing the behavior of Chef InSpec profiles.

InSpec Inputs are defined in the `inspec.yml` file. The `inputs` configured in this
file are **profile definitions and defaults for the profile** extracted from the profile
guidances and contain metadata that describe the profile, and shouldn't be modified.

InSpec provides several methods for customizing profile behaviors at run-time that does not require
modifying the `inspec.yml` file itself (see [Using Customized Inputs](#using-customized-inputs)).

The following inputs are permitted to be configured in an inputs `.yml` file (often named inputs.yml)
for the profile to run correctly on a specific environment, while still complying with the security
guidance document intent. This is important to prevent confusion when test results are passed downstream
to different stakeholders under the _security guidance name used by this profile repository_

For changes beyond the inputs cited in this section, users can create an _organizationally-named overlay repository_.
For more information on developing overlays, reference the [MITRE SAF Training](https://mitre-saf-training.netlify.app/courses/beginner/10.html)

#### Example of tailoring Inputs _While Still Complying_ with the security guidance document for the profile

```yaml
# 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.12, 1.14, 1.16
# 2.1, 2.2, 2.3, 2.4, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6
# 4.7, 4.8, 4.9, 4.10, 4.11, 4.12, 4.14, 4.15, 4.18
# 5.1.1, 5.1.2, 6.1, 6.2
# The Tenancy OCID can be found in the ~/.oci/config file used by the OCI Command Line Tool
tenancy_ocid: ""

# 1.1
# A list of expected tenancy level policy statements
tenancy_level_policy_statements: []

# 1.1
# A list of expected compartment level policy statements
compartment_level_policy_statements: []

# 1.4, 2.1, 2.2, 2.3, 2.4, 5.1.1
# OCID of the detector recipe named 'OCI Configuration Detector Recipe (Oracle Managed)'
detector_recipe_ocid: ""

# 2.6
# Expected values (IPs/CIDRs) for active Oracle Integration instances
allowed_oic_allowlisted_http_ips: []

# 2.6
# Expected map of VCN OCID to IP/CIDR for active Oracle Integration instances
allowed_oic_allowlisted_http_vcns: {}

# 2.7
# Allowed Oracle Analytics Cloud network endpoint types (e.g., PUBLIC, PRIVATE)
allowed_network_endpoint_types: ["PUBLIC"]

# 2.8
# Allowed Autonomous Database shared whitelist IPs/CIDRs for public endpoints
allowed_adb_whitelisted_ips: []

# 4.3
# Notification topic name for rule containing Identity Provider changes
identity_provider_notification_topic: ""

# 4.4
# Notification topic name for rule containing Group Mapping changes
group_mapping_notification_topic: ""

# 4.5
# Notification topic name for rule containing IAM Group changes
iam_group_notification_topic: ""

# 4.6
#Notification topic name for rule containing IAM Policy changes
iam_policy_notification_topic: ""

# 4.7
# Notification topic name for rule containing User changes
user_notification_topic: ""

# 4.8
# Notification topic name for rule containing VCN changes
vcn_list_notification_topic: ""

# 4.9
# Notification topic name for rule containing Route Table changes
route_table_notification_topic: ""

# 4.10
# Notification topic name for rule containing Security List changes
security_list_notification_topic: ""

# 4.11
# Notification topic name for rule containing Network Security Group changes
network_security_notification_topic: ""

# 4.12
# Notification topic name for rule containing Network Gateway changes
network_gateway_notification_topic: ""

# 4.15
# Notification topic name for rule containing Cloud Guard changes
cloud_guard_notification_topic: ""

# 4.18
# Notification topic name for rule containing Identity Sign-On changes
identity_signon_notification_topic: ""
```

> [!NOTE]
>Inputs are variables that are referenced by control(s) in the profile that implement them.
 They are declared (defined) and given a default value in the `inspec.yml` file.

#### Using Customized Inputs

Customized inputs may be used at the CLI by providing an input file or a flag at execution time.

1. Using the `--input` flag

    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input disable_slow_controls=true`

2. Using the `--input-file` flag.

    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input-file=<my_inputs_file.yml>`

>[!TIP]
> For additional information about `input` file examples reference the [MITRE SAF Training](https://mitre.github.io/saf-training/courses/beginner/06.html#input-file-example)

Chef InSpec Resources:

- [InSpec Profile Documentation](https://docs.chef.io/inspec/profiles/).
- [InSpec Inputs](https://docs.chef.io/inspec/profiles/inputs/).
- [inspec.yml](https://docs.chef.io/inspec/profiles/inspec_yml/).

[top](#table-of-contents)

### Testing the Profile Controls

The Gemfile provided contains all the necessary ruby dependencies for checking the profile controls.

#### Requirements

All action are conducted using `ruby` (gemstone/programming language). Currently `inspec`
commands have been tested with ruby version 3.1.2. A higher version of ruby is not guaranteed to
provide the expected results. Any modern distribution of Ruby comes with Bundler preinstalled by default.

Install ruby based on the OS being used, see [Installing Ruby](https://www.ruby-lang.org/en/documentation/installation/)

After installing `ruby` install the necessary dependencies by invoking the bundler command
(must be in the same directory where the Gemfile is located):

```bash
bundle install
```

#### Testing Commands

Linting and validating controls:

```bash
  bundle exec rake [inspec or cinc-auditor]:check # Validate the InSpec Profile
  bundle exec rake lint                           # Run RuboCop Linter
  bundle exec rake lint:auto_correct              # Autocorrect RuboCop offenses (only when it's safe)
  bundle exec rake pre_commit_checks              # Pre-commit checks
```

Ensure the controls are ready to be committed into the repo:

```bash
  bundle exec rake pre_commit_checks
```

[top](#table-of-contents)

## Setting up the Profile

1. **Clone the Repository**

    Start by cloning the `oci-foundations-cis-baseline` repository from GitHub to your local machine:

    ```sh
    git clone https://github.com/mitre/oci-foundations-cis-baseline.git
    cd oci-foundations-cis-baseline
    ```

2. **Clone the Repository**

    Once the repository is cloned, install the required Ruby dependencies by running:

    ```sh
    bundle install
    ```

3. **Create and Update `inputs.yml` for Inspec**

   Execute the following command to create the `inputs.yml` file by copying `template.inputs.yml` and renaming it to `inputs.yml`.
   Update this file with your values.

   ```sh
   cp template.inputs.yml inputs.yml
   ```

### Example `inputs.yml`

The [template.inputs.yml](https://github.com/mitre/oci-foundations-cis-baseline/blob/main/template.inputs.yml) file offers a comprehensive template that outlines all the inputs for this profile. The [inspec.yml](https://github.com/mitre/oci-foundations-cis-baseline/blob/main/inspec.yml) contains detailed descriptions for each input.

## Running the Profile

### Directly from Github

This option is best used when network connectivity is available and policies permit
access to the hosting repository.

```bash
[inspec or cinc-auditor] exec https://github.com/mitre/oci-foundations-cis-baseline/archive/main.tar.gz --input-file=<your_inputs_file.yml> --sudo --reporter=cli json:<your_results_file.json>
```

[top](#table-of-contents)

### Using a local Archive copy

If your runner is not always expected to have direct access to the profile's hosted location,
use the following steps to create an archive bundle of this overlay and all of its dependent tests:

Git is required to clone the InSpec profile using the instructions below.
Git can be downloaded from the [Git Web Site](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

When the **"runner"** host uses this profile overlay for the first time, follow these steps:

```bash
mkdir profiles
cd profiles
git clone https://github.com/mitre/oci-foundations-cis-baseline.git
[inspec or cinc-auditor] archive 

# Running locally
[inspec or cinc-auditor] exec <name of generated archive> --enhanced-outcomes --input-file=<your_inputs_file.yml> --sudo --reporter=cli json:<your_results_file.json>
```

For every successive run, follow these steps to always have the latest version of this profile baseline:

```bash
cd cis-oracle-cloud-infrastructure-foundations-benchmark-v3.0.0
git pull
cd ..
[inspec or cinc-auditor] archive cis-oracle-cloud-infrastructure-foundations-benchmark-v3.0.0 --overwrite

# Running locally
[inspec or cinc-auditor] exec <name of generated archive> --enhanced-outcomes --input-file=<your_inputs_file.yml> --sudo --reporter=cli json:<your_results_file.json>
```

[top](#table-of-contents)

## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

[top](#table-of-contents)

## Using Heimdall for Viewing Test Results

The JSON results output file can be loaded into **[Heimdall-Lite](https://heimdall-lite.mitre.org/)**
or **[Heimdall-Server](https://github.com/mitre/heimdall2)** for a user-interactive, graphical view of the profile scan results.

Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.
Heimdall-Server is configured with a `data-services backend` allowing for data persistency to a database (PostgreSQL).
For more detail on feature capabilities see [Heimdall Features](https://github.com/mitre/heimdall2?tab=readme-ov-file#features)

Heimdall can **_export your results into a DISA Checklist (CKL) file_** for easily uploading into eMass using the `Heimdall Export` function.

Depending on your environment restrictions, the [SAF CLI](https://saf-cli.mitre.org) can be used to run a local docker instance
of Heimdall-Lite via the `saf view:heimdall` command.

Additionally both Heimdall applications can be deployed via docker, kubernetes, or the installation packages.

[top](#table-of-contents)

## Authors

[Center for Internet Security (CIS)](https://www.cisecurity.org/)

[MITRE Security Automation Framework Team](https://saf.mitre.org)

## NOTICE

© 2018-2026 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

## NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

## NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

## NOTICE

[CIS Benchmarks are published by Center for Internet Security](https://www.cisecurity.org/cis-benchmarks)
