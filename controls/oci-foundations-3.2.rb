control 'oci-foundations-3.2' do
  title 'Ensure Secure Boot is enabled on Compute Instance'

  desc <<~DESC
    Shielded Instances with Secure Boot enabled prevents unauthorized boot loaders and
    operating systems from booting. This prevent rootkits, bootkits, and unauthorized software
    from running before the operating system loads. Secure Boot verifies the digital signature
    of the system's boot software to check its authenticity. The digital signature ensures the
    operating system has not been tampered with and is from a trusted source. When the system
    boots and attempts to execute the software, it will first check the digital signature to
    ensure validity. If the digital signature is not valid, the system will not allow the
    software to run. Secure Boot is a feature of UEFI(Unified Extensible Firmware Interface)
    that only allows approved operating systems to boot up. A Threat Actor with access to the
    operating system may seek to alter boot components to persist malware or rootkits during
    system initialization. Secure Boot helps ensure that the system only runs authentic
    software by verifying the digital signature of all boot components.
  DESC

  desc 'check', <<~CHECK
    From Console: Login to the OCI Console Select compute instance in your compartment. Click

    on each instance name. In the Launch Options section, Check if Secure Boot is Enabled .

    From CLI: Run command: for region in `oci iam region-subscription list | jq -r '.data[] |

    ."region-name"'`; do for compid in `oci iam compartment list --compartment-id-in-subtree
    TRUE 2>/dev/null | jq -r '.data[] | .id'` do output=`oci compute instance list
    --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] |
    select(."platform-config" == null or "platform-config"."is-secure-boot-enabled" == false
    )'` if [ ! -z "$output" ]; then echo $output; fi done done In response, check if
    platform-config are not null and is-secure-boot-enabled is set to true
  CHECK

  desc 'fix', <<~FIX
    Note: Secure Boot facility is available on selected VM images and Shapes in OCI. User have

    to configure Secured Boot at time of instance creation only. From Console: Navigate to
    https://cloud.oracle.com/compute/instances Select the instance from the Audit Procedure
    Click Terminate . Determine whether or not to permanently delete instance's attached boot
    volume. Click Terminate instance . Click on Create Instance . Select Image and Shape which
    supports Shielded Instance configuration. Icon for Shield in front of Image/Shape row
    indicates support of Shielded Instance. Click on edit of Security Blade. Turn On Shielded
    Instance, then Turn on the Secure Boot Toggle. Fill in the rest of the details as per
    requirements. Click Create .
  FIX

  desc 'potential_impacts', <<~POTENTIAL_IMPACTS
    "An existing instance cannot be changed to a Shielded instance with Secure boot enabled.
    Shielded Secure Boot not available on all instance shapes and Operating systems.
    Additionally the following limitations exist: Thus to enable you have to terminate the
    instance and create a new one. Also, Shielded instances do not support live migration.
    During an infrastructure maintenance event, Oracle Cloud Infrastructure live migrates
    supported VM instances from the physical VM host that needs maintenance to a healthy VM
    host with minimal disruption to running instances. If you enable Secure Boot on an
    instance, the instance cannot be migrated, because the hardware TPM is not migratable.
    This may result in an ou
  POTENTIAL_IMPACTS

  impact 0.5

  tag severity: 'medium'
  tag benchmark_ref: '3.2'
  tag cis_level: 'Level 2'
  tag assessment_status: 'Automated'
  tag cis_controls: %w[4.1]

  tag cci: %w[CCI-000364]

  tag nist: ['CM-6']

  regions_response = json(command: 'oci iam region-subscription list --all')
  regions_data = regions_response.params.fetch('data', [])
  regions = regions_data.map { |region| region['region-name'] }.compact

  compartments_response = json(command: 'oci iam compartment list --include-root --compartment-id-in-subtree TRUE --all 2>/dev/null')
  compartments_data = compartments_response.params.fetch('data', [])
  compartment_ids = compartments_data.map { |compartment| compartment['id'] }.compact

  non_compliant_instances = []
  total_instances = 0

  regions.each do |region|
    compartment_ids.each do |compartment_id|
      instances_response = json(command: %(oci compute instance list --compartment-id "#{compartment_id}" --region "#{region}" --all 2>/dev/null))
      instances = instances_response.params.fetch('data', [])

      instances.each do |instance|
        total_instances += 1
        platform_config = instance['platform-config']
        secure_boot_enabled = platform_config && platform_config['is-secure-boot-enabled']

        next if platform_config && secure_boot_enabled == true

        non_compliant_instances << {
          'display_name' => instance['display-name'],
          'id' => instance['id'],
          'region' => region,
          'compartment_id' => compartment_id,
          'platform_config_present' => !platform_config.nil?,
          'is_secure_boot_enabled' => secure_boot_enabled
        }
      end
    end
  end

  if total_instances.zero?
    impact 0.0
    describe 'Ensure Secure Boot is enabled on Compute Instance' do
      skip 'No compute instances found in tenancy.'
    end
  else
    describe 'Ensure Secure Boot is enabled on Compute Instance' do
      subject { non_compliant_instances }
      it { should cmp [] }
    end
  end
end
