control "3_2" do
  title "Ensure Secure Boot is enabled on Compute Instance"
  desc "Shielded Instances with Secure Boot enabled prevents unauthorized boot loaders and operating systems from booting.  This prevent rootkits, bootkits, and unauthorized software from running before the operating system loads.
Secure Boot verifies the digital signature of the system's boot software to check its authenticity. The digital signature ensures the operating system has not been tampered with and is from a trusted source.
When the system boots and attempts to execute the software, it will first check the digital signature to ensure validity. If the digital signature is not valid, the system will not allow the software to run.
Secure Boot is a feature of UEFI(Unified Extensible Firmware Interface) that only allows approved operating systems to boot up.

A Threat Actor with access to the operating system may seek to alter boot components to persist malware or rootkits during system initialization. Secure Boot helps ensure that the system only runs authentic software by verifying the digital signature of all boot components."
  desc "check", %q(From Console: Login to the OCI Console Select compute instance in your compartment. Click on each instance name. In the Launch Options section, Check if Secure Boot is Enabled . From CLI: Run command: for region in `oci iam region-subscription list | jq -r '.data[] | ."region-name"'`;
   do
       for compid in `oci iam compartment list --compartment-id-in-subtree TRUE 2>/dev/null | jq -r '.data[] | .id'`
        do
            output=`oci compute instance list --compartment-id $compid --region $region --all 2>/dev/null | jq -r '.data[] | select(."platform-config" == null or "platform-config"."is-secure-boot-enabled" == false )'`
            if [ ! -z "$output" ]; then echo $output; fi
        done
   done In response, check if platform-config are not null and is-secure-boot-enabled is set to true)
  desc "fix", "Note: Secure Boot facility is available on selected VM images and Shapes in OCI. User have to configure Secured Boot at time of instance creation only. From Console: Navigate to https://cloud.oracle.com/compute/instances Select the instance from the Audit Procedure Click Terminate . Determine whether or not to permanently delete instance's attached boot volume. Click Terminate instance . Click on Create Instance . Select Image and Shape which supports Shielded Instance configuration. Icon for Shield in front of Image/Shape row indicates support of Shielded Instance. Click on edit of Security Blade. Turn On Shielded Instance, then Turn on the Secure Boot Toggle. Fill in the rest of the details as per requirements. Click Create ."
  desc "potential_impacts", "An existing instance cannot be changed to a Shielded instance with Secure boot enabled.  Shielded Secure Boot not available on all instance shapes and Operating systems. Additionally the following limitations exist: Thus to enable you have to terminate the instance and create a new one.  Also, Shielded instances do not support live migration. During an infrastructure maintenance event, Oracle Cloud Infrastructure live migrates supported VM instances from the physical VM host that needs maintenance to a healthy VM host with minimal disruption to running instances. If you enable Secure Boot on an instance, the instance cannot be migrated, because the hardware TPM is not migratable.  This may result in an outage because the TPM can't be migrate from a unhealthy host to healthy host."
  impact 0.5
  tag check_id: "C-3_2"
  tag severity: "medium"
  tag gid: "CIS-3_2"
  tag rid: "xccdf_cis_cis_rule_3_2"
  tag stig_id: "3.2"
  tag gtitle: "<GroupDescription></GroupDescription>"
  tag "documentable"
  tag cci: ["CCI-000364", "CCI-000365", "CCI-000366", "CCI-000421"]
  tag nist: ["CM-6 a", "CM-6 a", "CM-6 b", "CM-9 a"]
end
