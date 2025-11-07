require 'oci'

# OCI backend classes

class OciConnection
    
    def initialize(params)
        params = {} if params.nil?
    end
end

class OciResourceBase < InSpec.resource(1)
    attr



client = OCI::ObjectStorage::client_name.new