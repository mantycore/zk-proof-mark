# An implementation of zero-knowledge proof, non-interactive version
# based on NARWHAL implementation[2] of Brandon Lum Jia Jun's ZKA_wzk auth protocol[1]
#
# [1] http://ojs.pythonpapers.org/index.php/tppm/article/download/155/142
# [2] https://courses.csail.mit.edu/6.857/2014/files/15-cheu-jaffe-lin-yang-zkp-authentication.pdf


require 'openssl'
require 'base64'

class ZKProofMark

    modulus_s = '4074071952668972172536891376818756322102936787331872501272280898708762599526673412366794779'
    @@modulus_bn = OpenSSL::BN.new(modulus_s)

    G = OpenSSL::BN.new('3')
    SHA256 = OpenSSL::Digest::SHA256.new
    @@salt = "DVS454sQ6VXhB8Xf"

    private_class_method def self.Y(x)
        G.mod_exp(x, @@modulus_bn)
    end

    private_class_method def self.hash_bn(str)
        OpenSSL::BN.new(SHA256.hexdigest(str), 16)
    end

    def self.salt=(new_salt)
        @@salt = new_salt
    end

    def self.signature(payload, private_key)
        Y(hash_bn(private_key + @@salt + payload))
    end

    def self.prove(payload_2, payload_1, private_key)
        x = hash_bn(private_key + @@salt + payload_1)
        y = Y(x)
        r = OpenSSL::BN.rand(512)
        t = G.mod_exp(r, @@modulus_bn)
        c = hash_bn(y.to_s + t.to_s + payload_2 + payload_1)
        [c, r - c * x]
    end

    def self.check(proof, payload_2, payload_1, signature_1)
        t = signature_1.mod_exp(proof[0], @@modulus_bn) * G.mod_exp(proof[1], @@modulus_bn) % @@modulus_bn
        proof[0] == hash_bn(signature_1.to_s + t.to_s + payload_2 + payload_1)
    end 


    def self.signature_b64(payload, private_key)
        Base64::encode64(signature(payload, private_key).to_s(0))
    end


    def self.prove_b64(payload_2, payload_1, private_key)
        proof = prove(payload_2, payload_1, private_key)
        proof = proof.map{|bn| Base64::encode64(bn.to_s(0))}
        proof[0].gsub!(/\n$/, "::\n")
        return proof.join('')
    end

    def self.check_b64(proof, payload_2, payload_1, signature_1)
        proof_bn = proof.split('::').map{|b64| OpenSSL::BN.new(Base64::decode64(b64), 0)}
        signature_1_bn = OpenSSL::BN.new(Base64::decode64(signature_1), 0)
        check(proof_bn, payload_2, payload_1, signature_1_bn)
    end
end
