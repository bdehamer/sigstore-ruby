# frozen_string_literal: true

# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative "error"

require_relative "trusted_root"

module Sigstore
  VerificationResult = Struct.new(:success, keyword_init: true) do
    # @implements VerificationResult

    alias_method :verified?, :success
  end

  class VerificationSuccess < VerificationResult
    # @implements VerificationSuccess
    def initialize
      super(success: true)
    end
  end

  class VerificationFailure < VerificationResult
    # @implements VerificationFailure
    attr_reader :reason

    def initialize(reason)
      @reason = reason
      super(success: false)
    end
  end

  class BundleType
    include Comparable

    attr_reader :media_type

    def initialize(media_type)
      @media_type = media_type
    end

    BUNDLE_0_1 = new("application/vnd.dev.sigstore.bundle+json;version=0.1")
    BUNDLE_0_2 = new("application/vnd.dev.sigstore.bundle+json;version=0.2")
    BUNDLE_0_3 = new("application/vnd.dev.sigstore.bundle.v0.3+json")

    VERSIONS = [BUNDLE_0_1, BUNDLE_0_2, BUNDLE_0_3].freeze

    def self.from_media_type(media_type)
      case media_type
      when BUNDLE_0_1.media_type
        BUNDLE_0_1
      when BUNDLE_0_2.media_type
        BUNDLE_0_2
      when BUNDLE_0_3.media_type, "application/vnd.dev.sigstore.bundle+json;version=0.3"
        BUNDLE_0_3
      else
        raise Error::InvalidBundle, "Unsupported bundle format: #{media_type.inspect}"
      end
    end

    def <=>(other)
      VERSIONS.index(self) <=> VERSIONS.index(other)
    end
  end

  class VerificationInput < DelegateClass(Verification::V1::Input)
    attr_reader :trusted_root, :sbundle, :hashed_input, :public_key

    def initialize(*, public_key: nil)
      super(*)

      unless bundle.is_a?(Bundle::V1::Bundle)
        raise ArgumentError,
              "bundle must be a #{Bundle::V1::Bundle}, is #{bundle.class}"
      end

      @trusted_root = TrustedRoot.new(artifact_trust_root)
      @sbundle = SBundle.new(bundle)
      @public_key = public_key
      if sbundle.message_signature? && !artifact
        raise Error::InvalidVerificationInput, "bundle with message_signature requires an artifact"
      end

      case artifact.data
      when :artifact_uri
        unless artifact.artifact_uri.start_with?("sha256:")
          raise Error::InvalidVerificationInput,
                "artifact_uri must be prefixed with 'sha256:'"
        end

        @hashed_input = Common::V1::HashOutput.new.tap do |hash_output|
          hash_output.algorithm = Common::V1::HashAlgorithm::SHA2_256
          hexdigest = artifact.artifact_uri.split(":", 2).last
          hash_output.digest = Internal::Util.hex_decode(hexdigest)
        end
      when :artifact
        @hashed_input = Common::V1::HashOutput.new.tap do |hash_output|
          hash_output.algorithm = Common::V1::HashAlgorithm::SHA2_256
          hash_output.digest = OpenSSL::Digest.new("SHA256").update(artifact.artifact).digest
        end
      else
        raise Error::InvalidVerificationInput, "Unsupported artifact data: #{artifact.data}"
      end

      # Validate that the bundle's message_digest (if present) matches the computed hash
      if sbundle.message_signature? && sbundle.message_signature.message_digest &&
         !sbundle.message_signature.message_digest.digest.empty?
        bundle_digest = sbundle.message_signature.message_digest
        if bundle_digest.digest != @hashed_input.digest
          raise Error::InvalidBundle,
                "bundle message digest does not match artifact"
        end
      end

      freeze
    end
  end

  class SBundle < DelegateClass(Bundle::V1::Bundle)
    attr_reader :bundle_type, :leaf_certificate

    def initialize(*)
      super
      @bundle_type = BundleType.from_media_type(media_type)
      validate_version!
      freeze
    end

    def self.for_cert_bytes_and_signature(cert_bytes, signature)
      bundle = Bundle::V1::Bundle.new
      bundle.media_type = BundleType::BUNDLE_0_3.media_type
      bundle.verification_material = Bundle::V1::VerificationMaterial.new
      bundle.verification_material.certificate = Common::V1::X509Certificate.new
      bundle.verification_material.certificate.raw_bytes = cert_bytes
      bundle.message_signature = Common::V1::MessageSignature.new
      bundle.message_signature.signature = signature
      new(bundle)
    end

    def expected_tlog_entry(hashed_input, public_key: nil)
      rekor_entry = verification_material.tlog_entries.first
      canonicalized_body = begin
        JSON.parse(rekor_entry.canonicalized_body)
      rescue JSON::ParserError
        raise Error::InvalidBundle, "expected canonicalized_body to be JSON"
      end

      kind_version = canonicalized_body.values_at("kind", "apiVersion")

      case content
      when :message_signature
        case kind_version
        when %w[hashedrekord 0.0.1]
          expected_hashed_rekord_tlog_entry(hashed_input, public_key: public_key)
        when %w[hashedrekord 0.0.2]
          expected_hashed_rekord_v002_tlog_entry(hashed_input)
        else
          raise Error::InvalidRekorEntry, "Unhandled rekor entry kind/version: #{kind_version.inspect}"
        end
      when :dsse_envelope
        case kind_version
        when %w[dsse 0.0.1]
          expected_dsse_0_0_1_tlog_entry
        when %w[intoto 0.0.2]
          expected_intoto_0_0_2_tlog_entry
        when %w[dsse 0.0.2]
          expected_dsse_v002_tlog_entry
        else
          raise Error::InvalidRekorEntry, "Unhandled rekor entry kind/version: #{kind_version.inspect}"
        end
      else
        raise Error::InvalidBundle, "expected either message_signature or dsse_envelope"
      end
    end

    private

    def validate_version!
      raise Error::InvalidBundle, "bundle requires verification material" unless verification_material

      case bundle_type
      when BundleType::BUNDLE_0_1
        unless verification_material.tlog_entries.all?(&:inclusion_promise)
          raise Error::InvalidBundle,
                "bundle v0.1 requires an inclusion promise"
        end
        if verification_material.tlog_entries.any? { |t| t.inclusion_proof&.checkpoint.nil? }
          raise Error::InvalidBundle,
                "0.1 bundle contains an inclusion proof without checkpoint"
        end
      else
        unless verification_material.tlog_entries.all?(&:inclusion_proof)
          raise Error::InvalidBundle,
                "must contain an inclusion proof"
        end
        unless verification_material.tlog_entries.all? { |t| t.inclusion_proof.checkpoint&.envelope }
          raise Error::InvalidBundle,
                "inclusion proof must contain a checkpoint"
        end
      end

      raise Error::InvalidBundle, "Expected one tlog entry" if verification_material.tlog_entries.size > 1

      case verification_material.content
      when :public_key
        @leaf_certificate = nil
      when :x509_certificate_chain
        certs = verification_material.x509_certificate_chain.certificates.map do |cert|
          Internal::X509::Certificate.read(cert.raw_bytes)
        end

        @leaf_certificate = certs.first
        certs.each do |cert|
          raise Error::InvalidBundle, "Root CA in chain" if cert.ca?
        end
      when :certificate
        @leaf_certificate = Internal::X509::Certificate.read(verification_material.certificate.raw_bytes)
      else
        raise Error::InvalidBundle, "Unsupported bundle content: #{content.inspect}"
      end
      raise Error::InvalidBundle, "expected certificate to be leaf" if @leaf_certificate && !@leaf_certificate.leaf?
    end

    def expected_hashed_rekord_tlog_entry(hashed_input, public_key: nil)
      key_content = if public_key
                      Internal::Util.base64_encode(public_key.to_pem)
                    else
                      Internal::Util.base64_encode(leaf_certificate.to_pem)
                    end
      {
        "spec" => {
          "signature" => {
            "content" => Internal::Util.base64_encode(message_signature.signature),
            "publicKey" => {
              "content" => key_content
            }
          },
          "data" => {
            "hash" => {
              "algorithm" => Internal::Util.hash_algorithm_name(hashed_input.algorithm),
              "value" => Internal::Util.hex_encode(hashed_input.digest)
            }
          }
        },
        "kind" => "hashedrekord",
        "apiVersion" => "0.0.1"
      }
    end

    def expected_intoto_0_0_2_tlog_entry
      {
        "apiVersion" => "0.0.2",
        "kind" => "intoto",
        "spec" => {
          "content" => {
            "envelope" => {
              "payloadType" => dsse_envelope.payloadType,
              "payload" => Internal::Util.base64_encode(Internal::Util.base64_encode(dsse_envelope.payload)),
              "signatures" => dsse_envelope.signatures.map do |sig|
                {
                  "publicKey" =>
                    # needed because #to_pem packs the key in base64 with m*
                    Internal::Util.base64_encode(
                      "-----BEGIN CERTIFICATE-----\n" \
                      "#{Internal::Util.base64_encode(leaf_certificate.to_der)}\n" \
                      "-----END CERTIFICATE-----\n"
                    ),
                  "sig" => Internal::Util.base64_encode(Internal::Util.base64_encode(sig.sig))
                }
              end
            },
            "payloadHash" => {
              "algorithm" => "sha256",
              "value" => OpenSSL::Digest::SHA256.hexdigest(dsse_envelope.payload)
            }
          }
        }
      }
    end

    def expected_dsse_0_0_1_tlog_entry
      {
        "apiVersion" => "0.0.1",
        "kind" => "dsse",
        "spec" => {
          "payloadHash" => {
            "algorithm" => "sha256",
            "value" => OpenSSL::Digest::SHA256.hexdigest(dsse_envelope.payload)
          },
          "signatures" =>
            dsse_envelope.signatures.map do |sig|
              {
                "signature" => Internal::Util.base64_encode(sig.sig),
                "verifier" => Internal::Util.base64_encode(leaf_certificate.to_pem)
              }
            end
        }
      }
    end

    def expected_hashed_rekord_v002_tlog_entry(hashed_input)
      algorithm = case hashed_input.algorithm
                  when Common::V1::HashAlgorithm::SHA2_256 then "SHA2_256"
                  when Common::V1::HashAlgorithm::SHA2_384 then "SHA2_384"
                  when Common::V1::HashAlgorithm::SHA2_512 then "SHA2_512"
                  else
                    raise ArgumentError, "unsupported hash algorithm: #{hashed_input.algorithm.inspect}"
                  end
      {
        "apiVersion" => "0.0.2",
        "kind" => "hashedrekord",
        "spec" => {
          "hashedRekordV002" => {
            "data" => {
              "algorithm" => algorithm,
              "digest" => Internal::Util.base64_encode(hashed_input.digest)
            },
            "signature" => {
              "content" => Internal::Util.base64_encode(message_signature.signature),
              "verifier" => v002_verifier
            }
          }
        }
      }
    end

    def expected_dsse_v002_tlog_entry
      {
        "apiVersion" => "0.0.2",
        "kind" => "dsse",
        "spec" => {
          "dsseV002" => {
            "payloadHash" => {
              "algorithm" => "SHA2_256",
              "digest" => Internal::Util.base64_encode(OpenSSL::Digest::SHA256.digest(dsse_envelope.payload))
            },
            "signatures" =>
              dsse_envelope.signatures.map do |sig|
                {
                  "content" => Internal::Util.base64_encode(sig.sig),
                  "verifier" => v002_verifier
                }
              end
          }
        }
      }
    end

    def v002_verifier
      key_details = key_details_for_certificate(leaf_certificate)
      {
        "keyDetails" => key_details,
        "x509Certificate" => {
          "rawBytes" => Internal::Util.base64_encode(leaf_certificate.to_der)
        }
      }
    end

    def key_details_for_certificate(cert)
      public_key = cert.public_key
      case public_key
      when OpenSSL::PKey::EC
        case public_key.group.curve_name
        when "prime256v1"
          "PKIX_ECDSA_P256_SHA_256"
        when "secp384r1"
          "PKIX_ECDSA_P384_SHA_384"
        when "secp521r1"
          "PKIX_ECDSA_P521_SHA_512"
        else
          raise Error::Unimplemented, "unsupported EC curve: #{public_key.group.curve_name}"
        end
      else
        raise Error::Unimplemented, "unsupported public key type: #{public_key.class}"
      end
    end
  end
end
