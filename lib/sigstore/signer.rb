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

require_relative "internal/util"
require_relative "internal/x509"
require_relative "models"
require_relative "oidc"
require_relative "policy"
require_relative "verifier"
require_relative "version"

module Sigstore
  class Signer
    include Loggable

    def initialize(jwt:, trusted_root:)
      @identity_token = OIDC::IdentityToken.new(jwt)
      @trusted_root = trusted_root

      @verifier = Verifier.for_trust_root(trust_root: @trusted_root)
    end

    def sign(payload)
      # 2) generate a keypair
      keypair = generate_keypair
      # 3) generate a CreateSigningCertificateRequest
      csr = generate_csr(keypair)
      # 4) get a cert chain from fulcio
      leaf = fetch_cert(csr)
      # 5) verify returned cert chain
      verify_chain(leaf)
      # 6) sign the payload
      signature = sign_payload(payload, keypair)
      # 7) send hash of signature to timestamping service
      timestamp_verification_data = submit_signature_hash_to_timstamping_service(signature)
      # 8) submit signed metadata to transparency service
      hashed_input = Common::V1::HashOutput.new
      hashed_input.algorithm = Common::V1::HashAlgorithm::SHA2_256
      hashed_input.digest = OpenSSL::Digest("SHA256").digest(payload)
      tlog_entry = submit_signed_metadata_to_transparency_service(signature, leaf, hashed_input)
      # 9) perform verification

      bundle = collect_bundle(leaf, [tlog_entry], timestamp_verification_data, hashed_input, signature)
      verify(payload, bundle)

      bundle
    end

    def sign_dsse(statement_payload)
      keypair = generate_keypair
      csr = generate_csr(keypair)
      leaf = fetch_cert(csr)
      verify_chain(leaf)

      # Build DSSE envelope
      payload_type = "application/vnd.in-toto+json"
      pae = "DSSEv1 #{payload_type.bytesize} #{payload_type} " \
            "#{statement_payload.bytesize} #{statement_payload}".b
      signature = keypair.sign("SHA256", pae)

      # Get timestamp
      timestamp_verification_data = submit_signature_hash_to_timstamping_service(signature)

      # Build the intoto/dsse entry for Rekor
      proposed_entry = build_proposed_intoto_entry(statement_payload, signature, leaf)

      ctlog = @trusted_root.tlog_for_signing
      logger.info { "Submitting DSSE entry to #{ctlog.base_url}" }
      tlog_entry = @verifier.rekor_client.log.entries.post(proposed_entry)

      bundle = collect_dsse_bundle(leaf, [tlog_entry], timestamp_verification_data,
                                   payload_type, statement_payload, signature)

      # Verify the DSSE bundle
      hashed_input = Common::V1::HashOutput.new
      hashed_input.algorithm = Common::V1::HashAlgorithm::SHA2_256
      in_toto = JSON.parse(statement_payload)
      subject = in_toto.fetch("subject").first
      digest_value = subject.fetch("digest").values.first
      hashed_input.digest = Internal::Util.hex_decode(digest_value)

      verification_input = Verification::V1::Input.new
      verification_input.bundle = bundle
      verification_input.artifact = Verification::V1::Artifact.new
      verification_input.artifact.artifact_uri = "sha256:#{digest_value}"

      result = @verifier.verify(
        input: VerificationInput.new(verification_input),
        policy: expected_identity,
        offline: false
      )
      raise Error::Signing, "Failed to verify DSSE: #{result.reason}" unless result.verified?

      bundle
    end

    private

    def generate_keypair
      # maybe allow configuring?
      key = OpenSSL::PKey::EC.generate("prime256v1")
      logger.debug { "Generated keypair #{key}" }
      key
    end

    def generate_csr(keypair)
      csr = OpenSSL::X509::Request.new

      # The subject is unused, but must be set to avoid an error on JRuby
      csr.subject = OpenSSL::X509::Name.new
      csr.public_key = keypair

      # The subject in the CertificationRequestInfo is an X.501 RelativeDistinguishedName.
      # The value of the RelativeDistinguishedName SHOULD be the subject of the authentication token;
      # its type MUST be the type identified in the Fulcio instance’s public configuration.
      # NOTE: the subject of the CSR is unused

      extension = OpenSSL::X509::ExtensionFactory.new.create_extension(
        "basicConstraints",
        "CA:FALSE",
        true # critical
      )
      csr.add_attribute OpenSSL::X509::Attribute.new(
        "extReq",
        OpenSSL::ASN1::Set.new(
          [OpenSSL::ASN1::Sequence.new([extension])]
        )
      )

      csr.sign keypair, OpenSSL::Digest.new("SHA256")

      logger.debug { "Generated CSR" }

      {
        credentials: {
          oidcIdentityToken: @identity_token.raw_token
        },
        certificateSigningRequest: Internal::Util.base64_encode(csr.to_pem)
      }
    end

    def fetch_cert(csr)
      uri = URI.parse @trusted_root.certificate_authority_for_signing.uri
      uri = URI.join(uri, "api/v2/signingCert")
      resp = Net::HTTP.post(
        uri,
        JSON.dump(csr),
        { "Content-Type" => "application/json", "User-Agent" => Sigstore::USER_AGENT }
      )

      unless resp.code == "200"
        raise Error::Signing,
              "#{resp.code} #{resp.message}\n\n#{resp.body}"
      end

      resp_body = JSON.parse(resp.body)

      unless resp_body.key?("signedCertificateEmbeddedSct")
        raise Error::Signing, "missing signedCertificateEmbeddedSct in response from fulcio"
      end

      cert = resp_body.fetch("signedCertificateEmbeddedSct").fetch("chain")
                      .fetch("certificates").first.then { |pem| Internal::X509::Certificate.read(pem) }
      logger.debug { "Fetched cert from fulcio" }
      cert
    end

    def verify_chain(leaf)
      # Perform certification path validation (RFC 5280 §6) of the returned certificate chain with the pre-distributed
      # Fulcio root certificate(s) as a trust anchor.

      now = Time.now
      if leaf.not_before > now
        unless leaf.not_before - now < 60
          raise Error::Signing, "leaf certificate not yet valid: #{leaf.not_before.inspect} vs #{now.inspect}"
        end

        logger.warn do
          "leaf certificate not yet valid: #{leaf.not_before.inspect} vs #{now.inspect}, sleeping until valid"
        end
        sleep(leaf.not_before - now)
      end

      chain, err = Internal::X509.validate_chain(@trusted_root.fulcio_cert_chains, leaf, nil)
      raise Error::Signing, "failed to validate returned certificate chain: #{err.reason}" if err

      logger.debug { "verified chain" }

      # Extract a SignedCertificateTimestamp, which may be embedded as an X.509 extension in the leaf certificate or
      # attached separately in the SigningCertificate returned from the Identity Service.
      # Verify this SignedCertificateTimestamp as in RFC 9162 §8.1.3, using the root certificate from
      # the Certificate Transparency Log.
      if (result = @verifier.verify_scts(leaf, chain)) && !result.verified?
        raise Error::Signing, "Failed to verify SCTs: #{result.reason}"
      end

      # Check that the leaf certificate contains the subject from the certificate signing request and encodes the
      # appropriate AuthenticationServiceIdentifier in an extension with OID 1.3.6.1.4.1.57264.1.8.

      fulcio_issuer = leaf.extension(Internal::X509::Extension::FulcioIssuer)
      unless fulcio_issuer && fulcio_issuer.issuer == @identity_token.issuer
        raise Error::Signing, "certificate does not contain expected Fulcio issuer"
      end

      unless leaf.subject.to_a.empty?
        raise Error::Signing,
              "certificate contains unexpected subject #{leaf.subject.to_a}"
      end

      general_names = leaf.extension(Internal::X509::Extension::SubjectAlternativeName).general_names
      expected_san = [@identity_token.identity]
      if general_names.map(&:last) != expected_san
        raise Error::Signing,
              "certificate does not contain expected SAN #{expected_san}, got #{general_names}"
      end

      [leaf, chain.unshift(leaf)]
    end

    def sign_payload(payload, key)
      # The Signer MAY pre-hash the payload using a hash algorithm from the registry (Spec: Sigstore Registries) for
      # compatibility with some signing metadata formats (see §Submission of Signing Metadata to Transparency Service).
      key.sign("SHA256", payload)
    end

    # TODO: implement
    def submit_signature_hash_to_timstamping_service(signature)
      # The Signer sends a hash of the signature as the messageImprint in a TimeStampReq to the Timestamping Service and
      # receives a TimeStampResp including a `TimeStampToken`.
      # The signer MUST verify the TimeStampToken against the payload and Timestamping Service root certificate.

      timestamp_authorities = @trusted_root.timestamp_authorities
      return nil if timestamp_authorities.empty?

      timestamps = []
      timestamp_authorities.each do |ta|
        next unless @trusted_root.send(:timerange_valid?, ta.valid_for, allow_expired: false)

        tsa_url = URI.parse(ta.uri)
        digest = OpenSSL::Digest::SHA256.digest(signature)

        req = OpenSSL::Timestamp::Request.new
        req.algorithm = "SHA256"
        req.message_imprint = digest
        req.cert_requested = true

        net = defined?(Gem::Net) ? Gem::Net : Net
        resp = net::HTTP.post(
          tsa_url,
          req.to_der,
          { "Content-Type" => "application/timestamp-query", "User-Agent" => Sigstore::USER_AGENT }
        )

        unless resp.code == "200"
          logger.warn { "TSA request to #{tsa_url} failed: #{resp.code} #{resp.message}" }
          next
        end

        tsr = OpenSSL::Timestamp::Response.new(resp.body)
        unless tsr.status == 0
          logger.warn { "TSA response status: #{tsr.status}" }
          next
        end

        logger.debug { "Got timestamp from #{tsa_url}" }
        ts = Common::V1::RFC3161SignedTimestamp.new
        ts.signed_timestamp = tsr.to_der
        timestamps << ts
      rescue StandardError => e
        logger.warn { "TSA request to #{ta.uri} failed: #{e}" }
      end

      return nil if timestamps.empty?

      tvd = Bundle::V1::TimestampVerificationData.new
      tvd.rfc3161_timestamps = timestamps
      tvd
    end

    def build_proposed_hashed_rekord_entry(signature, cert, hashed_input)
      algorithm = case hashed_input.algorithm
                  when Common::V1::HashAlgorithm::SHA2_256 then "sha256"
                  when Common::V1::HashAlgorithm::SHA2_384 then "sha384"
                  when Common::V1::HashAlgorithm::SHA2_512 then "sha512"
                  else
                    raise ArgumentError,
                          "unsupported hash algorithm: #{hashed_input.algorithm.inspect}"
                  end
      {
        "spec" => {
          "signature" => {
            "content" => Internal::Util.base64_encode(signature),
            "publicKey" => {
              "content" => Internal::Util.base64_encode(cert.to_pem)
            }
          },
          "data" => {
            "hash" => {
              "algorithm" => algorithm,
              "value" => Internal::Util.hex_encode(hashed_input.digest)
            }
          }
        },
        "kind" => "hashedrekord",
        "apiVersion" => "0.0.1"
      }
    end

    def submit_signed_metadata_to_transparency_service(signature, cert, hashed_input)
      # The Signer chooses a format for signing metadata; this format MUST be in the supportedMetadataFormats in the
      # Transparency Service configuration. The Signer prepares signing metadata containing at a minimum:
      # * The signature.
      # * The payload (possibly pre-hashed; if so, the entry also includes the identifier of the hash algorithm).
      # * Verification material (signing certificate or verification key).
      #   * If the verification material is a certificate, the client SHOULD upload only the signing certificate and
      #     SHOULD NOT upload the CA certificate chain.
      #
      # The signing metadata might contain additional, application-specific metadata according to the format used.
      # The Signer then canonically encodes the metadata (according to the chosen format).

      # TODO: allow configuring the entry kind?
      proposed_entry = build_proposed_hashed_rekord_entry(signature, cert, hashed_input)

      ctlog = @trusted_root.tlog_for_signing
      logger.info { "Submitting to #{ctlog.base_url}" }

      # The signer MUST verify the log entry as in Spec: Transparency Service.
      @verifier.rekor_client.log.entries.post(proposed_entry)
    end

    def verify(artifact, bundle)
      verification_input = Verification::V1::Input.new
      verification_input.bundle = bundle
      verification_input.artifact = Verification::V1::Artifact.new
      verification_input.artifact.artifact = artifact

      result = @verifier.verify(
        input: VerificationInput.new(verification_input),
        policy: expected_identity,
        offline: false
      )
      raise Error::Signing, "Failed to verify: #{result.reason}" unless result.verified?
    end

    def expected_identity
      Policy::Identity.new(identity: @identity_token.identity, issuer: @identity_token.issuer)
    end

    def collect_bundle(leaf_certificate, tlog_entries, timestamp_verification_data, hashed_input, signature)
      bundle = Bundle::V1::Bundle.new
      bundle.media_type = BundleType::BUNDLE_0_3.media_type
      bundle.verification_material = Bundle::V1::VerificationMaterial.new
      bundle.verification_material.certificate = Common::V1::X509Certificate.new
      bundle.verification_material.certificate.raw_bytes = leaf_certificate.to_der
      bundle.verification_material.tlog_entries = tlog_entries
      bundle.verification_material.timestamp_verification_data = timestamp_verification_data
      bundle.message_signature = Sigstore::Common::V1::MessageSignature.new.tap do |ms|
        ms.message_digest = hashed_input
        ms.signature = signature
      end
      bundle
    end

    def collect_dsse_bundle(leaf_certificate, tlog_entries, timestamp_verification_data,
                            payload_type, payload, signature)
      bundle = Bundle::V1::Bundle.new
      bundle.media_type = BundleType::BUNDLE_0_3.media_type
      bundle.verification_material = Bundle::V1::VerificationMaterial.new
      bundle.verification_material.certificate = Common::V1::X509Certificate.new
      bundle.verification_material.certificate.raw_bytes = leaf_certificate.to_der
      bundle.verification_material.tlog_entries = tlog_entries
      bundle.verification_material.timestamp_verification_data = timestamp_verification_data
      bundle.dsse_envelope = DSSE::Envelope.new.tap do |env|
        env.payloadType = payload_type
        env.payload = payload
        env.signatures = [
          DSSE::Signature.new.tap { |s| s.sig = signature }
        ]
      end
      bundle
    end

    def build_proposed_intoto_entry(statement_payload, signature, cert)
      {
        "apiVersion" => "0.0.2",
        "kind" => "intoto",
        "spec" => {
          "content" => {
            "envelope" => {
              "payloadType" => "application/vnd.in-toto+json",
              "payload" => Internal::Util.base64_encode(Internal::Util.base64_encode(statement_payload)),
              "signatures" => [
                {
                  "publicKey" => Internal::Util.base64_encode(
                    "-----BEGIN CERTIFICATE-----\n" \
                    "#{Internal::Util.base64_encode(cert.to_der)}\n" \
                    "-----END CERTIFICATE-----\n"
                  ),
                  "sig" => Internal::Util.base64_encode(Internal::Util.base64_encode(signature))
                }
              ]
            },
            "payloadHash" => {
              "algorithm" => "sha256",
              "value" => OpenSSL::Digest::SHA256.hexdigest(statement_payload)
            },
            "hash" => {
              "algorithm" => "sha256",
              "value" => "" # Will be set by Rekor
            }
          }
        }
      }
    end
  end
end
