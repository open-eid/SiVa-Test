/*
 * Copyright 2024 - 2025 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence")
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the Licence is
 * distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 */

package ee.openeid.siva.test.model

enum SignaturePolicy {
    POLICY_3(
            name: "POLv3",
            url: "http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv3",
            description: """Policy for validating Electronic Signatures and Electronic Seals \
regardless of the legal type of the signature or seal (according to Regulation (EU) No 910/2014, aka eIDAS), \
i.e. the fact that the electronic signature or electronic seal is either Advanced electronic Signature (AdES), \
AdES supported by a Qualified Certificate (AdES/QC) or a Qualified electronic Signature (QES) does not change \
the total validation result of the signature. Signatures which are not compliant with ETSI standards (referred by \
Regulation (EU) No 910/2014) may produce unknown or invalid validation result. Validation process is based on \
eIDAS Article 32, Commission Implementing Decision (EU) 2015/1506 and referred ETSI standards."""
    ),
    POLICY_4(
            name: "POLv4",
            url: "http://open-eid.github.io/SiVa/siva3/appendix/validation_policy/#POLv4",
            description: """Policy according most common requirements of Estonian Public \
Administration, to validate Qualified Electronic Signatures and Electronic Seals with Qualified Certificates \
(according to Regulation (EU) No 910/2014, aka eIDAS). I.e. signatures that have been recognized as Advanced \
electronic Signatures (AdES) and AdES supported by a Qualified Certificate (AdES/QC) do not produce a positive \
validation result, with exception for seals, where AdES/QC and above will produce positive result. Signatures \
and Seals which are not compliant with ETSI standards (referred by eIDAS) may produce unknown or invalid validation \
result. Validation process is based on eIDAS Article 32 and referred ETSI standards."""
    )

    final String name
    final String url
    final String description

    SignaturePolicy(Map<String, String> params) {
        this.name = params.name
        this.url = params.url
        this.description = params.description
    }

    static SignaturePolicy determineValidationPolicy(def signaturePolicy) {
        if (signaturePolicy == null) {
            return POLICY_4
        }

        SignaturePolicy policy = values().find { it.name == signaturePolicy.toString() }

        if (policy) {
            return policy
        }

        throw new IllegalArgumentException("Unknown validation policy '${signaturePolicy}'")
    }

    @Override
    String toString() {
        return name
    }
}
