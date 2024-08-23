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
}
