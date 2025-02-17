/*
 * Copyright 2024 - 2025 Riigi Infosüsteemi Amet
 *
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
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

enum DssMessage {

    BSV_IFCRC("BSV_IFCRC", "Is the result of the 'Format Checking' building block conclusive?"),
    BSV_IISCRC("BSV_IISCRC", "Is the result of the 'Identification of Signing Certificate' building block conclusive?"),
    BSV_IVCIRC("BSV_IVCIRC", "Is the result of the 'Validation Context Initialization' building block conclusive?"),
    BSV_IXCVRC("BSV_IXCVRC", "Is the result of the 'X.509 Certificate Validation' building block conclusive?"),
    BSV_ISCRAVTC("BSV_ISCRAVTC", "Is the signing certificate not revoked at validation time?"),
    BSV_IVTAVRSC("BSV_IVTAVRSC", "Is the validation time in the validity range of the signing certificate?"),
    BSV_ICVRC("BSV_ICVRC", "Is the result of the 'Cryptographic Verification' building block conclusive?"),
    BSV_ISAVRC("BSV_ISAVRC", "Is the result of the 'Signature Acceptance Validation' building block conclusive?"),

    BBB_XCV_CCCBB("BBB_XCV_CCCBB", "Can the certificate chain be built till a trust anchor?"),
    BBB_XCV_SUB("BBB_XCV_SUB", "Is the certificate validation conclusive?"),
    BBB_XCV_SUB_ANS("BBB_XCV_SUB_ANS", "The certificate validation is not conclusive!"),
    BBB_XCV_ICTIVRSC_ANS("BBB_XCV_ICTIVRSC_ANS", "The current time is not in the validity range of the signer's certificate!"),
    BBB_CV_ISI_ANS("BBB_CV_ISI_ANS", "The signature is not intact!"),
    BBB_CV_TSP_IRDOI_ANS("BBB_CV_TSP_IRDOI_ANS", "The time-stamp message imprint is not intact!"),
    BBB_CV_TSP_IRDOF("BBB_CV_TSP_IRDOF", "Has the message imprint data been found?"),
    BBB_CV_TSP_IRDOI("BBB_CV_TSP_IRDOI", "Is the message imprint data intact?"),
    BBB_CV_ISIT("BBB_CV_ISIT", "Is time-stamp's signature intact?"),
    BBB_CV_ISIR("BBB_CV_ISIR", "Is revocation's signature intact?"),
    BBB_ICS_ISCI("BBB_ICS_ISCI", "Is there an identified candidate for the signing certificate?"),
    BBB_CV_IRDOF("BBB_CV_IRDOF", "Has the reference data object been found?"),
    BBB_SAV_ISSV("BBB_SAV_ISSV", "Is the structure of the signature valid?"),
    BBB_SAV_ISQPSTP("BBB_SAV_ISQPSTP", "Is the signed qualifying property: 'signing-time' present?"),
    BBB_SAV_ISQPMDOSPP("BBB_SAV_ISQPMDOSPP", "Is the signed qualifying property: 'message-digest' or 'SignedProperties' present?"),
    BBB_SAV_DMICTSTMCMI("BBB_SAV_DMICTSTMCMI", "Does the message-imprint match the computed value?"),
    BBB_SAV_ISVA("BBB_SAV_ISVA", "Is the signature acceptable?"),
    BBB_XCV_IRDPFC("BBB_XCV_IRDPFC", "Is the revocation data present for the certificate?"),
    BBB_XCV_RAC("BBB_XCV_RAC", "Is the revocation acceptance check conclusive?"),
    BBB_XCV_IARDPFC("BBB_XCV_IARDPFC", "Is an acceptable revocation data present for the certificate?"),

    LTV_ABSV("LTV_ABSV", "Is the result of the Basic Validation Process acceptable?"),
    LTV_ABSV_ANS("LTV_ABSV_ANS", "The result of the Basic validation process is not acceptable to continue the process!"),

    ACCM("ACCM", "Are cryptographic constraints met for the {0}?"),

    ADEST_RORPIIC("ADEST_RORPIIC", "Is the result of the revocation data basic validation process acceptable?"),
    ADEST_IBSVPTC("ADEST_IBSVPTC", "Is the result of basic time-stamp validation process conclusive?"),
    ADEST_ISTPTDABST("ADEST_ISTPTDABST", "Is the signing-time plus the time-stamp delay after best-signature-time?"),

    ARCH_LTVV("ARCH_LTVV", "Is the result of the LTV validation process acceptable?"),

    TSV_ASTPTCT("TSV_ASTPTCT", "Are the time-stamps in the right order?"),
    TSV_IBSTAIDOSC("TSV_IBSTAIDOSC", "Is the best-signature-time not before the issuance date of the signing certificate?"),
    QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2("QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2", "The trusted certificate does not match the trust service!"),
    QUAL_HAS_GRANTED_AT_ANS("QUAL_HAS_GRANTED_AT_ANS", "The certificate is not related to a granted status at time-stamp lowest POE time!"),


    final String key
    final String message

    DssMessage(String key, String message) {
        this.key = key
        this.message = message
    }
}
