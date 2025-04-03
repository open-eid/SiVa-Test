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

package ee.openeid.siva.test.validate.asics

import ee.openeid.siva.test.GenericSpecification
import ee.openeid.siva.test.model.ContainerFormat
import ee.openeid.siva.test.model.SignatureFormat
import ee.openeid.siva.test.model.SignatureIndication
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description

import static ee.openeid.siva.test.TestData.VALIDATION_CONCLUSION_PREFIX
import static org.hamcrest.Matchers.*

class AsicsValidationPassSpec extends GenericSpecification {

    @Description("Validation of ASICs with DDOC inside")
    def "validDdocInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ddocWithRoleAndSigProductionPlace.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].info.bestSignatureTime", is("2009-06-01T10:46:42Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Test"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("eesti"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("ei tea"))
                .body("signatures[0].info.signatureProductionPlace.city", is("tõrva"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is(" "))
                .body("signatures[0].signedBy", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].commonName", is("ESTEID-SK 2007 OCSP RESPONDER"))
                .body("signatures[0].certificates.findAll{it.type == 'REVOCATION'}[0].content", startsWith("MIIDnDCCAoSgAwIBAgIERZ0acjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].commonName", is("SOONSEIN,SIMMO,38508134916"))
                .body("signatures[0].certificates.findAll{it.type == 'SIGNING'}[0].content", startsWith("MIID3zCCAsegAwIBAgIER4JChjANBgkqhkiG9w0BAQUFADBbMQ"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY 2020"))
                .body("timeStampTokens[0].signedTime", is("2020-06-02T11:18:22Z"))
                .body("timeStampTokens[0].certificates[0].commonName", is("SK TIMESTAMPING AUTHORITY 2020"))
                .body("timeStampTokens[0].certificates[0].type", is("CONTENT_TIMESTAMP"))
                .body("timeStampTokens[0].certificates[0].content", startsWith("MIIEFjCCAv6gAwIBAgIQYjZ9dFrZQ6tdpFC5Xj/6bjANBgkqhk"))
                .body("validatedDocument.filename", is("ddocWithRoleAndSigProductionPlace.asics"))
                .body("signaturesCount", is(3))
                .body("validSignaturesCount", is(3))
    }

    // SIVA-761 needs a new container (with SCS extension, but check the nested container type relevance)
    @Description("Validation of ASICs with DDOC inside SCS extension")
    def "validDdocInsideValidAsicsScsExtension"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsics.scs"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("ValidDDOCinsideAsics.scs"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2000/09/xmldsig#rsa-sha1"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", is("2012-10-03T07:46:51Z"))
                .body("signatures[0].signedBy", is("LUKIN,LIISA,47710110274"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    // SIVA-761 needs a new container (with signerRole and signatureProductionPlace info?)
    @Description("Validation of ASICs with BDOC inside")
    def "validBdocInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidBDOCinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("ValidBDOCinsideAsics.asics"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[0].signatureMethod", is("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].info.bestSignatureTime", is("2016-05-11T10:18:06Z"))
                .body("signatures[0].info.signerRole[0].claimedRole", is("Signer / Proper signature"))
                .body("signatures[0].info.signatureProductionPlace.countryName", is("Estonia"))
                .body("signatures[0].info.signatureProductionPlace.stateOrProvince", is("Harju"))
                .body("signatures[0].info.signatureProductionPlace.city", is("Tallinn"))
                .body("signatures[0].info.signatureProductionPlace.postalCode", is("22333"))
                .body("signatures[0].signedBy", is("NURM,AARE,38211015222"))
                .body("signatures[0].subjectDistinguishedName.serialNumber", is("38211015222"))
                .body("signatures[0].subjectDistinguishedName.commonName", is("NURM,AARE,38211015222"))
                .body("signatures[1].signatureFormat", is(SignatureFormat.XAdES_BASELINE_LT_TM))
                .body("signatures[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[1].info.bestSignatureTime", is("2016-05-11T10:19:38Z"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(2))
                .body("validSignaturesCount", is(2))
    }

    // SIVA-761 needs a new container
    @Description("Validation of ASICs with text document inside")
    def "textInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("TXTinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-25T09:56:33Z"))
                .body("validSignaturesCount", is(0))
                .body("signaturesCount", is(0))
                .body("validatedDocument.filename", is("TXTinsideAsics.asics"))
    }

    // SIVA-761 needs a new container
    @Description("Validation of ASICs with ASICs inside")
    def "asicsInsideValidAsics"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidASICSinsideAsics.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-25T11:24:01Z"))
                .body("validatedDocument.filename", is("ValidASICSinsideAsics.asics"))
    }

    // SIVA-761 needs a new container (with ZIP extension, but check the nested container type relevance)
    @Description("Validation of ASICs with DDOC inside ZIP extension")
    def "ValidDdocInsideValidAsicsZipExtension"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsics.zip"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", is("2012-10-03T07:46:51Z"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("validatedDocument.filename", is("ValidDDOCinsideAsics.zip"))
    }

    // SIVA-761 needs a new container (with wrong mimetype - consider relocating under MimetypeValidationSpec
    @Description("Validation of ASICs with wrong mimetype with DDOC inside")
    def "ValidDdocInsideValidAsicsWrongMimeType"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("ValidDDOCinsideAsicsWrongMime.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("ValidDDOCinsideAsicsWrongMime.asics"))
                .body("signatures[0].signatureFormat", is(SignatureFormat.DIGIDOC_XML_1_3))
                .body("signatures[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("signatures[0].claimedSigningTime", is("2012-10-03T07:46:31Z"))
                .body("signatures[0].info.bestSignatureTime", is("2012-10-03T07:46:51Z"))
                .body("timeStampTokens[0].indication", is("TOTAL-PASSED"))
                .body("timeStampTokens[0].signedBy", is("SK TIMESTAMPING AUTHORITY"))
                .body("timeStampTokens[0].signedTime", is("2017-08-10T12:40:40Z"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
    }

    static def sk = [name: "SK", indication: SignatureIndication.TOTAL_PASSED, signedBy  : "DEMO SK TIMESTAMPING UNIT 2025E"]
    static def baltstamp = [name: "Baltstamp", indication: SignatureIndication.TOTAL_PASSED, signedBy  : "BalTstamp QTSA TSU1"]
    static def entrust = [name: "Entrust", indication: SignatureIndication.TOTAL_FAILED, signedBy  : "Entrust Timestamp Authority - TSA1"]

    @Description("Validation of ASiC-S timestamped with different timestamps")
    def "Validating ASiC-S timestamped first with #first and then with #second"() {
        given:
        String fileName = "2xTst-${first.name}+${second.name}.asics"
        expect:
        SivaRequests.validate(RequestData.validationRequest(fileName))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is(fileName))
                .body("signaturesCount", is(0))

                .body("timeStampTokens[0].indication", is(first.indication))
                .body("timeStampTokens[0].signedBy", is(first.signedBy))
                .body("timeStampTokens[0].timestampScopes.findAll{it.scope=='FULL'}.name", is(["test.txt"]))
                .body("timeStampTokens[0].timestampScopes.findAll{it.scope=='ARCHIVED'}.name", is(empty()))

                .body("timeStampTokens[1].indication", is(second.indication))
                .body("timeStampTokens[1].signedBy", is(second.signedBy))
                .body("timeStampTokens[1].timestampScopes.findAll{it.scope=='FULL'}.name",
                        is(["META-INF/ASiCArchiveManifest.xml", "META-INF/timestamp.tst", "test.txt"]))
                .body("timeStampTokens[0].timestampScopes.findAll{it.scope=='ARCHIVED'}.name", is(empty()))

        where:
        first     | second
        sk        | baltstamp
        sk        | entrust
        baltstamp | sk
        baltstamp | baltstamp
        entrust   | sk
    }

    @Description("Validation of ASiC-S with timestamp not covering datafile/nested container")
    def "Validating ASiC-S with timestamp not covering #targetFile, then warning is returned#comment"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(fileName))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is(fileName))
                .body("signaturesCount", is(0))
                .body("timeStampTokens[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("timeStampTokens[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[1].warning.size()", is(1))
                .body("timeStampTokens[1].warning[0].content", is("The time-stamp token does not cover container datafile!"))
                .body('$', not(hasKey("signatures")))
                .body("timeStampTokens.collectMany{it.timestampScopes.findAll{it.scope=='ARCHIVED'}.name}", is(empty()))

        where:
        fileName                                                         | targetFile                 || comment
        "2xTstFirstInvalidSecondNotCoveringDatafile.asics"               | "datafile"                 || ""
        "2xTstFirstInvalidSecondNotCoveringNestedTimestampedAsics.asics" | "nested timestamped asics" || " and nested container is not validated"
        "2xTstFirstInvalidSecondNotCoveringNestedSignedAsics.asics"      | "nested signed asics"      || " and nested container is not validated"
        "2xTstFirstInvalidSecondNotCoveringNestedSignedAsice.asics"      | "nested signed asice"      || " and nested container is not validated"
    }

    @Description("Validation of composite ASiC-S with at least one valid covering timestamp")
    def "Validating composite ASiC-S with one valid covering timestamp, then nested timestamped container is validated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2xTstFirstInvalidSecondCoveringNestedContainer.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("2xTstFirstInvalidSecondCoveringNestedContainer.asics".toString()))
                .body("signaturesCount", is(0))
                .body("timeStampTokens[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("timeStampTokens[0].timestampScopes.findAll{it.scope=='ARCHIVED'}.name", is(empty()))

                .body("timeStampTokens[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[1].warning", emptyOrNullString())
                .body("timeStampTokens[1].timestampScopes.findAll{it.scope=='FULL'}.name",
                        is(["META-INF/ASiCArchiveManifest.xml", "META-INF/timestamp.tst", "ValidAsics.asics"]))

                .body("timeStampTokens[1].timestampScopes.findAll{it.scope=='ARCHIVED'}.name",
                        is(["mimetype", "META-INF/manifest.xml", "test.txt", "META-INF/timestamp.tst"]))
    }

    @Description("Validation of composite ASiC-S with at least one valid covering timestamp")
    def "Validating composite ASiC-S with at least one valid covering timestamp, then nested timestamped container is validated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("2xTstFirstValidSecondNotCoveringNestedContainer.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("2xTstFirstValidSecondNotCoveringNestedContainer.asics".toString()))
                .body("signaturesCount", is(0))
                .body("timeStampTokens[0].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[0].warning", emptyOrNullString())
                .body("timeStampTokens[0].timestampScopes.findAll{it.scope=='ARCHIVED'}.name",
                        is(["mimetype", "META-INF/manifest.xml", "test.txt", "META-INF/timestamp.tst"]))
                .body("timeStampTokens[1].warning.size()", is(1))
                .body("timeStampTokens[1].warning[0].content", is("The time-stamp token does not cover container datafile!"))
                .body("timeStampTokens[1].timestampScopes.findAll{it.scope=='ARCHIVED'}.name", is(empty()))
    }

    @Description("Validation of composite ASiC-S with at least one valid covering timestamp")
    def "Validating composite ASiC-S with at least one valid covering timestamp, then nested signed container is validated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("3xTST-valid-bdoc-data-file-1st-tst-invalid-2nd-tst-no-coverage-3rd-tst-valid.asics"))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", is(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", is("3xTST-valid-bdoc-data-file-1st-tst-invalid-2nd-tst-no-coverage-3rd-tst-valid.asics"))
                .body("signaturesCount", is(1))
                .body("validSignaturesCount", is(1))
                .body("timeStampTokens[0].indication", is(SignatureIndication.TOTAL_FAILED))
                .body("timeStampTokens[1].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[2].indication", is(SignatureIndication.TOTAL_PASSED))
                .body("timeStampTokens[0].warning", emptyOrNullString())
                .body("timeStampTokens[1].warning.size()", is(1))
                .body("timeStampTokens[1].warning[0].content", is("The time-stamp token does not cover container datafile!"))
                .body("timeStampTokens[1].timestampScopes.findAll{it.scope=='ARCHIVED'}.name", is(empty()))
                .body("timeStampTokens[2].warning", emptyOrNullString())
                .body("timeStampTokens[2].timestampScopes.findAll{it.scope=='ARCHIVED'}.name",
                        is(["mimetype", "META-INF/manifest.xml", "test.txt", "META-INF/signatures0.xml"]))
    }

    @Description("All signature profiles in container are validated")
    def "Given validation request with ASiC-S #profile signature, then validation report is returned"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest(file))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("signatureForm", equalTo(ContainerFormat.ASiC_S))
                .body("validatedDocument.filename", equalTo(file))
                .body("signatures[0].signatureFormat", is(profile))

        where:
        profile                            | file
        SignatureFormat.CAdES_BASELINE_B   | "TEST_ESTEID2018_ASiC-S_CAdES_B.scs"
        SignatureFormat.CAdES_BASELINE_T   | "TEST_ESTEID2018_ASiC-S_CAdES_T.scs"
        SignatureFormat.CAdES_BASELINE_LT  | "TEST_ESTEID2018_ASiC-S_CAdES_LT.scs"
        SignatureFormat.CAdES_BASELINE_LTA | "TEST_ESTEID2018_ASiC-S_CAdES_LTA.scs"
        SignatureFormat.XAdES_BASELINE_B   | "TEST_ESTEID2018_ASiC-S_XAdES_B.scs"
        SignatureFormat.XAdES_BASELINE_T   | "TEST_ESTEID2018_ASiC-S_XAdES_T.scs"
        SignatureFormat.XAdES_BASELINE_LT  | "TEST_ESTEID2018_ASiC-S_XAdES_LT.scs"
        SignatureFormat.XAdES_BASELINE_LTA | "TEST_ESTEID2018_ASiC-S_XAdES_LTA.scs"
    }
}
