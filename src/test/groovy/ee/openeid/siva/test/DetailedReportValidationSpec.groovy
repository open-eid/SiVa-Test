/*
 * Copyright 2024 - 2024 Riigi Infosüsteemi Amet
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

package ee.openeid.siva.test

import ee.openeid.siva.common.DateTimeMatcher
import ee.openeid.siva.test.model.*
import ee.openeid.siva.test.request.RequestData
import ee.openeid.siva.test.request.SivaRequests
import io.qameta.allure.Description
import io.qameta.allure.Link
import org.hamcrest.core.Every
import spock.lang.Ignore

import java.time.ZoneId
import java.time.ZonedDateTime

import static ee.openeid.siva.common.DssMessages.*
import static ee.openeid.siva.integrationtest.TestData.*
import static org.hamcrest.Matchers.*

@Link("http://open-eid.github.io/SiVa/siva3/interfaces/#validation-response-interface")
class DetailedReportValidationSpec extends GenericSpecification {

    @Description("Detailed report includes validationConclusion element and its values")
    def "Given detailed report, then it includes validationConclusion element"() {
        expect:
        ZonedDateTime testStartDate = ZonedDateTime.now(ZoneId.of("GMT"))

        SivaRequests.validate(RequestData.validationRequest("ValidLiveSignature.asice", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", equalTo(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", equalTo(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", equalTo(SignaturePolicy.POLICY_4.url))
                .body("signatureForm", equalTo(ContainerFormat.ASiC_E))
                .body("validationTime", DateTimeMatcher.isEqualOrAfter(testStartDate))
                .body("signaturesCount", equalTo(1))
                .body("validSignaturesCount", equalTo(1))
                .body("signatures", notNullValue())
                .body("signatures.id[0]", equalTo("S0"))
                .body("signatures.signatureFormat[0]", equalTo(SignatureFormat.XAdES_BASELINE_LT))
                .body("signatures.signatureLevel[0]", equalTo(SignatureLevel.QESIG))
                .body("signatures.signedBy[0]", equalTo("NURM,AARE,38211015222"))
                .body("signatures.indication[0]", equalTo(SignatureIndication.TOTAL_PASSED))
                .body("signatures.signatureScopes[0].name[0]", equalTo("Tresting.txt"))
                .body("signatures.signatureScopes[0].scope[0]", equalTo(SIGNATURE_SCOPE_FULL))
                .body("signatures.signatureScopes[0].content[0]", equalTo(VALID_SIGNATURE_SCOPE_CONTENT_FULL))
                .body("signatures.claimedSigningTime[0]", equalTo("2016-10-11T09:35:48Z"))
                .body("signatures.info.bestSignatureTime[0]", equalTo("2016-10-11T09:36:10Z"))
    }

    @Ignore
    //TODO: New test LOTL is needed with correct data
    @Description("Detailed report includes tlanalysis element and its values")
    def "Given detailed report, then it includes tlanalysis element"() {
        expect:

        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_PROCESS_PREFIX)
                .body("tlanalysis", notNullValue())
                .body("tlanalysis.constraint", notNullValue())
                .body("tlanalysis[0]", notNullValue())
                .body("tlanalysis[0].constraint[0]", notNullValue())
                .body("tlanalysis[0].constraint[0].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_1))
                .body("tlanalysis[0].constraint[0].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_1))
                .body("tlanalysis[0].constraint[0].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[0]", notNullValue())
                .body("tlanalysis[0].constraint[1]", notNullValue())
                .body("tlanalysis[0].constraint[1].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_2))
                .body("tlanalysis[0].constraint[1].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_2))
                .body("tlanalysis[0].constraint[1].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[0].constraint[2]", notNullValue())
                .body("tlanalysis[0].constraint[2].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_3))
                .body("tlanalysis[0].constraint[2].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_3))
                .body("tlanalysis[0].constraint[2].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[0].constraint[3]", notNullValue())
                .body("tlanalysis[0].constraint[3].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_4))
                .body("tlanalysis[0].constraint[3].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_4))
                .body("tlanalysis[0].constraint[3].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[0].conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("tlanalysis[0].countryCode", equalTo("EU"))
                .body("tlanalysis[1]", notNullValue())
                .body("tlanalysis[1].constraint[0]", notNullValue())
                .body("tlanalysis[1].constraint[0].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_1))
                .body("tlanalysis[1].constraint[0].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_1))
                .body("tlanalysis[1].constraint[0].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[1]", notNullValue())
                .body("tlanalysis[1].constraint[1]", notNullValue())
                .body("tlanalysis[1].constraint[1].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_2))
                .body("tlanalysis[1].constraint[1].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_2))
                .body("tlanalysis[1].constraint[1].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[1]", notNullValue())
                .body("tlanalysis[1].constraint[2]", notNullValue())
                .body("tlanalysis[1].constraint[2].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_3))
                .body("tlanalysis[1].constraint[2].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_3))
                .body("tlanalysis[1].constraint[2].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[1]", notNullValue())
                .body("tlanalysis[1].constraint[3]", notNullValue())
                .body("tlanalysis[1].constraint[3].name.nameId", equalTo(VALID_VALIDATION_PROCESS_NAMEID_4))
                .body("tlanalysis[1].constraint[3].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_4))
                .body("tlanalysis[1].constraint[3].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("tlanalysis[1].conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("tlanalysis[1].countryCode", equalTo("EE"))
    }

    @Ignore("SIVA-499")
    //TODO: This test misses validationSignatureQualification block
    @Description("Detailed report includes signatures element and its sub-elements and its values")
    def "Given detailed report, then it includes signatures element and its sub-elements"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-ec256.pdf", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_PROCESS_PREFIX + "signatureOrTimestampOrCertificate[0].")
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IFCRC.getKey()))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IISCRC.getKey()))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IVCIRC.getKey()))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IXCVRC.getKey()))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_ICVRC.getKey()))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_ISAVRC.getKey()))
                .body("validationProcessBasicSignature.constraint.status", Every.everyItem(equalTo("OK")))
                .body("validationProcessBasicSignature.constraint[0].id", notNullValue())
                .body("validationProcessBasicSignature.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("validationProcessBasicSignature.conclusion.errors", nullValue())

                .body("timestamps[0].validationProcessTimestamp.constraint.name.key", hasItem(BSV_IISCRC.getKey()))
                .body("timestamps[0].validationProcessTimestamp.constraint.name.key", hasItem(BSV_IXCVRC.getKey()))
                .body("timestamps[0].validationProcessTimestamp.constraint.name.key", hasItem(BSV_ICVRC.getKey()))
                .body("timestamps[0].validationProcessTimestamp.constraint.name.key", hasItem(BSV_ISAVRC.getKey()))
                .body("timestamps[0].validationProcessTimestamp.constraint.status", Every.everyItem(equalTo("OK")))
                .body("timestamps[0].validationProcessTimestamp.constraint[0].id", notNullValue())
                .body("timestamps[0].validationProcessTimestamp.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("timestamps[0].validationProcessTimestamp.conclusion.errors", nullValue())
                .body("timestamps[0].id", notNullValue())
                .body("timestamps[0].validationProcessTimestamp.type", equalTo("SIGNATURE_TIMESTAMP"))

                .body("validationProcessLongTermData.constraint.name.key", hasItem(LTV_ABSV.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'LTV_ABSV'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(BBB_XCV_IRDPFC.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'BBB_XCV_IRDPFC'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(BBB_XCV_IARDPFC.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'BBB_XCV_IARDPFC'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(BBB_SAV_DMICTSTMCMI.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'BBB_SAV_DMICTSTMCMI'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(ADEST_IBSVPTC.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'ADEST_IBSVPTC'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(TSV_IBSTAIDOSC.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'ADEST_IBSVPTC'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(TSV_ASTPTCT.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'TSV_ASTPTCT'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(BBB_SAV_ISQPSTP.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'BBB_SAV_ISQPSTP'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(ADEST_ISTPTDABST.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'ADEST_ISTPTDABST'}.status", equalTo("IGNORED"))
                .body("validationProcessLongTermData.constraint.name.key", hasItem(BBB_SAV_ISVA.getKey()))
                .body("validationProcessLongTermData.constraint.find {it.name.key == 'BBB_SAV_ISVA'}.status", equalTo("OK"))
                .body("validationProcessLongTermData.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("validationProcessLongTermData.conclusion.errors", nullValue())

                .body("validationProcessArchivalData.constraint.name.key", hasItem(ARCH_LTVV.getKey()))
                .body("validationProcessArchivalData.constraint.find {it.name.key == 'ARCH_LTVV'}.status", equalTo("OK"))
                .body("validationProcessArchivalData.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("validationProcessArchivalData.conclusion.errors", nullValue())
    }

    @Description("Detailed report includes basicBuildingBlocks element and its sub-elements and its values")
    def "Given detailed report, then it includes basicBuildingBlocks element, when type timestamp"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_PROCESS_PREFIX)
                .body("basicBuildingBlocks[1].isc.constraint[0].name.value", equalTo(VALID_VALIDATION_PROCESS_VALUE_9))
                .body("basicBuildingBlocks[1].isc.constraint[0].name.key", equalTo(VALID_VALIDATION_PROCESS_NAMEID_9))
                .body("basicBuildingBlocks[1].isc.constraint[0].status", equalTo(VALID_VALIDATION_PROCESS_STATUS_2))
                .body("basicBuildingBlocks[1].isc.conclusion.", notNullValue())
                .body("basicBuildingBlocks[1].isc.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[1].isc.certificateChain.chainItem[0].source", equalTo("TRUSTED_LIST"))
                .body("basicBuildingBlocks[1].isc.certificateChain.chainItem[0].id", notNullValue())
                .body("basicBuildingBlocks[1].cv.constraint.name.key", hasItems(BBB_CV_TSP_IRDOF.getKey(), BBB_CV_TSP_IRDOI.getKey(), BBB_CV_ISIT.getKey()))
                .body("basicBuildingBlocks[1].cv.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[1].cv.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[1].sav.constraint.name.key", Every.everyItem(equalTo(ACCM.getKey())))
                .body("basicBuildingBlocks[1].sav.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[1].sav.constraint[0].additionalInfo", notNullValue())
                .body("basicBuildingBlocks[1].sav.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[1].xcv.constraint.name.key", hasItems(BBB_XCV_CCCBB.getKey(), BBB_XCV_SUB.getKey()))
                .body("basicBuildingBlocks[1].xcv.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[1].xcv.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[1].xcv.subXCV[0].conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[1].xcv.subXCV[0].id", notNullValue())
                .body("basicBuildingBlocks[1].xcv.subXCV[0].trustAnchor", equalTo(true))
                .body("basicBuildingBlocks[1].certificateChain.chainItem[0].source", equalTo("TRUSTED_LIST"))
                .body("basicBuildingBlocks[1].certificateChain.chainItem[0].id", notNullValue())
                .body("basicBuildingBlocks[1].conclusion", notNullValue())
                .body("basicBuildingBlocks[1].conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[1].id", notNullValue())
                .body("basicBuildingBlocks[1].type", equalTo("TIMESTAMP"))
    }

    @Description("Detailed report includes basicBuildingBlocks element and its sub-elements and its values")
    def "Given detailed report, then it includes basicBuildingBlocks element, when type revocation"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_PROCESS_PREFIX)
                .body("basicBuildingBlocks[0].isc.constraint.name.key", hasItem(BBB_ICS_ISCI.getKey()))
                .body("basicBuildingBlocks[0].isc.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[0].isc.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[0].isc.certificateChain.chainItem[0].source", equalTo("TRUSTED_LIST"))
                .body("basicBuildingBlocks[0].isc.certificateChain.chainItem[0].id", notNullValue())
                .body("basicBuildingBlocks[0].cv.constraint.name.key", hasItem(BBB_CV_ISIR.getKey()))
                .body("basicBuildingBlocks[0].cv.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[0].cv.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[0].sav.constraint.name.key", hasItem(ACCM.getKey()))
                .body("basicBuildingBlocks[0].sav.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[0].sav.constraint[0].additionalInfo", notNullValue())
                .body("basicBuildingBlocks[0].sav.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[0].xcv.constraint.name.key", hasItems(BBB_XCV_CCCBB.getKey(), BBB_XCV_SUB.getKey()))
                .body("basicBuildingBlocks[0].xcv.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[0].xcv.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[0].xcv.subXCV[0].conclusion", notNullValue())
                .body("basicBuildingBlocks[0].xcv.subXCV[0].conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[0].xcv.subXCV[0].id", notNullValue())
                .body("basicBuildingBlocks[0].xcv.subXCV[0].trustAnchor", equalTo(true))
                .body("basicBuildingBlocks[0].certificateChain.chainItem[0].source", equalTo("TRUSTED_LIST"))
                .body("basicBuildingBlocks[0].certificateChain.chainItem[0].id", notNullValue())
                .body("basicBuildingBlocks[0].conclusion", notNullValue())
                .body("basicBuildingBlocks[0].conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[0].id", notNullValue())
                .body("basicBuildingBlocks[0].type", equalTo("REVOCATION"))
    }

    //TODO SIVA-349 needs investigation why the signature source is determined as OTHER not as SIGNATURE
    @Description("Detailed report includes basicBuildingBlocks element and its sub-elements and its values")
    def "Given detailed report, then it includes basicBuildingBlocks element, when type signature"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("pades-baseline-lta-live-aj.pdf", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_PROCESS_PREFIX)
                .body("basicBuildingBlocks[3].isc.constraint.name.key", hasItem(BBB_ICS_ISCI.getKey()))
                .body("basicBuildingBlocks[3].isc.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[3].isc.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
        //.body("basicBuildingBlocks[3].isc.certificateChain.chainItem[0].source", equalTo("SIGNATURE"))
                .body("basicBuildingBlocks[3].isc.certificateChain.chainItem[0].id", notNullValue())
                .body("basicBuildingBlocks[3].cv.constraint.name.key", hasItem(BBB_CV_IRDOF.getKey()))
                .body("basicBuildingBlocks[3].cv.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[3].cv.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[3].sav.constraint[0].name.value", notNullValue())
                .body("basicBuildingBlocks[3].sav.constraint.name.key", hasItems(BBB_SAV_ISSV.getKey(), BBB_SAV_ISQPSTP.getKey(), BBB_SAV_ISQPMDOSPP.getKey(), ACCM.getKey()))
                .body("basicBuildingBlocks[3].sav.constraint.status", Every.everyItem(equalTo("OK")))
                .body("basicBuildingBlocks[3].sav.constraint.additionalInfo", notNullValue())
                .body("basicBuildingBlocks[3].sav.conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[3].xcv.constraint.name.key", hasItems(BBB_XCV_CCCBB.getKey(), BBB_XCV_SUB.getKey()))
                .body("basicBuildingBlocks[3].xcv.constraint.find { it.name.key == 'BBB_XCV_CCCBB' }.status", equalTo("OK"))
                .body("basicBuildingBlocks[3].xcv.constraint.find { it.name.key == 'BBB_XCV_SUB' }.status", equalTo("NOT_OK"))
                .body("basicBuildingBlocks[3].xcv.conclusion.indication", equalTo(SignatureIndication.INDETERMINATE))
                .body("basicBuildingBlocks[3].xcv.subXCV[1].conclusion.indication", equalTo(VALID_INDICATION_VALUE_PASSED))
                .body("basicBuildingBlocks[3].xcv.subXCV[1].id", notNullValue())
                .body("basicBuildingBlocks[3].xcv.subXCV[1].trustAnchor", equalTo(true))
        //.body("basicBuildingBlocks[3].certificateChain.chainItem[0].source", equalTo("SIGNATURE"))
                .body("basicBuildingBlocks[3].certificateChain.chainItem[0].id", notNullValue())
                .body("basicBuildingBlocks[3].conclusion.indication", equalTo(SignatureIndication.INDETERMINATE))
                .body("basicBuildingBlocks[3].id", notNullValue())
                .body("basicBuildingBlocks[3].type", equalTo("SIGNATURE"))
    }

    @Description("Detailed report includes wrong signature value")
    def "Given detailed report, then it includes wrong signature value"() {
        expect:

        SivaRequests.validate(RequestData.validationRequest("TS-02_23634_TS_wrong_SignatureValue.asice", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_PROCESS_PREFIX + "signatureOrTimestampOrEvidenceRecord[0]")
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IFCRC.getKey()))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_IFCRC' }.status", equalTo("OK"))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_IFCRC' }.id", notNullValue())
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IISCRC.getKey()))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_IISCRC' }.status", equalTo("OK"))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IVCIRC.getKey()))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_IVCIRC' }.status", equalTo("OK"))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IXCVRC.getKey()))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_IXCVRC' }.status", equalTo("WARNING"))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_ISCRAVTC.getKey()))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_ISCRAVTC' }.status", equalTo("OK"))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_IVTAVRSC.getKey()))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_IVTAVRSC' }.status", equalTo("WARNING"))
                .body("validationProcessBasicSignature.constraint.name.key", hasItem(BSV_ICVRC.getKey()))
                .body("validationProcessBasicSignature.constraint.find { it.name.key == 'BSV_ICVRC' }.status", equalTo("NOT_OK"))
                .body("validationProcessBasicSignature.conclusion.indication", equalTo(VALID_INDICATION_VALUE_FAILED))
                .body("validationProcessBasicSignature.conclusion.subIndication", equalTo(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("validationProcessBasicSignature.conclusion.errors.key", hasItem(BBB_XCV_SUB_ANS.getKey()))
                .body("validationProcessBasicSignature.conclusion.errors.find { it.key == 'BBB_XCV_SUB_ANS' }.value", equalTo(BBB_XCV_SUB_ANS.getValue()))
                .body("validationProcessBasicSignature.conclusion.errors.key", hasItem(BBB_XCV_ICTIVRSC_ANS.getKey()))
                .body("validationProcessBasicSignature.conclusion.errors.find { it.key == 'BBB_XCV_ICTIVRSC_ANS' }.value", equalTo(BBB_XCV_ICTIVRSC_ANS.getValue()))
                .body("validationProcessBasicSignature.conclusion.errors.key", hasItem(BBB_CV_ISI_ANS.getKey()))
                .body("validationProcessBasicSignature.conclusion.errors.find { it.key == 'BBB_CV_ISI_ANS' }.value", equalTo(BBB_CV_ISI_ANS.getValue()))

                .body("timestamps[0].validationProcessBasicTimestamp.constraint.name.key", hasItem(BSV_IISCRC.getKey()))
                .body("timestamps[0].validationProcessBasicTimestamp.constraint.find { it.name.key == 'BSV_IISCRC' }.status", equalTo("OK"))
                .body("timestamps[0].validationProcessBasicTimestamp.constraint.find { it.name.key == 'BSV_IISCRC' }.id", notNullValue())
                .body("timestamps[0].validationProcessBasicTimestamp.constraint.name.key", hasItem(BSV_IXCVRC.getKey()))
                .body("timestamps[0].validationProcessBasicTimestamp.constraint.find { it.name.key == 'BSV_IXCVRC' }.status", equalTo("OK"))
                .body("timestamps[0].validationProcessBasicTimestamp.constraint.name.key", hasItem(BSV_IXCVRC.getKey()))
                .body("timestamps[0].validationProcessBasicTimestamp.constraint.find { it.name.key == 'BSV_ICVRC' }.status", equalTo("NOT_OK"))
                .body("timestamps[0].validationProcessBasicTimestamp.conclusion.indication", equalTo("FAILED"))
                .body("timestamps[0].validationProcessBasicTimestamp.conclusion.subIndication", equalTo(SUB_INDICATION_HASH_FAILURE))
                .body("timestamps[0].validationProcessBasicTimestamp.conclusion.errors.key", hasItem(BBB_CV_TSP_IRDOI_ANS.getKey()))
                .body("timestamps[0].validationProcessBasicTimestamp.conclusion.errors.value", hasItem(BBB_CV_TSP_IRDOI_ANS.getValue()))
                .body("timestamps[0].id", notNullValue())
                .body("timestamps[0].validationProcessBasicTimestamp.type", equalTo("SIGNATURE_TIMESTAMP"))

                .body("timestamps[0].validationProcessArchivalDataTimestamp.conclusion.indication", equalTo("FAILED"))
                .body("timestamps[0].validationProcessArchivalDataTimestamp.conclusion.subIndication", equalTo(SUB_INDICATION_HASH_FAILURE))
                .body("timestamps[0].validationProcessArchivalDataTimestamp.conclusion.errors.key", hasItem(BBB_CV_TSP_IRDOI_ANS.getKey()))
                .body("timestamps[0].validationProcessArchivalDataTimestamp.conclusion.errors.value", hasItem(BBB_CV_TSP_IRDOI_ANS.getValue()))
                .body("timestamps[0].validationProcessArchivalDataTimestamp.constraint.name.key", hasItem("ARCH_IRTVBBA"))
                .body("timestamps[0].validationProcessArchivalDataTimestamp.constraint.find { it.name.key == 'ARCH_IRTVBBA' }.status", equalTo("NOT_OK"))

                .body("validationProcessLongTermData.constraint.name.key", hasItem(LTV_ABSV.getKey()))
                .body("validationProcessLongTermData.constraint.find { it.name.key == 'LTV_ABSV' }.status", equalTo("NOT_OK"))
                .body("validationProcessLongTermData.constraint.error.key", hasItem(LTV_ABSV_ANS.getKey()))
                .body("validationProcessLongTermData.conclusion.indication", equalTo("FAILED"))
                .body("validationProcessLongTermData.conclusion.subIndication", equalTo(SUB_INDICATION_SIG_CRYPTO_FAILURE))
                .body("validationProcessLongTermData.conclusion.errors.key", hasItem(BBB_XCV_SUB_ANS.getKey()))
                .body("validationProcessLongTermData.conclusion.errors.find { it.key == 'BBB_XCV_SUB_ANS' }.value", equalTo(BBB_XCV_SUB_ANS.getValue()))
                .body("validationProcessLongTermData.conclusion.errors.key", hasItem(BBB_XCV_ICTIVRSC_ANS.getKey()))
                .body("validationProcessLongTermData.conclusion.errors.find { it.key == 'BBB_XCV_ICTIVRSC_ANS' }.value", equalTo(BBB_XCV_ICTIVRSC_ANS.getValue()))
    }

    @Description("Wrong data file in manifest")
    def "Given wrong datafile in manifest, then detailed report"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("WrongDataFileInManifestAsics.asics", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_CONCLUSION_PREFIX)
                .body("policy.policyDescription", equalTo(SignaturePolicy.POLICY_4.description))
                .body("policy.policyName", equalTo(SignaturePolicy.POLICY_4.name))
                .body("policy.policyUrl", equalTo(SignaturePolicy.POLICY_4.url))
                .body("signatureForm", equalTo(ContainerFormat.ASiC_S))
                .body("signaturesCount", equalTo(1))
                .body("validSignaturesCount", equalTo(1))
    }

    @Ignore("SIVA-196")
    @Description("Validate detailed report file hash if ReportSignatureEnabled value true. Result: fileHash calculated")
    def "Given reportSignatureEnabled true, then fileHash is calculated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa2048.pdf", null, ReportType.DETAILED))
                .then()
                .body("validationReport.validationConclusion.validatedDocument.filename", equalTo("hellopades-lt-sha256-rsa2048.pdf"))
                .body("validationReport.validationConclusion.validatedDocument.fileHash", notNullValue())
                .body("validationReport.validationConclusion.validatedDocument.hashAlgo", equalTo("SHA256"))
                .body("validationReportSignature", notNullValue())
    }

    @Ignore
    //TODO: Needs possibility to configure report signing in tests
    @Description("Validate detailed report file hash if ReportSignatureEnabled value false. Result: fileHash not calculated")
    def "Given reportSignatureEnabled false, then fileHash is not calculated"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("hellopades-lt-sha256-rsa2048.pdf", null, ReportType.DETAILED))
                .then()
                .body("validationReport.validationConclusion.validatedDocument.filename", equalTo("hellopades-lt-sha256-rsa2048.pdf"))
                .body("validationReport.validationConclusion.validatedDocument.fileHash", nullValue())
                .body("validationReport.validationConclusion.validatedDocument.hashAlgo", nullValue())
                .body("validationReportSignature", nullValue())
    }

    @Description("Warning \"The trusted certificate does not match the trust service!\" is not filtered out and is present in Detailed Report")
    def "Given detailed report, then trust service warning is not filtered out"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("validTsSignatureWithRolesAndProductionPlace.asice", null, ReportType.DETAILED))
                .then().rootPath(VALIDATION_PROCESS_PREFIX + "signatureOrTimestampOrEvidenceRecord.validationSignatureQualification.")
                .body("conclusion.warnings.key[0]", hasItem(QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.getKey()))
                .body("conclusion.warnings.value[0]", hasItem(QUAL_IS_TRUST_CERT_MATCH_SERVICE_ANS2.getValue()))
    }

    @Description("Error \"The certificate is not related to a granted status at time-stamp lowest POE time!\" is displayed in Detailed Report and signature is TOTAL-PASSED")
    def "Given detailed report, then lowest POE time error not filtered out"() {
        expect:
        SivaRequests.validate(RequestData.validationRequest("IB-4183_3.4kaart_RSA2047_TS.asice", null, ReportType.DETAILED))
                .then().rootPath("validationReport.")
                .body(VALIDATION_PROCESS_TS_PREFIX + "conclusion[0][0].indication", equalTo("PASSED"))
                .body(VALIDATION_PROCESS_TS_PREFIX + "validationTimestampQualification.conclusion.errors.key[0][0]", hasItem(QUAL_HAS_GRANTED_AT_ANS.getKey()))
                .body(VALIDATION_PROCESS_TS_PREFIX + "validationTimestampQualification.conclusion.errors.value[0][0]", hasItem(QUAL_HAS_GRANTED_AT_ANS.getValue()))
                .body("validationConclusion.signatures[0].indication", equalTo(SignatureIndication.TOTAL_PASSED))
    }
}
